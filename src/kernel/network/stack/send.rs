//! src/kernel/network/stack/send.rs
//! Packet transmission helpers for [`NetworkStack`].

use alloc::vec::Vec;

use crate::kernel::network::internet::ipv4::{self, Ipv4Addr};
use crate::kernel::network::internet::ipv6::{self, Ipv6Addr};
use crate::kernel::network::link::ethernet::{self, EtherType};
use crate::Result;

use super::NetworkStack;

impl NetworkStack {
    /// Send a raw IPv4 packet as an Ethernet broadcast (no ARP resolution).
    ///
    /// The Ethernet destination is set to `ff:ff:ff:ff:ff:ff`.  This is
    /// necessary for protocols like DHCP that must reach a server before the
    /// host has a routable IP address.
    pub fn send_ipv4_broadcast(&self, raw_ip: Vec<u8>) -> Result<()> {
        self.profiler.inc_ipv4_packets_tx();
        let frame = ethernet::EthernetFrame::new(
            ethernet::MacAddress::BROADCAST,
            ethernet::MacAddress(self.local_mac),
            EtherType::Ipv4,
            raw_ip,
        );
        let raw_frame = ethernet::build_frame(&frame)?;
        self.device.send(&raw_frame)
    }

    /// Send an IPv4 packet to `dst_ip`, resolving the MAC address via ARP
    /// and wrapping the packet in an Ethernet frame.
    ///
    /// Consults the routing table: if the destination is reached via a
    /// gateway (non-zero next-hop), ARP resolution targets the gateway's
    /// IP rather than the final destination.
    pub fn send_ipv4_packet(&self, dst_ip: Ipv4Addr, raw_ip: Vec<u8>) -> Result<()> {
        self.profiler.inc_ipv4_packets_tx();
        // ── Packet filter: outbound check ──────────────────────────────
        // The filter sees the original (pre-encapsulation) packet.
        if let Ok(parsed) = ipv4::parse_packet(&raw_ip) {
            let mut filter = self.filter_table.lock();
            if !filter.check_outbound(
                &parsed.header,
                &parsed.payload,
                self.local_ip(),
                self.current_tick(),
            ) {
                // Packet dropped by filter — silently fail.
                return Ok(());
            }
        }
        // ── IPsec outbound transform ───────────────────────────────────
        // ESP/AH may wrap the packet and change its destination (tunnel
        // mode).  `None` means the packet was discarded by SPD policy.
        let (dst_ip, raw_ip) = match crate::kernel::network::ipsec::transform::process_outbound_v4(
            self, dst_ip, raw_ip,
        )? {
            Some(transformed) => transformed,
            None => return Ok(()),
        };
        // ── NAT outbound translation (SNAT) ───────────────────────────
        let raw_ip = {
            let mut nat_table = self.nat_table.lock();
            let translated = nat_table.snat_ipv4(&raw_ip, self.current_tick());
            if translated.is_some() {
                self.profiler.inc_nat_translations();
            }
            translated.unwrap_or(raw_ip)
        };
        // Look up the route: if a gateway is configured, ARP-resolve the
        // gateway instead of the final destination.
        let arp_target = {
            let rt = self.routing_table.lock();
            match rt.lookup(dst_ip) {
                Some((gateway, _)) if gateway != [0, 0, 0, 0] => gateway,
                _ => dst_ip,
            }
        };
        let dst_mac = crate::kernel::network::internet::arp::resolve_mac(self, arp_target)?;
        let frame = ethernet::EthernetFrame::new(
            ethernet::MacAddress(dst_mac.0),
            ethernet::MacAddress(self.local_mac),
            EtherType::Ipv4,
            raw_ip,
        );
        let raw_frame = ethernet::build_frame(&frame)?;
        self.device.send(&raw_frame)
    }

    /// Send an IPv4 packet to a multicast destination using the Ethernet
    /// multicast MAC mapping (no ARP).  Used by the multicast forwarding
    /// engine.
    pub fn send_ipv4_multicast(&self, dst_ip: Ipv4Addr, raw_ip: Vec<u8>) -> Result<()> {
        self.profiler.inc_ipv4_packets_tx();
        let frame = ethernet::EthernetFrame::new(
            ethernet::MacAddress(ipv4::multicast_mac_from_ipv4(dst_ip)),
            ethernet::MacAddress(self.local_mac),
            EtherType::Ipv4,
            raw_ip,
        );
        let raw_frame = ethernet::build_frame(&frame)?;
        self.device.send(&raw_frame)
    }

    /// Send an IPv6 packet to `dst_ip`, resolving the MAC address via NDP
    /// (or using multicast MAC for multicast destinations) and wrapping
    /// the packet in an Ethernet frame.
    pub fn send_ipv6_packet(&self, dst_ip: Ipv6Addr, raw_ip: Vec<u8>) -> Result<()> {
        self.profiler.inc_ipv6_packets_tx();
        // ── IPsec outbound transform (IPv6) ───────────────────────────
        let (dst_ip, raw_ip) = match crate::kernel::network::ipsec::transform::process_outbound_v6(
            self, dst_ip, raw_ip,
        )? {
            Some(transformed) => transformed,
            None => return Ok(()),
        };
        let dst_mac = if dst_ip[0] == 0xff {
            // Multicast: use 33:33:xx:xx:xx:xx mapping.
            ethernet::MacAddress(ipv6::multicast_mac_from_ipv6(dst_ip))
        } else {
            // Unicast: resolve via NDP.
            crate::kernel::network::internet::icmpv6::resolve_mac_v6(self, dst_ip)?
        };

        // ── Path MTU / fragmentation (RFC 8201) ──────────────────────
        // The effective MTU is the minimum of the device MTU, the link MTU
        // learned from Router Advertisements, and any cached per-destination
        // PMTU from an ICMPv6 Packet Too Big.  Oversized packets are
        // fragmented before sending.
        let effective_mtu = {
            let link_mtu = self.link_mtu_v6() as usize;
            let pmtu = self
                .pmtu_cache_v6()
                .lock()
                .lookup(dst_ip)
                .unwrap_or(u32::MAX) as usize;
            self.device().mtu().min(link_mtu).min(pmtu)
        };
        if raw_ip.len() > effective_mtu {
            if let Ok(pkt) = ipv6::parse_packet(&raw_ip) {
                // Derive a fragment identifier from the tick and payload
                // length so same-tick transmissions of different packets
                // still differ.
                let ident = (self.current_tick() as u32) ^ ((raw_ip.len() as u32 & 0xFFFF) << 16);
                if let Some(fragments) =
                    ipv6::fragment_packet(&pkt.header, &pkt.payload, effective_mtu, ident)
                {
                    for fragment in fragments {
                        let frame = ethernet::EthernetFrame::new(
                            dst_mac,
                            ethernet::MacAddress(self.local_mac),
                            EtherType::Ipv6,
                            fragment,
                        );
                        let raw_frame = ethernet::build_frame(&frame)?;
                        self.device.send(&raw_frame)?;
                    }
                    return Ok(());
                }
            }
            // If the packet cannot be parsed or fragmented, fall through and
            // send it unfragmented (best effort).
        }

        let frame = ethernet::EthernetFrame::new(
            dst_mac,
            ethernet::MacAddress(self.local_mac),
            EtherType::Ipv6,
            raw_ip,
        );
        let raw_frame = ethernet::build_frame(&frame)?;
        self.device.send(&raw_frame)
    }
}
