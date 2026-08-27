//! src/kernel/network/stack/dispatch.rs
//!
//! Tick maintenance, polling, and protocol-layer demux for [`NetworkStack`].

use core::sync::atomic::Ordering;

use crate::kernel::network::internet::fragments;
use crate::kernel::network::internet::icmp;
use crate::kernel::network::internet::icmpv6;
use crate::kernel::network::internet::igmp;
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::IpProtocol;
use crate::kernel::network::internet::ipv4::Ipv4Header;
use crate::kernel::network::internet::ipv4::{self};
use crate::kernel::network::internet::ipv6::Ipv6Header;
use crate::kernel::network::internet::ipv6::Ipv6NextHeader;
use crate::kernel::network::internet::ipv6::{self};
use crate::kernel::network::internet::mld;
use crate::kernel::network::link::ethernet::EtherType;
use crate::kernel::network::link::ethernet::{self};
use crate::kernel::network::mdns;
use crate::kernel::network::mrouting::pim;
use crate::kernel::network::net_profiler::NetProfilerSnapshot;
use crate::kernel::network::ntp;
use crate::kernel::network::ppp;
use crate::kernel::network::pppoe::PppoePhase;
use crate::kernel::network::udp;
#[cfg(not(test))]
use crate::util::sync_unsafe_cell::SyncUnsafeCell;
use crate::Error;
use crate::Result;

#[cfg(target_os = "none")]
use crate::kernel::network::dhcp::LeaseState;

use super::NetworkStack;

/// Maximum receive buffer size for `poll()`.
const RX_BUFFER_SIZE: usize = 2048;

/// Reusable receive buffer shared across all `poll()` calls.
///
/// Using a static buffer avoids a 2 KiB stack allocation on every `poll()`
/// invocation.  `poll()` is inherently serialised on bare-metal (single-core
/// with global kernel lock), so a global buffer is safe there.
///
/// In test builds the buffer lives on the stack so that parallel test threads
/// do not race on a shared static — `cargo test --lib` runs tests concurrently
/// and each thread must have its own receive buffer.
///
/// # SMP future-proofing
///
/// When the kernel gains SMP support this buffer must be replaced with a
/// per-CPU allocation (or wrapped in a spinlock-protected ownership
/// handoff) to avoid data races between cores polling different devices
/// concurrently.
#[cfg(not(test))]
static RX_BUFFER: SyncUnsafeCell<[u8; RX_BUFFER_SIZE]> = SyncUnsafeCell::new([0u8; RX_BUFFER_SIZE]);

impl NetworkStack {
    /// Return a point-in-time snapshot of the network stack profiler
    /// counters.  When the `net_profiler` feature is disabled this
    /// returns all zeros.
    pub fn profiler_snapshot(&self) -> NetProfilerSnapshot {
        self.profiler.snapshot()
    }

    /// Advance the tick counter by one and run periodic protocol-layer
    /// maintenance.  Called from the scheduler tick ISR (100 Hz).
    ///
    /// This drives:
    /// - ARP cache entry eviction (stale entries beyond 6 s TTL).
    /// - TCP retransmission checks and TimeWait→Closed expiry.
    /// - DHCP lease renewal state transitions
    ///   (Bound→Renewing→Rebinding→Expired).
    pub fn advance_tick(&self) {
        let tick = self.ticks.fetch_add(1, Ordering::Relaxed) + 1;

        // Evict stale ARP cache entries.
        self.arp_cache.lock().evict_expired(tick);

        // Evict stale DNS cache entries (every tick — cheap when empty).
        #[cfg(target_os = "none")]
        crate::kernel::network::dns::evict_expired(tick);

        // Run retransmit / TimeWait checks for every TCP connection.
        let pending = self.tcp_table.lock().tick_maintenance(self);
        // Send any retransmitted segments after releasing the table lock.
        for (dst_ip, seg) in pending {
            let _ = crate::kernel::network::tcp::send_tcp_segment(self, dst_ip, &seg);
        }

        // ── Fragment reassembly eviction ────────────────────────────
        {
            let mut frag_cache = self.fragment_cache.lock();
            fragments::evict_expired_fragments(&mut frag_cache, tick);
        }

        // ── NAT connection-tracking expiry sweep ───────────────────
        self.nat_table.lock().sweep_expired(tick);

        // ── Packet filter flow-table expiry sweep ──────────────────
        self.filter_table.lock().sweep_expired(tick);

        // ── IPv6 fragment reassembly eviction ──────────────────────
        {
            let mut frag_cache = self.ipv6_fragment_cache.lock();
            fragments::evict_expired_ipv6_fragments(&mut frag_cache, tick);
        }

        // ── NTP periodic poll ──────────────────────────────────────
        {
            let mut ntp = self.ntp_client.lock();
            if ntp.should_poll(tick) {
                // Build an NTP request.  If we have the server's IP
                // address we can send it; otherwise skip this cycle.
                // The IP is resolved via DNS at first successful poll.
                if let Some(server_ip) = ntp.server_ip() {
                    if let Some(rtc_secs) = crate::arch::timer::rtc_now_unix() {
                        let request = ntp.build_request(rtc_secs, 0);
                        let raw_ip = udp::build_udp_ipv4_packet(
                            self.local_ip(),
                            server_ip,
                            ntp::NTP_PORT,
                            ntp::NTP_PORT,
                            &request.to_bytes(),
                        );
                        let _ = self.send_ipv4_packet(server_ip, raw_ip);
                        self.last_ntp_poll
                            .store(tick, core::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }

        // ── mDNS periodic tick (probe/announce/goodbye) ─────────────
        {
            let mut mdns = self.mdns_responder.lock();
            if let Some(mdns_packet) = mdns.tick(tick) {
                // Send mDNS packet to the link-local multicast group.
                use crate::kernel::network::internet::ipv4::IpProtocol;
                use crate::kernel::network::internet::ipv4::Ipv4Header;
                use crate::kernel::network::internet::ipv4::IPV4_DEFAULT_TTL;
                let reply_header = Ipv4Header {
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0,
                    ttl: IPV4_DEFAULT_TTL,
                    protocol: IpProtocol::Udp,
                    header_checksum: 0,
                    source: self.local_ip(),
                    destination: mdns::MDNS_IPV4_ADDR,
                };
                let raw_ip = ipv4::build_packet(&reply_header, &mdns_packet);
                let _ = self.send_ipv4_packet(mdns::MDNS_IPV4_ADDR, raw_ip);
            }
        }

        // ── IGMP / MLD periodic maintenance ──────────────────────────
        {
            let mut igmp_state = self.igmp_state.lock();
            let igmp_pending = igmp::igmp_tick_maintenance(self, &mut igmp_state);
            drop(igmp_state);
            for (ip_header, raw) in igmp_pending {
                let mut hdr = ip_header;
                hdr.source = self.local_ip();
                let raw_ip = ipv4::build_packet(&hdr, &raw);
                let _ = self.send_ipv4_packet(hdr.destination, raw_ip);
            }
        }
        {
            let mut mld_state = self.mld_state.lock();
            let mld_pending = mld::mld_tick_maintenance(self, &mut mld_state);
            drop(mld_state);
            for (ip_header, raw) in mld_pending {
                let raw_ip = ipv6::build_packet(&ip_header, &raw);
                let _ = self.send_ipv6_packet(ip_header.destination, raw_ip);
            }
        }

        // ── Multicast routing (PIM-DM) maintenance ────────────────────
        // Age out stale PIM prune entries and neighbor state.
        self.mrt().lock().tick(tick, self);

        // ── DHCP lease renewal check ─────────────────────────────────
        #[cfg(target_os = "none")]
        {
            let should_renew = {
                let lease = self.dhcp_lease.lock();
                if let Some(ref dhcp) = *lease {
                    let started = *self.dhcp_lease_started_at.lock();
                    let elapsed = tick.wrapping_sub(started);

                    let mut state = self.dhcp_renew_state.lock();
                    *state = if elapsed >= dhcp.lease_ticks {
                        LeaseState::Expired
                    } else if elapsed >= dhcp.rebinding_ticks {
                        LeaseState::Rebinding
                    } else if elapsed >= dhcp.renewal_ticks {
                        LeaseState::Renewing
                    } else {
                        LeaseState::Bound
                    };
                    *state == LeaseState::Renewing || *state == LeaseState::Rebinding
                } else {
                    false
                }
            }; // all locks dropped here — safe to call try_renew_lease
            if should_renew {
                crate::kernel::network::dhcp::try_renew_lease();
            }
        }

        // ── PPPoE periodic maintenance ─────────────────────────────────
        // Auto-establish the session (PADI with retransmit while in
        // Discovery) and, once PADS assigns a session, drive the PPP LCP
        // keepalive over the established session.  Zero-cost while the
        // PPPoE consumer is disabled.
        if self.pppoe_enabled() {
            let local_mac = self.local_mac;
            let discovery_frame = {
                let mut session = self.pppoe.lock();
                match session.phase {
                    PppoePhase::Idle => session.start_discovery(local_mac, tick).ok(),
                    PppoePhase::Discovery => session.tick(local_mac, tick),
                    PppoePhase::Session => None,
                }
            };
            if let Some(frame) = discovery_frame {
                let _ = self.device.send(&frame);
            }
            if self.pppoe.lock().in_session() {
                if let Some(echo) = {
                    let mut ppp_state = self.ppp_state.lock();
                    ppp_state.tick(tick)
                } {
                    let _ = self.send_ppp_packet(ppp::PPP_PROTO_LCP, &echo);
                }
            }
        }
    }

    /// Poll the network device for one received frame and process it
    /// through the protocol stack.
    ///
    /// Returns `Ok(true)` when a frame was processed, `Ok(false)` when no
    /// frame was available, or an error on hardware failure.
    pub fn poll(&self) -> Result<bool> {
        self.profiler.inc_poll_iterations();
        // SAFETY: `poll()` is never called concurrently — the kernel is
        // single-threaded in bare-metal builds.  In test mode the buffer is
        // stack-allocated so parallel test threads get independent buffers.
        #[cfg(test)]
        let mut rx_storage = [0u8; RX_BUFFER_SIZE];
        #[cfg(not(test))]
        let buffer = unsafe { &mut *RX_BUFFER.get() };
        #[cfg(test)]
        let buffer = &mut rx_storage;
        match self.device.receive(buffer) {
            Ok(0) => {
                self.profiler.inc_poll_rx_empty();
                Ok(false)
            }
            Ok(n) => {
                // Parse Ethernet frame and demux by EtherType.
                let frame = ethernet::parse_frame(&buffer[..n])?;
                match frame.ethertype {
                    EtherType::Arp => {
                        let arp_packet = crate::kernel::network::internet::arp::parse_arp_packet(
                            &frame.payload,
                        )?;
                        crate::kernel::network::internet::arp::process_arp_packet(
                            self,
                            &arp_packet,
                        )?;
                    }
                    EtherType::Ipv4 => {
                        let ip_packet = match ipv4::parse_packet(&frame.payload) {
                            Ok(pkt) => {
                                self.profiler.inc_ipv4_packets_rx();
                                pkt
                            }
                            Err(e) => {
                                if e == Error::DeviceError {
                                    self.profiler.inc_ipv4_checksum_errors();
                                }
                                return Err(e);
                            }
                        };
                        // ── Destination validation ──────────────────────
                        // Only process packets addressed to a local
                        // interface, a broadcast address, or multicast.
                        // Foreign-addressed packets are dropped before they
                        // can trigger replies, ICMP errors, or ARP traffic.
                        if !self.ipv4_destination_is_local(ip_packet.header.destination) {
                            return Ok(true); // silently drop
                        }
                        // ── Fragment reassembly ─────────────────────────
                        let ip_packet = {
                            let mut frag_cache = self.fragment_cache.lock();
                            match fragments::process_ipv4_fragment(
                                &mut frag_cache,
                                &ip_packet,
                                self.current_tick(),
                            ) {
                                Some(reassembled) => reassembled,
                                None => {
                                    // Fragment buffered — don't process further.
                                    return Ok(true);
                                }
                            }
                        };

                        // ── NAT inbound reverse translation (DNAT) ────────
                        // If NAT is enabled and this packet is addressed to
                        // our external IP, restore the original destination.
                        let ip_packet = {
                            let raw = ipv4::build_packet(&ip_packet.header, &ip_packet.payload);
                            let mut nat_table = self.nat_table.lock();
                            match nat_table.dnat_ipv4(&raw, self.current_tick()) {
                                Some(dnat_bytes) => {
                                    self.profiler.inc_nat_translations();
                                    match ipv4::parse_packet(&dnat_bytes) {
                                        Ok(pkt) => pkt,
                                        Err(_) => return Ok(true), // malformed after DNAT
                                    }
                                }
                                None => {
                                    // NAT is enabled, but this packet did not
                                    // match a reverse-NAT (DNAT) translation
                                    // entry.  Only drop it when it was actually
                                    // addressed to our external IP — that is a
                                    // genuine DNAT miss for the public address.
                                    // Packets addressed to any other
                                    // destination are unrelated to NAT and must
                                    // fall through to normal delivery rather
                                    // than being silently dropped.
                                    if nat_table.is_enabled()
                                        && ip_packet.header.destination == nat_table.external_ip()
                                    {
                                        return Ok(true);
                                    }
                                    // NAT not enabled, or the packet is not
                                    // addressed to the external IP — use the
                                    // original packet.
                                    ip_packet
                                }
                            }
                        };

                        // ── Packet filter: inbound check (IPv4) ──────────
                        {
                            let mut filter = self.filter_table.lock();
                            if !filter.check_inbound(
                                &ip_packet.header,
                                &ip_packet.payload,
                                self.local_ip(),
                                self.current_tick(),
                            ) {
                                // Packet dropped by filter.
                                return Ok(true);
                            }
                        }

                        // ── Raw socket delivery (IPv4) ─────────────────
                        {
                            let proto = ip_packet.header.protocol.to_u8();
                            let mut raw_sockets = self.raw_sockets.lock();
                            for sock in raw_sockets.values_mut() {
                                if sock.protocol == proto {
                                    let _ = sock.deliver(
                                        IpAddress::V4(ip_packet.header.source),
                                        IpAddress::V4(ip_packet.header.destination),
                                        &ip_packet.payload,
                                    );
                                }
                            }
                        }

                        // Protocol dispatch uses an else-if chain because each
                        // IPv4 packet belongs to exactly one protocol.  Testing
                        // all three sequentially would waste work: every TCP
                        // segment would first fail ICMP parsing, every UDP
                        // datagram would fail both ICMP and TCP parsing.
                        if ip_packet.header.protocol == ipv4::IpProtocol::Icmp {
                            if let Some((mut reply_header, reply_data)) = icmp::process_icmp_packet(
                                &ip_packet.payload,
                                ip_packet.header.source,
                            )? {
                                self.profiler.inc_icmp_echo_replies();
                                reply_header.source = self.local_ip();
                                let raw = ipv4::build_packet(&reply_header, &reply_data);
                                let _ = self.send_ipv4_packet(ip_packet.header.source, raw);
                            }
                            // Dispatch incoming Echo Replies (type 0) to
                            // registered pending pings.
                            if let Ok(icmp_hdr) = icmp::parse_icmp_header(&ip_packet.payload) {
                                if icmp_hdr.icmp_type == icmp::ICMP_TYPE_ECHO_REPLY {
                                    icmp::dispatch_echo_reply(
                                        ip_packet.header.source,
                                        icmp_hdr.rest_of_header,
                                        self.current_tick(),
                                    );
                                }
                            }
                            // Extract embedded packet info from ICMP error
                            // messages and update profiling counters.
                            if let Some(_err) = icmp::parse_icmp_error_info(&ip_packet.payload) {
                                self.profiler.inc_icmp_unreachable();
                                // TODO: notify the affected TCP/UDP connection
                                // using _err.original_{src,dst,protocol,
                                // src_port,dst_port}.
                            }
                        } else if ip_packet.header.protocol == ipv4::IpProtocol::Igmp {
                            let mut igmp_state = self.igmp_state.lock();
                            let replies = igmp::process_igmp_message(
                                self,
                                ip_packet.header.source,
                                &ip_packet.payload,
                                &mut igmp_state,
                            );
                            drop(igmp_state);
                            for (mut reply_header, reply_data) in replies {
                                reply_header.source = self.local_ip();
                                let raw = ipv4::build_packet(&reply_header, &reply_data);
                                let _ = self.send_ipv4_packet(reply_header.destination, raw);
                            }
                        } else if ip_packet.header.protocol
                            == ipv4::IpProtocol::Unknown(pim::PIM_PROTOCOL)
                        {
                            // ── PIM dispatch (IP protocol 103) ────────────────
                            // PIM-DM control messages (Hello / Join-Prune /
                            // Graft) reach the multicast-routing control plane.
                            // The MRT state lock is taken and released here;
                            // `on_pim_packet` does not take any other lock.
                            let mut mrt = self.mrt.lock();
                            let _ = pim::on_pim_packet(
                                self,
                                &mut mrt,
                                IpAddress::V4(ip_packet.header.source),
                                &ip_packet.payload,
                            );
                        } else if ip_packet.header.protocol == ipv4::IpProtocol::Tcp {
                            let pending = {
                                let mut table = self.tcp_table.lock();
                                crate::kernel::network::tcp::process_segment(
                                    &mut table,
                                    self,
                                    ip_packet.header.source,
                                    ip_packet.header.destination,
                                    &ip_packet.payload,
                                )?
                            }; // table lock released — safe to send now
                            for (dst_ip, seg) in pending {
                                let _ = crate::kernel::network::tcp::send_tcp_segment(
                                    self, dst_ip, &seg,
                                );
                            }
                        } else if ip_packet.header.protocol == ipv4::IpProtocol::Udp {
                            if let Ok(udp_dgram) = udp::parse_datagram(&ip_packet.payload) {
                                // ── mDNS handler (UDP port 5353) ───────────
                                if udp_dgram.header.destination_port == mdns::MDNS_PORT {
                                    let mut mdns_responder = self.mdns_responder.lock();
                                    if let Some(reply) =
                                        mdns_responder.handle_packet(&udp_dgram.payload)
                                    {
                                        let raw_ip = udp::build_udp_ipv4_packet(
                                            self.local_ip(),
                                            ip_packet.header.source,
                                            mdns::MDNS_PORT,
                                            udp_dgram.header.source_port,
                                            &reply,
                                        );
                                        let _ =
                                            self.send_ipv4_packet(ip_packet.header.source, raw_ip);
                                    }
                                    // mDNS packets are handled; also deliver to
                                    // any
                                    // bound socket listening on port 5353.
                                }
                                // ── NTP response handler (UDP port 123) ────
                                if udp_dgram.header.destination_port == ntp::NTP_PORT {
                                    if let Some(rtc_secs) = crate::arch::timer::rtc_now_unix() {
                                        if let Ok(response) =
                                            ntp::NtpPacket::from_bytes(&udp_dgram.payload)
                                        {
                                            let mut ntp_client = self.ntp_client.lock();
                                            let _ =
                                                ntp_client.process_response(&response, rtc_secs, 0);
                                        }
                                    }
                                }
                                let delivered = self.udp_table.lock().deliver(
                                    ip_packet.header.source,
                                    udp_dgram.header.source_port,
                                    udp_dgram.header.destination_port,
                                    udp_dgram.payload,
                                );
                                if delivered {
                                    self.profiler.inc_udp_datagrams_rx();
                                } else {
                                    self.profiler.inc_udp_dropped();
                                    // Port unreachable — ICMP Destination Unreachable.
                                    // The UDP table lock is already released (the
                                    // temporary MutexGuard from .lock() is dropped),
                                    // so this respects lock ordering.
                                    self.profiler.inc_icmp_unreachable();
                                    let icmp_msg = icmp::build_dest_unreachable(
                                        &ip_packet.header,
                                        &ip_packet.payload,
                                    );
                                    let reply_header = Ipv4Header {
                                        total_length: 0,
                                        identification: 0,
                                        flags_fragment_offset: 0,
                                        ttl: ipv4::IPV4_DEFAULT_TTL,
                                        protocol: IpProtocol::Icmp,
                                        header_checksum: 0,
                                        source: self.local_ip(),
                                        destination: ip_packet.header.source,
                                    };
                                    let raw = ipv4::build_packet(&reply_header, &icmp_msg);
                                    let _ = self.send_ipv4_packet(ip_packet.header.source, raw);
                                }
                            }
                        } else if ip_packet.header.protocol == ipv4::IpProtocol::Sctp {
                            // ── SCTP dispatch (IP protocol 132)
                            // ───────────────── For
                            // v1 we look up the association by the SCTP common
                            // header ports.  The association table is
                            // per-stack; a
                            // full implementation would maintain a global
                            // table. Here we simply
                            // pass the payload up to a registered
                            // handler stub (raw delivery via raw sockets
                            // already handles it
                            // for protocol 132 above).
                            //
                            // In the future this will dispatch to the SCTP
                            // association table.
                            //
                            // Currently SCTP packets are delivered to any raw
                            // socket bound to protocol 132 (handled above).
                            // The association layer can be integrated by
                            // maintaining a port-based association table
                            // similar to TcpConnectionTable.
                        }
                    }
                    EtherType::Ipv6 => {
                        let ip_packet = ipv6::parse_packet(&frame.payload)?;
                        self.profiler.inc_ipv6_packets_rx();

                        // ── Destination validation ──────────────────────
                        // Only process packets addressed to a local
                        // interface or multicast; foreign-addressed packets
                        // are dropped before any reply or NDP activity.
                        if !self.ipv6_destination_is_local(ip_packet.header.destination) {
                            return Ok(true); // silently drop
                        }
                        // ── IPv6 fragment reassembly ────────────────────
                        // If the next header is a Fragment extension header,
                        // reassemble before dispatching.
                        let (ipv6_next_header, ipv6_payload) =
                            if ip_packet.header.next_header == Ipv6NextHeader::Fragment {
                                // Parse the Fragment extension header from the payload.
                                if let Ok((frag_header, consumed)) =
                                    ipv6::parse_fragment_header(&ip_packet.payload)
                                {
                                    let frag_payload = &ip_packet.payload[consumed..];
                                    let mut frag_cache = self.ipv6_fragment_cache.lock();
                                    match fragments::process_ipv6_fragment(
                                        &mut frag_cache,
                                        &frag_header,
                                        frag_payload,
                                        ip_packet.header.source,
                                        ip_packet.header.destination,
                                        self.current_tick(),
                                    ) {
                                        Some((next_header, reassembled)) => {
                                            self.profiler.inc_ipv6_fragment_reassembled();
                                            (Ipv6NextHeader::from_u8(next_header), reassembled)
                                        }
                                        None => {
                                            // Fragment buffered — stop processing.
                                            return Ok(true);
                                        }
                                    }
                                } else {
                                    // Malformed fragment header — drop.
                                    self.profiler.inc_fragment_errors();
                                    return Ok(true);
                                }
                            } else {
                                (ip_packet.header.next_header, ip_packet.payload.clone())
                            };

                        // ── Extension header chain traversal ────────────
                        // Walk through any Hop-by-Hop, Destination Options,
                        // and Routing headers to reach the final protocol.
                        // (Fragment headers are already handled above.)
                        let (ipv6_next_header, ipv6_payload) = {
                            let mut nh = ipv6_next_header;
                            let mut payload_offset = 0usize;
                            while matches!(
                                nh,
                                Ipv6NextHeader::HopByHop
                                    | Ipv6NextHeader::DestinationOptions
                                    | Ipv6NextHeader::Routing
                            ) {
                                if payload_offset + 2 > ipv6_payload.len() {
                                    return Ok(true); // malformed
                                }
                                let hdr_ext_len =
                                    (ipv6_payload[payload_offset + 1] as usize + 1) * 8;
                                let next_nh = Ipv6NextHeader::from_u8(ipv6_payload[payload_offset]);
                                nh = next_nh;
                                payload_offset += hdr_ext_len;
                                if payload_offset > ipv6_payload.len() {
                                    return Ok(true); // malformed
                                }
                            }
                            (nh, ipv6_payload[payload_offset..].to_vec())
                        };

                        // ── Raw socket delivery (IPv6) ─────────────────
                        {
                            let proto = ipv6_next_header.to_u8();
                            let mut raw_sockets = self.raw_sockets.lock();
                            for sock in raw_sockets.values_mut() {
                                if sock.protocol == proto {
                                    let _ = sock.deliver(
                                        IpAddress::V6(ip_packet.header.source),
                                        IpAddress::V6(ip_packet.header.destination),
                                        &ipv6_payload,
                                    );
                                }
                            }
                        }
                        // Dispatch by Next Header.
                        if ipv6_next_header == Ipv6NextHeader::Icmpv6 {
                            if let Some((reply_header, reply_data)) = icmpv6::process_icmpv6_packet(
                                self,
                                ip_packet.header.source,
                                ip_packet.header.destination,
                                &ipv6_payload,
                            )? {
                                let raw = ipv6::build_packet(&reply_header, &reply_data);
                                let _ = self.send_ipv6_packet(ip_packet.header.source, raw);
                            }
                            // Extract embedded packet info from ICMPv6 error
                            // messages and update profiling counters.
                            if let Some(_err) = icmpv6::parse_icmpv6_error_info(&ipv6_payload) {
                                self.profiler.inc_icmp_unreachable();
                                // TODO: notify the affected TCP/UDP connection
                                // using _err.original_{src,dst,next_header,
                                // src_port,dst_port}.
                            }
                        } else if ipv6_next_header == Ipv6NextHeader::Unknown(pim::PIM_PROTOCOL) {
                            // ── PIM dispatch (IPv6 next header 103) ───────────
                            // PIM messages are identical on the wire for IPv4
                            // and IPv6; route them to the same MRT control plane.
                            let mut mrt = self.mrt.lock();
                            let _ = pim::on_pim_packet(
                                self,
                                &mut mrt,
                                IpAddress::V6(ip_packet.header.source),
                                &ipv6_payload,
                            );
                        } else if ipv6_next_header == Ipv6NextHeader::Tcp {
                            // IPv6 TCP: reuse the existing TCP processing.
                            let pending = {
                                let mut table = self.tcp_table.lock();
                                crate::kernel::network::tcp::process_segment_v6(
                                    &mut table,
                                    self,
                                    ip_packet.header.source,
                                    ip_packet.header.destination,
                                    &ipv6_payload,
                                )?
                            };
                            for (dst_ip, seg) in pending {
                                let _ = crate::kernel::network::tcp::send_tcp_segment_v6(
                                    self, dst_ip, &seg,
                                );
                            }
                        } else if ipv6_next_header == Ipv6NextHeader::Udp {
                            if let Ok(udp_dgram) = udp::parse_datagram(&ipv6_payload) {
                                // ── mDNS handler (UDP port 5353, IPv6) ─────
                                if udp_dgram.header.destination_port == mdns::MDNS_PORT {
                                    let mut mdns_responder = self.mdns_responder.lock();
                                    if let Some(reply) =
                                        mdns_responder.handle_packet(&udp_dgram.payload)
                                    {
                                        let raw_ip =
                                            crate::kernel::network::udp::build_udp_ipv6_packet(
                                                self.local_ip_v6,
                                                ip_packet.header.source,
                                                mdns::MDNS_PORT,
                                                udp_dgram.header.source_port,
                                                &reply,
                                            );
                                        let _ =
                                            self.send_ipv6_packet(ip_packet.header.source, raw_ip);
                                    }
                                }
                                let delivered = self.udp_table.lock().deliver(
                                    ip_packet.header.source,
                                    udp_dgram.header.source_port,
                                    udp_dgram.header.destination_port,
                                    udp_dgram.payload,
                                );
                                if delivered {
                                    self.profiler.inc_udp_datagrams_rx();
                                } else {
                                    self.profiler.inc_udp_dropped();
                                    // Send ICMPv6 Destination Unreachable (port unreachable).
                                    let unreach_body = icmpv6::build_icmpv6_dest_unreachable_for(
                                        self.local_ip_v6,
                                        ip_packet.header.source,
                                        &ipv6_payload,
                                    );
                                    let reply_header = Ipv6Header {
                                        traffic_class: 0,
                                        flow_label: 0,
                                        payload_length: 0,
                                        next_header: Ipv6NextHeader::Icmpv6,
                                        hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
                                        source: self.local_ip_v6,
                                        destination: ip_packet.header.source,
                                    };
                                    let raw = ipv6::build_packet(&reply_header, &unreach_body);
                                    let _ = self.send_ipv6_packet(ip_packet.header.source, raw);
                                }
                            }
                        }
                    }
                    EtherType::PppoeDiscovery | EtherType::PppoeSession => {
                        // PPPoE: drive the discovery handshake, then unwrap
                        // session frames into the PPP protocol stack.
                        self.handle_pppoe_frame(&frame)?;
                    }
                    _ => {
                        // Unknown EtherType — silently drop.
                    }
                }
                Ok(true)
            }
            Err(error) => {
                self.profiler.inc_poll_errors();
                Err(error)
            }
        }
    }

    /// Return `true` if `dst` is addressed to this host: a local interface
    /// address, a broadcast address (limited or subnet-directed), or an IPv4
    /// multicast address.  When NAT is enabled the external (public) address
    /// is also treated as local so inbound DNAT still runs.
    fn ipv4_destination_is_local(&self, dst: ipv4::Ipv4Addr) -> bool {
        if dst == self.local_ip() {
            return true;
        }
        // The NAT external (public) address is this host's address too.
        {
            let nat = self.nat_table.lock();
            if nat.is_enabled() && dst == nat.external_ip() {
                return true;
            }
        }
        // Limited broadcast and subnet-directed broadcast.
        if dst == ipv4::IPV4_BROADCAST {
            return true;
        }
        let mask = self.subnet_mask();
        let local = self.local_ip();
        let mut directed = [0u8; 4];
        for i in 0..4 {
            directed[i] = local[i] | !mask[i];
        }
        if dst == directed {
            return true;
        }
        // IPv4 multicast: 224.0.0.0/4.
        dst[0] & 0xF0 == 0xE0
    }

    /// Return `true` if `dst` is addressed to this host: a local interface
    /// address (link-local or global) or an IPv6 multicast address.
    fn ipv6_destination_is_local(&self, dst: ipv6::Ipv6Addr) -> bool {
        if dst == self.local_ip_v6() {
            return true;
        }
        if self.global_ip_v6().is_some_and(|global| dst == global) {
            return true;
        }
        // IPv6 multicast (covers solicited-node, all-nodes, and MLD groups).
        dst[0] == 0xff
    }
}
