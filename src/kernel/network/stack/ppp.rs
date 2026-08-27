//! src/kernel/network/stack/ppp.rs
//!
//! PPP (Point-to-Point Protocol) integration for [`NetworkStack`].
//!
//! Provides methods for receiving raw PPP frames and sending IP packets
//! encapsulated in PPP framing.  When PPP mode is enabled (by calling
//! [`NetworkStack::receive_ppp_bytes`]), the stack processes PPP-framed
//! data as an alternative to Ethernet framing.

use alloc::vec::Vec;

use crate::kernel::network::internet::fragments;
use crate::kernel::network::internet::icmp;
use crate::kernel::network::internet::icmpv6;
use crate::kernel::network::internet::igmp;
use crate::kernel::network::internet::ipv4::IpProtocol;
use crate::kernel::network::internet::ipv4::Ipv4Header;
use crate::kernel::network::internet::ipv4::IPV4_DEFAULT_TTL;
use crate::kernel::network::internet::ipv4::{self};
use crate::kernel::network::internet::ipv6::Ipv6Header;
use crate::kernel::network::internet::ipv6::Ipv6NextHeader;
use crate::kernel::network::internet::ipv6::{self};
use crate::kernel::network::ppp;
use crate::kernel::network::tcp;
use crate::kernel::network::udp;
use crate::Error;
use crate::Result;

use super::NetworkStack;

impl NetworkStack {
    /// Process incoming PPP-framed bytes and dispatch the encapsulated IP
    /// packet through the protocol stack.
    ///
    /// This is an alternative data path to the Ethernet-based `poll()`.
    /// Callers with a serial / byte-stream device should feed received
    /// bytes to this method.
    ///
    /// Returns `Ok(true)` when a complete PPP frame was processed, or
    /// `Ok(false)` when the frame could not be parsed.  The PPP state
    /// machine handles byte-stuffing, FCS verification, and LCP/IPCP
    /// negotiation internally.
    pub fn receive_ppp_bytes(&self, data: &[u8]) -> Result<bool> {
        // Parse the HDLC-framed PPP frame (unstuff, FCS verify, extract
        // protocol + payload).
        let (protocol, info) = match ppp::ppp_parse_frame(data) {
            Ok((proto, info)) => (proto, info),
            Err(_) => return Ok(false),
        };
        self.dispatch_ppp_protocol(protocol, info)
    }

    /// Dispatch a parsed `(protocol, information)` pair through the PPP
    /// protocol stack.  Framing-agnostic: the HDLC serial path and the PPPoE
    /// session path both land here after unwrapping their transport.
    pub(crate) fn dispatch_ppp_protocol(&self, protocol: u16, info: Vec<u8>) -> Result<bool> {
        match protocol {
            ppp::PPP_PROTO_IPV4 => {
                // Parse IPv4 packet and dispatch through the protocol stack
                // (same path as poll()'s Ipv4 EtherType handling, minus NAT).
                let ip_packet = match ipv4::parse_packet(&info) {
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

                // Fragment reassembly.
                let ip_packet = {
                    let mut frag_cache = self.fragment_cache.lock();
                    match fragments::process_ipv4_fragment(
                        &mut frag_cache,
                        &ip_packet,
                        self.current_tick(),
                    ) {
                        Some(reassembled) => reassembled,
                        None => return Ok(true), // fragment buffered
                    }
                };

                // Raw socket delivery.
                {
                    let proto = ip_packet.header.protocol.to_u8();
                    let mut raw_sockets = self.raw_sockets.lock();
                    for sock in raw_sockets.values_mut() {
                        if sock.protocol == proto {
                            let _ = sock.deliver(
                                crate::kernel::network::internet::ip::IpAddress::V4(
                                    ip_packet.header.source,
                                ),
                                crate::kernel::network::internet::ip::IpAddress::V4(
                                    ip_packet.header.destination,
                                ),
                                &ip_packet.payload,
                            );
                        }
                    }
                }

                // Protocol dispatch.
                if ip_packet.header.protocol == IpProtocol::Icmp {
                    if let Some((mut reply_header, reply_data)) =
                        icmp::process_icmp_packet(&ip_packet.payload, ip_packet.header.source)?
                    {
                        self.profiler.inc_icmp_echo_replies();
                        reply_header.source = self.local_ip();
                        let raw = ipv4::build_packet(&reply_header, &reply_data);
                        let _ = self.send_ipv4_packet(ip_packet.header.source, raw);
                    }
                    if let Ok(icmp_hdr) = icmp::parse_icmp_header(&ip_packet.payload) {
                        if icmp_hdr.icmp_type == icmp::ICMP_TYPE_ECHO_REPLY {
                            icmp::dispatch_echo_reply(
                                ip_packet.header.source,
                                icmp_hdr.rest_of_header,
                                self.current_tick(),
                            );
                        }
                    }
                } else if ip_packet.header.protocol == IpProtocol::Igmp {
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
                } else if ip_packet.header.protocol == IpProtocol::Tcp {
                    let pending = {
                        let mut table = self.tcp_table.lock();
                        tcp::process_segment(
                            &mut table,
                            self,
                            ip_packet.header.source,
                            ip_packet.header.destination,
                            &ip_packet.payload,
                        )?
                    };
                    for (dst_ip, seg) in pending {
                        let _ = tcp::send_tcp_segment(self, dst_ip, &seg);
                    }
                } else if ip_packet.header.protocol == IpProtocol::Udp {
                    if let Ok(udp_dgram) = udp::parse_datagram(&ip_packet.payload) {
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
                            self.profiler.inc_icmp_unreachable();
                            let icmp_msg =
                                icmp::build_dest_unreachable(&ip_packet.header, &ip_packet.payload);
                            let reply_header = Ipv4Header {
                                total_length: 0,
                                identification: 0,
                                flags_fragment_offset: 0,
                                ttl: IPV4_DEFAULT_TTL,
                                protocol: IpProtocol::Icmp,
                                header_checksum: 0,
                                source: self.local_ip(),
                                destination: ip_packet.header.source,
                            };
                            let raw = ipv4::build_packet(&reply_header, &icmp_msg);
                            let _ = self.send_ipv4_packet(ip_packet.header.source, raw);
                        }
                    }
                }
            }
            ppp::PPP_PROTO_IPV6 => {
                // Parse IPv6 packet and dispatch through the protocol stack.
                let ip_packet = ipv6::parse_packet(&info)?;

                // IPv6 fragment reassembly.
                let (ipv6_next_header, ipv6_payload) =
                    if ip_packet.header.next_header == Ipv6NextHeader::Fragment {
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
                                    (Ipv6NextHeader::from_u8(next_header), reassembled)
                                }
                                None => return Ok(true), // fragment buffered
                            }
                        } else {
                            return Ok(true); // malformed fragment header
                        }
                    } else {
                        (ip_packet.header.next_header, ip_packet.payload.clone())
                    };

                // Raw socket delivery (IPv6).
                {
                    let proto = ipv6_next_header.to_u8();
                    let mut raw_sockets = self.raw_sockets.lock();
                    for sock in raw_sockets.values_mut() {
                        if sock.protocol == proto {
                            let _ = sock.deliver(
                                crate::kernel::network::internet::ip::IpAddress::V6(
                                    ip_packet.header.source,
                                ),
                                crate::kernel::network::internet::ip::IpAddress::V6(
                                    ip_packet.header.destination,
                                ),
                                &ipv6_payload,
                            );
                        }
                    }
                }

                // Protocol dispatch by Next Header.
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
                } else if ipv6_next_header == Ipv6NextHeader::Tcp {
                    let pending = {
                        let mut table = self.tcp_table.lock();
                        tcp::process_segment_v6(
                            &mut table,
                            self,
                            ip_packet.header.source,
                            ip_packet.header.destination,
                            &ipv6_payload,
                        )?
                    };
                    for (dst_ip, seg) in pending {
                        let _ = tcp::send_tcp_segment_v6(self, dst_ip, &seg);
                    }
                } else if ipv6_next_header == Ipv6NextHeader::Udp {
                    if let Ok(udp_dgram) = udp::parse_datagram(&ipv6_payload) {
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
                            let unreach_body = icmpv6::build_icmpv6_dest_unreachable(&ipv6_payload);
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
            _ => {
                // LCP, IPCP, and other control protocols — let the PPP state
                // machine handle them.  If a reply is generated, send it back
                // with the transport-appropriate framing (HDLC on a serial
                // link, PPPoE encapsulation over an Ethernet session).
                let reply = {
                    let mut ppp = self.ppp_state.lock();
                    ppp.handle_frame_untagged(protocol, &info)
                };
                if let Some((reply_proto, reply_info)) = reply {
                    let _ = self.send_ppp_packet(reply_proto, &reply_info);
                }
            }
        }

        Ok(true)
    }

    /// Transmit a PPP `(protocol, information)` pair with the framing
    /// appropriate to the current transport.
    ///
    /// When PPPoE is enabled and a session is established the pair is wrapped
    /// as an RFC 2516 session payload (protocol + information only) inside a
    /// PPPoE session packet; otherwise it is framed as a full HDLC PPP frame
    /// for a serial / byte-stream device.
    pub(crate) fn send_ppp_packet(&self, protocol: u16, info: &[u8]) -> Result<()> {
        if self.pppoe_enabled() && self.pppoe.lock().in_session() {
            let payload = ppp::ppp_pppoe_build_payload(protocol, info);
            self.send_pppoe_session_frame(payload)
        } else {
            let frame = ppp::ppp_build_frame(protocol, info);
            self.device.send(&frame)
        }
    }

    /// Send an IPv4 packet encapsulated in a PPP frame.
    ///
    /// Frames the IP packet with the transport-appropriate PPP encapsulation
    /// (HDLC on a serial link, PPPoE session over Ethernet) and calls the
    /// device's `send` method.
    pub fn send_ppp_ipv4(&self, raw_ip: Vec<u8>) -> Result<()> {
        self.profiler.inc_ipv4_packets_tx();
        self.send_ppp_packet(ppp::PPP_PROTO_IPV4, &raw_ip)
    }

    /// Send an IPv6 packet encapsulated in a PPP frame.
    pub fn send_ppp_ipv6(&self, raw_ip: Vec<u8>) -> Result<()> {
        self.send_ppp_packet(ppp::PPP_PROTO_IPV6, &raw_ip)
    }

    /// Build and send an LCP Echo Request keepalive.
    pub fn send_ppp_lcp_echo_request(&self) -> Result<()> {
        let echo_req = {
            let mut ppp = self.ppp_state.lock();
            ppp.build_echo_request()
        };
        self.send_ppp_packet(ppp::PPP_PROTO_LCP, &echo_req)
    }

    /// Perform PPP link negotiation (LCP Configure-Request exchange).
    ///
    /// This brings the PPP link to the Network phase when successful.
    /// After calling this, the caller can use
    /// [`send_ppp_ipv4`](Self::send_ppp_ipv4)
    /// and [`send_ppp_ipv6`](Self::send_ppp_ipv6) to transmit IP packets.
    pub fn ppp_negotiate_link(&self) -> Result<()> {
        let conf_req = {
            let mut ppp = self.ppp_state.lock();
            ppp.link_up();
            ppp.build_configure_request()
        };
        self.send_ppp_packet(ppp::PPP_PROTO_LCP, &conf_req)
    }
}
