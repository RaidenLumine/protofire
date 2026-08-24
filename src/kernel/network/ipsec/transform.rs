//! src/kernel/network/ipsec/transform.rs
//!
//! IPsec data-plane transforms: apply the SPD/SAD on outbound and inbound
//! packets, for both IPv4 and IPv6 and both transport and tunnel modes.

use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header, Ipv4Packet};
use crate::kernel::network::internet::ipv6::{
    self, Ipv6Addr, Ipv6Header, Ipv6NextHeader, Ipv6Packet,
};
use crate::kernel::network::stack::NetworkStack;
use crate::{Error, Result};

use super::ah::{self, AH_HEADER_SIZE};
use super::esp;
use super::{transport_ports, IpsecProto, IpsecSa, SpAction};

/// Maximum IPsec tunnel decapsulation depth.  Re-entering dispatch deeper
/// than this with a nested ESP/AH tunnel drops the packet (loop prevention).
pub const IPSEC_MAX_DEPTH: u8 = 1;

/// Result of inbound IPsec processing for an IPv4 packet.
pub enum IpsecInboundV4 {
    /// Not IPsec (or a transport-mode decapsulation): continue normal
    /// dispatch with this (possibly rewritten) packet.
    Plain(Ipv4Packet),
    /// The packet was consumed by IPsec (discarded, or a tunnel-mode
    /// decapsulation that the caller re-dispatches).
    Consumed,
    /// Tunnel-mode decapsulation: the payload is a complete inner IP packet
    /// that the caller must re-dispatch.
    Decap(Vec<u8>),
}

/// Result of inbound IPsec processing for an IPv6 packet.
pub enum IpsecInboundV6 {
    Plain(Ipv6Header, Vec<u8>),
    Consumed,
    Decap(Vec<u8>),
}

fn v4_selector_ports(header: &Ipv4Header, payload: &[u8]) -> (u16, u16) {
    if header.protocol == IpProtocol::Tcp
        || header.protocol == IpProtocol::Udp
        || header.protocol == IpProtocol::Dccp
    {
        transport_ports(payload)
    } else {
        (0, 0)
    }
}

fn v6_selector_ports(next_header: u8, payload: &[u8]) -> (u16, u16) {
    if matches!(next_header, 6 | 17 | 33) {
        transport_ports(payload)
    } else {
        (0, 0)
    }
}

/// Maximum length of the wrapped packet (drop oversized packets).
fn mtu_ok(stack: &NetworkStack, packet_len: usize, overhead: usize) -> bool {
    let mtu = stack.device().mtu();
    packet_len + overhead <= mtu
}

// ─── Outbound (apply ESP/AH) ─────────────────────────────────────────────

/// Apply the outbound IPv4 IPsec transform.  Returns the (possibly changed)
/// destination and packet, or `None` when the packet is discarded by
/// policy.
pub fn process_outbound_v4(
    stack: &NetworkStack,
    dst_ip: Ipv4Addr,
    raw_ip: Vec<u8>,
) -> Result<Option<(Ipv4Addr, Vec<u8>)>> {
    let pkt = ipv4::parse_packet(&raw_ip)?;
    let (src_port, dst_port) = v4_selector_ports(&pkt.header, &pkt.payload);

    let action = {
        let spd = stack.ipsec_spd().lock();
        spd.lookup_outbound(
            IpAddress::V4(pkt.header.source),
            IpAddress::V4(pkt.header.destination),
            pkt.header.protocol.to_u8(),
            src_port,
            dst_port,
        )
    };
    match action {
        SpAction::Bypass => Ok(Some((dst_ip, raw_ip))),
        SpAction::Discard => Ok(None),
        SpAction::Protect => {
            // Find the SA referenced by the policy.
            let sa_id = {
                let spd = stack.ipsec_spd().lock();
                spd.entries
                    .iter()
                    .find(|entry| {
                        entry.action == SpAction::Protect
                            && entry.selector.matches(
                                IpAddress::V4(pkt.header.source),
                                IpAddress::V4(pkt.header.destination),
                                pkt.header.protocol.to_u8(),
                                src_port,
                                dst_port,
                            )
                    })
                    .and_then(|entry| entry.sa_id)
            };
            let sa_id = sa_id.ok_or(Error::NotFound)?;
            let mut sad = stack.ipsec_sad().lock();
            let sa = sad.by_id.get_mut(&sa_id).ok_or(Error::NotFound)?;
            let seq = sa.next_seq();
            let overhead = ipsec_overhead(sa);
            if !mtu_ok(stack, raw_ip.len(), overhead) {
                return Ok(None);
            }
            let (new_dst, new_raw) = match sa.proto {
                IpsecProto::Esp => apply_esp_outbound_v4(sa, seq, &pkt, raw_ip, dst_ip),
                IpsecProto::Ah => apply_ah_outbound_v4(sa, seq, &pkt, raw_ip, dst_ip),
            };
            sa.packets_out += 1;
            sa.bytes_out += new_raw.len() as u64;
            Ok(Some((new_dst, new_raw)))
        }
    }
}

/// Apply the outbound IPv6 IPsec transform.
pub fn process_outbound_v6(
    stack: &NetworkStack,
    dst_ip: Ipv6Addr,
    raw_ip: Vec<u8>,
) -> Result<Option<(Ipv6Addr, Vec<u8>)>> {
    let pkt = ipv6::parse_packet(&raw_ip)?;
    let (src_port, dst_port) = v6_selector_ports(pkt.header.next_header.to_u8(), &pkt.payload);

    let action = {
        let spd = stack.ipsec_spd().lock();
        spd.lookup_outbound(
            IpAddress::V6(pkt.header.source),
            IpAddress::V6(pkt.header.destination),
            pkt.header.next_header.to_u8(),
            src_port,
            dst_port,
        )
    };
    match action {
        SpAction::Bypass => Ok(Some((dst_ip, raw_ip))),
        SpAction::Discard => Ok(None),
        SpAction::Protect => {
            let sa_id = {
                let spd = stack.ipsec_spd().lock();
                spd.entries
                    .iter()
                    .find(|entry| {
                        entry.action == SpAction::Protect
                            && entry.selector.matches(
                                IpAddress::V6(pkt.header.source),
                                IpAddress::V6(pkt.header.destination),
                                pkt.header.next_header.to_u8(),
                                src_port,
                                dst_port,
                            )
                    })
                    .and_then(|entry| entry.sa_id)
            };
            let sa_id = sa_id.ok_or(Error::NotFound)?;
            let mut sad = stack.ipsec_sad().lock();
            let sa = sad.by_id.get_mut(&sa_id).ok_or(Error::NotFound)?;
            let seq = sa.next_seq();
            let overhead = ipsec_overhead(sa);
            if !mtu_ok(stack, raw_ip.len(), overhead) {
                return Ok(None);
            }
            let (new_dst, new_raw) = match sa.proto {
                IpsecProto::Esp => apply_esp_outbound_v6(sa, seq, &pkt, raw_ip, dst_ip),
                IpsecProto::Ah => apply_ah_outbound_v6(sa, seq, &pkt, raw_ip, dst_ip),
            };
            sa.packets_out += 1;
            sa.bytes_out += new_raw.len() as u64;
            Ok(Some((new_dst, new_raw)))
        }
    }
}

fn ipsec_overhead(sa: &IpsecSa) -> usize {
    match sa.proto {
        IpsecProto::Esp => esp::ESP_HEADER_SIZE + esp::ESP_ICV_SIZE + 16,
        IpsecProto::Ah => AH_HEADER_SIZE,
    }
}

fn apply_esp_outbound_v4(
    sa: &IpsecSa,
    seq: u64,
    pkt: &Ipv4Packet,
    raw_ip: Vec<u8>,
    dst_ip: Ipv4Addr,
) -> (Ipv4Addr, Vec<u8>) {
    match sa.mode {
        super::IpsecMode::Transport => {
            let payload =
                esp::build_esp_payload(sa, seq, &pkt.payload, pkt.header.protocol.to_u8())
                    .unwrap_or_default();
            let mut outer = pkt.header.clone();
            outer.protocol = IpProtocol::Esp;
            outer.total_length = 0;
            outer.header_checksum = 0;
            let new_raw = ipv4::build_packet(&outer, &payload);
            (dst_ip, new_raw)
        }
        super::IpsecMode::Tunnel => {
            let inner = raw_ip;
            let payload = esp::build_esp_payload(sa, seq, &inner, 4).unwrap_or_default();
            let tunnel_src = sa
                .tunnel_src
                .and_then(|a| a.as_ipv4())
                .unwrap_or(pkt.header.source);
            let tunnel_dst = sa.tunnel_dst.and_then(|a| a.as_ipv4()).unwrap_or(dst_ip);
            let outer = Ipv4Header {
                total_length: 0,
                identification: 0,
                flags_fragment_offset: 0,
                ttl: ipv4::IPV4_DEFAULT_TTL,
                protocol: IpProtocol::Esp,
                header_checksum: 0,
                source: tunnel_src,
                destination: tunnel_dst,
            };
            let new_raw = ipv4::build_packet(&outer, &payload);
            (tunnel_dst, new_raw)
        }
    }
}

fn apply_ah_outbound_v4(
    sa: &IpsecSa,
    seq: u64,
    pkt: &Ipv4Packet,
    raw_ip: Vec<u8>,
    dst_ip: Ipv4Addr,
) -> (Ipv4Addr, Vec<u8>) {
    match sa.mode {
        super::IpsecMode::Transport => {
            let mut outer = pkt.header.clone();
            outer.protocol = IpProtocol::Ah;
            outer.total_length = 0;
            outer.header_checksum = 0;
            let outer_header_bytes = ipv4::build_packet(&outer, &[]);
            let zeroed = ah::ipv4_mutable_zeroed(&outer_header_bytes[..20]);
            let ah_bytes =
                ah::build_ah(sa, seq, pkt.header.protocol.to_u8(), &zeroed, &pkt.payload)
                    .unwrap_or_default();
            let mut payload = ah_bytes;
            payload.extend_from_slice(&pkt.payload);
            let new_raw = ipv4::build_packet(&outer, &payload);
            (dst_ip, new_raw)
        }
        super::IpsecMode::Tunnel => {
            let inner = raw_ip;
            let tunnel_src = sa
                .tunnel_src
                .and_then(|a| a.as_ipv4())
                .unwrap_or(pkt.header.source);
            let tunnel_dst = sa.tunnel_dst.and_then(|a| a.as_ipv4()).unwrap_or(dst_ip);
            let outer = Ipv4Header {
                total_length: 0,
                identification: 0,
                flags_fragment_offset: 0,
                ttl: ipv4::IPV4_DEFAULT_TTL,
                protocol: IpProtocol::Ah,
                header_checksum: 0,
                source: tunnel_src,
                destination: tunnel_dst,
            };
            let outer_header_bytes = ipv4::build_packet(&outer, &[]);
            let zeroed = ah::ipv4_mutable_zeroed(&outer_header_bytes[..20]);
            let ah_bytes = ah::build_ah(sa, seq, 4, &zeroed, &inner).unwrap_or_default();
            let mut payload = ah_bytes;
            payload.extend_from_slice(&inner);
            let new_raw = ipv4::build_packet(&outer, &payload);
            (tunnel_dst, new_raw)
        }
    }
}

fn apply_esp_outbound_v6(
    sa: &IpsecSa,
    seq: u64,
    pkt: &Ipv6Packet,
    raw_ip: Vec<u8>,
    dst_ip: Ipv6Addr,
) -> (Ipv6Addr, Vec<u8>) {
    match sa.mode {
        super::IpsecMode::Transport => {
            let payload =
                esp::build_esp_payload(sa, seq, &pkt.payload, pkt.header.next_header.to_u8())
                    .unwrap_or_default();
            let outer = Ipv6Header {
                traffic_class: pkt.header.traffic_class,
                flow_label: pkt.header.flow_label,
                payload_length: 0,
                next_header: Ipv6NextHeader::Esp,
                hop_limit: pkt.header.hop_limit,
                source: pkt.header.source,
                destination: pkt.header.destination,
            };
            let new_raw = ipv6::build_packet(&outer, &payload);
            (dst_ip, new_raw)
        }
        super::IpsecMode::Tunnel => {
            let inner = raw_ip;
            let payload = esp::build_esp_payload(sa, seq, &inner, 41).unwrap_or_default();
            let tunnel_src = sa
                .tunnel_src
                .and_then(|a| a.as_ipv6())
                .unwrap_or(pkt.header.source);
            let tunnel_dst = sa.tunnel_dst.and_then(|a| a.as_ipv6()).unwrap_or(dst_ip);
            let outer = Ipv6Header {
                traffic_class: 0,
                flow_label: 0,
                payload_length: 0,
                next_header: Ipv6NextHeader::Esp,
                hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
                source: tunnel_src,
                destination: tunnel_dst,
            };
            let new_raw = ipv6::build_packet(&outer, &payload);
            (tunnel_dst, new_raw)
        }
    }
}

fn apply_ah_outbound_v6(
    sa: &IpsecSa,
    seq: u64,
    pkt: &Ipv6Packet,
    raw_ip: Vec<u8>,
    dst_ip: Ipv6Addr,
) -> (Ipv6Addr, Vec<u8>) {
    match sa.mode {
        super::IpsecMode::Transport => {
            let outer = Ipv6Header {
                traffic_class: pkt.header.traffic_class,
                flow_label: pkt.header.flow_label,
                payload_length: 0,
                next_header: Ipv6NextHeader::Ah,
                hop_limit: pkt.header.hop_limit,
                source: pkt.header.source,
                destination: pkt.header.destination,
            };
            let outer_bytes = ipv6::build_packet(&outer, &[]);
            let zeroed = ah::ipv6_mutable_zeroed(&outer_bytes[..40]);
            let ah_bytes = ah::build_ah(
                sa,
                seq,
                pkt.header.next_header.to_u8(),
                &zeroed,
                &pkt.payload,
            )
            .unwrap_or_default();
            let mut payload = ah_bytes;
            payload.extend_from_slice(&pkt.payload);
            let new_raw = ipv6::build_packet(&outer, &payload);
            (dst_ip, new_raw)
        }
        super::IpsecMode::Tunnel => {
            let inner = raw_ip;
            let tunnel_src = sa
                .tunnel_src
                .and_then(|a| a.as_ipv6())
                .unwrap_or(pkt.header.source);
            let tunnel_dst = sa.tunnel_dst.and_then(|a| a.as_ipv6()).unwrap_or(dst_ip);
            let outer = Ipv6Header {
                traffic_class: 0,
                flow_label: 0,
                payload_length: 0,
                next_header: Ipv6NextHeader::Ah,
                hop_limit: ipv6::IPV6_DEFAULT_HOP_LIMIT,
                source: tunnel_src,
                destination: tunnel_dst,
            };
            let outer_bytes = ipv6::build_packet(&outer, &[]);
            let zeroed = ah::ipv6_mutable_zeroed(&outer_bytes[..40]);
            let ah_bytes = ah::build_ah(sa, seq, 41, &zeroed, &inner).unwrap_or_default();
            let mut payload = ah_bytes;
            payload.extend_from_slice(&inner);
            let new_raw = ipv6::build_packet(&outer, &payload);
            (tunnel_dst, new_raw)
        }
    }
}

// ─── Inbound (decrypt / verify) ──────────────────────────────────────────

/// Process an inbound IPv4 packet: if it is ESP/AH, decrypt/verify it and
/// return the transformed packet.  Non-IPsec packets pass through.
pub fn process_inbound_v4(stack: &NetworkStack, packet: &Ipv4Packet) -> Result<IpsecInboundV4> {
    let protocol = packet.header.protocol;
    if protocol != IpProtocol::Esp && protocol != IpProtocol::Ah {
        return Ok(IpsecInboundV4::Plain(packet.clone()));
    }
    if packet.payload.len() < 4 {
        return Ok(IpsecInboundV4::Consumed);
    }
    let spi = u32::from_be_bytes([
        packet.payload[0],
        packet.payload[1],
        packet.payload[2],
        packet.payload[3],
    ]);
    let mut sad = stack.ipsec_sad().lock();
    let sa = sad.by_spi.get_mut(&spi).ok_or(Error::NotFound)?;
    let seq = if packet.payload.len() >= 8 {
        u32::from_be_bytes([
            packet.payload[4],
            packet.payload[5],
            packet.payload[6],
            packet.payload[7],
        ])
    } else {
        0
    };
    match sa.proto {
        IpsecProto::Esp => {
            let (inner, next_header) = esp::parse_esp_payload(sa, &packet.payload)?;
            // Only advance the anti-replay window after the AEAD tag is
            // verified, so unauthenticated packets cannot consume it.
            if !sa.check_replay(seq as u64) {
                return Ok(IpsecInboundV4::Consumed);
            }
            sa.packets_in += 1;
            sa.bytes_in += packet.payload.len() as u64;
            match sa.mode {
                super::IpsecMode::Transport => {
                    let mut header = packet.header.clone();
                    header.protocol = IpProtocol::from_u8(next_header);
                    header.total_length = 0;
                    header.header_checksum = 0;
                    Ok(IpsecInboundV4::Plain(Ipv4Packet {
                        header,
                        payload: inner,
                    }))
                }
                super::IpsecMode::Tunnel => Ok(IpsecInboundV4::Decap(inner)),
            }
        }
        IpsecProto::Ah => {
            let header_bytes = ipv4::build_packet(&packet.header, &[]);
            let zeroed = ah::ipv4_mutable_zeroed(&header_bytes[..20]);
            if packet.payload.len() < AH_HEADER_SIZE {
                return Ok(IpsecInboundV4::Consumed);
            }
            let ah_bytes = &packet.payload[..AH_HEADER_SIZE];
            let inner = &packet.payload[AH_HEADER_SIZE..];
            ah::verify_ah(sa, &zeroed, ah_bytes, inner)?;
            // Only advance the anti-replay window after the ICV is verified.
            if !sa.check_replay(seq as u64) {
                return Ok(IpsecInboundV4::Consumed);
            }
            let next_header = packet.payload[0];
            sa.packets_in += 1;
            sa.bytes_in += packet.payload.len() as u64;
            match sa.mode {
                super::IpsecMode::Transport => {
                    let mut header = packet.header.clone();
                    header.protocol = IpProtocol::from_u8(next_header);
                    header.total_length = 0;
                    header.header_checksum = 0;
                    Ok(IpsecInboundV4::Plain(Ipv4Packet {
                        header,
                        payload: inner.to_vec(),
                    }))
                }
                super::IpsecMode::Tunnel => Ok(IpsecInboundV4::Decap(inner.to_vec())),
            }
        }
    }
}

/// Process an inbound IPv6 packet.  `next_header`/`payload` follow the
/// extension-header chain (ESP/AH are the final next header).
pub fn process_inbound_v6(
    stack: &NetworkStack,
    next_header: Ipv6NextHeader,
    payload: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<IpsecInboundV6> {
    if next_header != Ipv6NextHeader::Esp && next_header != Ipv6NextHeader::Ah {
        // Rebuild a minimal header for the Plain case.
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: payload.len() as u16,
            next_header,
            hop_limit: 0,
            source: src,
            destination: dst,
        };
        return Ok(IpsecInboundV6::Plain(header, payload.to_vec()));
    }
    if payload.len() < 8 {
        return Ok(IpsecInboundV6::Consumed);
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut sad = stack.ipsec_sad().lock();
    let sa = sad.by_spi.get_mut(&spi).ok_or(Error::NotFound)?;
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

    match sa.proto {
        IpsecProto::Esp => {
            let (inner, inner_nh) = esp::parse_esp_payload(sa, payload)?;
            // Only advance the anti-replay window after the AEAD tag is
            // verified, so unauthenticated packets cannot consume it.
            if !sa.check_replay(seq as u64) {
                return Ok(IpsecInboundV6::Consumed);
            }
            sa.packets_in += 1;
            sa.bytes_in += payload.len() as u64;
            match sa.mode {
                super::IpsecMode::Transport => {
                    let header = Ipv6Header {
                        traffic_class: 0,
                        flow_label: 0,
                        payload_length: inner.len() as u16,
                        next_header: Ipv6NextHeader::from_u8(inner_nh),
                        hop_limit: 0,
                        source: src,
                        destination: dst,
                    };
                    Ok(IpsecInboundV6::Plain(header, inner))
                }
                super::IpsecMode::Tunnel => Ok(IpsecInboundV6::Decap(inner)),
            }
        }
        IpsecProto::Ah => {
            let header_bytes = ipv6::build_packet(
                &Ipv6Header {
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: payload.len() as u16,
                    next_header: Ipv6NextHeader::Ah,
                    hop_limit: 0,
                    source: src,
                    destination: dst,
                },
                &[],
            );
            let zeroed = ah::ipv6_mutable_zeroed(&header_bytes[..40]);
            if payload.len() < AH_HEADER_SIZE {
                return Ok(IpsecInboundV6::Consumed);
            }
            let ah_bytes = &payload[..AH_HEADER_SIZE];
            let inner = &payload[AH_HEADER_SIZE..];
            ah::verify_ah(sa, &zeroed, ah_bytes, inner)?;
            // Only advance the anti-replay window after the ICV is verified.
            if !sa.check_replay(seq as u64) {
                return Ok(IpsecInboundV6::Consumed);
            }
            let inner_nh = payload[0];
            sa.packets_in += 1;
            sa.bytes_in += payload.len() as u64;
            match sa.mode {
                super::IpsecMode::Transport => {
                    let header = Ipv6Header {
                        traffic_class: 0,
                        flow_label: 0,
                        payload_length: inner.len() as u16,
                        next_header: Ipv6NextHeader::from_u8(inner_nh),
                        hop_limit: 0,
                        source: src,
                        destination: dst,
                    };
                    Ok(IpsecInboundV6::Plain(header, inner.to_vec()))
                }
                super::IpsecMode::Tunnel => Ok(IpsecInboundV6::Decap(inner.to_vec())),
            }
        }
    }
}
