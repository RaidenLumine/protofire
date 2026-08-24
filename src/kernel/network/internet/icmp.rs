//! src/kernel/network/internet/icmp.rs
//!
//! ICMP protocol (RFC 792): Echo Reply generation.

use alloc::vec::Vec;

use super::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header};
use crate::{Error, Result};

// ─── ICMP type constants ───

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_CODE_PORT_UNREACHABLE: u8 = 3;

// ─── ICMP header ───

/// ICMP header fields common to all message types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: u32, // identifier (16 bits) + sequence number (16 bits)
}

/// A complete ICMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPacket {
    pub header: IcmpHeader,
    pub payload: Vec<u8>,
}

// ─── ICMP header size ───

pub const ICMP_HEADER_SIZE: usize = 8; // type(1) + code(1) + checksum(2) + rest(4)

// ─── Parse / build ───

/// Parse an ICMP header from a byte slice.
pub fn parse_icmp_header(data: &[u8]) -> Result<IcmpHeader> {
    if data.len() < ICMP_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let icmp_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let rest_of_header = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    Ok(IcmpHeader {
        icmp_type,
        code,
        checksum,
        rest_of_header,
    })
}

/// Build an ICMP message (header + payload) into wire-format bytes.
/// The checksum is computed over the entire message.
pub fn build_icmp_message(header: &IcmpHeader, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ICMP_HEADER_SIZE + payload.len());
    buf.push(header.icmp_type);
    buf.push(header.code);
    // Checksum placeholder
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&header.rest_of_header.to_be_bytes());
    buf.extend_from_slice(payload);

    // Compute checksum over the entire message
    let checksum = ipv4::compute_checksum(&buf);
    buf[2] = (checksum >> 8) as u8;
    buf[3] = checksum as u8;

    buf
}

/// Build an ICMP Destination Unreachable message (type 3, code 3).
///
/// Embeds the offending packet's IPv4 header + first 8 bytes of its
/// payload (the UDP header) as required by RFC 792.
///
/// The embedded portion is at most 28 bytes (20-byte IP header + 8-byte
/// payload prefix), so we build it on the stack to avoid two intermediate
/// heap allocations.
pub fn build_dest_unreachable(original_ip_header: &Ipv4Header, original_payload: &[u8]) -> Vec<u8> {
    let header = IcmpHeader {
        icmp_type: ICMP_TYPE_DEST_UNREACHABLE,
        code: ICMP_CODE_PORT_UNREACHABLE,
        checksum: 0,
        rest_of_header: 0,
    };

    // Build the original IP header wire format on the stack (20 bytes).
    let ip_total_length = (ipv4::IPV4_MIN_HEADER_SIZE) as u16;
    let ip_hdr: [u8; ipv4::IPV4_MIN_HEADER_SIZE] = {
        let mut h = [0u8; ipv4::IPV4_MIN_HEADER_SIZE];
        h[0] = 0x45; // version=4, IHL=5
        h[1] = 0; // DSCP+ECN
        h[2] = (ip_total_length >> 8) as u8;
        h[3] = ip_total_length as u8;
        h[4] = (original_ip_header.identification >> 8) as u8;
        h[5] = original_ip_header.identification as u8;
        let flags_fo = 0x4000u16 | (original_ip_header.flags_fragment_offset & 0x1FFF);
        h[6] = (flags_fo >> 8) as u8;
        h[7] = flags_fo as u8;
        h[8] = original_ip_header.ttl;
        h[9] = original_ip_header.protocol.to_u8();
        // Checksum placeholder at [10..12]
        h[12..16].copy_from_slice(&original_ip_header.source);
        h[16..20].copy_from_slice(&original_ip_header.destination);
        let cs = ipv4::compute_checksum(&h);
        h[10] = (cs >> 8) as u8;
        h[11] = cs as u8;
        h
    };

    // Embed: 20-byte IP header + up to 8 bytes of original payload.
    let prefix_len = original_payload.len().min(8);
    let mut embedded = [0u8; 28];
    embedded[..20].copy_from_slice(&ip_hdr);
    embedded[20..20 + prefix_len].copy_from_slice(&original_payload[..prefix_len]);

    build_icmp_message(&header, &embedded[..20 + prefix_len])
}

// ─── Pending ping tracking ───

/// In-flight ICMP Echo Request tracked by the ping builtin.
pub struct PendingPing {
    pub id: u16,
    pub seq: u16,
    pub dst: Ipv4Addr,
    pub sent_at: u64,
    pub reply_at: core::cell::Cell<u64>, // 0 = no reply yet
}

/// Global registry of in-flight ping requests.
///
/// The `ping` shell command pushes entries here and the network stack's
/// `poll()` dispatches incoming Echo Replies to matching entries via
/// [`dispatch_echo_reply`].
pub static PENDING_PINGS: crate::kernel::sync::Mutex<Vec<PendingPing>> =
    crate::kernel::sync::Mutex::new(Vec::new());

/// Called by the network stack `poll()` when an Echo Reply (type 0) arrives.
///
/// Matches the reply against registered pending pings by (id, seq, dst) and
/// records the receive tick in `reply_at`.
pub fn dispatch_echo_reply(src_ip: Ipv4Addr, rest_of_header: u32, recv_tick: u64) {
    let id = ((rest_of_header >> 16) & 0xFFFF) as u16;
    let seq = (rest_of_header & 0xFFFF) as u16;
    let pings = PENDING_PINGS.lock();
    for ping in pings.iter() {
        if ping.id == id && ping.seq == seq && ping.dst == src_ip && ping.reply_at.get() == 0 {
            ping.reply_at.set(recv_tick);
            break;
        }
    }
}

// ─── ICMP processing ───

/// Process an incoming ICMP packet embedded in an IPv4 datagram.
///
/// Returns `Ok(Some(reply_bytes))` if a reply should be sent, or
/// `Ok(None)` if the packet was silently consumed.
pub fn process_icmp_packet(
    icmp_data: &[u8],
    source_ip: Ipv4Addr,
) -> Result<Option<(Ipv4Header, Vec<u8>)>> {
    if icmp_data.len() < ICMP_HEADER_SIZE {
        return Ok(None);
    }

    let header = parse_icmp_header(icmp_data)?;

    match header.icmp_type {
        ICMP_TYPE_ECHO_REQUEST => {
            // Build an Echo Reply with the same identifier + sequence
            let reply_header = IcmpHeader {
                icmp_type: ICMP_TYPE_ECHO_REPLY,
                code: 0,
                checksum: 0,
                rest_of_header: header.rest_of_header,
            };
            let payload = &icmp_data[ICMP_HEADER_SIZE..];
            let reply_msg = build_icmp_message(&reply_header, payload);

            let ip_header = Ipv4Header {
                total_length: 0, // recomputed by build_packet
                identification: 0,
                flags_fragment_offset: 0,
                ttl: ipv4::IPV4_DEFAULT_TTL,
                protocol: IpProtocol::Icmp,
                header_checksum: 0,
                source: [0; 4],         // filled by caller
                destination: source_ip, // reply to the sender
            };

            Ok(Some((ip_header, reply_msg)))
        }
        _ => {
            // Silently ignore other ICMP types for now.
            Ok(None)
        }
    }
}

// ─── ICMP error-message inspection ───

/// Information about the original packet embedded in an ICMP error message.
///
/// Populated by [`parse_icmp_error_info`] from a Destination Unreachable
/// message, which carries the offending IPv4 header (plus the first 8 bytes of
/// its transport header for TCP/UDP) per RFC 792.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpErrorInfo {
    pub original_src: Ipv4Addr,
    pub original_dst: Ipv4Addr,
    pub original_protocol: u8,
    pub original_src_port: u16,
    pub original_dst_port: u16,
}

/// Parse the embedded original-packet information from an ICMP Destination
/// Unreachable message (type 3).
///
/// Returns `Some` when the message is a Destination Unreachable (used by the
/// stack to detect an unreachable destination and to notify the affected
/// TCP/UDP connection), or `None` for any other ICMP type or a malformed
/// packet.  The parse is deliberately lenient — ports are only extracted when
/// the embedded transport header is present.
pub fn parse_icmp_error_info(data: &[u8]) -> Option<IcmpErrorInfo> {
    // ICMP header (8) + embedded IPv4 header (20).
    if data.len() < ICMP_HEADER_SIZE + ipv4::IPV4_MIN_HEADER_SIZE {
        return None;
    }
    if data[0] != ICMP_TYPE_DEST_UNREACHABLE {
        return None;
    }

    // The embedded IPv4 header starts at offset 8 (after the ICMP header).
    let ip = &data[ICMP_HEADER_SIZE..];
    let mut original_src = [0u8; 4];
    original_src.copy_from_slice(&ip[12..16]);
    let mut original_dst = [0u8; 4];
    original_dst.copy_from_slice(&ip[16..20]);
    let original_protocol = ip[9];

    let mut original_src_port = 0u16;
    let mut original_dst_port = 0u16;
    // TCP (6) and UDP (17) embed 8 bytes of the transport header; the source
    // and destination ports are its first four bytes.
    if (original_protocol == 6 || original_protocol == 17)
        && data.len() >= ICMP_HEADER_SIZE + ipv4::IPV4_MIN_HEADER_SIZE + 4
    {
        let transport = &data[ICMP_HEADER_SIZE + ipv4::IPV4_MIN_HEADER_SIZE..];
        original_src_port = u16::from_be_bytes([transport[0], transport[1]]);
        original_dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    }

    Some(IcmpErrorInfo {
        original_src,
        original_dst,
        original_protocol,
        original_src_port,
        original_dst_port,
    })
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::internet::ipv4::{compute_checksum, parse_packet};

    #[test]
    fn echo_request_generates_reply() {
        let echo_request = build_icmp_message(
            &IcmpHeader {
                icmp_type: ICMP_TYPE_ECHO_REQUEST,
                code: 0,
                checksum: 0,
                rest_of_header: 0x12340001, // id=0x1234, seq=1
            },
            b"ping data",
        );

        let result = process_icmp_packet(&echo_request, [10, 0, 2, 100])
            .expect("should process")
            .expect("should generate reply");

        let (ip_header, reply_msg) = result;

        assert_eq!(ip_header.protocol, IpProtocol::Icmp);
        assert_eq!(ip_header.destination, [10, 0, 2, 100]);
        assert_eq!(reply_msg[0], ICMP_TYPE_ECHO_REPLY);
        assert_eq!(reply_msg[1], 0); // code
                                     // rest_of_header should match
        let rest = u32::from_be_bytes([reply_msg[4], reply_msg[5], reply_msg[6], reply_msg[7]]);
        assert_eq!(rest, 0x12340001);
        // Payload should match
        assert_eq!(&reply_msg[ICMP_HEADER_SIZE..], b"ping data");
        // Checksum should be valid
        assert_eq!(compute_checksum(&reply_msg), 0);
    }

    #[test]
    fn non_echo_icmp_is_silently_ignored() {
        // Build a Destination Unreachable (type 3) message
        let msg = build_icmp_message(
            &IcmpHeader {
                icmp_type: 3,
                code: 0,
                checksum: 0,
                rest_of_header: 0,
            },
            &[],
        );

        let result = process_icmp_packet(&msg, [10, 0, 2, 1]).expect("should process");
        assert!(result.is_none());
    }

    #[test]
    fn icmp_header_parse_round_trip() {
        let original = IcmpHeader {
            icmp_type: ICMP_TYPE_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            rest_of_header: 0xABCD0005,
        };
        let msg = build_icmp_message(&original, b"data");
        let parsed = parse_icmp_header(&msg).expect("should parse");
        assert_eq!(parsed.icmp_type, ICMP_TYPE_ECHO_REQUEST);
        assert_eq!(parsed.code, 0);
        assert_eq!(parsed.rest_of_header, 0xABCD0005);
        // Checksum should be valid
        assert_eq!(compute_checksum(&msg), 0);
    }

    #[test]
    fn icmp_echo_reply_is_valid_ipv4_packet() {
        let echo_request = build_icmp_message(
            &IcmpHeader {
                icmp_type: ICMP_TYPE_ECHO_REQUEST,
                code: 0,
                checksum: 0,
                rest_of_header: 0,
            },
            b"hello",
        );

        let (mut ip_header, reply_msg) = process_icmp_packet(&echo_request, [10, 0, 2, 2])
            .expect("should process")
            .expect("should generate reply");

        // Set source IP (normally done by the caller)
        ip_header.source = [10, 0, 2, 15];

        let raw = ipv4::build_packet(&ip_header, &reply_msg);
        // Should be parseable as a valid IPv4 packet
        let parsed = parse_packet(&raw).expect("should be valid IPv4");
        assert_eq!(parsed.header.protocol, IpProtocol::Icmp);
    }

    #[test]
    fn dest_unreachable_embeds_original_packet() {
        let original_header = Ipv4Header {
            total_length: 0,
            identification: 0x1234,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Udp,
            header_checksum: 0,
            source: [10, 0, 2, 100],
            destination: [10, 0, 2, 15],
        };
        let original_payload = [
            0x04, 0xD2, // source_port = 1234
            0x00, 0x35, // dest_port = 53
            0x00, 0x10, // length = 16
            0x00, 0x00, // checksum = 0
        ];

        let msg = build_dest_unreachable(&original_header, &original_payload);
        assert_eq!(msg[0], ICMP_TYPE_DEST_UNREACHABLE);
        assert_eq!(msg[1], ICMP_CODE_PORT_UNREACHABLE);
        assert_eq!(compute_checksum(&msg), 0);
        // 8-byte ICMP header + 20-byte IP header + 8-byte UDP header = 36 bytes
        assert_eq!(msg.len(), ICMP_HEADER_SIZE + 28);
    }
}
