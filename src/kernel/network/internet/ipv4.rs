//! src/kernel/network/internet/ipv4.rs
//!
//! IPv4 packet parse / build, header checksum, and protocol demux.

use alloc::vec::Vec;

use crate::Error;
use crate::Result;

// ─── IPv4 address ───

/// IPv4 address represented as four octets in network byte order.
pub type Ipv4Addr = [u8; 4];

/// Standard broadcast address.
pub const IPV4_BROADCAST: Ipv4Addr = [255, 255, 255, 255];

/// Minimum IPv4 header size (no options).
pub const IPV4_MIN_HEADER_SIZE: usize = 20;

/// Default TTL for outgoing packets.
pub const IPV4_DEFAULT_TTL: u8 = 64;

/// IP version + IHL field for a standard 20-byte header.
const IPV4_VERSION_IHL: u8 = 0x45; // version=4, IHL=5 (5 × 4 = 20 bytes)

// ─── Protocol numbers ───

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Dccp,
    Esp,
    Ah,
    Sctp,
    Unknown(u8),
}

impl IpProtocol {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            2 => Self::Igmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            33 => Self::Dccp,
            50 => Self::Esp,
            51 => Self::Ah,
            132 => Self::Sctp,
            other => Self::Unknown(other),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Igmp => 2,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Dccp => 33,
            Self::Esp => 50,
            Self::Ah => 51,
            Self::Sctp => 132,
            Self::Unknown(v) => v,
        }
    }
}

// ─── Flags / fragment offset ───

const IP_FLAG_DF: u16 = 0x4000; // Don't Fragment

// ─── IPv4 header ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub header_checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

impl Ipv4Header {
    /// Return the IHL (Internet Header Length) in 32-bit words.
    pub fn ihl(&self) -> u8 {
        5 // standard 20-byte header, no options
    }

    /// Return the header length in bytes.
    pub fn header_len(&self) -> usize {
        self.ihl() as usize * 4
    }
}

// ─── IPv4 packet ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

// ─── Checksum ───

/// Add `data` to a running RFC 791 internet checksum accumulator.
///
/// The data is processed as 16-bit big-endian words.  If `data` has an
/// odd number of bytes a zero pad byte is appended for the calculation.
/// The caller must initialise `sum` to 0 before the first call and call
/// [`checksum_finalize`] after the last [`checksum_add`].
#[inline]
pub fn checksum_add(sum: &mut u32, data: &[u8]) {
    let mut i = 0;
    let len = data.len();
    while i + 1 < len {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        *sum = sum.wrapping_add(word as u32);
        i += 2;
    }
    if i < len {
        let word = u16::from_be_bytes([data[i], 0]);
        *sum = sum.wrapping_add(word as u32);
    }
}

/// Finalise a running checksum accumulator, folding carries and returning
/// the one's-complement 16-bit value.
#[inline]
pub fn checksum_finalize(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute the RFC 791 internet checksum over `data`.
///
/// This is a convenience wrapper around [`checksum_add`] +
/// [`checksum_finalize`] for the common single-buffer case.
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    checksum_add(&mut sum, data);
    checksum_finalize(sum)
}

/// Add the 12-byte IPv4 pseudo-header to a running checksum accumulator.
///
/// The pseudo-header is built on the stack — zero heap allocation.  This
/// is the incremental counterpart of [`pseudo_header_checksum_input`];
/// prefer this on hot paths (e.g. `build_tcp_segment`) where it avoids
/// one `Vec` allocation per segment.
///
/// Pseudo-header layout: source IP (4) | dest IP (4) | zero (1) |
/// protocol (1) | segment length (2).
#[inline]
pub fn pseudo_header_checksum_add(
    sum: &mut u32,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    segment_len: u16,
) {
    let pseudo: [u8; 12] = [
        source[0],
        source[1],
        source[2],
        source[3],
        destination[0],
        destination[1],
        destination[2],
        destination[3],
        0,
        protocol,
        (segment_len >> 8) as u8,
        segment_len as u8,
    ];
    checksum_add(sum, &pseudo);
}

/// Build the IPv4 pseudo-header checksum input used by TCP and UDP.
///
/// This convenience function returns a contiguous `Vec<u8>` containing
/// the pseudo-header followed by `segment`.  On hot paths prefer the
/// zero-allocation [`pseudo_header_checksum_add`] + [`checksum_add`] +
/// [`checksum_finalize`] incremental API instead.
pub fn pseudo_header_checksum_input(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> Vec<u8> {
    let seg_len = segment.len() as u16;
    let pseudo: [u8; 12] = [
        source[0],
        source[1],
        source[2],
        source[3],
        destination[0],
        destination[1],
        destination[2],
        destination[3],
        0,
        protocol,
        (seg_len >> 8) as u8,
        seg_len as u8,
    ];
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&pseudo);
    buf.extend_from_slice(segment);
    buf
}

// ─── Parse / build ───

/// Parse an IPv4 packet from a byte slice.
///
/// Validates the minimum header length, IHL, total length, and header
/// checksum.  Returns the packet on success.
pub fn parse_packet(data: &[u8]) -> Result<Ipv4Packet> {
    if data.len() < IPV4_MIN_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;

    // Only IPv4 is supported.
    if version != 4 {
        return Err(Error::Unsupported);
    }

    // We only support standard 20-byte headers (IHL = 5).
    if ihl < 5 {
        return Err(Error::Unsupported);
    }
    let header_len = (ihl as usize) * 4;
    if data.len() < header_len {
        return Err(Error::InvalidArgument);
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]);
    if total_length as usize > data.len() {
        return Err(Error::InvalidArgument);
    }

    // Verify header checksum
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);
    if compute_checksum(&data[..header_len]) != 0 {
        return Err(Error::DeviceError);
    }

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let ttl = data[8];
    let protocol = IpProtocol::from_u8(data[9]);

    let mut source = [0u8; 4];
    source.copy_from_slice(&data[12..16]);
    let mut destination = [0u8; 4];
    destination.copy_from_slice(&data[16..20]);

    // Extract payload
    let payload_start = header_len;
    let payload_end = total_length as usize;
    let payload = if payload_end > payload_start {
        Vec::from(&data[payload_start..payload_end.min(data.len())])
    } else {
        Vec::new()
    };

    Ok(Ipv4Packet {
        header: Ipv4Header {
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source,
            destination,
        },
        payload,
    })
}

/// Build a wire-format IPv4 packet from header and payload.
///
/// The `total_length` field in `header` is ignored and recomputed.
/// The header checksum is computed automatically.
pub fn build_packet(header: &Ipv4Header, payload: &[u8]) -> Vec<u8> {
    let total_length = (IPV4_MIN_HEADER_SIZE + payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_length as usize);

    // Version + IHL
    buf.push(IPV4_VERSION_IHL);
    // DSCP + ECN (always 0)
    buf.push(0);
    // Total length
    buf.extend_from_slice(&total_length.to_be_bytes());
    // Identification
    buf.extend_from_slice(&header.identification.to_be_bytes());
    // Flags + fragment offset (DF always set)
    let flags_fo = IP_FLAG_DF | (header.flags_fragment_offset & 0x1FFF);
    buf.extend_from_slice(&flags_fo.to_be_bytes());
    // TTL
    buf.push(header.ttl);
    // Protocol
    buf.push(header.protocol.to_u8());
    // Header checksum (placeholder)
    buf.extend_from_slice(&[0u8; 2]);
    // Source IP
    buf.extend_from_slice(&header.source);
    // Destination IP
    buf.extend_from_slice(&header.destination);
    // Payload
    buf.extend_from_slice(payload);

    // Compute and insert the header checksum (header only, not payload)
    let checksum = compute_checksum(&buf[..IPV4_MIN_HEADER_SIZE]);
    buf[10] = (checksum >> 8) as u8;
    buf[11] = checksum as u8;

    buf
}

// ─── Lenient header parse / multicast MAC mapping ───

/// Parse just the IPv4 header, without validating the checksum or the total
/// length against the available data.
///
/// Returns the header and the header length in bytes (so callers can index
/// past it to reach the transport header).  Used by NAT, which only needs the
/// addressing and protocol fields and must accept packets whose payload has
/// already been truncated or that arrive fragmented.
pub fn parse_ipv4_header(data: &[u8]) -> Option<(Ipv4Header, usize)> {
    if data.len() < IPV4_MIN_HEADER_SIZE {
        return None;
    }
    let version_ihl = data[0];
    // Only IPv4 is supported.
    if version_ihl >> 4 != 4 {
        return None;
    }
    let header_len = ((version_ihl & 0x0F) as usize) * 4;
    // A 20-byte header is required and must fit in the available data.
    if header_len < IPV4_MIN_HEADER_SIZE || header_len > data.len() {
        return None;
    }

    let mut source = [0u8; 4];
    source.copy_from_slice(&data[12..16]);
    let mut destination = [0u8; 4];
    destination.copy_from_slice(&data[16..20]);

    Some((
        Ipv4Header {
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags_fragment_offset: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: IpProtocol::from_u8(data[9]),
            header_checksum: u16::from_be_bytes([data[10], data[11]]),
            source,
            destination,
        },
        header_len,
    ))
}

/// Compute the Ethernet multicast MAC address for an IPv4 multicast address
/// (`01:00:5E:xx:xx:xx`, mapping the low 23 bits of the address per
/// RFC 1112 §6.4).
pub fn multicast_mac_from_ipv4(addr: Ipv4Addr) -> [u8; 6] {
    [0x01, 0x00, 0x5E, addr[1] & 0x7F, addr[2], addr[3]]
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_protocol_conversion() {
        assert_eq!(IpProtocol::from_u8(1), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
        assert_eq!(IpProtocol::from_u8(99), IpProtocol::Unknown(99));
        assert_eq!(IpProtocol::Icmp.to_u8(), 1);
        assert_eq!(IpProtocol::Tcp.to_u8(), 6);
        assert_eq!(IpProtocol::Udp.to_u8(), 17);
    }

    #[test]
    fn checksum_known_vector() {
        // From RFC 1071: a simple example
        let data: [u8; 8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cs = compute_checksum(&data);
        // 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2DDF0 → fold: 0x0002 + 0xDDF0 = 0xDDF2
        // ~0xDDF2 = 0x220D
        // Wait, let me recalculate:
        // 0x0001 + 0xf203 = 0xf204
        // 0xf204 + 0xf4f5 = 0x1E6F9 → 0x0001 + 0xE6F9 = 0xE6FA
        // 0xE6FA + 0xf6f7 = 0x1DDF1 → 0x0001 + 0xDDF1 = 0xDDF2
        // ~0xDDF2 = 0x220D
        assert_eq!(cs, 0x220D);
    }

    #[test]
    fn checksum_valid_packet_passes() {
        // Build a minimal packet
        let header = Ipv4Header {
            total_length: 0, // will be recomputed
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Icmp,
            header_checksum: 0, // will be recomputed
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 2],
        };

        let raw = build_packet(&header, b"ping");
        // The built packet should have a valid checksum
        let header_len = 20;
        assert_eq!(compute_checksum(&raw[..header_len]), 0);
    }

    #[test]
    fn parse_and_build_round_trip() {
        let header = Ipv4Header {
            total_length: 0,
            identification: 0x1234,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Udp,
            header_checksum: 0,
            source: [192, 168, 1, 1],
            destination: [192, 168, 1, 2],
        };

        let raw = build_packet(&header, b"test payload");
        let parsed = parse_packet(&raw).expect("should parse");

        assert_eq!(parsed.header.identification, 0x1234);
        assert_eq!(parsed.header.ttl, 64);
        assert_eq!(parsed.header.protocol, IpProtocol::Udp);
        assert_eq!(parsed.header.source, [192, 168, 1, 1]);
        assert_eq!(parsed.header.destination, [192, 168, 1, 2]);
        assert_eq!(&parsed.payload, b"test payload");
    }

    #[test]
    fn parse_rejects_short_data() {
        let short = [0u8; 10];
        assert_eq!(parse_packet(&short), Err(Error::InvalidArgument));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // Manually corrupt a valid packet
        let header = Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Icmp,
            header_checksum: 0,
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 2],
        };
        let mut raw = build_packet(&header, b"data");
        // Corrupt a byte
        raw[5] ^= 0xFF;
        assert_eq!(parse_packet(&raw), Err(Error::DeviceError));
    }

    #[test]
    fn parse_empty_payload() {
        let header = Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 1,
            protocol: IpProtocol::Icmp,
            header_checksum: 0,
            source: [1, 1, 1, 1],
            destination: [2, 2, 2, 2],
        };
        let raw = build_packet(&header, &[]);
        let parsed = parse_packet(&raw).expect("should parse");
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn pseudo_header_includes_protocol_and_length() {
        let input = pseudo_header_checksum_input(
            [10, 0, 2, 15],
            [10, 0, 2, 2],
            6, // TCP
            b"test",
        );
        // 12 bytes pseudo-header + 4 bytes payload
        assert_eq!(input.len(), 16);
        // Check protocol byte
        assert_eq!(input[9], 6);
        // Check length (4 bytes in big-endian)
        assert_eq!(u16::from_be_bytes([input[10], input[11]]), 4);
    }
}
