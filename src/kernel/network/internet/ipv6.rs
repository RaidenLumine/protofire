//! src/kernel/network/internet/ipv6.rs
//!
//! IPv6 packet parsing, building, checksums, and fragmentation (RFC 8200).

use alloc::vec::Vec;

use crate::{Error, Result};

/// An IPv6 address: 16 octets (RFC 8200 §2.5).
pub type Ipv6Addr = [u8; 16];

/// Size of the fixed 40-byte IPv6 base header (no extension headers).
pub const IPV6_HEADER_SIZE: usize = 40;

/// Minimum link MTU for IPv6 (RFC 8200 §5).
pub const IPV6_MIN_MTU: usize = 1280;

/// Default hop limit for locally generated IPv6 packets (Linux: 64).
pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;

/// Byte 0 of the IPv6 header: version(4) = 6, traffic class upper nybble = 0.
pub const IPV6_VERSION_TC1: u8 = 0x60;

/// IPv6 next-header protocol values (RFC 8200 §4.7 / IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv6NextHeader {
    HopByHop = 0,
    Tcp = 6,
    Udp = 17,
    Dccp = 33,
    Routing = 43,
    Fragment = 44,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    NoNextHeader = 59,
    DestinationOptions = 60,
    /// A wire value with no kernel-native interpretation.
    Unknown(u8),
}

impl Ipv6NextHeader {
    /// Map a raw wire byte to an [`Ipv6NextHeader`].
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::HopByHop,
            6 => Self::Tcp,
            17 => Self::Udp,
            33 => Self::Dccp,
            43 => Self::Routing,
            44 => Self::Fragment,
            50 => Self::Esp,
            51 => Self::Ah,
            58 => Self::Icmpv6,
            59 => Self::NoNextHeader,
            60 => Self::DestinationOptions,
            other => Self::Unknown(other),
        }
    }

    /// The wire byte for this next-header value.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::HopByHop => 0,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Dccp => 33,
            Self::Routing => 43,
            Self::Fragment => 44,
            Self::Esp => 50,
            Self::Ah => 51,
            Self::Icmpv6 => 58,
            Self::NoNextHeader => 59,
            Self::DestinationOptions => 60,
            Self::Unknown(value) => value,
        }
    }
}

/// Fixed 40-byte IPv6 base header (RFC 8200 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Differentiated Services / ECN field.
    pub traffic_class: u8,
    /// 20-bit flow label.
    pub flow_label: u32,
    /// Payload length in bytes (extension headers + upper-layer data).
    pub payload_length: u16,
    /// Next-header protocol value.
    pub next_header: Ipv6NextHeader,
    /// Hop limit.
    pub hop_limit: u8,
    /// 128-bit source address.
    pub source: Ipv6Addr,
    /// 128-bit destination address.
    pub destination: Ipv6Addr,
}

/// A parsed IPv6 packet: base header + payload bytes.
#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    pub header: Ipv6Header,
    pub payload: Vec<u8>,
}

/// IPv6 fragment extension header (RFC 8200 §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6FragmentHeader {
    /// Next-header value that follows the fragment header.
    pub next_header: Ipv6NextHeader,
    /// Fragment offset in 8-octet units.
    pub fragment_offset: u16,
    /// Whether more fragments follow.
    pub more_fragments: bool,
    /// Fragment identification value.
    pub identification: u32,
}

/// Size of the IPv6 fragment extension header (8 bytes).
const FRAGMENT_HEADER_SIZE: usize = 8;

/// Build an 8-byte IPv6 fragment extension header.
pub fn build_fragment_header(
    next_header: u8,
    fragment_offset: u16,
    more_fragments: bool,
    identification: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAGMENT_HEADER_SIZE);
    buf.push(next_header);
    buf.push(0); // reserved
    let offset_field = ((fragment_offset & 0x1FFF) << 3) | u16::from(more_fragments);
    buf.extend_from_slice(&offset_field.to_be_bytes());
    buf.extend_from_slice(&identification.to_be_bytes());
    buf
}

/// Parse an 8-byte IPv6 fragment extension header.
///
/// Returns `(header, bytes_consumed)` on success, `Err(Error::InvalidArgument)`
/// when `data` is too short to hold the fixed 8-byte fragment header.
pub fn parse_fragment_header(data: &[u8]) -> Result<(Ipv6FragmentHeader, usize)> {
    if data.len() < FRAGMENT_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let offset_field = u16::from_be_bytes([data[2], data[3]]);
    Ok((
        Ipv6FragmentHeader {
            next_header: Ipv6NextHeader::from_u8(data[0]),
            fragment_offset: (offset_field >> 3) & 0x1FFF,
            more_fragments: offset_field & 1 != 0,
            identification: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        },
        FRAGMENT_HEADER_SIZE,
    ))
}

/// Fragment `payload` into complete IPv6 packets each under `mtu`.
///
/// Returns `None` when the whole packet fits within `mtu` (no fragmentation
/// required).  Each fragment is a full IPv6 packet whose next header is
/// `Fragment` and whose payload starts with the 8-byte fragment extension
/// header followed by a chunk of the original payload, aligned down to 8
/// bytes (RFC 8200 §4.5).
pub fn fragment_packet(
    header: &Ipv6Header,
    payload: &[u8],
    mtu: usize,
    identification: u32,
) -> Option<Vec<Vec<u8>>> {
    // Space for upper-layer data after base header + fragment header.
    let usable = mtu.checked_sub(IPV6_HEADER_SIZE + FRAGMENT_HEADER_SIZE)?;
    if usable >= payload.len() {
        return None;
    }
    let chunk = usable & !7;
    if chunk == 0 {
        return None;
    }
    let mut fragments = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        let len = (payload.len() - offset).min(chunk);
        let more = offset + len < payload.len();
        let frag_header = build_fragment_header(
            header.next_header.to_u8(),
            (offset / 8) as u16,
            more,
            identification,
        );
        let mut combined = Vec::with_capacity(frag_header.len() + len);
        combined.extend_from_slice(&frag_header);
        combined.extend_from_slice(&payload[offset..offset + len]);
        let mut frag_header_for_pkt = *header;
        frag_header_for_pkt.next_header = Ipv6NextHeader::Fragment;
        frag_header_for_pkt.payload_length = 0;
        fragments.push(build_packet(&frag_header_for_pkt, &combined));
        offset += len;
    }
    Some(fragments)
}

// ─── Checksum helpers ───────────────────────────────────────────────────

/// Add the 40-byte IPv6 pseudo-header to a running checksum accumulator.
///
/// Pseudo-header layout (RFC 2460 §8.1):
///   Source Address (16) | Destination Address (16) | Upper-Layer Packet
///   Length (4) | zero (3) | Next Header (1).
#[inline]
pub fn pseudo_header_checksum_add(
    sum: &mut u32,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    upper_layer_len: u32,
) {
    // Source address (16 bytes)
    super::ipv4::checksum_add(sum, &source);
    // Destination address (16 bytes)
    super::ipv4::checksum_add(sum, &destination);
    // Upper-layer length (4 bytes, big-endian)
    super::ipv4::checksum_add(sum, &upper_layer_len.to_be_bytes());
    // Three zero bytes + next header
    super::ipv4::checksum_add(sum, &[0u8, 0u8, 0u8, next_header]);
}

/// Build the IPv6 pseudo-header checksum input used by TCP and UDP.
///
/// Returns a contiguous `Vec<u8>` containing the 40-byte pseudo-header
/// followed by `segment`.  On hot paths prefer the zero-allocation
/// [`pseudo_header_checksum_add`] + [`super::ipv4::checksum_add`] +
/// [`super::ipv4::checksum_finalize`] incremental API.
pub fn pseudo_header_checksum_input(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    segment: &[u8],
) -> Vec<u8> {
    let upper_len = segment.len() as u32;
    // 40-byte pseudo-header + segment
    let mut buf = Vec::with_capacity(40 + segment.len());
    // Source (16)
    buf.extend_from_slice(&source);
    // Destination (16)
    buf.extend_from_slice(&destination);
    // Upper-layer length (4)
    buf.extend_from_slice(&upper_len.to_be_bytes());
    // Zero (3) + next header (1)
    buf.extend_from_slice(&[0u8, 0u8, 0u8, next_header]);
    // Segment
    buf.extend_from_slice(segment);
    buf
}

// ─── Parse / build ──────────────────────────────────────────────────────

/// Parse an IPv6 packet from a byte slice.
///
/// Validates the minimum header size, version field, and payload length
/// consistency.  Does not handle extension headers — only the first
/// non-extension next-header value is exposed.
pub fn parse_packet(data: &[u8]) -> Result<Ipv6Packet> {
    if data.len() < IPV6_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Version is in the upper 4 bits of byte 0.
    let version = data[0] >> 4;
    if version != 6 {
        return Err(Error::Unsupported);
    }

    // Traffic class: lower 4 bits of byte 0 + upper 4 bits of byte 1.
    let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);

    // Flow label: lower 4 bits of byte 1 + byte 2 + byte 3.
    let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header_value = data[6];
    let hop_limit = data[7];

    let mut source = [0u8; 16];
    source.copy_from_slice(&data[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&data[24..40]);

    // Total packet size must be >= header + payload_length.
    let total_expected = IPV6_HEADER_SIZE + payload_length as usize;
    if data.len() < total_expected {
        return Err(Error::InvalidArgument);
    }

    let payload = if payload_length > 0 {
        Vec::from(&data[IPV6_HEADER_SIZE..total_expected.min(data.len())])
    } else {
        Vec::new()
    };

    Ok(Ipv6Packet {
        header: Ipv6Header {
            traffic_class,
            flow_label,
            payload_length,
            next_header: Ipv6NextHeader::from_u8(next_header_value),
            hop_limit,
            source,
            destination,
        },
        payload,
    })
}

/// Build a wire-format IPv6 packet from header and payload.
///
/// The `payload_length` field in `header` is ignored and recomputed.
pub fn build_packet(header: &Ipv6Header, payload: &[u8]) -> Vec<u8> {
    let payload_length = payload.len() as u16;
    let mut buf = Vec::with_capacity(IPV6_HEADER_SIZE + payload.len());

    // Version(4) | Traffic Class upper(4)
    buf.push(IPV6_VERSION_TC1 | ((header.traffic_class >> 4) & 0x0F));
    // Traffic Class lower(4) | Flow Label upper(4)
    buf.push(((header.traffic_class & 0x0F) << 4) | ((header.flow_label >> 16) as u8 & 0x0F));
    // Flow Label lower 16 bits
    buf.push((header.flow_label >> 8) as u8);
    buf.push(header.flow_label as u8);
    // Payload length
    buf.extend_from_slice(&payload_length.to_be_bytes());
    // Next header
    buf.push(header.next_header.to_u8());
    // Hop limit
    buf.push(header.hop_limit);
    // Source address (16 bytes)
    buf.extend_from_slice(&header.source);
    // Destination address (16 bytes)
    buf.extend_from_slice(&header.destination);
    // Payload
    buf.extend_from_slice(payload);

    buf
}

// ─── Well-known addresses & helpers ─────────────────────────────────────

/// IPv6 unspecified address `::`.
pub const IPV6_UNSPECIFIED: Ipv6Addr = [0u8; 16];

/// IPv6 link-local all-nodes multicast `ff02::1`.
pub const IPV6_ALL_NODES_MULTICAST: Ipv6Addr = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// IPv6 link-local all-routers multicast `ff02::2`.
pub const IPV6_ALL_ROUTERS_MULTICAST: Ipv6Addr = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// Build the solicited-node multicast address for `target` (`ff02::1:ffXX:XXXX`).
/// Used by NDP Neighbor Solicitation to reach the target without broadcasting
/// to all nodes.
pub fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let mut addr = [
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, target[13],
        target[14], target[15],
    ];
    addr[13] = target[13];
    addr[14] = target[14];
    addr[15] = target[15];
    addr
}

/// Derive an IPv6 link-local address from a MAC address using the modified
/// EUI-64 format (RFC 4291 §2.5.1).
///
/// Format: `fe80::<modified-eui64>` where the modified EUI-64 is formed by:
///   - Inserting `0xfffe` between the OUI (bytes 0-2) and NIC-specific
///     (bytes 3-5) halves of the MAC.
///   - Flipping the universal/local bit (bit 1 of byte 0).
pub fn link_local_from_mac(mac: [u8; 6]) -> Ipv6Addr {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    // Modified EUI-64
    addr[8] = mac[0] ^ 0x02; // flip universal/local bit
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xff;
    addr[12] = 0xfe;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    addr
}

/// Compute the IPv6 multicast MAC address for a given IPv6 destination
/// address (`33:33:xx:xx:xx:xx` where `xx:xx:xx:xx` are the low 32 bits
/// of the IPv6 address).
pub fn multicast_mac_from_ipv6(ip: Ipv6Addr) -> [u8; 6] {
    [0x33, 0x33, ip[12], ip[13], ip[14], ip[15]]
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::internet::ipv4;
    use alloc::vec::Vec;

    #[test]
    fn next_header_conversion() {
        assert_eq!(Ipv6NextHeader::from_u8(58), Ipv6NextHeader::Icmpv6);
        assert_eq!(Ipv6NextHeader::from_u8(6), Ipv6NextHeader::Tcp);
        assert_eq!(Ipv6NextHeader::from_u8(17), Ipv6NextHeader::Udp);
        assert_eq!(Ipv6NextHeader::from_u8(0), Ipv6NextHeader::HopByHop);
        assert_eq!(Ipv6NextHeader::from_u8(43), Ipv6NextHeader::Routing);
        assert_eq!(Ipv6NextHeader::from_u8(59), Ipv6NextHeader::NoNextHeader);
        assert_eq!(
            Ipv6NextHeader::from_u8(60),
            Ipv6NextHeader::DestinationOptions
        );
        assert_eq!(Ipv6NextHeader::from_u8(99), Ipv6NextHeader::Unknown(99));
        assert_eq!(Ipv6NextHeader::Icmpv6.to_u8(), 58);
        assert_eq!(Ipv6NextHeader::Tcp.to_u8(), 6);
        assert_eq!(Ipv6NextHeader::Udp.to_u8(), 17);
        assert_eq!(Ipv6NextHeader::Routing.to_u8(), 43);
        assert_eq!(Ipv6NextHeader::DestinationOptions.to_u8(), 60);
    }

    #[test]
    fn parse_and_build_round_trip() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0x12345,
            payload_length: 0,
            next_header: Ipv6NextHeader::Udp,
            hop_limit: 64,
            source: [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
            ],
            destination: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        let raw = build_packet(&header, b"test_payload");
        let parsed = parse_packet(&raw).expect("should parse");

        assert_eq!(parsed.header.traffic_class, 0);
        assert_eq!(parsed.header.flow_label, 0x12345);
        assert_eq!(parsed.header.next_header, Ipv6NextHeader::Udp);
        assert_eq!(parsed.header.hop_limit, 64);
        assert_eq!(parsed.header.source, header.source);
        assert_eq!(parsed.header.destination, header.destination);
        assert_eq!(&parsed.payload, b"test_payload");
    }

    #[test]
    fn parse_rejects_short_data() {
        let short = [0u8; 20];
        assert!(matches!(parse_packet(&short), Err(Error::InvalidArgument)));
    }

    #[test]
    fn parse_rejects_non_ipv6_version() {
        // Build a packet and modify the version nybble to 4 (IPv4).
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: Ipv6NextHeader::NoNextHeader,
            hop_limit: 1,
            source: [0u8; 16],
            destination: [0u8; 16],
        };
        let mut raw = build_packet(&header, &[]);
        raw[0] = 0x40; // version=4 (not 6)
        assert!(matches!(parse_packet(&raw), Err(Error::Unsupported)));
    }

    #[test]
    fn parse_empty_payload() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: Ipv6NextHeader::NoNextHeader,
            hop_limit: 1,
            source: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        let raw = build_packet(&header, &[]);
        let parsed = parse_packet(&raw).expect("should parse");
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn build_packet_computes_payload_length() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 999, // ignored by build_packet
            next_header: Ipv6NextHeader::Icmpv6,
            hop_limit: 255,
            source: [0u8; 16],
            destination: [0u8; 16],
        };
        let payload = [0xABu8; 100];
        let raw = build_packet(&header, &payload);
        assert_eq!(raw.len(), IPV6_HEADER_SIZE + 100);
        // Payload length field is at bytes 4-5
        let pkt_len = u16::from_be_bytes([raw[4], raw[5]]);
        assert_eq!(pkt_len, 100);
    }

    #[test]
    fn parse_validates_payload_length_consistency() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: Ipv6NextHeader::NoNextHeader,
            hop_limit: 64,
            source: [0u8; 16],
            destination: [0u8; 16],
        };
        // Build with 10-byte payload, but truncate to header-only.
        let raw = build_packet(&header, &[0u8; 10]);
        let truncated = &raw[..IPV6_HEADER_SIZE]; // payload missing
        assert!(matches!(
            parse_packet(truncated),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn pseudo_header_checksum_round_trip() {
        let src: Ipv6Addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let segment = b"test_segment";

        // Incremental API
        let mut sum: u32 = 0;
        pseudo_header_checksum_add(&mut sum, src, dst, 17, segment.len() as u32);
        ipv4::checksum_add(&mut sum, segment);
        let cs1 = ipv4::checksum_finalize(sum);

        // Convenience API
        let input = pseudo_header_checksum_input(src, dst, 17, segment);
        let cs2 = ipv4::compute_checksum(&input);

        assert_eq!(cs1, cs2);
    }

    #[test]
    fn solicited_node_multicast_has_correct_prefix() {
        let target: Ipv6Addr = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78,
        ];
        let sn = solicited_node_multicast(target);
        assert_eq!(sn[0], 0xff);
        assert_eq!(sn[1], 0x02);
        assert_eq!(sn[11], 0x01);
        assert_eq!(sn[12], 0xff);
        // Low 24 bits match target
        assert_eq!(sn[13], target[13]);
        assert_eq!(sn[14], target[14]);
        assert_eq!(sn[15], target[15]);
    }

    #[test]
    fn link_local_from_mac_has_fe80_prefix() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let ll = link_local_from_mac(mac);
        assert_eq!(ll[0], 0xfe);
        assert_eq!(ll[1], 0x80);
        // EUI-64: ff:fe inserted in the middle
        assert_eq!(ll[11], 0xff);
        assert_eq!(ll[12], 0xfe);
        // Universal/local bit flipped on byte 0 of MAC
        assert_eq!(ll[8], mac[0] ^ 0x02);
    }

    #[test]
    fn multicast_mac_has_3333_prefix() {
        let ip: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34];
        let mac = multicast_mac_from_ipv6(ip);
        assert_eq!(mac[0], 0x33);
        assert_eq!(mac[1], 0x33);
        assert_eq!(mac[2], ip[12]);
        assert_eq!(mac[3], ip[13]);
        assert_eq!(mac[4], ip[14]);
        assert_eq!(mac[5], ip[15]);
    }

    #[test]
    fn fragment_packet_returns_none_when_payload_fits() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: Ipv6NextHeader::Udp,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        // 100 bytes fits in MTU 1280.
        assert!(fragment_packet(&header, &[0xAB; 100], 1280, 0x1234).is_none());
    }

    #[test]
    fn fragment_packet_splits_oversized_payload_at_1280() {
        let header = Ipv6Header {
            traffic_class: 0x0f,
            flow_label: 0xabcde,
            payload_length: 0,
            next_header: Ipv6NextHeader::Udp,
            hop_limit: 32,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        let payload = [0xCD; 2000];
        let fragments = fragment_packet(&header, &payload, 1280, 0x1234)
            .expect("oversized payload must fragment");
        // 2000-byte payload at MTU 1280 → chunk 1232 + remainder 768 = 2 fragments.
        assert_eq!(fragments.len(), 2);

        // Each fragment is a complete IPv6 packet with next header Fragment.
        for (index, frag) in fragments.iter().enumerate() {
            let parsed = parse_packet(frag).expect("fragment parses");
            assert_eq!(parsed.header.next_header, Ipv6NextHeader::Fragment);
            assert_eq!(parsed.header.source, header.source);
            assert_eq!(parsed.header.destination, header.destination);
            assert_eq!(parsed.header.hop_limit, 32);
            // Traffic class preserved.
            assert_eq!(parsed.header.traffic_class, 0x0f);
            let (fh, consumed) = parse_fragment_header(&parsed.payload).expect("frag header");
            assert_eq!(fh.next_header, Ipv6NextHeader::Udp);
            assert_eq!(fh.identification, 0x1234);
            if index == 0 {
                assert_eq!(fh.fragment_offset, 0);
                assert!(fh.more_fragments);
            } else {
                assert_eq!(fh.fragment_offset, 1232 / 8);
                assert!(!fh.more_fragments);
            }
            let chunk = &parsed.payload[consumed..];
            assert_eq!(chunk.len(), if index == 0 { 1232 } else { 768 });
        }

        // Concatenation reproduces the original payload.
        let mut reassembled = Vec::new();
        for frag in &fragments {
            let parsed = parse_packet(frag).unwrap();
            let (_, consumed) = parse_fragment_header(&parsed.payload).unwrap();
            reassembled.extend_from_slice(&parsed.payload[consumed..]);
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn fragment_packet_keeps_final_fragment_more_flag_clear() {
        let header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: Ipv6NextHeader::Tcp,
            hop_limit: 64,
            source: [0x20; 16],
            destination: [0x30; 16],
        };
        // 1300 bytes → 2 fragments (1232 + 68).
        let fragments = fragment_packet(&header, &[0xEE; 1300], 1280, 7).expect("must fragment");
        assert_eq!(fragments.len(), 2);
        let parsed = parse_packet(&fragments[1]).unwrap();
        let (fh, _) = parse_fragment_header(&parsed.payload).unwrap();
        assert!(!fh.more_fragments);
    }

    #[test]
    fn build_fragment_header_round_trip() {
        let bytes = build_fragment_header(17, 7, true, 0xdeadbeef);
        let (parsed, consumed) = parse_fragment_header(&bytes).expect("parse");
        assert_eq!(consumed, 8);
        assert_eq!(parsed.next_header, Ipv6NextHeader::Udp);
        assert_eq!(parsed.fragment_offset, 7);
        assert!(parsed.more_fragments);
        assert_eq!(parsed.identification, 0xdeadbeef);
    }
}
