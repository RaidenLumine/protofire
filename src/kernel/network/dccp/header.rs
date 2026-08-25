//! src/kernel/network/dccp/header.rs
//!
//! DCCP (RFC 4340) generic header, packet types, and checksum.
//!
//! This kernel always transmits the extended generic header (X = 1) with
//! 48-bit sequence numbers.  The short form (X = 0, 24-bit sequence) is
//! accepted on receive.
//!
//! Wire layout of the 16-byte extended generic header:
//! ```text
//! byte  0-1 : Source Port (BE)
//! byte  2-3 : Dest Port (BE)
//! byte    4 : Data Offset (number of 32-bit words covering the generic
//!             header + type-specific header + options)
//! byte    5 : CCVal (high 4 bits) | CsCov (low 4 bits)
//! byte  6-7 : Checksum (BE)
//! byte    8 : Reserved (bits 7-5) | X (bit 4) | Type (bits 3-0)
//! byte    9 : X marker (bit 7, must equal byte 8 bit 4) | reserved (bits 6-0)
//! byte 10-15: Sequence Number, 48-bit big-endian (X = 1)
//!             or, for the 12-byte short form, bytes 9-11 hold the 24-bit
//!             sequence number (byte 9 bit 7 = 0).
//! ```
//!
//! Type-specific headers follow the generic header:
//! - Request / Response : 4-byte Service Code.
//! - Ack / DataAck / CloseReq / Close / Sync / SyncAck : 8-byte Acknowledgment
//!   Number (48-bit value in 8 bytes).
//! - Reset : 8-byte Acknowledgment Number + 1-byte Reset Code + 3 reserved.
//! - Data : no type-specific header.
//!
//! Options follow the type-specific header, byte-aligned:
//! `[type(1)][length(1)][length - 2 bytes of data]`.
//!
//! The DCCP checksum (RFC 4340 §9) covers the IP pseudo-header (protocol
//! 33) plus the entire DCCP packet, exactly like the TCP/UDP checksum.

use alloc::vec::Vec;

use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::{self, IpProtocol};
use crate::kernel::network::internet::ipv6::{self, Ipv6NextHeader};
use crate::{Error, Result};

/// Extended generic header size (X = 1, 48-bit sequence numbers).  Always
/// used on transmission.
pub const GENERIC_HEADER_SIZE: usize = 16;
/// Short generic header size (X = 0, 24-bit sequence numbers).  Accepted on
/// receive.
pub const SHORT_HEADER_SIZE: usize = 12;
/// Size of the acknowledgment-number field.
pub const ACK_FIELD_SIZE: usize = 8;
/// Size of the service-code field (Request / Response).
pub const SERVICE_CODE_SIZE: usize = 4;

/// DCCP packet types (RFC 4340 §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DccpPacketType {
    Request,
    Response,
    Data,
    Ack,
    DataAck,
    CloseReq,
    Close,
    Reset,
    Sync,
    SyncAck,
}

impl DccpPacketType {
    /// Map a 4-bit packet-type field.  Returns `None` for the reserved
    /// values 10-15.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Request),
            1 => Some(Self::Response),
            2 => Some(Self::Data),
            3 => Some(Self::Ack),
            4 => Some(Self::DataAck),
            5 => Some(Self::CloseReq),
            6 => Some(Self::Close),
            7 => Some(Self::Reset),
            8 => Some(Self::Sync),
            9 => Some(Self::SyncAck),
            _ => None,
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Response => 1,
            Self::Data => 2,
            Self::Ack => 3,
            Self::DataAck => 4,
            Self::CloseReq => 5,
            Self::Close => 6,
            Self::Reset => 7,
            Self::Sync => 8,
            Self::SyncAck => 9,
        }
    }

    /// Whether this packet type carries an acknowledgment number.
    pub const fn carries_ack(self) -> bool {
        matches!(
            self,
            Self::Ack
                | Self::DataAck
                | Self::CloseReq
                | Self::Close
                | Self::Reset
                | Self::Sync
                | Self::SyncAck
        )
    }

    /// Whether this packet type carries a service code.
    pub const fn carries_service_code(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

/// Parsed DCCP header fields (excluding ports, which are returned with the
/// parsed segment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccpHeader {
    pub packet_type: DccpPacketType,
    /// 48-bit sequence number.
    pub seq: u64,
    /// 48-bit acknowledgment number, when the packet type carries one.
    pub ack: Option<u64>,
    /// Service code (Request / Response only).
    pub service_code: Option<u32>,
    /// Reset code (Reset only).
    pub reset_code: Option<u8>,
    /// Congestion Control Value (per-packet, used by CCID 2).
    pub ccval: u8,
    /// Checksum coverage nibble (0 = full coverage).
    pub cscov: u8,
}

/// A parsed DCCP segment (header + options + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccpSegment {
    pub header: DccpHeader,
    pub src_port: u16,
    pub dst_port: u16,
    /// Raw options bytes (each option is `[type][len][len-2 data]`).
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Compute the DCCP checksum over the pseudo-header + segment.
pub fn compute_checksum(segment: &[u8], src: IpAddress, dst: IpAddress) -> u16 {
    let mut sum: u32 = 0;
    match (src, dst) {
        (IpAddress::V4(s), IpAddress::V4(d)) => {
            ipv4::pseudo_header_checksum_add(
                &mut sum,
                s,
                d,
                IpProtocol::Dccp.to_u8(),
                segment.len() as u16,
            );
        }
        (IpAddress::V6(s), IpAddress::V6(d)) => {
            ipv6::pseudo_header_checksum_add(
                &mut sum,
                s,
                d,
                Ipv6NextHeader::Dccp.to_u8(),
                segment.len() as u32,
            );
        }
        _ => return 0,
    }
    ipv4::checksum_add(&mut sum, segment);
    let checksum = ipv4::checksum_finalize(sum);
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

/// Parse a DCCP segment (including checksum verification).
pub fn parse_segment(data: &[u8], src_ip: IpAddress, dst_ip: IpAddress) -> Result<DccpSegment> {
    if data.len() < SHORT_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Verify the checksum before trusting any field.  The checksum is
    // computed over the segment with its own checksum field zeroed
    // (RFC 4340 §9), so the field is cleared before recomputation.
    let expected = u16::from_be_bytes([data[6], data[7]]);
    if expected != 0 {
        let mut copy = data.to_vec();
        copy[6] = 0;
        copy[7] = 0;
        let actual = compute_checksum(&copy, src_ip, dst_ip);
        if actual != expected {
            return Err(Error::InvalidArgument);
        }
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    let ccval = data[5] >> 4;
    let cscov = data[5] & 0x0F;

    let byte8 = data[8];
    let x = byte8 & 0x10 != 0;
    let ptype = DccpPacketType::from_u8(byte8 & 0x0F).ok_or(Error::InvalidArgument)?;

    // The redundant X bit in byte 9 bit 7 must agree with byte 8 bit 4.
    let x2 = data[9] & 0x80 != 0;
    if x != x2 {
        return Err(Error::InvalidArgument);
    }

    let header_size = if x {
        GENERIC_HEADER_SIZE
    } else {
        SHORT_HEADER_SIZE
    };
    if data.len() < header_size {
        return Err(Error::InvalidArgument);
    }

    let seq = if x {
        let mut s = 0u64;
        for i in 0..6 {
            s = (s << 8) | data[10 + i] as u64;
        }
        s
    } else {
        // Short form: 24-bit sequence number in bytes 9-11.
        ((data[9] as u64) << 16) | ((data[10] as u64) << 8) | data[11] as u64
    };

    let mut offset = header_size;
    let mut ack = None;
    let mut service_code = None;
    let mut reset_code = None;

    if ptype.carries_ack() {
        if data.len() < offset + ACK_FIELD_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut a = 0u64;
        for i in 0..8 {
            a = (a << 8) | data[offset + i] as u64;
        }
        ack = Some(a);
        offset += ACK_FIELD_SIZE;
    }
    if ptype.carries_service_code() {
        if data.len() < offset + SERVICE_CODE_SIZE {
            return Err(Error::InvalidArgument);
        }
        service_code = Some(u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]));
        offset += SERVICE_CODE_SIZE;
    }
    if ptype == DccpPacketType::Reset {
        if data.len() < offset + 4 {
            return Err(Error::InvalidArgument);
        }
        reset_code = Some(data[offset]);
        offset += 4;
    }

    // Split options from payload using the Data Offset field (32-bit words).
    let header_end = (data[4] as usize)
        .checked_mul(4)
        .ok_or(Error::InvalidArgument)?
        .max(offset)
        .min(data.len());
    let options = data[offset..header_end].to_vec();
    let payload = data[header_end..].to_vec();

    Ok(DccpSegment {
        header: DccpHeader {
            packet_type: ptype,
            seq,
            ack,
            service_code,
            reset_code,
            ccval,
            cscov,
        },
        src_port,
        dst_port,
        options,
        payload,
    })
}

/// Builder for a DCCP packet.  The caller sets header fields and options,
/// then calls [`finalize_v4`](DccpPacketBuilder::finalize_v4) or
/// [`finalize_v6`](DccpPacketBuilder::finalize_v6) to produce a complete
/// DCCP segment with a valid checksum.
#[derive(Debug, Clone)]
pub struct DccpPacketBuilder {
    pub src_port: u16,
    pub dst_port: u16,
    pub header: DccpHeader,
    pub options: Vec<u8>,
}

impl DccpPacketBuilder {
    pub fn new(src_port: u16, dst_port: u16, header: DccpHeader) -> Self {
        Self {
            src_port,
            dst_port,
            header,
            options: Vec::new(),
        }
    }

    /// Append a raw option (`[type][len][len-2 data]`).
    pub fn push_option(&mut self, option: &[u8]) {
        self.options.extend_from_slice(option);
    }

    fn type_specific_len(&self) -> usize {
        let mut len = 0usize;
        if self.header.packet_type.carries_ack() {
            len += ACK_FIELD_SIZE;
        }
        if self.header.packet_type.carries_service_code() {
            len += SERVICE_CODE_SIZE;
        }
        if self.header.packet_type == DccpPacketType::Reset {
            len += 4;
        }
        len
    }

    /// Build the complete DCCP segment bytes (generic + type-specific +
    /// options + payload) with the checksum computed for `src`/`dst`.
    ///
    /// The options area is zero-padded so that the application data begins
    /// on the 4-byte boundary implied by the Data Offset field (measured in
    /// 32-bit words).
    pub fn finalize(self, src: IpAddress, dst: IpAddress, payload: &[u8]) -> Vec<u8> {
        let generic = GENERIC_HEADER_SIZE;
        let specific = self.type_specific_len();
        let unpadded = generic + specific + self.options.len();
        let pad = (4 - (unpadded % 4)) % 4;
        let header_len = unpadded + pad;
        let data_offset = (header_len / 4).max(1) as u8;

        let mut buf = Vec::with_capacity(header_len + payload.len());

        // Generic header.
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.push(data_offset);
        buf.push(((self.header.ccval & 0x0F) << 4) | (self.header.cscov & 0x0F));
        buf.extend_from_slice(&[0u8; 2]); // checksum placeholder
        buf.push(0x10 | self.header.packet_type.to_u8()); // X=1, type
        buf.push(0x80); // redundant X marker
                        // 48-bit sequence number in bytes 10-15 (the low six bytes of the
                        // u64 value).
        let seq = (self.header.seq & 0xFFFF_FFFF_FFFF).to_be_bytes();
        buf.extend_from_slice(&seq[2..]);

        // Type-specific header.
        if self.header.packet_type.carries_ack() {
            let ack = self.header.ack.unwrap_or(0) & 0xFFFF_FFFF_FFFF;
            buf.extend_from_slice(&ack.to_be_bytes());
        }
        if self.header.packet_type.carries_service_code() {
            buf.extend_from_slice(&self.header.service_code.unwrap_or(0).to_be_bytes());
        }
        if self.header.packet_type == DccpPacketType::Reset {
            buf.push(self.header.reset_code.unwrap_or(0));
            buf.extend_from_slice(&[0u8; 3]);
        }

        // Options, zero-padded to a 4-byte boundary.
        buf.extend_from_slice(&self.options);
        buf.extend_from_slice(&[0u8; 4][..pad]);

        // Payload.
        buf.extend_from_slice(payload);

        // Checksum.
        let checksum = compute_checksum(&buf, src, dst);
        buf[6] = (checksum >> 8) as u8;
        buf[7] = checksum as u8;
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_v4_addrs() -> (IpAddress, IpAddress) {
        (
            IpAddress::V4([10, 0, 2, 15]),
            IpAddress::V4([10, 0, 2, 100]),
        )
    }

    fn test_v6_addrs() -> (IpAddress, IpAddress) {
        (
            IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        )
    }

    #[test]
    fn packet_type_mapping() {
        for value in 0..10 {
            let ptype = DccpPacketType::from_u8(value).expect("type 0-9");
            assert_eq!(ptype.to_u8(), value);
        }
        assert!(DccpPacketType::from_u8(10).is_none());
        assert!(DccpPacketType::from_u8(15).is_none());
    }

    #[test]
    fn ack_and_service_code_carriers() {
        assert!(DccpPacketType::Ack.carries_ack());
        assert!(DccpPacketType::Reset.carries_ack());
        assert!(!DccpPacketType::Data.carries_ack());
        assert!(!DccpPacketType::Request.carries_ack());
        assert!(DccpPacketType::Request.carries_service_code());
        assert!(DccpPacketType::Response.carries_service_code());
        assert!(!DccpPacketType::Data.carries_service_code());
    }

    #[test]
    fn request_response_round_trip_v4() {
        let (src, dst) = test_v4_addrs();
        let header = DccpHeader {
            packet_type: DccpPacketType::Request,
            seq: 0x010203040506,
            ack: None,
            service_code: Some(0x01020304),
            reset_code: None,
            ccval: 0,
            cscov: 0,
        };
        let builder = DccpPacketBuilder::new(12345, 5000, header.clone());
        let packet = builder.finalize(src, dst, b"hello");

        let seg = parse_segment(&packet, src, dst).expect("parse request");
        assert_eq!(seg.header, header);
        assert_eq!(seg.src_port, 12345);
        assert_eq!(seg.dst_port, 5000);
        assert_eq!(seg.payload, b"hello");
    }

    #[test]
    fn data_with_ack_round_trip_v6() {
        let (src, dst) = test_v6_addrs();
        let header = DccpHeader {
            packet_type: DccpPacketType::DataAck,
            seq: 0xABCDEF012345,
            ack: Some(0x112233445566),
            service_code: None,
            reset_code: None,
            ccval: 2,
            cscov: 0,
        };
        let builder = DccpPacketBuilder::new(2000, 3000, header.clone());
        let packet = builder.finalize(src, dst, b"data_ack");

        let seg = parse_segment(&packet, src, dst).expect("parse data ack");
        assert_eq!(seg.header, header);
        assert_eq!(seg.payload, b"data_ack");
    }

    #[test]
    fn reset_carries_reset_code() {
        let (src, dst) = test_v4_addrs();
        let header = DccpHeader {
            packet_type: DccpPacketType::Reset,
            seq: 0x111111111111,
            ack: Some(0x222222222222),
            service_code: None,
            reset_code: Some(4), // Connection Reset
            ccval: 0,
            cscov: 0,
        };
        let builder = DccpPacketBuilder::new(1111, 2222, header.clone());
        let packet = builder.finalize(src, dst, &[]);

        let seg = parse_segment(&packet, src, dst).expect("parse reset");
        assert_eq!(seg.header, header);
        assert_eq!(seg.header.reset_code, Some(4));
    }

    #[test]
    fn options_are_preserved() {
        let (src, dst) = test_v4_addrs();
        let header = DccpHeader {
            packet_type: DccpPacketType::Ack,
            seq: 5,
            ack: Some(1),
            service_code: None,
            reset_code: None,
            ccval: 0,
            cscov: 0,
        };
        let mut builder = DccpPacketBuilder::new(1, 2, header);
        // Timestamp option: [type 6][len 6][4-byte value].
        builder.push_option(&[6, 6, 0x12, 0x34, 0x56, 0x78]);
        let packet = builder.finalize(src, dst, &[]);

        let seg = parse_segment(&packet, src, dst).expect("parse");
        // The option bytes are preserved; the region is zero-padded to a
        // 4-byte boundary for the Data Offset.
        assert_eq!(&seg.options[..6], &[6, 6, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&seg.options[6..], &[0, 0]);
    }

    #[test]
    fn checksum_detects_tampering() {
        let (src, dst) = test_v4_addrs();
        let header = DccpHeader {
            packet_type: DccpPacketType::Data,
            seq: 7,
            ack: None,
            service_code: None,
            reset_code: None,
            ccval: 0,
            cscov: 0,
        };
        let builder = DccpPacketBuilder::new(10, 20, header);
        let mut packet = builder.finalize(src, dst, b"tamper_me");
        // Flip a payload byte; checksum must now mismatch.
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;
        assert_eq!(
            parse_segment(&packet, src, dst),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn short_form_sequence_is_accepted() {
        // Hand-build a 12-byte short header with a 24-bit sequence number.
        let (src, dst) = test_v4_addrs();
        let mut packet = Vec::new();
        packet.extend_from_slice(&1000u16.to_be_bytes()); // src port
        packet.extend_from_slice(&2000u16.to_be_bytes()); // dst port
        packet.push(3); // data offset: 3 words = 12 bytes (short generic)
        packet.push(0); // ccval/cscov
        packet.extend_from_slice(&[0u8; 2]); // checksum placeholder
        packet.push(0x02); // X=0, type=2 (Data)
        packet.push(0x45); // seq high (bit 7 must be 0 for X=0)
        packet.push(0x67); // seq
        packet.push(0xEF); // seq low
        packet.extend_from_slice(b"short");

        let checksum = compute_checksum(&packet, src, dst);
        packet[6] = (checksum >> 8) as u8;
        packet[7] = checksum as u8;

        let seg = parse_segment(&packet, src, dst).expect("parse short form");
        assert_eq!(seg.header.seq, 0x004567EF);
        assert_eq!(seg.header.packet_type, DccpPacketType::Data);
        assert_eq!(seg.payload, b"short");
    }
}
