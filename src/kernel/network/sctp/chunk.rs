//! src/kernel/network/sctp/chunk.rs
//!
//! SCTP chunk encoding / parsing, packet framing, and CRC32C (RFC 4960 §6.8).

use alloc::vec::Vec;

use crate::{Error, Result};

/// Size of the SCTP common header (source port + destination port +
/// verification tag + checksum).
pub const SCTP_COMMON_HEADER_LEN: usize = 12;
/// Size of the per-chunk header (type + flags + length).
pub const SCTP_CHUNK_HEADER_LEN: usize = 4;

/// SCTP chunk types (RFC 4960 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpChunkType {
    Data,
    Init,
    InitAck,
    Sack,
    Heartbeat,
    HeartbeatAck,
    Abort,
    Shutdown,
    ShutdownAck,
    Error,
    CookieEcho,
    CookieAck,
    ECNE,
    CWR,
    ShutdownComplete,
    Unknown(u8),
}

impl SctpChunkType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Data,
            1 => Self::Init,
            2 => Self::InitAck,
            3 => Self::Sack,
            4 => Self::Heartbeat,
            5 => Self::HeartbeatAck,
            6 => Self::Abort,
            7 => Self::Shutdown,
            8 => Self::ShutdownAck,
            9 => Self::Error,
            10 => Self::CookieEcho,
            11 => Self::CookieAck,
            12 => Self::ECNE,
            13 => Self::CWR,
            14 => Self::ShutdownComplete,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Init => 1,
            Self::InitAck => 2,
            Self::Sack => 3,
            Self::Heartbeat => 4,
            Self::HeartbeatAck => 5,
            Self::Abort => 6,
            Self::Shutdown => 7,
            Self::ShutdownAck => 8,
            Self::Error => 9,
            Self::CookieEcho => 10,
            Self::CookieAck => 11,
            Self::ECNE => 12,
            Self::CWR => 13,
            Self::ShutdownComplete => 14,
            Self::Unknown(other) => other,
        }
    }
}

pub const SCTP_DATA: SctpChunkType = SctpChunkType::Data;
pub const SCTP_INIT: SctpChunkType = SctpChunkType::Init;
pub const SCTP_INIT_ACK: SctpChunkType = SctpChunkType::InitAck;
pub const SCTP_SACK: SctpChunkType = SctpChunkType::Sack;
pub const SCTP_HEARTBEAT: SctpChunkType = SctpChunkType::Heartbeat;
pub const SCTP_HEARTBEAT_ACK: SctpChunkType = SctpChunkType::HeartbeatAck;
pub const SCTP_ABORT: SctpChunkType = SctpChunkType::Abort;
pub const SCTP_SHUTDOWN: SctpChunkType = SctpChunkType::Shutdown;
pub const SCTP_SHUTDOWN_ACK: SctpChunkType = SctpChunkType::ShutdownAck;
pub const SCTP_ERROR: SctpChunkType = SctpChunkType::Error;
pub const SCTP_COOKIE_ECHO: SctpChunkType = SctpChunkType::CookieEcho;
pub const SCTP_COOKIE_ACK: SctpChunkType = SctpChunkType::CookieAck;

/// Parsed SCTP common header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpCommonHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    /// CRC32C checksum (bytes 8-11, stored little-endian).
    pub checksum: u32,
}

/// One-step CRC-32C (Castagnoli polynomial 0x1EDC6F41, reflected 0x82F63B78).
fn crc32c_step(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    for _ in 0..8 {
        crc = if crc & 1 != 0 {
            (crc >> 1) ^ 0x82F63B78
        } else {
            crc >> 1
        };
    }
    crc
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF;
    for &byte in data {
        crc = crc32c_step(crc, byte);
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a complete SCTP packet from a list of chunks, computing and
/// inserting the CRC32C checksum.
pub fn build_sctp_packet(
    source_port: u16,
    destination_port: u16,
    verification_tag: u32,
    chunks: &[(SctpChunkType, u8, Vec<u8>)],
) -> Vec<u8> {
    let payload_len: usize = chunks
        .iter()
        .map(|(_, _, data)| SCTP_CHUNK_HEADER_LEN + data.len())
        .sum();
    let mut packet = Vec::with_capacity(SCTP_COMMON_HEADER_LEN + payload_len);

    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&verification_tag.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]); // checksum placeholder

    for (ctype, flags, data) in chunks {
        packet.push(ctype.as_u8());
        packet.push(*flags);
        let chunk_len = (SCTP_CHUNK_HEADER_LEN + data.len()) as u16;
        packet.extend_from_slice(&chunk_len.to_be_bytes());
        packet.extend_from_slice(data);
        // Chunks are padded to a 4-byte boundary.
        let padded = (SCTP_CHUNK_HEADER_LEN + data.len() + 3) & !3;
        packet.resize(
            packet.len() + padded - (SCTP_CHUNK_HEADER_LEN + data.len()),
            0,
        );
    }

    let checksum = crc32c(&packet);
    packet[8..12].copy_from_slice(&checksum.to_le_bytes());
    packet
}

/// Parse the 12-byte SCTP common header, returning it and the remainder.
pub fn parse_common_header(data: &[u8]) -> Result<(SctpCommonHeader, &[u8])> {
    if data.len() < SCTP_COMMON_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    let header = SctpCommonHeader {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        destination_port: u16::from_be_bytes([data[2], data[3]]),
        verification_tag: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        checksum: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
    };
    Ok((header, &data[SCTP_COMMON_HEADER_LEN..]))
}

/// A parsed SCTP chunk: `(chunk_type, flags, data)` where `data` includes
/// the 4-byte chunk header (matching how the protocol frames a chunk).
pub type ParsedChunk = (SctpChunkType, u8, Vec<u8>);

/// Parse a full SCTP packet into its common header and chunk list.
///
/// Each chunk is returned as a [`ParsedChunk`].
pub fn parse_sctp_packet(data: &[u8]) -> Result<(SctpCommonHeader, Vec<ParsedChunk>)> {
    let (header, mut rest) = parse_common_header(data)?;
    if !verify_crc32c(data) {
        return Err(Error::InvalidArgument);
    }

    let mut chunks = Vec::new();
    while rest.len() >= SCTP_CHUNK_HEADER_LEN {
        let ctype = SctpChunkType::from_u8(rest[0]);
        let flags = rest[1];
        let length = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if length < SCTP_CHUNK_HEADER_LEN || length > rest.len() {
            break;
        }
        chunks.push((ctype, flags, rest[..length].to_vec()));
        // Chunks are padded to a 4-byte boundary; stop when the declared
        // length is not aligned and would advance past the buffer end.
        let padded = (length + 3) & !3;
        if padded > rest.len() {
            break;
        }
        rest = &rest[padded..];
    }
    Ok((header, chunks))
}

/// Verify the CRC32C checksum of a received SCTP packet.
pub fn verify_crc32c(data: &[u8]) -> bool {
    if data.len() < SCTP_COMMON_HEADER_LEN {
        return false;
    }
    let stored = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let mut zeroed = data.to_vec();
    zeroed[8..12].copy_from_slice(&[0; 4]);
    crc32c(&zeroed) == stored
}

/// Build the fixed 16-byte INIT payload as a chunk `(type, flags, data)`.
pub fn build_init_chunk(
    initiate_tag: u32,
    a_rwnd: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    initial_tsn: u32,
) -> (SctpChunkType, u8, Vec<u8>) {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&initiate_tag.to_be_bytes());
    data.extend_from_slice(&a_rwnd.to_be_bytes());
    data.extend_from_slice(&outbound_streams.to_be_bytes());
    data.extend_from_slice(&inbound_streams.to_be_bytes());
    data.extend_from_slice(&initial_tsn.to_be_bytes());
    (SCTP_INIT, 0, data)
}

/// Parse the fixed 16-byte INIT parameters (initiate tag, advertised receive
/// window, stream counts, initial TSN) from the raw INIT payload, with the
/// 4-byte chunk header already stripped by the caller.
pub fn parse_init_params(params: &[u8]) -> Result<(u32, u32, u16, u16, u32)> {
    if params.len() < 16 {
        return Err(Error::InvalidArgument);
    }
    let initiate_tag = u32::from_be_bytes([params[0], params[1], params[2], params[3]]);
    let a_rwnd = u32::from_be_bytes([params[4], params[5], params[6], params[7]]);
    let outbound_streams = u16::from_be_bytes([params[8], params[9]]);
    let inbound_streams = u16::from_be_bytes([params[10], params[11]]);
    let initial_tsn = u32::from_be_bytes([params[12], params[13], params[14], params[15]]);
    Ok((
        initiate_tag,
        a_rwnd,
        outbound_streams,
        inbound_streams,
        initial_tsn,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_round_trips() {
        let init = build_init_chunk(0xAAAAAAAA, 65536, 1, 1, 0x12345678);
        let packet = build_sctp_packet(1234, 5678, 0, &[init]);
        let (hdr, chunks) = parse_sctp_packet(&packet).expect("should parse");
        assert_eq!(hdr.source_port, 1234);
        assert_eq!(hdr.destination_port, 5678);
        assert!(!chunks.is_empty());
        let (ctype, _flags, cdata) = &chunks[0];
        assert_eq!(*ctype, SCTP_INIT);
        let params = &cdata[SCTP_CHUNK_HEADER_LEN..];
        let (tag, rwnd, os, is, tsn) = parse_init_params(params).expect("parse init params");
        assert_eq!(tag, 0xAAAAAAAA);
        assert_eq!(rwnd, 65536);
        assert_eq!(os, 1);
        assert_eq!(is, 1);
        assert_eq!(tsn, 0x12345678);
    }

    #[test]
    fn crc_checksum_detects_corruption() {
        let init = build_init_chunk(1, 65536, 1, 1, 2);
        let mut packet = build_sctp_packet(1234, 5678, 0, &[init]);
        assert!(verify_crc32c(&packet));
        packet[20] ^= 0xFF;
        assert!(!verify_crc32c(&packet));
    }
}
