//! src/kernel/network/sctp/mod.rs
//!
//! SCTP protocol (RFC 4960): chunk types, association state machine, and
//! IP protocol-132 dispatch.
//!
//! This is a minimal single-stream implementation:
//! - 4-way handshake: INIT → INIT_ACK → COOKIE_ECHO → COOKIE_ACK
//! - CRC32C verification (whole-packet checksum)
//! - Single stream (no multi-streaming)
//! - No multi-homing
//! - Basic DATA/SACK exchange

pub mod association;
pub mod chunk;

// ─── Public re-exports ──────────────────────────────────────────────────────

pub use association::{
    create_server_association, process_incoming, AssocState, Association, ProcessResult,
};
pub use chunk::{
    build_sctp_packet, parse_common_header, parse_sctp_packet, verify_crc32c, SctpChunkType,
    SctpCommonHeader,
};
