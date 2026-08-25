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

pub use association::create_server_association;
pub use association::process_incoming;
pub use association::AssocState;
pub use association::Association;
pub use association::ProcessResult;
pub use chunk::build_sctp_packet;
pub use chunk::parse_common_header;
pub use chunk::parse_sctp_packet;
pub use chunk::verify_crc32c;
pub use chunk::SctpChunkType;
pub use chunk::SctpCommonHeader;
