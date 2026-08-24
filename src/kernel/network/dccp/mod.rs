//! src/kernel/network/dccp/mod.rs
//!
//! DCCP — Datagram Congestion Control Protocol (RFC 4340).
//!
//! DCCP is a transport protocol that provides unreliable datagram delivery
//! with congestion control and a connection-oriented setup/teardown
//! handshake (Request → Response → Ack), like TCP's connect but with
//! datagram semantics.
//!
//! Sub-modules:
//! - `header` — generic header, packet types, checksum
//! - `options` — options and minimal feature negotiation
//! - `ccid2`  — CCID 2 TCP-like congestion control
//! - `table`  — connection table, listeners, per-connection state
//! - `ops`    — state machine and user-space operations

pub mod ccid2;
pub mod header;
pub mod ops;
pub mod options;
pub mod table;

// ─── Public re-exports ─────────────────────────────────────────────────────

pub use header::{parse_segment, DccpHeader, DccpPacketBuilder, DccpPacketType, DccpSegment};
pub use ops::{
    accept_nonblocking, close, connect, process_segment, recv, send, send_packet, tick_maintenance,
};
pub use table::{
    DccpConnKey, DccpConnectionState, DccpConnectionTable, DccpListener, DccpState,
    NativeDccpConnection,
};
