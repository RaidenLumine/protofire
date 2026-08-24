//! src/kernel/fs/fuse/mod.rs
//!
//! Minimal FUSE protocol support: wire types and a FUSE-backed filesystem.
//!
//! A `FuseHeader` struct (24 bytes, `#[repr(C)]`) is used for both requests
//! and responses:
//!
//! ```text
//! #[repr(C)]
//! struct FuseHeader {
//!     seq: u64,          // sequence number
//!     opcode: u32,       // FuseOpcode as u32
//!     ino: u64,          // target inode number
//!     payload_len: u32,  // length of payload following header
//! }
//! ```
//!
//! The `FuseFileSystem` is registered via the existing
//! [`FileSystem::register`] / mount path, exactly like tmpfs or procfs.  The
//! `FuseMount` syscall performs the pipe creation, filesystem construction,
//! registration, and mount atomically, then returns the two pipe FDs to the
//! caller.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

use crate::kernel::fs::vfs::VNode;
use crate::kernel::fs::NodeKind;
use crate::kernel::sync::Mutex;

// ── Submodules ──────────────────────────────────────────────────────────

pub mod connection;
pub mod error;
pub mod filesystem;
pub mod protocol;
pub mod vnode;

// ── Wire protocol types ────────────────────────────────────────────────

/// Fixed 24-byte request/response header shared by both directions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseHeader {
    /// Sequence number.
    pub seq: u64,
    /// Opcode as a raw `u32` (wire format).
    pub opcode: u32,
    /// Target inode number.
    pub ino: u64,
    /// Length of the payload following the header.
    pub payload_len: u32,
}

/// FUSE protocol opcodes (wire values).
///
/// These must match the userspace daemon constants in
/// `src/user/shared/commands/fuse.rs` (and the pre-deletion original): the
/// wire bytes are authoritative, not the variant order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    /// Look up a name under an inode.
    Lookup = 0x01,
    /// Stat an inode.
    Stat = 0x02,
    /// Read data at an offset.
    Read = 0x03,
    /// Write data at an offset.
    Write = 0x04,
    /// Read one directory entry at an index.
    ReadDir = 0x05,
    /// Create a file.
    Create = 0x06,
    /// Remove a path.
    Remove = 0x07,
    /// Create a directory.
    CreateDir = 0x08,
    /// Rename a path.
    Rename = 0x09,
    /// Truncate / extend a file to a length.
    SetLen = 0x0A,
    /// Flush buffered data for an inode.
    Flush = 0x0B,
    /// Error response.
    Error = 0xFF,
}

/// A request: header + payload.
#[derive(Debug, Clone)]
pub struct FuseRequest {
    pub header: FuseHeader,
    pub payload: Vec<u8>,
}

/// A response: header + payload.
#[derive(Debug, Clone)]
pub struct FuseResponse {
    pub header: FuseHeader,
    pub payload: Vec<u8>,
}

/// FUSE protocol error codes (wire values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseError {
    Ok = 0,
    ENoEnt = 1,
    EPerm = 2,
    EIo = 3,
    ENomem = 4,
    EExists = 5,
    ENosys = 6,
    EBusy = 7,
    EInval = 8,
}

// ── Connection ──────────────────────────────────────────────────────────

/// Per-mount FUSE channel: kernel-end pipe pair + sequential dispatch.
pub struct FuseConnection {
    req_write: Arc<dyn VNode>,
    resp_read: Arc<dyn VNode>,
    next_seq: AtomicU64,
    lock: Mutex<()>,
}

// ── Filesystem ──────────────────────────────────────────────────────────

/// FUSE-backed filesystem implementing the kernel `FileSystem` trait.
pub struct FuseFileSystem {
    pub name: String,
    conn: Arc<FuseConnection>,
    root_ino: AtomicU64,
    handshake_done: AtomicBool,
}

// ── VNode ───────────────────────────────────────────────────────────────

/// Per-node wrapper for FUSE-backed files.
pub struct FuseVNode {
    name: String,
    ino: u64,
    kind: NodeKind,
    size: AtomicUsize,
    conn: Arc<FuseConnection>,
}

#[cfg(test)]
mod tests {
    use super::FuseOpcode;

    /// Wire constants must stay pinned to the userspace daemon
    /// (`src/user/shared/commands/fuse.rs`). A recovery pipeline once
    /// renumbered these and silently broke every file op at runtime.
    #[test]
    fn opcode_wire_values_match_daemon() {
        assert_eq!(FuseOpcode::Lookup as u32, 0x01);
        assert_eq!(FuseOpcode::Stat as u32, 0x02);
        assert_eq!(FuseOpcode::Read as u32, 0x03);
        assert_eq!(FuseOpcode::Write as u32, 0x04);
        assert_eq!(FuseOpcode::ReadDir as u32, 0x05);
        assert_eq!(FuseOpcode::Create as u32, 0x06);
        assert_eq!(FuseOpcode::Remove as u32, 0x07);
        assert_eq!(FuseOpcode::CreateDir as u32, 0x08);
        assert_eq!(FuseOpcode::Rename as u32, 0x09);
        assert_eq!(FuseOpcode::SetLen as u32, 0x0A);
        assert_eq!(FuseOpcode::Flush as u32, 0x0B);
        assert_eq!(FuseOpcode::Error as u32, 0xFF);
    }
}
