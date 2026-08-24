//! src/kernel/fs/fuse/protocol.rs
//!
//! Wire-format serialisation and deserialisation for the minimal FUSE protocol.
//!
//! All multi-byte integers are little-endian on the wire.

use crate::kernel::fs::fuse::{FuseHeader, FuseOpcode, FuseRequest};
use crate::kernel::fs::NodeKind;
use crate::Result;
use alloc::string::String;
use alloc::string::ToString;

// ── Header serialisation ─────────────────────────────────────────────────

/// Serialise a [`FuseHeader`] into its 24-byte little-endian wire format.
pub fn serialize_header(header: &FuseHeader) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..8].copy_from_slice(&header.seq.to_le_bytes());
    buf[8..12].copy_from_slice(&header.opcode.to_le_bytes());
    buf[12..20].copy_from_slice(&header.ino.to_le_bytes());
    buf[20..24].copy_from_slice(&header.payload_len.to_le_bytes());
    buf
}

/// Deserialise a 24-byte little-endian wire buffer into a [`FuseHeader`].
pub fn deserialize_header(bytes: &[u8; 24]) -> FuseHeader {
    FuseHeader {
        seq: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        opcode: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        ino: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        payload_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
    }
}

// ── Request helpers ──────────────────────────────────────────────────────

/// Build a [`FuseRequest`] from its parts.
pub fn build_request(seq: u64, opcode: FuseOpcode, ino: u64, payload: &[u8]) -> FuseRequest {
    let header = FuseHeader {
        seq,
        opcode: opcode as u32,
        ino,
        payload_len: payload.len() as u32,
    };
    FuseRequest {
        header,
        payload: payload.to_vec(),
    }
}

// ── NodeInfo helpers ─────────────────────────────────────────────────────

/// Wire format of a NodeInfo response.
///
/// Layout: ino(8) + kind(4) + size(8) + name_len(4) + name(name_len bytes)
const NODEINFO_FIXED_SIZE: usize = 8 + 4 + 8 + 4; // 24

/// Parse a NodeInfo payload into (ino, kind, size, name).
pub fn parse_node_info_payload(data: &[u8]) -> Result<(u64, u32, u64, String)> {
    if data.len() < NODEINFO_FIXED_SIZE {
        return Err(crate::Error::InternalError);
    }
    let ino = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let kind = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let size = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let name_len = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
    if data.len() < NODEINFO_FIXED_SIZE + name_len {
        return Err(crate::Error::InternalError);
    }
    let name =
        core::str::from_utf8(&data[24..24 + name_len]).map_err(|_| crate::Error::InternalError)?;
    Ok((ino, kind, size, name.to_string()))
}

/// Map a FUSE wire kind value to a kernel [`NodeKind`].
pub fn kind_from_wire(kind: u32) -> NodeKind {
    match kind {
        0 => NodeKind::File,
        1 => NodeKind::Directory,
        2 => NodeKind::Device,
        3 => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}

// ── DirEntry helpers ─────────────────────────────────────────────────────

/// Parse a DirEntry payload from a READDIR response.
pub fn parse_readdir_entry_payload(data: &[u8]) -> Result<(u64, u32, u64, String)> {
    parse_node_info_payload(data)
}
