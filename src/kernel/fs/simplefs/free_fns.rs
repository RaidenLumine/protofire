//! src/kernel/fs/simplefs/free_fns.rs
//!
//! Low-level helpers: byte I/O, kind encoding, test utilities.
//!
//! Larger format I/O functions (superblock, inode/dirent tables,
//! image building) are in [`super::format_io`].

use crate::{Error, Result};

use super::super::vfs::NodeKind;

// Re-export format_io functions so that existing `use super::free_fns::*`
// imports continue to work without changes.
pub(crate) use super::format_io::*;

pub(crate) fn encode_kind(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Directory => 1,
        NodeKind::File => 2,
        NodeKind::Device => 3,
        NodeKind::Symlink => 4,
    }
}

pub(crate) fn decode_kind(value: u8) -> Result<NodeKind> {
    match value {
        1 => Ok(NodeKind::Directory),
        2 => Ok(NodeKind::File),
        3 => Ok(NodeKind::Device),
        4 => Ok(NodeKind::Symlink),
        _ => Err(Error::InvalidArgument),
    }
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::InvalidArgument)?;
    let value = bytes.get(offset..end).ok_or(Error::InvalidArgument)?;
    let mut bytes4 = [0_u8; 4];
    bytes4.copy_from_slice(value);
    Ok(u32::from_le_bytes(bytes4))
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(Error::InvalidArgument)?;
    let value = bytes.get(offset..end).ok_or(Error::InvalidArgument)?;
    let mut bytes2 = [0_u8; 2];
    bytes2.copy_from_slice(value);
    Ok(u16::from_le_bytes(bytes2))
}

pub(crate) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// XOR-rotate checksum over file content. 0 means "not computed" (backward
/// compatible with existing images whose reserved inode bytes are zero).
pub(crate) fn compute_data_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for chunk in data.chunks(4) {
        let mut word: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            word |= (byte as u32) << (i * 8);
        }
        checksum = checksum.rotate_left(1) ^ word;
    }
    checksum
}
