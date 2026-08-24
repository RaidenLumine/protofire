//! src/kernel/fs/squashfs/types.rs
//!
//! On-disk data structures for SquashFS.
//!
//! Reference: <https://dr-emann.github.io/squashfs/squashfs.html>
//
// NOTE: The SquashFS driver is a work-in-progress.  This file defines the
// complete on-disk format, but only a subset of fields are wired through.
// The module-level annotation below suppresses dead-code warnings on
// intentionally-defined-but-not-yet-used structures.
#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

// ── Superblock ──────────────────────────────────────────────────────────────

pub const SQUASHFS_MAGIC: u32 = 0x7371_7368; // "hsqs"
pub const SUPERBLOCK_SIZE: usize = 96;

/// Compression algorithms.
pub const COMPRESSION_LZ4: u16 = 2;
pub const COMPRESSION_ZSTD: u16 = 4;

/// Bit 24 of a data block size: set when the block is *uncompressed*.
pub const BLOCK_IS_COMPRESSED: u32 = 1 << 24;
/// Bit 15 of a metadata header size: set when the metadata block is
/// *uncompressed*.
pub const METADATA_UNCOMPRESSED: u16 = 1 << 15;

#[derive(Debug, Clone)]
pub struct Superblock {
    pub magic: u32,
    pub block_size: u32,
    pub compression: u16,
    pub inode_count: u32,
    pub fragment_entry_count: u32,
    pub id_table_start: u64,
    /// Offset of the xattr ID table (SquashFS 4.0+, superblock byte offset 56).
    pub xattr_id_table_start: u64,
    pub root_inode_offset: u32,
    pub bytes_used: u64,
}

impl Superblock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 96 {
            return None;
        }
        let magic = get_u32(buf, 0);
        if magic != SQUASHFS_MAGIC {
            return None;
        }
        Some(Self {
            magic,
            block_size: get_u32(buf, 12),
            compression: get_u16(buf, 20),
            inode_count: get_u32(buf, 4),
            fragment_entry_count: get_u32(buf, 32),
            id_table_start: get_u64(buf, 48),
            xattr_id_table_start: get_u64(buf, 56),
            root_inode_offset: get_u32(buf, 68),
            bytes_used: get_u64(buf, 24),
        })
    }
}

// ── Inode types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Inode {
    Directory(DirInode),
    File(FileInode),
    Symlink(SymlinkInode),
}

/// Basic directory inode (type 1).
#[derive(Debug, Clone)]
pub struct DirInode {
    pub nlink: u32,
    pub file_size: u32,   // uncompressed size of directory metadata
    pub start_block: u32, // first metadata block index
    pub parent_inode: u32,
}

/// Basic file inode (type 2).
#[derive(Debug, Clone)]
pub struct FileInode {
    pub nlink: u32,
    pub file_size: u64,
    pub start_block: u64, // first data block index
    pub fragments: Option<FragmentEntry>,
}

/// Symlink inode (type 3).
#[derive(Debug, Clone)]
pub struct SymlinkInode {
    pub nlink: u32,
    pub target: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FragmentEntry {
    pub fragment_block_index: u32,
    pub fragment_offset: u32,
}

/// Parse an inode from the inode table at `offset`. Returns (inode, bytes_consumed).
pub fn parse_inode(table: &[u8], offset: u32) -> Option<(Inode, usize)> {
    let off = offset as usize;
    if off + 2 > table.len() {
        return None;
    }
    let inode_type = get_u16(table, off) as u8;
    match inode_type {
        1 => {
            // Directory inode: 16 bytes header.
            if off + 16 > table.len() {
                return None;
            }
            Some((
                Inode::Directory(DirInode {
                    nlink: get_u32(table, off + 4),
                    file_size: get_u32(table, off + 8),
                    start_block: get_u32(table, off + 12),
                    parent_inode: get_u32(table, off + 16),
                }),
                20,
            ))
        }
        2 => {
            // File inode: basic layout.
            if off + 20 > table.len() {
                return None;
            }
            let nlink = get_u32(table, off + 4);
            let file_size = if off + 16 <= table.len() {
                get_u64(table, off + 8)
            } else {
                get_u32(table, off + 8) as u64
            };
            let has_frags = get_u32(table, off + 16) != 0xFFFF_FFFF;
            let fragments = if has_frags {
                Some(FragmentEntry {
                    fragment_block_index: get_u32(table, off + 16),
                    fragment_offset: get_u32(table, off + 20),
                })
            } else {
                None
            };
            let frag_len = if has_frags { 8 } else { 4 };
            let start_off = off + 16 + frag_len;
            let start_block = if start_off + 4 <= table.len() {
                get_u32(table, start_off) as u64
            } else {
                0
            };

            Some((
                Inode::File(FileInode {
                    nlink,
                    file_size,
                    start_block,
                    fragments,
                }),
                start_off + 4,
            ))
        }
        3 => {
            // Symlink inode.
            if off + 10 > table.len() {
                return None;
            }
            let nlink = get_u32(table, off + 4);
            let target_len = get_u32(table, off + 6) as usize;
            if off + 10 + target_len > table.len() {
                return None;
            }
            let target = table[off + 10..off + 10 + target_len].to_vec();
            Some((
                Inode::Symlink(SymlinkInode { nlink, target }),
                10 + target_len,
            ))
        }
        _ => None,
    }
}

// ── Directory entries ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedDirEntry {
    pub name: String,
    pub inode_offset: u32,
    pub entry_type: u16,
}

/// Parse an uncompressed directory metadata block.
///
/// Each group starts with an 8-byte header: a u16 whose value is one less
/// than the total entry-data byte count (`header + 1`), two reserved bytes,
/// and a u32 inode offset shared by every entry in the group.  The entries
/// follow as `u16 entry_type` + NUL-terminated name.
pub fn parse_dir_entries(data: &[u8]) -> Vec<ParsedDirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 8 < data.len() {
        let header = get_u16(data, offset);
        let total = header as usize + 1; // entry-data bytes for this group
        let group_end = (offset + 8 + total).min(data.len());

        let mut name_start = offset + 8;
        while name_start + 2 <= group_end {
            let etype = get_u16(data, name_start);
            name_start += 2;
            // Read null-terminated name.
            let name_end = data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| name_start + p)
                .unwrap_or(group_end);
            let name_bytes = &data[name_start..name_end.min(data.len())];

            let name = String::from_utf8_lossy(name_bytes).into_owned();
            entries.push(ParsedDirEntry {
                name,
                inode_offset: get_u32(data, offset + 4),
                entry_type: etype,
            });

            name_start = name_end + 1; // skip null terminator
        }

        offset += total + 8;
    }

    entries
}

// ── Extended attributes ──────────────────────────────────────────────────────

/// Each xattr ID table entry is 16 bytes: u64 position + u32 count + u32 size.
pub const XATTR_ID_TABLE_ENTRY_SIZE: usize = 16;
/// Sentinel value for "no xattrs" in the xattr ID table.
const XATTR_ID_ABSENT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// Xattr type flag: value stored out-of-line (separate block).
const XATTR_VALUE_OOL: u16 = 0x0100;

/// SquashFS xattr prefix strings.
static SQUASHFS_XATTR_PREFIXES: &[&[u8]] = &[
    b"user.",     // 0
    b"trusted.",  // 1
    b"security.", // 2
    b"system.",   // 3
];

/// Parse a decompressed xattr data block.  Returns `(name, value)` pairs.
pub fn parse_squashfs_xattrs(data: &[u8], count: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let mut off = 0usize;

    for _ in 0..count {
        if off + 4 > data.len() {
            break;
        }
        let etype = get_u16(data, off);
        let name_size = get_u16(data, off + 2) as usize;
        off += 4;

        if off + name_size > data.len() {
            break;
        }
        let name = data[off..off + name_size].to_vec();
        off += name_size;

        // Build full name with prefix.
        let prefix_idx = (etype & 0xFF) as usize;
        let prefix = SQUASHFS_XATTR_PREFIXES
            .get(prefix_idx)
            .copied()
            .unwrap_or(b"");
        let mut full_name = Vec::with_capacity(prefix.len() + name.len());
        full_name.extend_from_slice(prefix);
        full_name.extend_from_slice(&name);

        // Read value.
        let value = if etype & XATTR_VALUE_OOL != 0 {
            // Out-of-line value: skip u64 position.
            if off + 8 > data.len() {
                break;
            }
            let _val_pos = get_u64(data, off);
            off += 8;
            // Can't read OOL value here — return empty.
            Vec::new()
        } else {
            if off + 4 > data.len() {
                break;
            }
            let val_size = get_u32(data, off) as usize;
            off += 4;
            if val_size > 0 && off + val_size <= data.len() {
                let v = data[off..off + val_size].to_vec();
                off += val_size;
                v
            } else {
                Vec::new()
            }
        };

        result.push((full_name, value));
    }

    result
}

/// Parse an extended inode (type 8, 9, or 10) to extract the `xattr_idx`.
///
/// Extended inodes have an additional `u32 xattr_idx` field right after the
/// standard inode fields.  Returns `(xattr_idx, total_bytes_consumed)`.
pub fn parse_extended_inode_xattr_idx(
    table: &[u8],
    offset: u32,
    inode_type: u8,
) -> Option<(u32, usize)> {
    let off = offset as usize;
    // Extended directory (type 8): 16 + 4 (xattr_idx) + 4 (inode_number) = 24 bytes header
    // Extended file (type 9): same layout as basic + xattr_idx
    // Extended symlink (type 10): same layout as basic + xattr_idx
    match inode_type {
        8 => {
            // Extended directory: 16 bytes basic + 4 (xattr_idx) + 4 (inode_number)
            if off + 24 > table.len() {
                return None;
            }
            let xattr_idx = get_u32(table, off + 16);
            Some((xattr_idx, 24))
        }
        9 => {
            // Extended file: basic file layout + 4 (xattr_idx) at the end.
            if off + 20 > table.len() {
                return None;
            }
            let has_frags = get_u32(table, off + 16) != 0xFFFF_FFFF;
            let frag_len = if has_frags { 8 } else { 4 };
            let start_off = off + 16 + frag_len;
            let xattr_off = start_off + 4; // after start_block
            if xattr_off + 4 > table.len() {
                return None;
            }
            let xattr_idx = get_u32(table, xattr_off);
            Some((xattr_idx, xattr_off + 4))
        }
        10 => {
            // Extended symlink: basic layout + 4 (xattr_idx) after target.
            if off + 10 > table.len() {
                return None;
            }
            let target_len = get_u32(table, off + 6) as usize;
            let xattr_off = off + 10 + target_len;
            if xattr_off + 4 > table.len() {
                return None;
            }
            let xattr_idx = get_u32(table, xattr_off);
            Some((xattr_idx, xattr_off + 4))
        }
        _ => None,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}
fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
fn get_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}
