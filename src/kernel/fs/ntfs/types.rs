//! src/kernel/fs/ntfs/types.rs
//! On-disk data structures for NTFS.
//
// NOTE: The NTFS driver is a work-in-progress.  This file defines the
// complete on-disk format, but only a subset of fields are wired through.
// The module-level annotation below suppresses dead-code warnings on
// intentionally-defined-but-not-yet-used structures.
#![allow(dead_code)]
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::fs::vfs::XattrEntry;

pub const BLOCK_SIZE: usize = 512;

// ── BPB / Boot sector ─────────────────────────────────────────────────────

pub const NTFS_MAGIC: &[u8; 4] = b"NTFS";

#[derive(Debug, Clone)]
pub struct BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_mirr_lcn: u64,
    pub clusters_per_mft_record: u32,
    pub clusters_per_index_buffer: u32,
    pub volume_serial: u32,
}

impl BootSector {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 84 {
            return None;
        }
        if buf[3..7] != *b"NTFS" {
            return None;
        }
        let sectors_per_cluster = buf[13];
        let bytes_per_sector = u16::from_le_bytes([buf[11], buf[12]]);
        let cluster_size = bytes_per_sector as u32 * sectors_per_cluster as u32;

        let mft_rec_exp = buf[64] as i8;
        let clusters_per_mft_record = if mft_rec_exp < 0 {
            let exp = (-mft_rec_exp) as u32;
            if exp >= 32 {
                1
            } else {
                (1u32 << exp) / cluster_size
            }
        } else {
            mft_rec_exp as u32
        }
        .max(1);

        let idx_exp = buf[68] as i8;
        let clusters_per_index_buffer = if idx_exp < 0 {
            let exp = (-idx_exp) as u32;
            if exp >= 32 {
                1
            } else {
                (1u32 << exp) / cluster_size
            }
        } else {
            idx_exp as u32
        }
        .max(1);

        Some(Self {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors: u64::from_le_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]),
            mft_lcn: u64::from_le_bytes([
                buf[48], buf[49], buf[50], buf[51], buf[52], buf[53], buf[54], buf[55],
            ]),
            mft_mirr_lcn: u64::from_le_bytes([
                buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63],
            ]),
            clusters_per_mft_record,
            clusters_per_index_buffer,
            volume_serial: u32::from_le_bytes([buf[72], buf[73], buf[74], buf[75]]),
        })
    }
}

// ── MFT Record ────────────────────────────────────────────────────────────

pub const MFT_MAGIC: [u8; 4] = *b"FILE";
pub const MFT_RECORD_IN_USE: u16 = 0x0001;
pub const MFT_RECORD_DIRECTORY: u16 = 0x0002;

#[derive(Debug, Clone)]
pub struct MftRecordHeader {
    pub magic: [u8; 4],
    pub usa_offset: u16,
    pub usa_count: u16,
    pub flags: u16,
    pub first_attr_offset: u16,
}

impl MftRecordHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 48 {
            return None;
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != MFT_MAGIC {
            return None;
        }
        Some(Self {
            magic,
            usa_offset: u16::from_le_bytes([buf[4], buf[5]]),
            usa_count: u16::from_le_bytes([buf[6], buf[7]]),
            flags: u16::from_le_bytes([buf[22], buf[23]]),
            first_attr_offset: u16::from_le_bytes([buf[20], buf[21]]),
        })
    }

    pub fn is_dir(&self) -> bool {
        self.flags & MFT_RECORD_DIRECTORY != 0
    }
}

// ── Attributes ────────────────────────────────────────────────────────────

pub const ATTR_TYPE_STANDARD_INFO: u32 = 0x10;
pub const ATTR_TYPE_FILENAME: u32 = 0x30;
pub const ATTR_TYPE_DATA: u32 = 0x80;
pub const ATTR_TYPE_INDEX_ROOT: u32 = 0x90;
pub const ATTR_TYPE_INDEX_ALLOC: u32 = 0xA0;
pub const ATTR_TYPE_EA: u32 = 0xE0;
pub const ATTR_TYPE_EA_INFORMATION: u32 = 0xD0;
pub const ATTR_TYPE_REPARSE_POINT: u32 = 0xC0;
pub const ATTR_TYPE_END: u32 = 0xFFFF_FFFF;

/// NTFS reparse tag: symbolic link.
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// NTFS reparse tag: junction point (directory mount point).
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

pub type AttrType = u32;

#[derive(Debug, Clone)]
pub struct AttrHeader {
    pub attr_type: AttrType,
    pub attr_len: u32,
    pub non_resident: bool,
    pub name_len: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub instance: u16,
}

impl AttrHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let attr_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if attr_type == ATTR_TYPE_END || attr_type == 0 {
            return None;
        }
        Some(Self {
            attr_type,
            attr_len: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            non_resident: buf[8] != 0,
            name_len: buf[9],
            name_offset: u16::from_le_bytes([buf[10], buf[11]]),
            flags: u16::from_le_bytes([buf[12], buf[13]]),
            instance: u16::from_le_bytes([buf[14], buf[15]]),
        })
    }
}

// ── ParsedAttribute ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedAttr {
    pub attr_type: AttrType,
    pub content: Vec<u8>,
    pub data_runs_offset: Option<u64>,
    pub data_size: u64,
}

/// Parse all attributes from an MFT record starting at first_attr_offset.
pub fn parse_attributes(buf: &[u8], mut offset: usize) -> Vec<ParsedAttr> {
    let mut attrs = Vec::new();
    while offset + 16 <= buf.len() {
        let attr_type = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        if attr_type == ATTR_TYPE_END {
            break;
        }
        if attr_type == 0 {
            offset += 8;
            continue;
        }
        let attr_len = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as usize;
        if attr_len == 0 || offset + attr_len > buf.len() {
            break;
        }
        let non_resident = buf[offset + 8] != 0;

        if non_resident {
            // Non-resident: data runs at offset 64.
            let runs_off = u16::from_le_bytes([buf[offset + 32], buf[offset + 33]]) as usize;
            let data_size = u64::from_le_bytes([
                buf[offset + 48],
                buf[offset + 49],
                buf[offset + 50],
                buf[offset + 51],
                buf[offset + 52],
                buf[offset + 53],
                buf[offset + 54],
                buf[offset + 55],
            ]);
            attrs.push(ParsedAttr {
                attr_type,
                content: Vec::new(),
                data_runs_offset: Some(runs_off as u64),
                data_size,
            });
        } else {
            // Resident: content at offset + attr_header.content_offset.
            let content_off = u16::from_le_bytes([buf[offset + 20], buf[offset + 21]]) as usize;
            let content_size = u32::from_le_bytes([
                buf[offset + 16],
                buf[offset + 17],
                buf[offset + 18],
                buf[offset + 19],
            ]) as usize;
            let start = offset + content_off;
            let end = (start + content_size).min(buf.len());
            attrs.push(ParsedAttr {
                attr_type,
                content: buf[start..end].to_vec(),
                data_runs_offset: None,
                data_size: content_size as u64,
            });
        }
        offset += attr_len;
    }
    attrs
}

// ── Filename ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileName {
    pub parent_mft_ref: u64,
    pub name: String,
    pub flags: u32,
    /// NTFS filename namespace (0 = POSIX, 1 = Win32, 2 = DOS, 3 = Win32 & DOS).
    pub namespace: u8,
}

impl FileName {
    /// Parse a `$FILE_NAME` attribute body (resident).
    ///
    /// Layout: parent MFT ref (8) + timestamps (24) + allocated size (8) +
    /// real size (8) + flags (4) + reparse value (4) + name length (1) +
    /// namespace (1) + name (name_len * 2, UTF-16).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 66 {
            return None;
        }
        let name_len = buf[64] as usize;
        if 66 + name_len * 2 > buf.len() {
            return None;
        }
        let name_bytes = &buf[66..66 + name_len * 2];
        let utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        let flags = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);
        Some(Self {
            parent_mft_ref: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            name,
            flags,
            namespace: buf[65],
        })
    }

    /// Whether this name is the preferred (most human-friendly) spelling:
    /// Win32 (1) or Win32 & DOS (3) win over POSIX (0), which wins over
    /// DOS-only 8.3 (2).
    pub fn preferred_namespace(&self) -> bool {
        matches!(self.namespace, 1 | 3)
    }

    /// Whether the file is a directory (FILE_ATTRIBUTE_DIRECTORY).
    pub fn is_directory(&self) -> bool {
        self.flags & 0x1000_0000 != 0
    }
}

/// `$STANDARD_INFORMATION` attribute — timestamps + DOS flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardInfoAttr {
    /// Creation time, NTFS 100 ns ticks since 1601-01-01.
    pub created: u64,
    /// Last modification time.
    pub modified: u64,
    /// Last MFT change time.
    pub mft_changed: u64,
    /// Last access time.
    pub accessed: u64,
    /// DOS/standard file flags (FILE_ATTRIBUTE_*).
    pub flags: u32,
}

impl StandardInfoAttr {
    /// Parse a resident `$STANDARD_INFORMATION` body.
    ///
    /// Layout: created (8) + modified (8) + mft_changed (8) + accessed (8) +
    /// flags (4) + version/max version (4) + class id (4) + owner id (4) +
    /// security id (4) + quota charged (8) + usn (8).  The first 36 bytes
    /// cover everything we read.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 36 {
            return None;
        }
        let read_u64 = |off: usize| {
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
        };
        Some(Self {
            created: read_u64(0),
            modified: read_u64(8),
            mft_changed: read_u64(16),
            accessed: read_u64(24),
            flags: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        })
    }

    /// Whether the file is a directory (FILE_ATTRIBUTE_DIRECTORY).
    pub fn is_directory(&self) -> bool {
        self.flags & 0x1000_0000 != 0
    }

    /// Convert NTFS time (100 ns ticks since 1601-01-01) to Unix seconds.
    pub fn to_unix_secs(ntfs_ticks: u64) -> u64 {
        // Offset between 1601-01-01 and 1970-01-01 in 100 ns ticks.
        const NTFS_TO_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
        ntfs_ticks.saturating_sub(NTFS_TO_UNIX_OFFSET) / 10_000_000
    }
}

// ── Data run parsing ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    pub lcn: i64,
    pub cluster_count: u64,
}

/// Parse NTFS data runs from the raw run list bytes.
pub fn parse_data_runs(buf: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut offset = 0usize;
    let mut prev_lcn: i64 = 0;

    while offset < buf.len() {
        let header = buf[offset];
        if header == 0 {
            break;
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        offset += 1;

        if offset + len_bytes + off_bytes > buf.len() {
            break;
        }

        let mut len: u64 = 0;
        for i in 0..len_bytes {
            len |= (buf[offset + i] as u64) << (i * 8);
        }
        offset += len_bytes;

        let mut off_delta: i64 = 0;
        for i in 0..off_bytes {
            off_delta |= (buf[offset + i] as i64) << (i * 8);
        }
        // Sign-extend.
        if off_bytes > 0 && off_bytes < 8 {
            let sign_bit = 1i64 << (off_bytes * 8 - 1);
            if off_delta & sign_bit != 0 {
                off_delta |= !((1i64 << (off_bytes * 8)) - 1);
            }
        }
        offset += off_bytes;

        let lcn = if off_delta == 0 {
            -1 // Sparse run
        } else {
            prev_lcn + off_delta
        };
        prev_lcn = lcn;
        runs.push(DataRun {
            lcn,
            cluster_count: len,
        });
    }
    runs
}

/// Parse an NTFS reparse point buffer and extract the symlink/junction target.
///
/// The reparse data buffer layout:
///   u32 reparse_tag
///   u16 reparse_data_length
///   u16 reserved
///   u16 substitute_name_offset
///   u16 substitute_name_length
///   u16 print_name_offset
///   u16 print_name_length
///   … path buffer (UTF-16LE) …
///
/// Returns `(reparse_tag, Some(target))` where `target` is the decoded
/// substitution name with a `\??\` or `\DosDevices\` prefix stripped.
pub fn parse_reparse_point(buf: &[u8]) -> Option<(u32, Option<String>)> {
    if buf.len() < 16 {
        return None;
    }
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let sub_off = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let sub_len = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    if sub_off.checked_add(sub_len)? > buf.len() {
        return None;
    }

    let raw = &buf[sub_off..sub_off + sub_len];
    let mut utf16 = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.chunks_exact(2) {
        utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let mut target = String::from_utf16_lossy(&utf16);

    // Strip NT namespace prefixes.
    for prefix in &["\\??\\", "\\DosDevices\\"] {
        if let Some(stripped) = target.strip_prefix(prefix) {
            target = stripped.into();
            break;
        }
    }

    Some((tag, Some(target)))
}

/// Parse NTFS `$EA` attribute content into [`XattrEntry`] pairs.
///
/// The EA buffer layout:
///   u32  ea_length  (total size, including this field)
///   …    repeating entries until end …
///
/// Each entry:
///   u32  next_entry_offset  (byte offset to next entry from start of this one; 0 = last)
///   u8   flags              (0x80 = NEED_EA)
///   u8   name_length        (in bytes, not characters)
///   u16  value_length       (in bytes)
///   u8[] name               (name_length bytes — ASCII / ANSI)
///   u8[] value              (value_length bytes)
///   …    pad to 4-byte boundary
pub fn parse_ea_entries(content: &[u8]) -> Vec<XattrEntry> {
    if content.len() < 4 {
        return Vec::new();
    }
    // The first 4 bytes are the total EA data length.
    let _ea_len = u32::from_le_bytes([content[0], content[1], content[2], content[3]]) as usize;
    let mut pos = 4usize;
    let mut entries = Vec::new();

    while pos + 8 <= content.len() {
        let next_off = u32::from_le_bytes([
            content[pos],
            content[pos + 1],
            content[pos + 2],
            content[pos + 3],
        ]) as usize;
        let flags = content[pos + 4];
        let name_len = content[pos + 5] as usize;
        let val_len = u16::from_le_bytes([content[pos + 6], content[pos + 7]]) as usize;

        let data_start = pos + 8;
        if name_len.checked_add(val_len).is_none()
            || data_start + name_len + val_len > content.len()
        {
            break;
        }

        // Build namespace-prefixed name: "user.<name>".
        let ea_name = &content[data_start..data_start + name_len];
        let ea_value = &content[data_start + name_len..data_start + name_len + val_len];
        let mut prefixed = Vec::with_capacity(5 + name_len);
        prefixed.extend_from_slice(b"user.");
        prefixed.extend_from_slice(ea_name);

        entries.push(XattrEntry::new(prefixed, ea_value.to_vec()));

        let _ea_flags = flags; // 0x80 = NEED_EA

        if next_off == 0 || next_off <= 8 {
            // Last entry or malformed — stop.
            break;
        }
        pos += next_off;
    }

    entries
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_bpb_basic() {
        let mut buf = vec![0u8; 84];
        buf[3..7].copy_from_slice(b"NTFS");
        buf[11..13].copy_from_slice(&512u16.to_le_bytes());
        buf[13] = 8; // 8 sectors per cluster = 4096
        buf[64] = (-10i8) as u8;
        buf[68] = (-12i8) as u8;
        let bs = BootSector::parse(&buf).expect("parse");
        assert_eq!(bs.bytes_per_sector, 512);
        assert_eq!(bs.sectors_per_cluster, 8);
    }

    #[test]
    fn parse_mft_record_header() {
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(b"FILE");
        buf[20..22].copy_from_slice(&56u16.to_le_bytes());
        buf[22..24].copy_from_slice(&0x0003u16.to_le_bytes());
        let hdr = MftRecordHeader::parse(&buf).expect("parse");
        assert!(hdr.is_dir());
    }

    #[test]
    fn parse_filename_attr() {
        let mut buf = vec![0u8; 66 + 10];
        // Name "test" = 4 chars = 8 bytes UTF-16LE
        buf[64] = 4; // name_len in characters
                     // "test" in UTF-16LE
        let name = "test";
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = 66 + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let fn_ = FileName::parse(&buf).expect("parse");
        assert_eq!(fn_.name, "test");
    }

    #[test]
    fn parse_data_runs_basic() {
        // Run: 8 clusters starting at LCN 100.
        // Header: 0x21 (len_bytes=1, off_bytes=2)
        // len: 8
        // off: 100 (LE)
        let mut buf = vec![0u8; 4];
        buf[0] = 0x21; // 1 length byte, 2 offset bytes
        buf[1] = 8; // cluster count
        buf[2] = 100; // offset bytes LE
        buf[3] = 0;
        let runs = parse_data_runs(&buf);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].cluster_count, 8);
        assert_eq!(runs[0].lcn, 100);
    }

    #[test]
    fn parse_data_runs_two_runs() {
        // Run 1: 5 clusters at LCN 10
        // Run 2: 3 clusters at LCN 20
        let mut buf = vec![0u8; 8];
        buf[0] = 0x21;
        buf[1] = 5;
        buf[2] = 10;
        buf[3] = 0;
        buf[4] = 0x21; // delta from prev: 20-10=10
        buf[5] = 3;
        buf[6] = 10;
        buf[7] = 0;
        let runs = parse_data_runs(&buf);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].lcn, 10);
        assert_eq!(runs[1].lcn, 20);
    }
}
