//! src/kernel/fs/ntfs/types.rs
//!
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

    pub fn size(&self) -> u16 {
        self.first_attr_offset
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
    pub content_size: u32,
    pub data_runs_offset: u16,
    pub data_runs_length: u16,
}

impl AttrHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        Some(Self {
            attr_type: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            attr_len: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            non_resident: buf[8] != 0,
            name_len: buf[9],
            name_offset: u16::from_le_bytes([buf[10], buf[11]]),
            flags: u16::from_le_bytes([buf[12], buf[13]]),
            instance: u16::from_le_bytes([buf[14], buf[15]]),
            content_size: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            data_runs_offset: u16::from_le_bytes([buf[20], buf[21]]),
            data_runs_length: u16::from_le_bytes([buf[22], buf[23]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedAttr {
    pub attr_type: AttrType,
    pub content: Vec<u8>,
    pub data_runs_offset: Option<usize>,
    pub data_runs: Vec<DataRun>,
    pub data_size: u32,
}

#[derive(Debug, Clone)]
pub struct DataRun {
    pub lcn: i64, // Logical Cluster Number; -1 = sparse
    pub cluster_count: u64,
}

#[derive(Debug, Clone)]
pub struct StandardInfoAttr {
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub file_attributes: u32,
}

impl StandardInfoAttr {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 68 {
            return None;
        }
        Some(Self {
            created: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            modified: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            mft_changed: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            accessed: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            file_attributes: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        })
    }

    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x1000_0000 != 0
    }

    pub fn to_unix_secs(ntfs_ticks: u64) -> f64 {
        // NTFS uses 100-nanosecond intervals since 1601-01-01
        // Unix time is seconds since 1970-01-01
        const NTFS_EPOCH_UNIX_OFFSET: f64 = 11644473600.0;
        ntfs_ticks as f64 * 1e-7 - NTFS_EPOCH_UNIX_OFFSET
    }
}

#[derive(Debug, Clone)]
pub struct FileName {
    pub parent_directory: u64,
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub file_attributes: u32,
    pub name: String,
    pub namespace: u8,
}

impl FileName {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 66 {
            return None;
        }
        let parent_directory = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let created = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let modified = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        let mft_changed = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        let accessed = u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
        ]);
        // NTFS file attributes live at offset 56 in the `$FILE_NAME` record
        // (bits 32–35 hold allocated/real size, not flags).
        let file_attributes = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);
        let name_len = buf[64] as usize;
        let namespace = buf[65];

        if buf.len() < 66 + name_len * 2 {
            return None;
        }

        let name_bytes = &buf[66..66 + name_len * 2];
        let utf16: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16);

        Some(Self {
            parent_directory,
            created,
            modified,
            mft_changed,
            accessed,
            file_attributes,
            name,
            namespace,
        })
    }

    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x1000_0000 != 0
    }

    pub fn preferred_namespace(&self) -> bool {
        self.namespace == 3 || self.namespace == 1
    }
}

/// Parse NTFS reparse-point buffer into tag and optional target path.
///
/// The buffer layout:
///   u32  reparse_tag
///   u16  reparse_data_length
///   u16  reserved
///   u8[] reparse_data (variable length)
///
/// For symbolic links, the reparse_data layout:
///   u16  substitute_name_offset
///   u16  substitute_name_length
///   u16  print_name_offset
///   u16  print_name_length
///   u8   path_buffer[]
pub fn parse_reparse_point(buf: &[u8]) -> Option<(u32, Option<String>)> {
    if buf.len() < 8 {
        return None;
    }
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let data_len = u16::from_le_bytes([buf[4], buf[5]]) as usize;

    if tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT {
        if buf.len() < 8 + data_len {
            return None;
        }
        let data = &buf[8..8 + data_len];

        if data.len() >= 8 {
            let sub_off = u16::from_le_bytes([data[0], data[1]]) as usize;
            let sub_len = u16::from_le_bytes([data[2], data[3]]) as usize;
            let print_off = u16::from_le_bytes([data[4], data[5]]) as usize;
            let print_len = u16::from_le_bytes([data[6], data[7]]) as usize;

            // Use substitute name if available, otherwise print name
            let (name_off, name_len) = if sub_len > 0 {
                (sub_off, sub_len)
            } else if print_len > 0 {
                (print_off, print_len)
            } else {
                return Some((tag, None));
            };

            if name_off + name_len <= data.len() {
                let name_bytes = &data[name_off..name_off + name_len];
                let utf16: Vec<u16> = name_bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                    .collect();
                let mut target = String::from_utf16_lossy(&utf16);

                // Strip NT namespace prefixes so the target is a plain path.
                for prefix in &["\\??\\", "\\DosDevices\\"] {
                    if let Some(stripped) = target.strip_prefix(prefix) {
                        target = stripped.into();
                        break;
                    }
                }
                return Some((tag, Some(target)));
            }
        }
    }

    Some((tag, None))
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
    use crate::kernel::fs::ntfs::fs::{get_best_filename, parse_data_runs, parse_index_entries};
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

    #[test]
    fn standard_info_parse_timestamps_and_dir() {
        let mut body = vec![0u8; 68];
        // NTFS ticks for 2024-01-01 ≈ 1782576000 Unix secs → ticks.
        put_u64_le(&mut body, 0, 133_000_000_000_000_000); // created
        put_u64_le(&mut body, 8, 133_000_000_100_000_000); // modified
        put_u64_le(&mut body, 16, 133_000_000_200_000_000); // mft_changed
        put_u64_le(&mut body, 24, 133_000_000_300_000_000); // accessed
        put_u32_le(&mut body, 32, 0x1000_0000); // FILE_ATTRIBUTE_DIRECTORY
        let si = StandardInfoAttr::parse(&body).expect("parse standard info");
        assert!(si.is_directory());
        assert_eq!(si.created, 133_000_000_000_000_000);
        assert_eq!(si.modified, 133_000_000_100_000_000);
        // Converted Unix seconds should be finite and sane.
        let unix = StandardInfoAttr::to_unix_secs(si.created);
        assert!(unix > 1_600_000_000.0 && unix < 2_000_000_000.0);
    }

    #[test]
    fn get_best_filename_prefers_win32_over_dos() {
        let dos = ParsedAttr {
            attr_type: ATTR_TYPE_FILENAME,
            content: make_filename_body("HELLO~1", 2, 0, 5),
            data_runs_offset: None,
            data_runs: Vec::new(),
            data_size: 0,
        };
        let win32 = ParsedAttr {
            attr_type: ATTR_TYPE_FILENAME,
            content: make_filename_body("hello.txt", 3, 0, 5),
            data_runs_offset: None,
            data_runs: Vec::new(),
            data_size: 0,
        };
        let best = get_best_filename(&[dos.clone(), win32]).expect("best filename");
        assert_eq!(best.name, "hello.txt");
        assert_eq!(best.namespace, 3);
    }

    #[test]
    fn parse_index_entries_dedups_namespaces() {
        // Two index entries for the same MFT record (42): a pure-DOS 8.3 name and
        // a Win32 long name.  Only the Win32 name should survive.
        let make_entry = |name: &str, namespace: u8| -> Vec<u8> {
            let name_bytes = make_filename_body(name, namespace, 0, 5);
            let entry_len = 16 + name_bytes.len();
            let mut e = vec![0u8; entry_len];
            put_u64_le(&mut e, 0, 42); // MFT ref
            put_u16_le(&mut e, 8, entry_len as u16);
            put_u16_le(&mut e, 10, 16); // content offset
                                        // flags at 12..16 (0 = not last for entry 1; set by caller)
            e[16..16 + name_bytes.len()].copy_from_slice(&name_bytes);
            e
        };
        let mut e1 = make_entry("HELLO~1", 2);
        let e2 = make_entry("hello.txt", 1);
        put_u32_le(&mut e1, 12, 0x02); // last-entry flag on the DOS entry
                                       // Prepend the 16-byte `$INDEX_ROOT` header: first entry at 16, total
                                       // index size spans both entries.
        let mut buf = vec![0u8; 16];
        put_u16_le(&mut buf, 8, 16); // first entry offset
        put_u16_le(&mut buf, 10, (16 + e1.len() + e2.len()) as u16); // index size
        buf.extend_from_slice(&e1);
        buf.extend_from_slice(&e2);

        let entries = parse_index_entries(&buf).expect("parse index");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "hello.txt");
        assert_eq!(entries[0].1, 42);
    }

    // Helper functions for tests
    fn put_u16_le(buf: &mut [u8], off: usize, value: u16) {
        buf[off] = value as u8;
        buf[off + 1] = (value >> 8) as u8;
    }

    fn put_u32_le(buf: &mut [u8], off: usize, value: u32) {
        buf[off] = value as u8;
        buf[off + 1] = (value >> 8) as u8;
        buf[off + 2] = (value >> 16) as u8;
        buf[off + 3] = (value >> 24) as u8;
    }

    fn put_u64_le(buf: &mut [u8], off: usize, value: u64) {
        for i in 0..8 {
            buf[off + i] = (value >> (i * 8)) as u8;
        }
    }

    fn make_filename_body(name: &str, namespace: u8, flags: u32, parent: u64) -> Vec<u8> {
        let mut body = vec![0u8; 66 + name.len() * 2];
        put_u64_le(&mut body, 0, parent);
        put_u32_le(&mut body, 56, flags);
        body[64] = name.len() as u8;
        body[65] = namespace;
        for (i, u) in name.encode_utf16().enumerate() {
            body[66 + i * 2] = u as u8;
            body[66 + i * 2 + 1] = (u >> 8) as u8;
        }
        body
    }
}
