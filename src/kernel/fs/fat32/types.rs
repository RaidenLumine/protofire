//! src/kernel/fs/fat32/types.rs
//! On-disk type definitions, BPB geometry parsing, directory entry parse/serialize
//! helpers, and byte-level I/O utilities for FAT12/16/32.

use alloc::string::String;
use alloc::vec::Vec;

pub(crate) use crate::kernel::fs::block::BLOCK_SIZE;
use crate::kernel::fs::unicode::{self, OemCodePage};
pub(crate) use crate::kernel::fs::vfs::NodeKind;
use crate::{Error, Result};

// ─── FAT type classification ───────────────────────────────────────────────

/// FAT type determined from data cluster count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FatType {
    /// FAT12 — fewer than 4085 data clusters (floppy disks, small volumes).
    Fat12,
    /// FAT16 — 4085 to 65524 data clusters.
    Fat16,
    /// FAT32 — 65525 or more data clusters.
    Fat32,
}

impl FatType {
    /// End-of-cluster-chain minimum value (inclusive).
    pub(crate) fn eoc_min(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// End-of-cluster-chain mask (applied to FAT entry before comparison).
    pub(crate) fn eoc_mask(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFFF,
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// Human-readable label used in the volume name.
    pub(crate) fn label(self) -> &'static str {
        match self {
            FatType::Fat12 => "fat12",
            FatType::Fat16 => "fat16",
            FatType::Fat32 => "fat32",
        }
    }
}

// ─── FAT constants ─────────────────────────────────────────────────────────

/// FAT32 end-of-cluster-chain marker (high bits).
/// Kept for documentation and potential use in write support.
#[allow(dead_code)]
pub(crate) const FAT32_EOC_MASK: u32 = 0x0FFF_FFFF;
#[allow(dead_code)]
pub(crate) const FAT32_EOC_MIN: u32 = 0x0FFF_FFF8;
#[allow(dead_code)]
pub(crate) const FAT32_BAD_CLUSTER: u32 = 0x0FFF_FFF7;
#[allow(dead_code)]
pub(crate) const FAT32_RESERVED_CLUSTER_MIN: u32 = 0x0FFF_FFF0;

/// Minimum valid data cluster number (cluster 2 is the first data cluster).
pub(crate) const FIRST_DATA_CLUSTER: u32 = 2;

/// Directory entry attribute bits.
pub(crate) const ATTR_READ_ONLY: u8 = 0x01;
pub(crate) const ATTR_HIDDEN: u8 = 0x02;
pub(crate) const ATTR_SYSTEM: u8 = 0x04;
#[allow(dead_code)]
pub(crate) const ATTR_VOLUME_ID: u8 = 0x08;
pub(crate) const ATTR_DIRECTORY: u8 = 0x10;
#[allow(dead_code)]
pub(crate) const ATTR_ARCHIVE: u8 = 0x20;
/// LFN entries use a combination of attribute bits: READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID = 0x0F.
/// This is an invalid combination for a regular file, which is how OSes detect LFN entries.
pub(crate) const ATTR_LFN_MASK: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID; // 0x0F
/// Convenience alias: LFN attribute mask for LFN entry recognition.
#[allow(dead_code)]
pub(crate) const ATTR_LFN: u8 = ATTR_LFN_MASK;

/// BPB offsets in the boot sector (512 bytes).
pub(crate) const BPB_BYTES_PER_SECTOR: usize = 11; // u16
pub(crate) const BPB_SECTORS_PER_CLUSTER: usize = 13; // u8
pub(crate) const BPB_RESERVED_SECTORS: usize = 14; // u16
pub(crate) const BPB_NUM_FATS: usize = 16; // u8
pub(crate) const BPB_ROOT_ENTRIES: usize = 17; // u16 (0 for FAT32)
pub(crate) const BPB_TOTAL_SECTORS_16: usize = 19; // u16 (0 for FAT32)
#[allow(dead_code)]
pub(crate) const BPB_MEDIA: usize = 21; // u8
pub(crate) const BPB_SECTORS_PER_FAT_16: usize = 22; // u16 (0 for FAT32)
pub(crate) const BPB_TOTAL_SECTORS_32: usize = 32; // u32
pub(crate) const BPB_SECTORS_PER_FAT_32: usize = 36; // u32
pub(crate) const BPB_ROOT_CLUSTER: usize = 44; // u32
#[allow(dead_code)]
pub(crate) const BPB_FSINFO_SECTOR: usize = 48; // u16
#[allow(dead_code)]
pub(crate) const BPB_BACKUP_BOOT_SECTOR: usize = 50; // u16
#[allow(dead_code)]
pub(crate) const BPB_EXTENDED_BOOT_SIGNATURE: usize = 66; // u8 (0x29)
#[allow(dead_code)]
pub(crate) const BPB_VOLUME_LABEL: usize = 71; // 11 bytes
pub(crate) const BPB_FS_TYPE: usize = 82; // 8 bytes ("FAT32   ")

/// Size of a directory entry in bytes.
pub(crate) const DIR_ENTRY_SIZE: usize = 32;

// ─── FAT geometry (parsed from BPB) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct FatGeometry {
    pub(crate) fat_type: FatType,
    #[allow(dead_code)]
    pub(crate) bytes_per_sector: u16,
    pub(crate) sectors_per_cluster: u8,
    #[allow(dead_code)]
    pub(crate) reserved_sectors: u16,
    #[allow(dead_code)]
    pub(crate) num_fats: u8,
    #[allow(dead_code)]
    pub(crate) sectors_per_fat: u32,
    /// FAT32 root directory cluster number (0 for FAT12/16).
    pub(crate) root_cluster: u32,
    /// FAT12/16 root directory entries count (0 for FAT32).
    #[allow(dead_code)]
    pub(crate) root_entries: u16,
    #[allow(dead_code)]
    pub(crate) total_sectors: u32,

    // Derived fields
    pub(crate) cluster_size_bytes: u32,
    pub(crate) fat_start_lba: u64,
    /// Start LBA of the data region (cluster 2…N).
    pub(crate) data_start_lba: u64,
    /// FAT12/16 root directory region: starting LBA and size in sectors.
    pub(crate) root_dir_lba: u64,
    pub(crate) root_dir_sectors: u64,
    pub(crate) data_cluster_count: u32,
}

impl FatGeometry {
    /// Parse the BPB from the first 512 bytes of the boot sector.
    pub(crate) fn from_boot_sector(data: &[u8; BLOCK_SIZE]) -> Result<Self> {
        let bytes_per_sector = read_u16(data, BPB_BYTES_PER_SECTOR);
        let sectors_per_cluster = data[BPB_SECTORS_PER_CLUSTER];
        let reserved_sectors = read_u16(data, BPB_RESERVED_SECTORS);
        let num_fats = data[BPB_NUM_FATS];
        let root_entries = read_u16(data, BPB_ROOT_ENTRIES);
        let sectors_per_fat_16 = read_u16(data, BPB_SECTORS_PER_FAT_16);
        let total_sectors_16 = read_u16(data, BPB_TOTAL_SECTORS_16);
        let total_sectors_32 = read_u32(data, BPB_TOTAL_SECTORS_32);
        let sectors_per_fat_32 = read_u32(data, BPB_SECTORS_PER_FAT_32);
        let root_cluster = read_u32(data, BPB_ROOT_CLUSTER);

        // Validate basic constraints
        if bytes_per_sector != 512 {
            return Err(Error::Unsupported);
        }
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if num_fats == 0 || num_fats > 4 {
            return Err(Error::InvalidArgument);
        }

        // Pick the larger-of-pair fields (FAT32 uses the 32-bit variants;
        // FAT12/16 use the 16-bit variants).
        let sectors_per_fat = if sectors_per_fat_32 != 0 {
            sectors_per_fat_32
        } else {
            sectors_per_fat_16 as u32
        };
        let total_sectors = if total_sectors_32 != 0 {
            total_sectors_32
        } else {
            total_sectors_16 as u32
        };

        if sectors_per_fat == 0 || total_sectors == 0 {
            return Err(Error::InvalidArgument);
        }

        // Verify the filesystem type string against the FAT family.
        let fs_type_raw = &data[BPB_FS_TYPE..BPB_FS_TYPE + 8];
        let fs_type = core::str::from_utf8(fs_type_raw).unwrap_or("");
        if !(fs_type.starts_with("FAT32")
            || fs_type.starts_with("FAT16")
            || fs_type.starts_with("FAT12")
            || fs_type.starts_with("FAT     "))
        {
            return Err(Error::Unsupported);
        }

        let fat_start_lba = reserved_sectors as u64;
        let fat_size_blocks = sectors_per_fat as u64 * num_fats as u64;

        // FAT12/16 root directory occupies a fixed region between the FAT
        // tables and the data area.
        let root_dir_sectors =
            (root_entries as u64 * DIR_ENTRY_SIZE as u64).div_ceil(bytes_per_sector as u64);
        let root_dir_lba = fat_start_lba + fat_size_blocks;

        // Data area starts after the root directory region (FAT12/16) or
        // immediately after the FAT tables (FAT32).
        let data_start_lba = root_dir_lba + root_dir_sectors;
        let cluster_size_bytes = sectors_per_cluster as u32 * bytes_per_sector as u32;

        let data_sectors =
            total_sectors as u64 - reserved_sectors as u64 - fat_size_blocks - root_dir_sectors;
        let data_cluster_count = (data_sectors / sectors_per_cluster as u64) as u32;

        // Determine FAT type.  Prefer the FS type string (explicit in the BPB
        // for all modern formatting tools), falling back to the cluster-count
        // heuristic when the string is the legacy "FAT     ".
        let fat_type = if fs_type.starts_with("FAT32") {
            FatType::Fat32
        } else if fs_type.starts_with("FAT16") || (4085..65525).contains(&data_cluster_count) {
            FatType::Fat16
        } else {
            // FAT12: explicit string, "FAT     " with few clusters, or
            // unrecognised string on a small volume.
            FatType::Fat12
        };

        Ok(Self {
            fat_type,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_cluster,
            root_entries,
            total_sectors,
            cluster_size_bytes,
            fat_start_lba,
            data_start_lba,
            root_dir_lba,
            root_dir_sectors,
            data_cluster_count,
        })
    }

    /// Convert a cluster number to its starting LBA.
    pub(crate) fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba
            + (cluster as u64 - FIRST_DATA_CLUSTER as u64) * self.sectors_per_cluster as u64
    }
}

// ─── Helper: read little-endian values from byte slices ────────────────────

pub(crate) fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

// ─── Date / time conversion ──────────────────────────────────────────────────

/// Convert a DOS date+time pair to Unix epoch seconds.
///
/// DOS date format (u16): bits 15-9 = year since 1980, bits 8-5 = month,
/// bits 4-0 = day.
/// DOS time format (u16): bits 15-11 = hour, bits 10-5 = minute,
/// bits 4-0 = second / 2.
///
/// Returns 0 when the date field is 0 (unset).  Handles year values up to
/// 2107 (the DOS date field limit).
pub(crate) fn dos_datetime_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    let year = ((date >> 9) & 0x7F) as u32 + 1980;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    let min = ((time >> 5) & 0x3F) as u32;
    let sec = ((time & 0x1F) * 2) as u32;

    // Days since Unix epoch for the given date.
    let days = days_since_epoch(year, month, day);
    (days as u64) * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64
}

/// Convert a DOS date (with implicit midnight time) to Unix epoch seconds.
pub(crate) fn dos_date_to_unix(date: u16) -> u64 {
    dos_datetime_to_unix(date, 0)
}

/// Compute days since 1970-01-01 for a given year/month/day.
fn days_since_epoch(year: u32, month: u32, day: u32) -> u32 {
    let y = year as i64;
    let m = month as i64;
    let d = day as i64;

    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    // Shift to a March-based year so February is the last month.
    let y_adj = if m <= 2 { y - 1 } else { y };
    let m_adj = if m <= 2 { m + 12 } else { m };
    let era = if y_adj >= 0 {
        y_adj / 400
    } else {
        (y_adj / 400) - 1
    };
    let yoe = (y_adj - era * 400) as u32; // year of era [0, 399]
    let doy = (153 * (m_adj as u32 - 3) + 2) / 5 + d as u32 - 1; // day of year
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era
    era as u32 * 146097 + doe - 719468
}

// ─── Directory entry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct FatDirEntry {
    pub(crate) name: String,
    pub(crate) kind: NodeKind,
    pub(crate) first_cluster: u32,
    pub(crate) file_size: u32,
    /// Create timestamp (Unix epoch seconds) — parsed from DOS date/time fields.
    pub(crate) created: u64,
    /// Last-modified timestamp (Unix epoch seconds).
    pub(crate) modified: u64,
    /// Last-access timestamp (Unix epoch seconds, date only, midnight UTC).
    pub(crate) accessed: u64,
}

/// Parse one 32-byte directory entry (raw bytes → FatDirEntry).
/// Returns `None` for deleted entries, volume label entries, and LFN entries
/// (LFNs are collected separately).
pub(crate) fn parse_short_dir_entry(data: &[u8], code_page: OemCodePage) -> Option<FatDirEntry> {
    if data.len() < DIR_ENTRY_SIZE {
        return None;
    }

    let first_byte = data[0];
    // 0x00 = end of directory, 0xE5 = deleted entry
    if first_byte == 0x00 || first_byte == 0xE5 {
        return None;
    }

    let attr = data[11];
    // Skip LFN entries (they're handled by the caller)
    if attr == ATTR_LFN_MASK {
        return None;
    }
    // Skip volume label
    if attr & 0x08 != 0 {
        return None;
    }

    // Extract 8.3 name
    let name = parse_short_name(&data[0..11], code_page);

    let kind = if attr & ATTR_DIRECTORY != 0 {
        NodeKind::Directory
    } else {
        NodeKind::File
    };

    let first_cluster = read_u16(data, 26) as u32 | ((read_u16(data, 20) as u32) << 16);
    let file_size = read_u32(data, 28);

    // Parse timestamps from the directory entry.
    let create_time = read_u16(data, 14);
    let create_date = read_u16(data, 16);
    let access_date = read_u16(data, 18);
    let modify_time = read_u16(data, 22);
    let modify_date = read_u16(data, 24);

    Some(FatDirEntry {
        name,
        kind,
        first_cluster,
        file_size,
        created: dos_datetime_to_unix(create_date, create_time),
        modified: dos_datetime_to_unix(modify_date, modify_time),
        accessed: dos_date_to_unix(access_date),
    })
}

/// Parse an 8.3 short name (11 bytes: 8 for name + 3 for extension).
///
/// ASCII graphic bytes are lowercased to follow FAT's case-insensitive
/// convention.  Bytes ≥ 0x80 are decoded through the given OEM `code_page`
/// (**CP437** or **CP850**), then case-folded via Unicode `to_lowercase()`
/// so that uppercase accented letters match their lowercase equivalents
/// during lookup.
pub(crate) fn parse_short_name(raw: &[u8], code_page: OemCodePage) -> String {
    let name_part = &raw[0..8];
    let ext_part = &raw[8..11];

    let name_end = name_part
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(name_part.len());
    let ext_end = ext_part
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(ext_part.len());

    let mut name = String::new();
    for &b in &name_part[..name_end] {
        push_oem_byte_lower(b, code_page, &mut name);
    }
    if ext_end > 0 {
        name.push('.');
        for &b in &ext_part[..ext_end] {
            push_oem_byte_lower(b, code_page, &mut name);
        }
    }
    name
}

/// Push a single OEM byte onto `name`, lowercasing it appropriately.
///
/// ASCII graphic bytes are lowercased with `to_ascii_lowercase`.
/// High bytes (≥ 0x80) are decoded through the OEM code page and then
/// case-folded via Unicode `to_lowercase()` (handles one-to-many mappings).
/// ASCII control characters (0x00–0x1F, 0x7F) pass through unchanged
/// as replacement characters — they should never appear in valid 8.3 names.
fn push_oem_byte_lower(byte: u8, code_page: OemCodePage, name: &mut String) {
    if byte.is_ascii_graphic() {
        name.push(byte.to_ascii_lowercase() as char);
    } else if byte >= 0x80 {
        let ch = unicode::oem_byte_to_char(byte, code_page);
        for lower in ch.to_lowercase() {
            name.push(lower);
        }
    } else {
        // ASCII control character (0x00–0x1F, 0x7F) or space before
        // trimming — pass through as-is (shouldn't appear in valid names).
        name.push(byte as char);
    }
}

/// Try to parse an LFN entry, returning the raw UTF-16LE code units and the
/// sequence metadata.  Returns `None` if this isn't an LFN entry.
///
/// FAT32 LFN entries store file names as UCS-2 (BMP) code units encoded in
/// UTF-16LE.  Each fragment holds 13 code units spread across three groups
/// at fixed offsets within the 32-byte directory entry.  NUL (`\0`) marks the
/// end of the name within the fragment; code units beyond the first NUL are
/// ignored.
///
/// Raw `u16` code units are returned so that surrogate pairs (non-BMP
/// characters like emoji) can be correctly decoded once all fragments are
/// collected.  The caller is responsible for decoding via
/// [`unicode::utf16le_to_utf8`].
pub(crate) fn parse_lfn_fragment(data: &[u8]) -> Option<(u8, [u16; 13])> {
    if data.len() < DIR_ENTRY_SIZE {
        return None;
    }
    if data[11] != ATTR_LFN_MASK {
        return None;
    }
    let seq = data[0];
    let last = (seq & 0x40) != 0;
    let seq_num = seq & 0x1F;

    let mut code_units = [0u16; 13];
    let mut idx = 0;

    // Characters at offsets 1,3,5,7,9 (5 code units × 2 bytes each = UTF-16LE)
    for off in [1, 3, 5, 7, 9] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }
    // Characters at offsets 14,16,18,20,22,24 (6 code units × 2 bytes)
    for off in [14, 16, 18, 20, 22, 24] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }
    // Characters at offsets 28,30 (2 code units × 2 bytes)
    for off in [28, 30] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }

    Some(((if last { 0x80 } else { 0 }) | seq_num, code_units))
}

/// Build a long file name from collected LFN fragments (in reverse order).
///
/// Collects raw UTF-16LE code units from all fragments and decodes them with
/// [`unicode::utf16le_to_utf8`], which handles surrogate pairs for non-BMP
/// characters like emoji.
pub(crate) fn build_lfn_name(fragments: &[(u8, [u16; 13])]) -> String {
    // Fragments are collected in order of appearance (reverse sequence order).
    // Process them in reverse to get the correct name order, collecting all
    // code units into a flat buffer.
    let mut code_units: Vec<u16> = Vec::new();
    for &(_seq, units) in fragments.iter().rev() {
        for &cu in &units {
            if cu == 0 {
                break;
            }
            code_units.push(cu);
        }
    }
    unicode::utf16le_to_utf8(&code_units)
}

// ─── Directory entry serialization (write path) ────────────────────────────

/// Compute the LFN checksum over the 11-byte 8.3 short name.
pub(crate) fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in short_name.iter() {
        sum = sum
            .wrapping_shr(1)
            .wrapping_add(sum << 7)
            .wrapping_add(byte);
    }
    sum
}

/// Generate an 8.3 short name from a long filename.
///
/// Algorithm: take up to 6 alphanumeric chars from the start (uppercased),
/// append "~1", and use the extension from the last dot (uppercased, up to
/// 3 chars).  If the base part is short enough to fit without a tilde
/// suffix, no tilde suffix is added.
pub(crate) fn generate_short_name(long_name: &str, code_page: OemCodePage) -> [u8; 11] {
    let mut short = [b' '; 11];

    // Split at last dot for extension.
    let (stem, ext) = match long_name.rfind('.') {
        Some(dot) => (&long_name[..dot], &long_name[dot + 1..]),
        None => (long_name, ""),
    };

    // Build stem: convert to OEM bytes, keep only valid code-page chars.
    let stem_bytes = unicode::utf8_to_oem(stem, code_page);
    let stem_chars: Vec<u8> = stem_bytes
        .iter()
        .filter_map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                Some(b.to_ascii_uppercase())
            } else if b >= 0x80 {
                Some(b) // Keep OEM high bytes as-is (already in target code page).
            } else if b == b'?' {
                Some(b'_') // Unmappable Unicode char → underscore.
            } else {
                None
            }
        })
        .take(8)
        .collect();

    let need_tilde = stem_chars.len() > 6 || stem.len() > 8 || !ext.is_empty();
    let stem_len = if need_tilde {
        let n = stem_chars.len().min(6);
        for (i, &c) in stem_chars[..n].iter().enumerate() {
            short[i] = c;
        }
        short[6] = b'~';
        short[7] = b'1';
        8
    } else {
        for (i, &c) in stem_chars.iter().enumerate() {
            short[i] = c;
        }
        stem_chars.len()
    };

    // Build extension: convert to OEM bytes, uppercase, up to 3 chars.
    let ext_bytes = unicode::utf8_to_oem(ext, code_page);
    let ext_chars: Vec<u8> = ext_bytes
        .iter()
        .filter_map(|&b| {
            if b.is_ascii_alphanumeric() {
                Some(b.to_ascii_uppercase())
            } else if b >= 0x80 {
                Some(b) // Keep OEM high bytes.
            } else if b == b'?' {
                Some(b'_') // Unmappable Unicode char → underscore.
            } else {
                None
            }
        })
        .take(3)
        .collect();
    for (i, &c) in ext_chars.iter().enumerate() {
        short[8 + i] = c;
    }
    let _ = stem_len;

    short
}

/// Write an LFN entry (32 bytes) into `buf` at `offset`.
pub(crate) fn write_lfn_entry(
    buf: &mut [u8],
    offset: usize,
    seq_num: u8,
    is_last: bool,
    chars: &[u16; 13],
    checksum: u8,
) {
    let entry = &mut buf[offset..offset + 32];
    entry.fill(0);
    // Sequence number: bits 0–5 = sequence, bit 6 = last flag.
    let seq = (seq_num & 0x1F) | if is_last { 0x40 } else { 0 };
    entry[0] = seq;
    entry[11] = 0x0F; // LFN attribute
    entry[12] = 0x00; // Type (must be 0)
    entry[13] = checksum;
    // Entry[26..28] = first cluster (must be 0 for LFN)

    // Write 13 UTF-16LE chars across the three groups inside the entry using
    // the shared unicode utility.
    // Group 1: offset 1 (5 chars)
    unicode::write_utf16le_chars(entry, 1, &chars[0..5], 5);
    // Group 2: offset 14 (6 chars)
    unicode::write_utf16le_chars(entry, 14, &chars[5..11], 6);
    // Group 3: offset 28 (2 chars)
    unicode::write_utf16le_chars(entry, 28, &chars[11..13], 2);
}

/// Write a standard 8.3 directory entry (32 bytes) into `buf` at `offset`.
pub(crate) fn write_short_entry(
    buf: &mut [u8],
    offset: usize,
    short_name: &[u8; 11],
    attrs: u8,
    first_cluster: u32,
    file_size: u32,
) {
    let entry = &mut buf[offset..offset + 32];
    entry.fill(0);
    entry[0..11].copy_from_slice(short_name);
    entry[11] = attrs;
    // entry[12] reserved
    // entry[13] = create_time_tenth (tenths of second) — leave 0
    // entry[14..20] = create time/date — leave 0
    // entry[20..22] = first cluster high (FAT32)
    entry[20] = (first_cluster >> 16) as u8;
    entry[21] = (first_cluster >> 24) as u8;
    // entry[22..24] = modify time
    // entry[24..26] = modify date
    // entry[26..28] = first cluster low
    entry[26] = first_cluster as u8;
    entry[27] = (first_cluster >> 8) as u8;
    // entry[28..32] = file size
    entry[28] = file_size as u8;
    entry[29] = (file_size >> 8) as u8;
    entry[30] = (file_size >> 16) as u8;
    entry[31] = (file_size >> 24) as u8;
}

/// Build the raw bytes for a directory entry set (LFN entries + short
/// entry) for a given file.  Returns the number of 32-byte entries written.
pub(crate) fn build_dir_entry_set(
    raw: &mut [u8],
    name: &str,
    attrs: u8,
    first_cluster: u32,
    file_size: u32,
    code_page: OemCodePage,
) -> usize {
    let short_name = generate_short_name(name, code_page);
    let checksum = lfn_checksum(&short_name);

    let name_utf16 = unicode::utf8_to_utf16le(name);
    let name_len = name_utf16.len();

    if name_len == 0 {
        // Write only the short entry for an empty name.
        write_short_entry(raw, 0, &short_name, attrs, first_cluster, file_size);
        return 1;
    }

    // Calculate how many LFN entries are needed.  Each LFN entry holds
    // up to 13 UTF-16 code units.
    let lfn_entries_needed = name_len.div_ceil(13);
    let total_entries = lfn_entries_needed + 1; // +1 for the short entry

    // Write LFN entries in reverse order (last fragment first in memory).
    // FAT stores the highest sequence number first, so fragment at directory
    // offset 0 contains the LAST 13 chars of the name, fragment at offset 32
    // contains the second-to-last 13 chars, etc.
    for frag_idx in 0..lfn_entries_needed {
        let seq_num = (lfn_entries_needed - frag_idx) as u8;
        let is_last = frag_idx == 0;
        // Segment index in reverse: the last segment in the name (highest
        // offset) goes into the first directory LFN entry.
        let seg_idx = lfn_entries_needed - 1 - frag_idx;
        let char_start = seg_idx * 13;
        let char_end = (char_start + 13).min(name_len);
        let mut chars = [0u16; 13];
        for (i, &ch) in name_utf16[char_start..char_end].iter().enumerate() {
            chars[i] = ch;
        }
        write_lfn_entry(raw, frag_idx * 32, seq_num, is_last, &chars, checksum);
    }

    // Write the short entry immediately after the LFN entries.
    let short_offset = lfn_entries_needed * 32;
    write_short_entry(
        raw,
        short_offset,
        &short_name,
        attrs,
        first_cluster,
        file_size,
    );

    total_entries
}

/// Insert a directory entry set into raw directory bytes at `insert_offset`,
/// shifting existing entries down and zeroing the space taken by the new
/// entries.  If the directory doesn't have enough free space, returns an
/// error.
pub(crate) fn insert_dir_entry_set(
    raw: &mut Vec<u8>,
    insert_offset: usize,
    num_entries: usize,
    entry_set_data: &[u8],
) {
    let needed = num_entries * DIR_ENTRY_SIZE;
    let old_len = raw.len();
    let new_len = old_len + needed;

    // Make room: extend the raw buffer and shift down.
    raw.resize(new_len, 0);
    raw.copy_within(insert_offset..old_len, insert_offset + needed);

    // Write the new entry set.
    raw[insert_offset..insert_offset + needed].copy_from_slice(&entry_set_data[..needed]);
}
