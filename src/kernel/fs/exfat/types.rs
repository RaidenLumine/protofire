//! src/kernel/fs/exfat/types.rs
//!
//! On-disk type definitions, boot region parsing, entry type classification,
//! and byte-level I/O utilities for exFAT.

use alloc::string::String;

pub(crate) use crate::kernel::fs::block::BLOCK_SIZE;
pub(crate) use crate::kernel::fs::vfs::NodeKind;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum valid data cluster number (cluster 2 is the first data cluster,
/// same convention as FAT32).
pub(crate) const FIRST_DATA_CLUSTER: u32 = 2;

/// End-of-chain marker for 32-bit FAT entries.
pub(crate) const FAT32_EOC: u32 = 0xFFFF_FFFF;

/// Bad cluster marker.
#[allow(dead_code)]
pub(crate) const FAT32_BAD: u32 = 0xFFFF_FFF7;

/// Size of a directory entry in bytes (exFAT uses 32-byte entries, same as
/// FAT32 but with a different internal layout).
pub(crate) const DIR_ENTRY_SIZE: usize = 32;

/// Maximum entries per directory listing (safety cap).
pub(crate) const MAX_DIR_ENTRIES: usize = 4096;

// ─── directory entry type codes ──────────────────────────────────────────

/// End of directory marker — no more entries beyond this point.
pub(crate) const EXFAT_ENTRY_EOD: u8 = 0x00;

/// Allocation bitmap entry (primary, type 0x01).
pub(crate) const EXFAT_ENTRY_BITMAP: u8 = 0x81;

/// Up-case table entry (primary, type 0x02).
pub(crate) const EXFAT_ENTRY_UPCASE: u8 = 0x82;

/// Volume label entry (primary, type 0x03).
#[allow(dead_code)]
pub(crate) const EXFAT_ENTRY_LABEL: u8 = 0x83;

/// File directory entry (primary, type 0x05).  Always followed by one
/// Stream Extension (0xC0) and zero or more File Name Extension (0xC1)
/// entries.
#[allow(dead_code)]
pub(crate) const EXFAT_ENTRY_FILE: u8 = 0x85;

/// Stream extension entry (secondary, identifies data extent info).
pub(crate) const EXFAT_ENTRY_STREAM: u8 = 0xC0;

/// File name extension entry (secondary, holds a fragment of the UTF-16LE
/// filename).
pub(crate) const EXFAT_ENTRY_FILENAME: u8 = 0xC1;

pub(crate) const ENTRY_TYPE_MASK: u8 = 0x1F;
pub(crate) const ENTRY_INUSE_MASK: u8 = 0x80;

/// File attribute bits (stored in the File entry at offset 4, u16 LE).
#[allow(dead_code)]
pub(crate) const EXFAT_ATTR_READ_ONLY: u16 = 0x0001;
#[allow(dead_code)]
pub(crate) const EXFAT_ATTR_HIDDEN: u16 = 0x0002;
#[allow(dead_code)]
pub(crate) const EXFAT_ATTR_SYSTEM: u16 = 0x0004;
#[allow(dead_code)]
pub(crate) const EXFAT_ATTR_VOLUME_LABEL: u16 = 0x0008;
pub(crate) const EXFAT_ATTR_DIRECTORY: u16 = 0x0010;
#[allow(dead_code)]
pub(crate) const EXFAT_ATTR_ARCHIVE: u16 = 0x0020;

/// Boot signature at offset 510–511 (0x55, 0xAA).
pub(crate) const BOOT_SIGNATURE_OFFSET: usize = 510;

// ─── boot region layout ──────────────────────────────────────────────────

/// Number of sectors in the Main (and Backup) Boot Region.
/// Sectors 0–11: 1 boot + 8 extended + 1 OEM params + 1 checksum + 1 reserved
pub(crate) const BOOT_REGION_SECTORS: usize = 12;

/// Offsets within the boot sector (512 bytes).
pub(crate) const B_OEM_NAME: usize = 0x03; // 8 bytes
pub(crate) const B_VOLUME_LENGTH: usize = 0x48; // u64 LE
pub(crate) const B_FAT_OFFSET: usize = 0x50; // u32 LE
pub(crate) const B_FAT_LENGTH: usize = 0x54; // u32 LE
pub(crate) const B_CLUSTER_HEAP_OFFSET: usize = 0x58; // u32 LE
pub(crate) const B_CLUSTER_COUNT: usize = 0x5C; // u32 LE
pub(crate) const B_ROOT_DIR_CLUSTER: usize = 0x60; // u32 LE
pub(crate) const B_VOLUME_SERIAL: usize = 0x64; // u32 LE
pub(crate) const B_FS_REVISION: usize = 0x68; // u16 LE
pub(crate) const B_VOLUME_FLAGS: usize = 0x6A; // u16 LE
pub(crate) const B_BYTES_PER_SECTOR_SHIFT: usize = 0x6C; // u8
pub(crate) const B_SECTORS_PER_CLUSTER_SHIFT: usize = 0x6D; // u8
pub(crate) const B_NUM_FATS: usize = 0x6E; // u8
/// Sector offset where the 4-byte boot checksum is stored within the checksum
/// sector (sector 11 in the Main Boot Region).  This is NOT in sector 0.
pub(crate) const B_CHECKSUM_SECTOR: usize = 11;
pub(crate) const B_CHECKSUM_OFFSET: usize = 0x1FC; // u32 LE — within the checksum sector

/// Volume flags.
#[allow(dead_code)]
pub(crate) const VOLUME_FLAG_DIRTY: u16 = 0x0002;

// ─── file entry field offsets (type 0x85) ────────────────────────────────

pub(crate) const F_ATTR: usize = 4; // u16 LE
#[allow(dead_code)]
pub(crate) const F_CREATE_TIME: usize = 8; // u32 LE
#[allow(dead_code)]
pub(crate) const F_MODIFY_TIME: usize = 12; // u32 LE
#[allow(dead_code)]
pub(crate) const F_ACCESS_TIME: usize = 16; // u32 LE

// ─── stream extension field offsets (type 0xC0) ─────────────────────────

/// Flags byte within the stream extension entry.
pub(crate) const S_FLAGS: usize = 1;
pub(crate) const S_FLAG_NO_FAT_CHAIN: u8 = 0x02; // file is stored in one contiguous run

pub(crate) const S_NAME_LENGTH: usize = 3; // u8 — number of Unicode chars in filename
pub(crate) const S_VALID_DATA_LEN: usize = 12; // u32 LE (low), high at offset 28
pub(crate) const S_FIRST_CLUSTER: usize = 20; // u32 LE
pub(crate) const S_DATA_LEN: usize = 24; // u32 LE (low), high implied by ValidDataLen

/// Valid data length high word offset within stream extension.
#[allow(dead_code)]
pub(crate) const S_VALID_DATA_LEN_HI: usize = 28; // u32 LE

// ─── file name extension field offsets (type 0xC1) ──────────────────────

/// GeneralPurposeFlag at offset 1 (bit 0 = alloc possible, bit 1 = no fat
/// chain). Each file name extension holds up to 15 UTF-16LE code units (30
/// bytes at offset 2–31).
pub(crate) const FN_NAME_START: usize = 2; // 15 × u16 LE (30 bytes)

/// Maximum code units per file name extension entry.
pub(crate) const FN_CHARS_PER_ENTRY: usize = 15;

// ---------------------------------------------------------------------------
// Boot region
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ExfatBootRegion {
    /// Sector size in bytes: `2^bytes_per_sector_shift`.
    #[allow(dead_code)]
    pub(crate) bytes_per_sector: u16,
    /// Sectors per cluster: `2^sectors_per_cluster_shift`.
    pub(crate) sectors_per_cluster: u8,
    /// Number of FAT tables.
    #[allow(dead_code)]
    pub(crate) num_fats: u8,
    /// Total number of sectors on the volume.
    #[allow(dead_code)]
    pub(crate) volume_length: u64,
    /// FAT table start sector relative to partition start.
    pub(crate) fat_offset: u32,
    /// FAT table length in sectors.
    #[allow(dead_code)]
    pub(crate) fat_length: u32,
    /// Cluster heap start sector relative to partition start.
    pub(crate) cluster_heap_offset: u32,
    /// Number of data clusters in the cluster heap.
    pub(crate) cluster_count: u32,
    /// First cluster of the root directory.
    pub(crate) root_dir_cluster: u32,
    /// Volume serial number (32-bit).
    #[allow(dead_code)]
    pub(crate) volume_serial: u32,
    /// Filesystem revision (1.00 = 0x0100).
    #[allow(dead_code)]
    pub(crate) fs_revision: u16,
    /// Volume flags (dirty, media failure, etc.).
    #[allow(dead_code)]
    pub(crate) volume_flags: u16,
    /// Computed cluster size in bytes: `2^bytes_per_sector_shift *
    /// 2^sectors_per_cluster_shift`.
    pub(crate) cluster_size_bytes: u32,
}

impl ExfatBootRegion {
    /// Parse the exFAT boot region from the first 12 sectors (512 bytes each).
    pub(crate) fn parse(data: &[u8; BLOCK_SIZE * BOOT_REGION_SECTORS]) -> Result<Self> {
        // Validate boot signature.
        if data[BOOT_SIGNATURE_OFFSET] != 0x55 || data[BOOT_SIGNATURE_OFFSET + 1] != 0xAA {
            return Err(Error::InvalidArgument);
        }

        // Verify the filesystem type string "EXFAT   " at offset 3.
        let oem = &data[B_OEM_NAME..B_OEM_NAME + 8];
        if oem != b"EXFAT   " {
            return Err(Error::InvalidArgument);
        }

        // Validate the boot checksum over sectors 0–10.
        // The stored checksum lives at offset 0x1FC of sector 11 (the checksum sector).
        let cs_sector_offset = B_CHECKSUM_SECTOR * BLOCK_SIZE + B_CHECKSUM_OFFSET;
        let stored_checksum = read_u32_le(data, cs_sector_offset);
        let computed = boot_checksum(data);
        if stored_checksum != computed {
            return Err(Error::InvalidArgument);
        }

        let bytes_per_sector_shift = data[B_BYTES_PER_SECTOR_SHIFT];
        let sectors_per_cluster_shift = data[B_SECTORS_PER_CLUSTER_SHIFT];
        let num_fats = data[B_NUM_FATS];
        let volume_length = read_u64_le(data, B_VOLUME_LENGTH);
        let fat_offset = read_u32_le(data, B_FAT_OFFSET);
        let fat_length = read_u32_le(data, B_FAT_LENGTH);
        let cluster_heap_offset = read_u32_le(data, B_CLUSTER_HEAP_OFFSET);
        let cluster_count = read_u32_le(data, B_CLUSTER_COUNT);
        let root_dir_cluster = read_u32_le(data, B_ROOT_DIR_CLUSTER);
        let volume_serial = read_u32_le(data, B_VOLUME_SERIAL);
        let fs_revision = read_u16_le(data, B_FS_REVISION);
        let volume_flags = read_u16_le(data, B_VOLUME_FLAGS);

        // Sector size must be 512 for now.
        if bytes_per_sector_shift != 9 {
            // 2^9 = 512
            return Err(Error::Unsupported);
        }
        let bytes_per_sector: u16 = 1 << bytes_per_sector_shift;

        // Sanity: sectors_per_cluster must be between 0 (1 sector) and 24
        // (16 MB), powers of two.  Value stored is the shift count.
        if sectors_per_cluster_shift > 24 {
            return Err(Error::InvalidArgument);
        }
        let sectors_per_cluster: u32 = 1u32 << sectors_per_cluster_shift;
        let cluster_size_bytes = sectors_per_cluster * bytes_per_sector as u32;

        if num_fats == 0 || num_fats > 2 {
            return Err(Error::InvalidArgument);
        }
        if fat_offset == 0 || fat_length == 0 {
            return Err(Error::InvalidArgument);
        }
        if cluster_count < 2 {
            return Err(Error::InvalidArgument);
        }
        if root_dir_cluster < FIRST_DATA_CLUSTER
            || root_dir_cluster >= FIRST_DATA_CLUSTER + cluster_count
        {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster: sectors_per_cluster as u8,
            num_fats,
            volume_length,
            fat_offset,
            fat_length,
            cluster_heap_offset,
            cluster_count,
            root_dir_cluster,
            volume_serial,
            fs_revision,
            volume_flags,
            cluster_size_bytes,
        })
    }

    /// Convert a cluster number to its starting byte offset within the volume.
    #[allow(dead_code)]
    pub(crate) fn cluster_to_offset(&self, cluster: u32) -> u64 {
        let sectors_per_cluster = self.sectors_per_cluster as u64;
        let bytes_per_sector = self.bytes_per_sector as u64;
        let heap_start_sector = self.cluster_heap_offset as u64;
        let cluster_index = (cluster - FIRST_DATA_CLUSTER) as u64;
        (heap_start_sector + cluster_index * sectors_per_cluster) * bytes_per_sector
    }

    /// Convert a cluster number to its starting LBA.
    pub(crate) fn cluster_to_lba(&self, cluster: u32) -> u64 {
        let sectors_per_cluster = self.sectors_per_cluster as u64;
        let heap_start_sector = self.cluster_heap_offset as u64;
        let cluster_index = (cluster - FIRST_DATA_CLUSTER) as u64;
        heap_start_sector + cluster_index * sectors_per_cluster
    }

    /// Convert a sector offset to LBA (used for FAT reads).
    pub(crate) fn offset_to_lba(&self, sector_offset: u32) -> u64 {
        sector_offset as u64
    }
}

// ---------------------------------------------------------------------------
// Boot checksum
// ---------------------------------------------------------------------------

/// Compute the exFAT boot checksum over the first 11 sectors (sectors 0–10)
/// of the boot region.
///
/// The checksum is a simple unsigned 32-bit sum of all bytes in sectors 0–10.
/// The result is compared against the stored value at offset 0x1FC of
/// sector 11 (the checksum sector).
pub(crate) fn boot_checksum(data: &[u8; BLOCK_SIZE * BOOT_REGION_SECTORS]) -> u32 {
    let checksum_range_end = BLOCK_SIZE * B_CHECKSUM_SECTOR; // sectors 0–10
    let mut sum: u32 = 0;
    for &b in &data[..checksum_range_end] {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

// ---------------------------------------------------------------------------
// Directory entries
// ---------------------------------------------------------------------------

/// The kind of an entry and its associated metadata.
pub(crate) struct ExfatEntryType {
    /// True if this entry is a primary entry in an entry set.
    #[allow(dead_code)]
    pub(crate) is_primary: bool,
    /// True if this entry is a secondary entry.
    pub(crate) _is_secondary: bool,
    /// Entry type code (bits 0–4 of the raw EntryType byte).
    pub(crate) type_code: u8,
}

impl ExfatEntryType {
    pub(crate) fn from_byte(raw: u8) -> Self {
        let is_end = raw == EXFAT_ENTRY_EOD;
        let type_code = raw & ENTRY_TYPE_MASK;
        let _in_use = raw & ENTRY_INUSE_MASK != 0;

        // Secondary entries have bit 6 set and bits 0–4 holding the type code.
        // File name (0xC1): type code 0x01, bit 7 set → raw = 0xC1
        // Stream (0xC0): type code 0x00, bit 7 set → raw = 0xC0
        let is_secondary = raw & 0x40 != 0;

        let is_primary = !is_secondary && !is_end;

        ExfatEntryType {
            is_primary,
            _is_secondary: is_secondary,
            type_code,
        }
    }

    /// Number of secondary entries following this primary entry.
    #[allow(dead_code)]
    pub(crate) fn secondary_count(raw: u8) -> u8 {
        // Secondary count is stored in bits 4–6 of the primary entry type byte.
        // For File entries (0x85), bits 4–6 encode the count of secondary
        // entries that follow (0–3, meaning 0–3 more entries).
        // The value at bits 4–6 is (raw >> 4) & 0x07... but actually for
        // 0x85, the bits are:
        //   Bit 7: InUse
        //   Bit 6: (part of secondary count or 0)
        //   Bit 5: (part of secondary count or 0)
        //   Bit 4: (part of secondary count or 0)
        //   Bits 0–3: type code (0x5 for file)
        //
        // However, looking at how exFAT works:
        //   SecondaryCount is always determined by walking entries until the
        //   next primary entry or EOD.  The secondary count field in the entry
        //   type byte is not always reliable.
        //
        // We parse secondary count by scanning ahead instead.
        let _ = raw;
        0
    }
}

/// A decoded exFAT directory entry representing a file or directory.
#[derive(Debug, Clone)]

pub(crate) struct ExfatDirEntry {
    pub(crate) name: String,
    pub(crate) kind: NodeKind,
    /// First cluster of the data stream (0 for empty files).
    pub(crate) first_cluster: u32,
    /// Valid data length in bytes (may be less than allocated).
    pub(crate) valid_data_length: u64,
    /// Allocated data length in bytes.
    #[allow(dead_code)]
    pub(crate) data_length: u64,
    /// When true, the file is stored in one contiguous run (no FAT chain).
    pub(crate) no_fat_chain: bool,
    /// Create timestamp (Unix epoch seconds) — parsed from exFAT file entry.
    pub(crate) created: u64,
    /// Last-modified timestamp (Unix epoch seconds).
    pub(crate) modified: u64,
    /// Last-access timestamp (Unix epoch seconds).
    pub(crate) accessed: u64,
}

/// Convert an exFAT DOS timestamp (u32, low u16 = time, high u16 = date) to
/// Unix epoch seconds.  Uses the same DOS date/time bitfield format as FAT32.
///
/// Returns 0 when the timestamp word is 0 (unset).
pub(crate) fn dos_timestamp_to_unix(ts: u32) -> u64 {
    if ts == 0 {
        return 0;
    }
    let time = (ts & 0xFFFF) as u16;
    let date = ((ts >> 16) & 0xFFFF) as u16;
    super::super::fat32::types::dos_datetime_to_unix(date, time)
}

// ---------------------------------------------------------------------------
// Internal exFAT filesystem state
// ---------------------------------------------------------------------------

pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let lo = read_u32_le(data, offset) as u64;
    let hi = read_u32_le(data, offset + 4) as u64;
    lo | (hi << 32)
}

pub(crate) fn write_u16_le(data: &mut [u8], offset: usize, val: u16) {
    if offset + 2 <= data.len() {
        let bytes = val.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
    }
}

pub(crate) fn write_u32_le(data: &mut [u8], offset: usize, val: u32) {
    if offset + 4 <= data.len() {
        let bytes = val.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
        data[offset + 2] = bytes[2];
        data[offset + 3] = bytes[3];
    }
}

#[allow(dead_code)]
pub(crate) fn write_u64_le(data: &mut [u8], offset: usize, val: u64) {
    write_u32_le(data, offset, val as u32);
    write_u32_le(data, offset + 4, (val >> 32) as u32);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
