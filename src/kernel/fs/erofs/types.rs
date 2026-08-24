//! src/kernel/fs/erofs/types.rs
//!
//! EROFS on-disk structures and parsers.
//! On-disk data structures for EROFS (Enhanced Read-Only File System).
//!
//! Reference: EROFS was developed by Huawei; the layout described here
//! follows the upstream Linux implementation (≥ 4.19).
//!
//! All multi-byte fields are little-endian unless noted otherwise.

// ── Constants ──────────────────────────────────────────────────────────

/// EROFS magic number ("\xE2\xF5\xE1\xE0" stored little-endian).
pub const EROFS_MAGIC: u32 = 0xE0F5E1E2;

/// Offset (in bytes) of the superblock from the start of the device.
/// On a standard 4-KiB-block device the superblock lives at LBA 0,
/// offset 1024.
pub const EROFS_SUPERBLOCK_OFFSET: u64 = 1024;

/// Size of the on-disk superblock structure (128 bytes used).
pub const EROFS_SUPERBLOCK_SIZE: usize = 128;

/// Size of a compact inode (32 bytes).
pub const EROFS_COMPACT_INODE_SIZE: usize = 32;

// Inode format field masks:
//   i_format[15]: inline   — data is stored inside the inode itself
//   i_format[14]: extent   — data uses an extent list
//   i_format[13]: compress — data is compressed
//   i_format[11:0] → remaining bits for the actual layout variant

/// Inode mode constants (same values as ext2/ext3).
pub const EROFS_S_IFMT: u16 = 0o170000;
pub const EROFS_S_IFDIR: u16 = 0o040000;
pub const EROFS_S_IFREG: u16 = 0o100000;
pub const EROFS_S_IFLNK: u16 = 0o120000;
pub const EROFS_S_IFCHR: u16 = 0o020000;
pub const EROFS_S_IFBLK: u16 = 0o060000;

/// Directory-entry file-type codes (same as ext2/ext3).
pub const EROFS_FT_REG_FILE: u8 = 1;
pub const EROFS_FT_DIR: u8 = 2;
pub const EROFS_FT_CHRDEV: u8 = 3;
pub const EROFS_FT_BLKDEV: u8 = 4;
pub const EROFS_FT_SYMLINK: u8 = 7;

/// Feature flag: device supports the `NID` lookup table.
pub const EROFS_FEATURE_INCOMPAT_NID_TABLE: u32 = 1 << 2;
/// Feature flag: device uses data mapping in `i_frags` (chunk index).
pub const EROFS_FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 1 << 5;

// ── On-disk Superblock ─────────────────────────────────────────────────

/// EROFS superblock, always at byte offset 1024 of the device.
///
/// The structure is packed with `repr(C)` so it maps directly to the
/// on-disk layout.
#[derive(Debug, Clone)]
#[repr(C)]
pub(crate) struct ErofsSuperblock {
    /// Magic number: `0xE0F5E1E2` (EROFS_MAGIC).
    pub magic: u32,
    /// CRC32 checksum of the superblock (excluding `checksum` itself).
    pub checksum: u32,
    /// Compatible feature flags.
    pub feature_compat: u32,
    /// Block size = 2 ^ blkszbits (most commonly 12 → 4096).
    pub blkszbits: u8,
    /// Reserved (originally used for extra slots in multi-device setups).
    pub extslots: u8,
    /// NID of the root inode (16-bit).
    pub root_nid: u16,
    /// Total number of inodes in the volume.
    pub inos: u64,
    /// Build time (seconds since UNIX epoch).
    pub build_time: u64,
    /// Build-time nanoseconds.
    pub build_time_nsec: u32,
    /// Total number of blocks in the filesystem.
    pub blocks: u32,
    /// Start block address of the metadata area (inode table).
    pub meta_blkaddr: u32,
    /// Start block address of the shared xattr area.
    pub xattr_blkaddr: u32,
    /// 128-bit UUID.
    pub uuid: [u8; 16],
    /// Volume name (may not be NUL-terminated if exactly 16 bytes).
    pub volume_name: [u8; 16],
    /// Incompatible feature flags.
    pub feature_incompat: u32,
}

// Safety: the superblock is read from a byte buffer.
unsafe impl Send for ErofsSuperblock {}
unsafe impl Sync for ErofsSuperblock {}

impl ErofsSuperblock {
    /// Parse a superblock from a raw byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < EROFS_SUPERBLOCK_SIZE {
            return None;
        }

        let magic = u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]);
        if magic != EROFS_MAGIC {
            return None;
        }

        // Reject feature combinations we don't support yet.
        let feature_incompat = u32::from_le_bytes([data[0x50], data[0x51], data[0x52], data[0x53]]);

        // We require the NID table for inode lookup and reject chunked files.
        if feature_incompat & EROFS_FEATURE_INCOMPAT_NID_TABLE == 0 {
            return None;
        }
        if feature_incompat & EROFS_FEATURE_INCOMPAT_CHUNKED_FILE != 0 {
            return None;
        }

        let sb = ErofsSuperblock {
            magic,
            checksum: u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]),
            feature_compat: u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]),
            blkszbits: data[0x0C],
            extslots: data[0x0D],
            root_nid: u16::from_le_bytes([data[0x0E], data[0x0F]]),
            inos: u64::from_le_bytes([
                data[0x10], data[0x11], data[0x12], data[0x13], data[0x14], data[0x15], data[0x16],
                data[0x17],
            ]),
            build_time: u64::from_le_bytes([
                data[0x18], data[0x19], data[0x1A], data[0x1B], data[0x1C], data[0x1D], data[0x1E],
                data[0x1F],
            ]),
            build_time_nsec: u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]),
            blocks: u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]),
            meta_blkaddr: u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]),
            xattr_blkaddr: u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]),
            uuid: data[0x30..0x40].try_into().unwrap_or([0u8; 16]),
            volume_name: data[0x40..0x50].try_into().unwrap_or([0u8; 16]),
            feature_incompat,
        };

        Some(sb)
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> usize {
        1usize << self.blkszbits
    }

    /// Check whether the underlying block size matches expectations.
    pub fn validate_block_size(&self) -> bool {
        self.blkszbits >= 9 && self.blkszbits <= 16
    }

    /// Validate that root NID is within bounds.
    pub fn validate_root_nid(&self) -> bool {
        self.root_nid > 0 && (self.root_nid as u64) < self.inos
    }
}

// ── On-disk Inode (compact, 32-byte) ───────────────────────────────────

/// Compact EROFS inode (32 bytes).
///
/// The `i_format` field encodes both the file type (`i_mode & S_IFMT`)
/// and the data-layout hints (plain, inline, extent, compressed).
#[derive(Debug, Clone)]
pub(crate) struct ErofsInodeCompact {
    pub i_format: u16,
    pub i_size: u32,
    /// Format-specific union data (16 bytes).
    pub i_u: [u32; 4],
}

impl ErofsInodeCompact {
    /// Parse a compact inode from 32 bytes at `offset` within `block`.
    pub fn parse(data: &[u8]) -> Self {
        ErofsInodeCompact {
            i_format: u16::from_le_bytes([data[0x00], data[0x01]]),
            i_size: u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]),
            i_u: [
                u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]),
                u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]),
                u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]),
                u32::from_le_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]),
            ],
        }
    }

    /// Return the full `i_format` field which encodes both the file type
    /// (bits 15:12, using the standard S_IFMT values) and the permission
    /// bits (bits 11:0).
    pub fn mode(&self) -> u16 {
        self.i_format
    }

    /// Return just the permission bits (lower 12 bits of `i_format`).
    pub fn perm(&self) -> u16 {
        self.i_format & 0x0FFF
    }

    /// Number of direct block pointers stored in `i_u`.
    /// For flat plain inodes this is 4 (u32 × 4 = 16 bytes).
    pub fn direct_block_count(&self) -> usize {
        4
    }

    /// Read a direct block address from `i_u[slot]`.
    pub fn direct_block(&self, slot: usize) -> Option<u32> {
        if slot < 4 {
            let blk = self.i_u[slot];
            if blk != 0 {
                Some(blk)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Convert a file-type code to [`super::super::vfs::NodeKind`].
pub(crate) fn erofs_ft_to_kind(ft: u8) -> crate::kernel::fs::vfs::NodeKind {
    match ft {
        EROFS_FT_DIR => crate::kernel::fs::vfs::NodeKind::Directory,
        EROFS_FT_REG_FILE => crate::kernel::fs::vfs::NodeKind::File,
        EROFS_FT_SYMLINK => crate::kernel::fs::vfs::NodeKind::Symlink,
        EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => crate::kernel::fs::vfs::NodeKind::Device,
        _ => crate::kernel::fs::vfs::NodeKind::File,
    }
}

/// Convert a POSIX mode to [`super::super::vfs::NodeKind`].
pub(crate) fn erofs_mode_to_kind(mode: u16) -> crate::kernel::fs::vfs::NodeKind {
    match mode & EROFS_S_IFMT {
        EROFS_S_IFDIR => crate::kernel::fs::vfs::NodeKind::Directory,
        EROFS_S_IFREG => crate::kernel::fs::vfs::NodeKind::File,
        EROFS_S_IFLNK => crate::kernel::fs::vfs::NodeKind::Symlink,
        EROFS_S_IFCHR | EROFS_S_IFBLK => crate::kernel::fs::vfs::NodeKind::Device,
        _ => crate::kernel::fs::vfs::NodeKind::File,
    }
}

impl ErofsSuperblock {
    /// Derive the inode size from the superblock.
    /// EROFS uses compact (32 B) inodes when `blkszbits == 12` and
    /// extended (64 B) inodes otherwise; this can be overridden by
    /// `feature_incompat` bits but for simplicity we derive it from
    /// block-size.
    pub fn inode_size(&self) -> usize {
        // The upstream EROFS inode size is typically 32 for 4K blocks.
        // We hard-code 32 bytes here; extend later if 64-byte inodes
        // are needed.
        EROFS_COMPACT_INODE_SIZE
    }

    /// Compute the block address and byte offset for a given NID.
    /// Returns `(blkaddr, offset_within_block)`.
    pub fn nid_to_location(&self, nid: u32) -> (u32, usize) {
        let inode_bytes = (nid as u64) * (self.inode_size() as u64);
        let block_size = self.block_size() as u64;
        let blkaddr = self.meta_blkaddr as u64 + inode_bytes / block_size;
        let offset = (inode_bytes % block_size) as usize;
        (blkaddr as u32, offset)
    }
}

// ── On-disk Directory Entry ────────────────────────────────────────────

/// An EROFS directory entry (like ext2 `ext2_dir_entry_2`).
///
/// EROFS directory blocks are a linear sequence of variable-length entries.
#[derive(Debug, Clone)]
pub(crate) struct ErofsDirEntry {
    /// Inode number (NID) of this entry.
    pub nid: u64,
    /// Name of this entry (not NUL-terminated).
    pub name: alloc::string::String,
    /// File type code (EROFS_FT_*).
    pub file_type: u8,
}

/// Parse directory entries from a raw block buffer.
///
/// EROFS directory entries consist of 12-byte headers followed by
/// names packed at the tail of the block.  Names are NOT
/// NUL-terminated — each name extends from its `name_off` to the
/// start of the adjacent name (or to the end of the block for the
/// name closest to the block tail).
///
/// Returns entries in header order (not name order).
pub(crate) fn parse_erofs_dir_entries(
    data: &[u8],
    block_size: usize,
) -> alloc::vec::Vec<ErofsDirEntry> {
    let mut raw_entries: alloc::vec::Vec<(usize, u64, u8)> = alloc::vec::Vec::new();
    let mut offset = 0usize;

    // First pass: collect all entry headers.
    while offset + 12 <= data.len() && offset < block_size {
        let nid = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let name_off = u16::from_le_bytes([data[offset + 8], data[offset + 9]]) as usize;
        let file_type = u16::from_le_bytes([data[offset + 10], data[offset + 11]]) as u8;

        offset += 12;

        if nid == 0 || name_off >= block_size {
            continue;
        }

        raw_entries.push((name_off, nid, file_type));
    }

    // Sort name_offs in ascending order so we know where each name
    // ends: it's the start of the next-largest name_off.
    let mut sorted_offs: alloc::vec::Vec<usize> =
        raw_entries.iter().map(|(off, _, _)| *off).collect();
    sorted_offs.sort();
    sorted_offs.dedup();
    sorted_offs.push(block_size); // sentinel — end of last name

    let mut entries = alloc::vec::Vec::new();
    for (name_off, nid, file_type) in &raw_entries {
        // Find the end of this name.
        let name_end = sorted_offs
            .iter()
            .find(|&&off| off > *name_off)
            .copied()
            .unwrap_or(block_size);

        let name_bytes = &data[*name_off..name_end.min(data.len())];
        let name = match alloc::string::String::from_utf8(name_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        entries.push(ErofsDirEntry {
            nid: *nid,
            name,
            file_type: *file_type,
        });
    }

    entries
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal valid superblock in a buffer and parse it back.
    #[test]
    fn parse_minimal_superblock() {
        let mut buf = vec![0u8; 4096];
        let sb_off = EROFS_SUPERBLOCK_OFFSET as usize;

        // Magic
        buf[sb_off..sb_off + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        // blkszbits = 12 (4096)
        buf[sb_off + 0x0C] = 12;
        // root_nid = 2 (non-zero)
        buf[sb_off + 0x0E..sb_off + 0x10].copy_from_slice(&2u16.to_le_bytes());
        // inos = 100
        buf[sb_off + 0x10..sb_off + 0x18].copy_from_slice(&100u64.to_le_bytes());
        // blocks = 1024
        buf[sb_off + 0x24..sb_off + 0x28].copy_from_slice(&1024u32.to_le_bytes());
        // meta_blkaddr = 64
        buf[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&64u32.to_le_bytes());
        // Feature INCOMPAT with NID_TABLE set
        buf[sb_off + 0x50..sb_off + 0x54]
            .copy_from_slice(&EROFS_FEATURE_INCOMPAT_NID_TABLE.to_le_bytes());

        let sb = ErofsSuperblock::parse(&buf[sb_off..]).expect("valid superblock");
        assert_eq!(sb.magic, EROFS_MAGIC);
        assert_eq!(sb.blkszbits, 12);
        assert_eq!(sb.root_nid, 2);
        assert_eq!(sb.block_size(), 4096);
        assert_eq!(sb.meta_blkaddr, 64);
        assert!(sb.validate_root_nid());
    }

    #[test]
    fn parse_superblock_rejects_wrong_magic() {
        let mut buf = vec![0u8; 128];
        buf[0x50..0x54].copy_from_slice(&EROFS_FEATURE_INCOMPAT_NID_TABLE.to_le_bytes());
        // Wrong magic
        buf[0x00..0x04].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(ErofsSuperblock::parse(&buf).is_none());
    }

    #[test]
    fn parse_superblock_rejects_missing_nid_table() {
        let mut buf = vec![0u8; 128];
        buf[0x00..0x04].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        // No NID_TABLE feature flag
        buf[0x50..0x54].copy_from_slice(&0u32.to_le_bytes());
        assert!(ErofsSuperblock::parse(&buf).is_none());
    }

    #[test]
    fn nid_to_location_correct() {
        let mut buf = vec![0u8; 128];
        buf[0x00..0x04].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        buf[0x0C] = 12; // 4K blocks
        buf[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&100u64.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&64u32.to_le_bytes()); // meta at block 64
        buf[0x50..0x54].copy_from_slice(&EROFS_FEATURE_INCOMPAT_NID_TABLE.to_le_bytes());

        let sb = ErofsSuperblock::parse(&buf).expect("valid");
        // NID 0 → block 64, offset 0
        let (blk, off) = sb.nid_to_location(0);
        assert_eq!(blk, 64);
        assert_eq!(off, 0);

        // NID 1 → block 64, offset 32
        let (blk, off) = sb.nid_to_location(1);
        assert_eq!(blk, 64);
        assert_eq!(off, 32);

        // NID 128 → block 65, offset 0 (128 * 32 = 4096 = 1 block)
        let (blk, off) = sb.nid_to_location(128);
        assert_eq!(blk, 65);
        assert_eq!(off, 0);
    }
}
