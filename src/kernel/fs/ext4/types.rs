//! src/kernel/fs/ext4/types.rs
//!
//! ext2/ext4 on-disk structures, in-memory helpers, and serialisation
//! functions.
//!
//! All multi-byte fields are little-endian.  Field offsets follow the
//! standard ext4 layout (128-byte base inode, 256-byte extension fields
//! at offsets `0x6A`/`0x6C` when `inode_size >= 256`).

use alloc::string::String;

use crate::kernel::fs::vfs::NodeKind;

use super::constants::*;

// ─── Ext4 inode ─────────────────────────────────────────────────────────

/// Parsed ext2/ext4 inode.  The 256-byte extension fields (`size_high`,
/// `block_high`) are zero when the volume uses 128-byte inodes.
#[derive(Debug, Clone)]
pub(crate) struct Ext4Inode {
    pub(crate) mode: u16,
    pub(crate) uid: u16,
    pub(crate) size_low: u32,
    pub(crate) atime: u32,
    pub(crate) ctime: u32,
    pub(crate) mtime: u32,
    pub(crate) gid: u16,
    pub(crate) links_count: u16,
    pub(crate) block: [u32; EXT4_TIND_BLOCK + 1],
    pub(crate) uid_high: u16,
    pub(crate) gid_high: u16,
    pub(crate) flags: u32,
    pub(crate) size_high: u32,
    pub(crate) block_high: [u16; EXT4_TIND_BLOCK + 1],
}

impl Ext4Inode {
    /// Return the [`NodeKind`] derived from `mode`.
    pub(crate) fn kind(&self) -> NodeKind {
        match self.mode & EXT4_S_IFMT {
            EXT4_S_IFDIR => NodeKind::Directory,
            EXT4_S_IFREG => NodeKind::File,
            EXT4_S_IFCHR | EXT4_S_IFBLK => NodeKind::Device,
            EXT4_S_IFLNK => NodeKind::Symlink,
            _ => NodeKind::File,
        }
    }

    /// File size in bytes (48-bit field split across `size_low`/`size_high`).
    pub(crate) fn file_size(&self) -> u64 {
        ((self.size_high as u64) << 32) | self.size_low as u64
    }

    /// Effective owner uid (32-bit field split across `uid`/`uid_high`).
    pub(crate) fn owner_uid(&self) -> u32 {
        ((self.uid_high as u32) << 16) | self.uid as u32
    }

    /// Effective owner gid (32-bit field split across `gid`/`gid_high`).
    pub(crate) fn owner_gid(&self) -> u32 {
        ((self.gid_high as u32) << 16) | self.gid as u32
    }

    /// Permission bits only (lower 12 bits of `mode`).
    pub(crate) fn permission_mode(&self) -> u16 {
        self.mode & 0o777
    }

    /// True when the inode uses the extent tree format.
    pub(crate) fn has_extents(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL != 0
    }

    /// True when the directory has the casefold (case-insensitive) flag set.
    pub(crate) fn has_casefold(&self) -> bool {
        self.flags & EXT4_CASEFOLD_FL != 0
    }

    /// 48-bit physical block address at index `idx`, combining the
    /// high/low halves stored in the inode.
    pub(crate) fn block_48(&self, idx: usize) -> u64 {
        ((self.block_high[idx] as u64) << 32) | self.block[idx] as u64
    }
}

// ─── Ext4 superblock ────────────────────────────────────────────────────

/// Parsed ext2/ext4 superblock (subset of fields the driver uses).
#[derive(Debug, Clone)]
pub(crate) struct Ext4Superblock {
    pub(crate) inodes_count: u32,
    pub(crate) blocks_count: u32,
    // On-disk wire-format fields: parsed from the superblock and kept for
    // layout completeness.  No statfs consumer exists yet, so they are
    // currently dead code.
    #[allow(dead_code)]
    pub(crate) free_blocks_count: u32,
    #[allow(dead_code)]
    pub(crate) free_inodes_count: u32,
    pub(crate) log_block_size: u32,
    pub(crate) blocks_per_group: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) magic: u16,
    pub(crate) rev_level: u32,
    pub(crate) inode_size: u16,
    pub(crate) feature_compat: u32,
    pub(crate) feature_incompat: u32,
}

impl Ext4Superblock {
    /// Block size in bytes (`1024 << log_block_size`).
    pub(crate) fn block_size(&self) -> usize {
        (1024usize) << self.log_block_size
    }

    /// Number of block groups.
    pub(crate) fn block_group_count(&self) -> u32 {
        self.blocks_count.div_ceil(self.blocks_per_group)
    }

    /// Block group that owns `ino` (ino is 1-based).
    pub(crate) fn group_of_ino(&self, ino: u32) -> u32 {
        (ino - 1) / self.inodes_per_group
    }

    /// Index of `ino` within its block group.
    pub(crate) fn inode_index_in_group(&self, ino: u32) -> u32 {
        (ino - 1) % self.inodes_per_group
    }

    /// True when the volume has the extents incompat feature enabled.
    pub(crate) fn has_extents(&self) -> bool {
        self.feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS != 0
    }
}

// ─── Block group descriptor ─────────────────────────────────────────────

/// Parsed block-group descriptor.
#[derive(Debug, Clone)]
pub(crate) struct Ext4BgDescriptor {
    pub(crate) bg_block_bitmap: u32,
    pub(crate) bg_inode_bitmap: u32,
    pub(crate) bg_inode_table: u32,
    pub(crate) bg_free_blocks_count: u16,
    pub(crate) bg_free_inodes_count: u16,
    pub(crate) bg_used_dirs_count: u16,
}

// ─── Extent tree ────────────────────────────────────────────────────────

/// On-disk extent-tree node header (12 bytes).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ext4ExtentHeader {
    pub(crate) eh_magic: u16,
    pub(crate) eh_entries: u16,
    pub(crate) eh_max: u16,
    pub(crate) eh_depth: u16,
    pub(crate) eh_generation: u32,
}

/// On-disk extent entry (12 bytes), stored in leaf nodes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ext4Extent {
    pub(crate) ee_block: u32,
    pub(crate) ee_len: u16,
    pub(crate) ee_start_hi: u16,
    pub(crate) ee_start_lo: u32,
}

impl Ext4Extent {
    /// Number of contiguous blocks in this extent.
    pub(crate) fn len(&self) -> u16 {
        self.ee_len
    }

    /// 48-bit physical start block.
    pub(crate) fn start_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | self.ee_start_lo as u64
    }
}

/// On-disk extent-tree index entry (12 bytes), stored in internal nodes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ext4ExtentIdx {
    pub(crate) ei_block: u32,
    ei_leaf_lo: u32,
    ei_leaf_hi: u16,
    _ei_unused: u16,
}

impl Ext4ExtentIdx {
    /// 48-bit child-node block address.
    pub(crate) fn leaf_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | self.ei_leaf_lo as u64
    }
}

// ─── Directory entries ──────────────────────────────────────────────────

pub(crate) struct Ext4DirEntry {
    pub(crate) inode: u32,
    pub(crate) name: String,
    pub(crate) file_type: u8,
}

// ─── Inode serialisation ────────────────────────────────────────────────

/// Parse a raw inode (128- or 256-byte) into an [`Ext4Inode`].
pub(crate) fn read_ext4_inode(raw: &[u8], inode_size: u16) -> Ext4Inode {
    let mode = u16::from_le_bytes([raw[0], raw[1]]);
    let uid = u16::from_le_bytes([raw[2], raw[3]]);
    let size_low = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let atime = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let ctime = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let mtime = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
    let gid = u16::from_le_bytes([raw[24], raw[25]]);
    let links_count = u16::from_le_bytes([raw[26], raw[27]]);
    let flags = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);

    let mut block = [0_u32; EXT4_TIND_BLOCK + 1];
    for (i, item) in block.iter_mut().enumerate() {
        let off = 40 + i * 4;
        *item = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    }

    let osd2_start = 40 + (EXT4_TIND_BLOCK + 1) * 4;
    let uid_high = u16::from_le_bytes([raw[osd2_start + 4], raw[osd2_start + 5]]);
    let gid_high = u16::from_le_bytes([raw[osd2_start + 6], raw[osd2_start + 7]]);

    // 256-byte inode extension fields (zero for 128-byte inodes).
    let (size_high, block_high) = if inode_size >= 256 {
        // i_size_hi at raw offset 0x6C; i_block_hi starts at 0x6A.
        let size_high = u32::from_le_bytes([raw[0x6C], raw[0x6D], raw[0x6E], raw[0x6F]]);
        let mut block_high = [0_u16; EXT4_TIND_BLOCK + 1];
        for (i, item) in block_high.iter_mut().enumerate().take(EXT4_TIND_BLOCK + 1) {
            let off = 0x6A + i * 2;
            *item = u16::from_le_bytes([raw[off], raw[off + 1]]);
        }
        (size_high, block_high)
    } else {
        (0, [0_u16; EXT4_TIND_BLOCK + 1])
    };

    Ext4Inode {
        mode,
        uid,
        size_low,
        atime,
        ctime,
        mtime,
        gid,
        links_count,
        block,
        uid_high,
        gid_high,
        flags,
        size_high,
        block_high,
    }
}

/// Serialise the first 60 bytes of `i_block` (the extent tree root) into a
/// fixed-size buffer.
pub(crate) fn inode_block_bytes(inode: &Ext4Inode) -> [u8; 60] {
    let mut out = [0_u8; 60];
    for (i, word) in inode.block.iter().enumerate().take(15) {
        let off = i * 4;
        out[off..off + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Write the extent tree root stored in `i_block[0..60]` back into the inode.
pub(crate) fn write_inode_block_bytes(inode: &mut Ext4Inode, bytes: &[u8; 60]) {
    for i in 0..15 {
        let off = i * 4;
        inode.block[i] =
            u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
}

// ─── Extent-tree node parsing / writing ────────────────────────────────

/// Parse a 12-byte extent-tree node header.
pub(crate) fn parse_extent_header(raw: &[u8]) -> Ext4ExtentHeader {
    Ext4ExtentHeader {
        eh_magic: u16::from_le_bytes([raw[0], raw[1]]),
        eh_entries: u16::from_le_bytes([raw[2], raw[3]]),
        eh_max: u16::from_le_bytes([raw[4], raw[5]]),
        eh_depth: u16::from_le_bytes([raw[6], raw[7]]),
        eh_generation: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
    }
}

/// Parse a 12-byte extent entry.
pub(crate) fn parse_extent(raw: &[u8]) -> Ext4Extent {
    Ext4Extent {
        ee_block: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ee_len: u16::from_le_bytes([raw[4], raw[5]]),
        ee_start_hi: u16::from_le_bytes([raw[6], raw[7]]),
        ee_start_lo: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
    }
}

/// Parse a 12-byte extent-tree index entry.
pub(crate) fn parse_extent_idx(raw: &[u8]) -> Ext4ExtentIdx {
    Ext4ExtentIdx {
        ei_block: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ei_leaf_lo: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        ei_leaf_hi: u16::from_le_bytes([raw[8], raw[9]]),
        _ei_unused: u16::from_le_bytes([raw[10], raw[11]]),
    }
}

/// Serialise an extent-tree header into 12 bytes.
pub(crate) fn write_extent_header(raw: &mut [u8], header: &Ext4ExtentHeader) {
    raw[0..2].copy_from_slice(&header.eh_magic.to_le_bytes());
    raw[2..4].copy_from_slice(&header.eh_entries.to_le_bytes());
    raw[4..6].copy_from_slice(&header.eh_max.to_le_bytes());
    raw[6..8].copy_from_slice(&header.eh_depth.to_le_bytes());
    raw[8..12].copy_from_slice(&header.eh_generation.to_le_bytes());
}

/// Serialise an extent entry into 12 bytes.
pub(crate) fn write_extent(raw: &mut [u8], ext: &Ext4Extent) {
    raw[0..4].copy_from_slice(&ext.ee_block.to_le_bytes());
    raw[4..6].copy_from_slice(&ext.ee_len.to_le_bytes());
    raw[6..8].copy_from_slice(&ext.ee_start_hi.to_le_bytes());
    raw[8..12].copy_from_slice(&ext.ee_start_lo.to_le_bytes());
}
