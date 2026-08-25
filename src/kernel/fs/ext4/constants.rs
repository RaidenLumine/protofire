//! src/kernel/fs/ext4/constants.rs
//!
//! ext4 on-disk constants and feature flags.

// ─── ext4 on-disk constants ────────────────────────────────────────────────

pub(crate) const EXT4_MAGIC: u16 = 0xEF53;
pub(crate) const SUPERBLOCK_BYTE_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
pub(crate) const EXT4_GOOD_OLD_INODE_SIZE: usize = 128;

pub(crate) const EXT4_ROOT_INO: u32 = 2;
pub(crate) const EXT4_NDIR_BLOCKS: usize = 12;
pub(crate) const EXT4_IND_BLOCK: usize = 12;
pub(crate) const EXT4_DIND_BLOCK: usize = 13;
pub(crate) const EXT4_TIND_BLOCK: usize = 14;

pub(crate) const EXT4_FT_REG_FILE: u8 = 1;
pub(crate) const EXT4_FT_DIR: u8 = 2;
pub(crate) const EXT4_FT_CHRDEV: u8 = 3;
pub(crate) const EXT4_FT_BLKDEV: u8 = 4;
pub(crate) const EXT4_FT_SYMLINK: u8 = 7;

pub(crate) const EXT4_S_IFMT: u16 = 0xF000;
pub(crate) const EXT4_S_IFREG: u16 = 0x8000;
pub(crate) const EXT4_S_IFDIR: u16 = 0x4000;
pub(crate) const EXT4_S_IFCHR: u16 = 0x2000;
pub(crate) const EXT4_S_IFBLK: u16 = 0x6000;
pub(crate) const EXT4_S_IFLNK: u16 = 0xA000;

pub(crate) const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
#[allow(dead_code)] // used in tests; not visible to non-test compilation
pub(crate) const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;

// ext4-specific feature flags
pub(crate) const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub(crate) const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub(crate) const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub(crate) const EXT4_FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

/// Incompat features this driver can safely handle.
pub(crate) const EXT4_FEATURE_INCOMPAT_SUPPORTED: u32 = EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_CASEFOLD;

/// EXT4_EXTENTS_FL — set in `inode.flags` when the inode uses extent-based
/// block mapping.
pub(crate) const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// EXT4_CASEFOLD_FL — set in `inode.flags` when a directory is
/// case-insensitive.
pub(crate) const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;

/// Extent tree magic value, stored in Ext4ExtentHeader.eh_magic.
/// Feature flag: filesystem has a journal.
pub(crate) const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;

/// Reserved inode number for the journal.
pub(crate) const EXT4_JOURNAL_INO: u32 = 8;
pub(crate) const EXT4_EXT_MAGIC: u16 = 0xF30A;

pub(crate) fn ptrs_per_block(block_size: usize) -> usize {
    block_size / 4
}
