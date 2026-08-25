//! src/kernel/fs/f2fs/constants.rs
//!
//! F2FS layout and inode field constants.

// ─── Inode field offsets (custom simplified layout, contiguous) ────────

/// Offset of `i_mode` within the inode block (u16).
pub(crate) const F2FS_INODE_MODE_OFF: usize = 0;
/// Offset of `i_uid` within the inode block (u32).
pub(crate) const F2FS_INODE_UID_OFF: usize = 4;
/// Offset of `i_gid` within the inode block (u32).
pub(crate) const F2FS_INODE_GID_OFF: usize = 8;
/// Offset of `i_links` within the inode block (u32).
pub(crate) const F2FS_INODE_LINKS_OFF: usize = 12;
/// Offset of `i_size` within the inode block (u64).
pub(crate) const F2FS_INODE_SIZE_OFF: usize = 16;
/// Offset of `i_blocks` within the inode block (u64, 512-byte sectors).
pub(crate) const F2FS_INODE_BLOCKS_OFF: usize = 24;
/// Offset of `i_atime` within the inode block (u64 seconds).
pub(crate) const F2FS_INODE_ATIME_OFF: usize = 32;
/// Offset of `i_ctime` within the inode block (u64 seconds).
pub(crate) const F2FS_INODE_CTIME_OFF: usize = 40;
/// Offset of `i_mtime` within the inode block (u64 seconds).
pub(crate) const F2FS_INODE_MTIME_OFF: usize = 48;
/// Offset of `i_atime_nsec` within the inode block (u32).
pub(crate) const F2FS_INODE_ATIME_NSEC_OFF: usize = 56;
/// Offset of `i_ctime_nsec` within the inode block.
pub(crate) const F2FS_INODE_CTIME_NSEC_OFF: usize = 60;
/// Offset of `i_mtime_nsec` within the inode block.
pub(crate) const F2FS_INODE_MTIME_NSEC_OFF: usize = 64;
/// Offset of `i_current_depth` within the inode block.
#[allow(dead_code)]
pub(crate) const F2FS_INODE_CURRENT_DEPTH_OFF: usize = 68;
/// Offset of `i_xattr_nid` within the inode block.
pub(crate) const F2FS_INODE_XATTR_NID_OFF: usize = 72;
/// Offset of `i_flags` within the inode block.
pub(crate) const F2FS_INODE_FLAGS_OFF: usize = 76;
/// Start of the `i_addr` block pointer array.
pub(crate) const F2FS_INODE_ADDR_OFF: usize = 80;

// ─── Inode file-type / mode mask constants ────────────────────────────

pub(crate) const F2FS_S_IFMT: u16 = 0xF000;
pub(crate) const F2FS_S_IFREG: u16 = 0x8000;
pub(crate) const F2FS_S_IFDIR: u16 = 0x4000;
pub(crate) const F2FS_S_IFCHR: u16 = 0x2000;
pub(crate) const F2FS_S_IFBLK: u16 = 0x6000;
pub(crate) const F2FS_S_IFLNK: u16 = 0xA000;

// ─── Directory-entry file-type codes ──────────────────────────────────

pub(crate) const F2FS_FT_REG_FILE: u8 = 1;
pub(crate) const F2FS_FT_DIR: u8 = 2;
pub(crate) const F2FS_FT_CHRDEV: u8 = 3;
pub(crate) const F2FS_FT_BLKDEV: u8 = 4;
pub(crate) const F2FS_FT_SYMLINK: u8 = 7;

// ─── Extended attribute constants ────────────────────────────────────────

/// Minimum size per xattr entry (name_len = 0, padded to 4 bytes).
#[allow(dead_code)]
pub(crate) const F2FS_XATTR_ENTRY_MIN_SIZE: usize = 4;
/// Xattr name index for the "user." namespace prefix.
#[allow(dead_code)]
pub(crate) const F2FS_XATTR_INDEX_USER: u8 = 1;

// ─── Superblock field offsets ─────────────────────────────────────────
//
// These match the Linux F2FS superblock layout (little-endian) up to
// `F2FS_SB_META_INO_OFF`; the trailing custom fields (`cp_payload` onward)
// use a contiguous packed layout that is written and read by this driver's
// own `parse_f2fs_superblock` / `write_f2fs_superblock` helpers.

/// Superblock magic value (`F2FS_SUPER_MAGIC`).
pub(crate) const F2FS_MAGIC: u32 = 0xF2F5_2010;

pub(crate) const F2FS_SB_MAGIC_OFF: usize = 0;
pub(crate) const F2FS_SB_MAJOR_VER_OFF: usize = 4;
pub(crate) const F2FS_SB_MINOR_VER_OFF: usize = 6;
pub(crate) const F2FS_SB_LOG_SECTORSIZE_OFF: usize = 8;
pub(crate) const F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF: usize = 12;
pub(crate) const F2FS_SB_LOG_BLOCKSIZE_OFF: usize = 16;
pub(crate) const F2FS_SB_LOG_BLOCKS_PER_SEG_OFF: usize = 20;
pub(crate) const F2FS_SB_SEGS_PER_SEC_OFF: usize = 24;
pub(crate) const F2FS_SB_SECS_PER_ZONE_OFF: usize = 28;
pub(crate) const F2FS_SB_CHECKSUM_OFFSET_OFF: usize = 32;
pub(crate) const F2FS_SB_BLOCK_COUNT_OFF: usize = 36;
pub(crate) const F2FS_SB_SECTION_COUNT_OFF: usize = 44;
pub(crate) const F2FS_SB_SEGMENT_COUNT_OFF: usize = 48;
pub(crate) const F2FS_SB_SEGMENT_COUNT_MAIN_OFF: usize = 52;
pub(crate) const F2FS_SB_SEGMENT0_BLKADDR_OFF: usize = 56;
pub(crate) const F2FS_SB_CP_BLKADDR_OFF: usize = 60;
pub(crate) const F2FS_SB_SIT_BLKADDR_OFF: usize = 64;
pub(crate) const F2FS_SB_NAT_BLKADDR_OFF: usize = 68;
pub(crate) const F2FS_SB_SSA_BLKADDR_OFF: usize = 72;
pub(crate) const F2FS_SB_MAIN_BLKADDR_OFF: usize = 76;
pub(crate) const F2FS_SB_ROOT_INO_OFF: usize = 80;
pub(crate) const F2FS_SB_NODE_INO_OFF: usize = 84;
pub(crate) const F2FS_SB_META_INO_OFF: usize = 88;
/// `cp_payload`: # of fsync-inode blocks between the two CP copies.
pub(crate) const F2FS_SB_CP_PAYLOAD_OFF: usize = 209;
/// `feature`: enabled-features bitmask.
pub(crate) const F2FS_SB_FEATURE_OFF: usize = 277;
/// Custom: NAT entry count (driver extension).
pub(crate) const F2FS_SB_NAT_ENTRY_CNT_OFF: usize = 281;
/// Custom: SIT entry count (driver extension).
pub(crate) const F2FS_SB_SIT_ENTRY_CNT_OFF: usize = 285;
/// Custom: total node count (driver extension).
pub(crate) const F2FS_SB_NODE_COUNT_OFF: usize = 289;

// ─── Checkpoint field offsets (custom contiguous layout) ──────────────

pub(crate) const F2FS_CP_CHECK_VER_OFF: usize = 0;
pub(crate) const F2FS_CP_NAT_VER_OFF: usize = 8;
pub(crate) const F2FS_CP_SIT_VER_OFF: usize = 16;
pub(crate) const F2FS_CP_NEXT_FREE_NID_OFF: usize = 24;
pub(crate) const F2FS_CP_VALID_BLOCK_COUNT_OFF: usize = 28;
pub(crate) const F2FS_CP_VALID_NODE_COUNT_OFF: usize = 32;
pub(crate) const F2FS_CP_VALID_INODE_COUNT_OFF: usize = 36;
pub(crate) const F2FS_CP_NAT_JOURNAL_COUNT_OFF: usize = 40;
pub(crate) const F2FS_CP_SIT_JOURNAL_COUNT_OFF: usize = 44;
/// Start of the inline NAT journal area (12 bytes per entry).
pub(crate) const F2FS_CP_NAT_JOURNAL_OFF: usize = 48;

// ─── Structural constants ──────────────────────────────────────────────

/// Default block size in bytes.
pub(crate) const F2FS_DEFAULT_BLOCK_SIZE: usize = 4096;
/// Direct block addresses stored inline in an inode.
pub(crate) const F2FS_ADDRS_PER_INODE: usize = 923;
/// NAT entry size in bytes (block_addr + ino).
pub(crate) const F2FS_NAT_ENTRY_SIZE: usize = 8;
/// NAT entries per block (block size / entry size).
pub(crate) const F2FS_NAT_ENTRIES_PER_BLOCK: usize = F2FS_DEFAULT_BLOCK_SIZE / F2FS_NAT_ENTRY_SIZE;
/// Maximum inline NAT journal entries kept in a checkpoint block.
pub(crate) const F2FS_MAX_NAT_JOURNAL_ENTRIES: usize = 512;
/// Root inode NID.
pub(crate) const F2FS_NID_ROOT: u32 = 3;
/// Sentinel: block address for a free / hole NID.
pub(crate) const F2FS_NULL_ADDR: u32 = 0x0000_0000;
/// Sentinel: block address for a freshly allocated (not yet written) block.
pub(crate) const F2FS_NEW_ADDR: u32 = 0xFFFF_FFFF;
