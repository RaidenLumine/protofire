//! src/kernel/fs/simplefs/constants.rs
//!
//! Superblock and table geometry constants for the on-disk SimpleFs layout.

// Superblock and table geometry constants for the on-disk SimpleFs layout.
pub(crate) const MAGIC: &[u8; 8] = b"ADAFS1\0\0";
pub(crate) const PRIMARY_SUPERBLOCK_BLOCK: usize = 0;
pub(crate) const SECONDARY_SUPERBLOCK_BLOCK: usize = 1;
pub(crate) const SUPERBLOCK_LABEL_OFFSET: usize = 64;
pub(crate) const SUPERBLOCK_LABEL_LEN: usize = 32;
pub(crate) const SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET: usize = 24;
pub(crate) const SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET: usize = 28;
pub(crate) const SUPERBLOCK_DATA_BLOCK_START_OFFSET: usize = 32;
pub(crate) const SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET: usize = 36;
pub(crate) const SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET: usize = 40;
pub(crate) const SUPERBLOCK_INODE_TABLE_BLOCKS_OFFSET: usize = 44;
pub(crate) const SUPERBLOCK_DIRENT_TABLE_BLOCKS_OFFSET: usize = 48;
pub(crate) const SUPERBLOCK_GENERATION_OFFSET: usize = 52;
pub(crate) const SUPERBLOCK_CHECKSUM_OFFSET: usize = 56;
/// Offset of the pending-commit marker in the superblock (V3+).
/// Non-zero value means a metadata commit was in progress when the
/// system stopped.  The value is the target generation number.
pub(crate) const SUPERBLOCK_PENDING_COMMIT_OFFSET: usize = 96;

/// V4+: active xattr table slot (block index). Zero for V2/V3.
pub(crate) const SUPERBLOCK_ACTIVE_XATTR_TABLE_OFFSET: usize = 100;
/// V4+: shadow xattr table slot (block index). Zero for V2/V3.
pub(crate) const SUPERBLOCK_SHADOW_XATTR_TABLE_OFFSET: usize = 104;
/// V4+: size of each xattr table slot in blocks.
pub(crate) const SUPERBLOCK_XATTR_TABLE_BLOCKS_OFFSET: usize = 108;
/// V4+: number of xattr records in the active xattr table.
pub(crate) const SUPERBLOCK_XATTR_COUNT_OFFSET: usize = 112;

pub(crate) const INODE_SIZE: usize = 32;
pub(crate) const DIRENT_SIZE: usize = 64;
pub(crate) const INITIAL_FILE_BLOCKS: u32 = 1;

/// V4+ inode-flag bits (flags byte, offset 1).
/// Bit 0 (`INODE_FLAG_DELETED`) is used by all formats.
/// Bit 1: the file's extent holds a chunked compressed stream.
/// Bit 2: the file's extent is a member of the cross-file dedup pool.
pub(crate) const INODE_FLAG_COMPRESSED: u8 = 1 << 1;
pub(crate) const INODE_FLAG_DEDUPED: u8 = 1 << 2;

/// Compressed extent geometry (V4+, `compression` module).
/// A compressed stream is one page per chunk (matches `memory::compressed`),
/// prefixed by a magic marker, a chunk count, and per-chunk offsets.
pub(crate) const COMPRESSED_CHUNK_SIZE: usize = 4096;
pub(crate) const COMPRESSED_MAGIC: u32 = 0x5043_4D53; // "SMCP" when little-endian on disk

/// Fixed-size on-disk xattr record geometry (V4+).
pub(crate) const XATTR_NAME_MAX: usize = 64;
pub(crate) const XATTR_VALUE_MAX: usize = 256;
/// Header: inode_index + name_len + value_len + status = 16 bytes.
pub(crate) const XATTR_RECORD_SIZE: usize = 16 + XATTR_NAME_MAX + XATTR_VALUE_MAX; // 336
pub(crate) const XATTR_STATUS_LIVE: u32 = 0;
pub(crate) const XATTR_STATUS_DELETED: u32 = 1;

/// Maximum length of a symlink target stored inline inside the inode
/// fields (entry_start + entry_count + data_block = 12 bytes).
pub(crate) const MAX_INLINE_SYMLINK_LEN: usize = 12;

/// Maximum symlink resolution depth to prevent infinite loops.
pub(crate) const MAX_SYMLINK_DEPTH: usize = 8;
pub(crate) const INODE_FLAG_DELETED: u8 = 1 << 0;
