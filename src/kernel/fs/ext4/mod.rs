//! src/kernel/fs/ext4/mod.rs
//! ext2/ext4 filesystem: on-disk types, block/group operations, journal
//! replay, and VFS integration.

pub(crate) mod constants;
pub(crate) mod fs;
pub(crate) mod journal;
pub(crate) mod types;
pub(crate) mod vfs;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block_cache::BlockCache;
use crate::kernel::fs::filesystem::profiler::FsProfiler;
use crate::kernel::fs::vfs::checksum::ChecksumPolicy;
use crate::kernel::sync::Mutex;

pub struct Ext4FsVolume {
    name: String,
    fs: Arc<Ext4Fs>,
}

// ─── internal filesystem state ──────────────────────────────────────────────

/// Internal ext2 filesystem state, shared between [`Ext4FsVolume`] and every
/// [`Ext4VNode`] it hands out.
pub(crate) struct Ext4Fs {
    device: Arc<dyn BlockDevice>,
    cache: BlockCache,
    sb: Ext4Superblock,
    bg_descriptors: Mutex<Vec<Ext4BgDescriptor>>,
    /// When true, all mutating operations return [`Error::PermissionDenied`].
    read_only: bool,
    /// Reusable block-sized buffer, eliminating repeated heap allocations in
    /// the indirect-block pointer read/write hot paths.
    block_buf: Mutex<Vec<u8>>,
    /// Journal writer for metadata write-ahead logging.  `None` when the
    /// filesystem does not have a journal or when mounted read-only.
    journal_writer: Option<Mutex<JournalWriter>>,
    /// Filesystem operation profiler for diagnostics.
    pub(crate) profiler: FsProfiler,
    /// Checksum verification policy (CRC32C on journal commit blocks).
    pub(crate) checksum_policy: ChecksumPolicy,
}

// ─── re-exports ─────────────────────────────────────────────────────────────

// Re-export types, constants, and helpers needed by sibling modules
// (and tests via `use super::*`).
#[allow(unused_imports)]
pub(crate) use constants::*;
pub(crate) use journal::*;
#[allow(unused_imports)]
pub(crate) use types::{
    inode_block_bytes, parse_extent, parse_extent_header, parse_extent_idx, read_ext4_inode,
    write_extent, write_extent_header, write_inode_block_bytes, Ext4BgDescriptor, Ext4DirEntry,
    Ext4Extent, Ext4ExtentHeader, Ext4ExtentIdx, Ext4Inode, Ext4Superblock,
};
#[allow(unused_imports)]
pub(crate) use vfs::{split_path, to_node_kind};
