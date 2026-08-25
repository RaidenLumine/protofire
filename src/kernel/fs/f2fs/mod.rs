//! src/kernel/fs/f2fs/mod.rs
//!
//! F2FS (Flash-Friendly File System) read-write implementation.
//!
//! Implements the VFS [`FileSystem`] trait so F2FS-formatted volumes
//! can be mounted alongside other filesystems.
//!
//! ## Architecture
//!
//! [`F2fsVolume`] is the public entry point — it wraps an `Arc<F2fsFs>` so
//! that [`VNode`] handles created by `lookup()` can cheaply hold a
//! reference to the underlying filesystem state.
//!
//! ## v1 Limitations
//!
//! - No garbage collection: blocks are appended and never reclaimed.
//! - Single-stream writes (no hot/warm/cold segment separation).
//! - Direct block pointers only (no indirect node blocks).
//! - No extended attributes.
//! - Fast symlinks only (target fits in i_addr inline area).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block_cache::BlockCache;
use crate::kernel::sync::Mutex;

pub(crate) mod checkpoint;
pub(crate) mod constants;
pub(crate) mod data;
pub(crate) mod fs;
pub(crate) mod node;
pub(crate) mod segment;
#[cfg(test)]
mod tests;
pub(crate) mod types;
pub(crate) mod vfs;

// ─── Public Volume Wrapper ────────────────────────────────────────────

/// A mounted F2FS volume that implements [`VfsFileSystem`].
///
/// Created via [`F2fsVolume::open`], then registered with the kernel's
/// [`FileSystem`](super::FileSystem) and mounted at a path.
pub struct F2fsVolume {
    name: String,
    fs: Arc<F2fsFs>,
}

// ─── Internal Filesystem State ────────────────────────────────────────

/// Internal F2FS filesystem state, shared between [`F2fsVolume`] and every
/// [`F2VNode`] it hands out.
pub(crate) struct F2fsFs {
    /// Underlying block device.
    pub(crate) device: Arc<dyn BlockDevice>,
    /// Sector-level block cache wrapping the device.
    pub(crate) cache: BlockCache,
    /// Parsed superblock from block 0.
    pub(crate) sb: F2fsSuperblock,
    /// Current checkpoint (the newer of the two copies).
    pub(crate) checkpoint: Mutex<F2fsCheckpoint>,
    /// In-memory NAT cache (NID → physical block address).
    pub(crate) nat_cache: Mutex<F2fsNatCache>,
    /// In-memory SIT cache (segment → valid-block bitmap).
    pub(crate) sit_cache: Mutex<F2fsSitCache>,
    /// Current active segment for append writes.
    pub(crate) cur_seg: Mutex<u32>,
    /// Next free block offset within the current active segment.
    pub(crate) cur_seg_off: Mutex<u16>,
    /// Reusable block-sized buffer for read/write operations.
    pub(crate) block_buf: Mutex<Vec<u8>>,
    /// When true, all mutating operations return [`Error::PermissionDenied`].
    pub(crate) read_only: bool,
    /// Dirty NAT entries pending flush to the NAT area (NID → new entry).
    pub(crate) dirty_nat: Mutex<BTreeMap<u32, F2fsNatEntry>>,
    /// Dirty SIT segments pending flush to the SIT area.
    pub(crate) dirty_sit: Mutex<Vec<u32>>,
    /// Monotonically incrementing NID allocator.
    pub(crate) next_nid: Mutex<u32>,
}

// ─── Re-exports ───────────────────────────────────────────────────────

// Re-export types, constants, and helpers needed by sibling modules
// (and tests via `use super::*`).
#[allow(unused_imports)]
pub(crate) use constants::*;
#[allow(unused_imports)]
pub(crate) use types::parse_f2fs_checkpoint;
#[allow(unused_imports)]
pub(crate) use types::parse_f2fs_dir_entries;
#[allow(unused_imports)]
pub(crate) use types::parse_f2fs_inode;
#[allow(unused_imports)]
pub(crate) use types::parse_f2fs_superblock;
#[allow(unused_imports)]
pub(crate) use types::parse_nat_entry;
#[allow(unused_imports)]
pub(crate) use types::parse_sit_entry;
#[allow(unused_imports)]
pub(crate) use types::write_f2fs_checkpoint;
#[allow(unused_imports)]
pub(crate) use types::write_f2fs_dir_entry;
#[allow(unused_imports)]
pub(crate) use types::write_f2fs_inode;
#[allow(unused_imports)]
pub(crate) use types::write_f2fs_superblock;
#[allow(unused_imports)]
pub(crate) use types::write_nat_entry;
#[allow(unused_imports)]
pub(crate) use types::F2fsCheckpoint;
#[allow(unused_imports)]
pub(crate) use types::F2fsDirEntry;
#[allow(unused_imports)]
pub(crate) use types::F2fsInode;
#[allow(unused_imports)]
pub(crate) use types::F2fsNatCache;
#[allow(unused_imports)]
pub(crate) use types::F2fsNatEntry;
#[allow(unused_imports)]
pub(crate) use types::F2fsSitCache;
#[allow(unused_imports)]
pub(crate) use types::F2fsSitEntry;
#[allow(unused_imports)]
pub(crate) use types::F2fsSuperblock;
#[allow(unused_imports)]
pub(crate) use types::NatJournalEntry;
