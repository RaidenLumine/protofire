//! src/kernel/fs/simplefs/mod.rs
//!
//! SimpleFs — on-disk format parser, validator, and runtime file/directory
//! operations.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;

use super::block::BlockDevice;
use super::block_cache::BlockCache;
use super::filesystem::profiler::FsProfiler;

#[allow(dead_code)] // wired for compilation; the read/write path consumes it later (see types.rs)
pub(crate) mod compression;
pub(crate) mod constants;
#[allow(dead_code)] // wired for compilation; complements the inline dedup pool in SimpleFsState
pub(crate) mod dedup;
pub(crate) mod dir_ops;
pub(crate) mod extent_repair;
pub(crate) mod file_io;
pub(crate) mod format_io;
pub(crate) mod free_fns;
pub(crate) mod fs;
pub(crate) mod image_staging;
pub(crate) mod inode_dirent;
pub(crate) mod path;
pub(crate) mod superblock;
#[cfg(test)]
mod tests;
pub(crate) mod transaction;
pub(crate) mod types;
pub(crate) mod vfs;
pub(crate) mod xattr;

// Types imported via pub(crate) use types::* below.
pub(crate) use types::{OnDiskDirEntry, OnDiskInode, SimpleFsFormatVersion, XattrRecord};

// ── Core struct definitions ──

#[derive(Clone, Default)]
pub(crate) struct UndoLog {
    inodes: Vec<(usize, OnDiskInode)>,
    dirents: Vec<(usize, OnDiskDirEntry)>,
    all_dirents: Option<Vec<OnDiskDirEntry>>,
    all_inode_to_entry_index: Option<Vec<Option<usize>>>,
    parent_of: Vec<(usize, Option<usize>)>,
    inode_to_entry_index: Vec<(usize, Option<usize>)>,
    inodes_len: Option<usize>,
    parent_of_len: Option<usize>,
    inode_to_entry_index_len: Option<usize>,
    free_data_extents: Option<BTreeMap<usize, usize>>,
    free_inode_slots: Option<Vec<usize>>,
    dir_inode_indices: Option<Vec<usize>>,
    staging_roots_len: Option<usize>,
    old_inode_table_dirty: Option<bool>,
    old_dirent_table_dirty: Option<bool>,
    /// Per-record snapshots for xattr-table mutations (V4+).
    xattrs: Vec<(usize, XattrRecord)>,
    /// Length of `xattrs` before the first push (for rollback truncation).
    xattr_len: Option<usize>,
}

#[derive(Clone)]
pub(crate) struct SimpleFsState {
    inodes: Vec<OnDiskInode>,
    dir_entries: Vec<OnDiskDirEntry>,
    active_inode_table_block: usize,
    active_dirent_table_block: usize,
    shadow_inode_table_block: usize,
    shadow_dirent_table_block: usize,
    generation: u32,
    inode_table_dirty: bool,
    dirent_table_dirty: bool,
    needs_shadow_sync: bool,
    staging_roots: Vec<String>,
    free_inode_slots: Vec<usize>,
    parent_of: Vec<Option<usize>>,
    inode_to_entry_index: Vec<Option<usize>>,
    free_data_extents: BTreeMap<usize, usize>,
    dir_inode_indices: Vec<usize>,
    undo: UndoLog,
    /// V4+: active xattr records (may include `XATTR_STATUS_DELETED` slots).
    xattrs: Vec<XattrRecord>,
    /// V4+: active / shadow xattr table slots (mirror of the inode/dirent
    /// active/shadow pair).
    active_xattr_table_block: usize,
    shadow_xattr_table_block: usize,
    xattr_table_dirty: bool,
    /// V4+: live cross-file dedup refcounts keyed by `(data_block,
    /// block_count)`.
    dedup_refcounts: BTreeMap<(u32, u32), usize>,
    /// V4+: content hash → pooled extents `(data_block, block_count, size)`
    /// (opportunistic cross-file dedup).  Only pooled extents are eligible
    /// sharing candidates; the map is populated lazily as files are written.
    dedup_hash_to_extents: BTreeMap<u64, Vec<(u32, u32, u32)>>,
    /// Live open-handle counts per inode slot.  A slot with `open_handles > 0`
    /// is never pushed onto `free_inode_slots` on unlink, so a stale handle can
    /// never read/write a file that reused its slot.
    open_handles: BTreeMap<usize, usize>,
}

pub struct SimpleFs {
    label: String,
    format_version: SimpleFsFormatVersion,
    device: Arc<dyn BlockDevice>,
    cache: BlockCache,
    state: Mutex<SimpleFsState>,
    case_sensitive: bool,
    inode_table_blocks: usize,
    dirent_table_blocks: usize,
    data_block_start: usize,
    inode_capacity: usize,
    dirent_capacity: usize,
    profiler: FsProfiler,
    /// V4+: size of each xattr table slot in blocks.
    xattr_table_blocks: usize,
    /// V4+: number of xattr records each xattr table slot can hold.
    xattr_capacity: usize,
}

impl Drop for SimpleFs {
    fn drop(&mut self) {
        let _ = self.cache.flush();
    }
}

pub struct SimpleFsVolume {
    inner: Arc<SimpleFs>,
}

struct SimpleVNode {
    fs: Arc<SimpleFs>,
    inode_index: usize,
    name: String,
}

impl Drop for SimpleVNode {
    fn drop(&mut self) {
        let mut state = self.fs.state.lock();
        if let Some(count) = state.open_handles.get_mut(&self.inode_index) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.open_handles.remove(&self.inode_index);
                // If the inode was unlinked while a handle was still open, it
                // could not be recycled then (the unlink path skipped the push
                // to `free_inode_slots`).  Free the slot once the last handle
                // closes, but only if the inode is still deleted — a transaction
                // rollback may have restored it to a live inode in the meantime.
                let deleted = state
                    .inodes
                    .get(self.inode_index)
                    .map(|inode| inode.deleted)
                    .unwrap_or(false);
                if deleted && !state.free_inode_slots.contains(&self.inode_index) {
                    state.free_inode_slots.push(self.inode_index);
                }
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct ImageEntry<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

// ── Re-exports ─────────────────────────────────────────────────────────

pub use image_staging::{StagingArea, VersionSwitch};
pub use transaction::TransactionContext;
