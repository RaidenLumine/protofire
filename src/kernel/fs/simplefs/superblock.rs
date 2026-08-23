//! src/kernel/fs/simplefs/superblock.rs
//! Superblock parsing, mount, label, block I/O caching helpers.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::super::block::{BlockDevice, DeviceHealth, BLOCK_SIZE};
use super::super::block_cache::{BlockCache, CacheStats};
use super::super::filesystem::profiler::{FsProfiler, FsProfilerSnapshot};
use super::super::vfs::{NodeKind, SecurityDescriptorMutationSupport};

use super::constants::*;
use super::free_fns::*;
use super::types::*;
use super::{SimpleFs, SimpleFsState, UndoLog};

impl SimpleFs {
    /// Mount a SimpleFS image from `device`, exposing the read/write API used
    /// by the host integration-test suite (and the unified filesystem layer).
    pub fn open(device: Arc<dyn BlockDevice>, case_sensitive: bool) -> Result<Arc<Self>> {
        Self::open_with_runtime_policy(device, case_sensitive, SimpleFsRuntimeMountPolicy::Public)
    }

    pub(crate) fn open_with_runtime_policy(
        device: Arc<dyn BlockDevice>,
        case_sensitive: bool,
        mount_policy: SimpleFsRuntimeMountPolicy,
    ) -> Result<Arc<Self>> {
        let (label, parsed_superblock, inodes, dir_entries) =
            load_current_runtime_state(&*device, case_sensitive, mount_policy)?;
        let pending_commit_on_mount = parsed_superblock.record.pending_commit;
        let inode_capacity = parsed_superblock
            .format_version
            .inode_capacity(parsed_superblock.record.inode_table_blocks);
        let dirent_capacity = parsed_superblock
            .format_version
            .dirent_capacity(parsed_superblock.record.dirent_table_blocks);

        let cache = BlockCache::new(device.clone());

        // V4+: reload the persisted xattr records from the active xattr table
        // so attributes set before the last clean unmount survive a remount.
        // V2/V3 formats have no xattr table (`supports_persistent_xattrs` is
        // false there).  The on-disk `xattr_count` field is not persisted by
        // `write_superblock`, so the table is scanned for the contiguous run
        // of written records instead of trusting that count.
        let xattrs = if parsed_superblock
            .format_version
            .supports_persistent_xattrs()
        {
            read_xattr_records(
                &*device,
                parsed_superblock.format_version,
                parsed_superblock.record.active_xattr_table_block,
                parsed_superblock
                    .format_version
                    .xattr_capacity(parsed_superblock.record.xattr_table_blocks),
            )?
        } else {
            Vec::new()
        };

        let mut free_inode_slots = Vec::new();
        for (i, inode) in inodes.iter().enumerate().skip(1) {
            if inode.deleted {
                free_inode_slots.push(i);
            }
        }

        let mut parent_of = vec![None; inodes.len()];
        let mut inode_to_entry_index = vec![None; inodes.len()];
        for (dir_index, inode) in inodes.iter().enumerate() {
            if inode.kind != NodeKind::Directory || inode.deleted {
                continue;
            }
            let start = inode.entry_start as usize;
            let end = start + inode.entry_count as usize;
            if let Some(entries) = dir_entries.get(start..end) {
                for (offset, entry) in entries.iter().enumerate() {
                    let child = entry.inode_index as usize;
                    if child < parent_of.len() {
                        parent_of[child] = Some(dir_index);
                        inode_to_entry_index[child] = Some(start + offset);
                    }
                }
            }
        }

        let fs = Arc::new(Self {
            label,
            format_version: parsed_superblock.format_version,
            device,
            cache,
            state: Mutex::new(SimpleFsState {
                inodes,
                dir_entries,
                active_inode_table_block: parsed_superblock.record.active_inode_table_block,
                active_dirent_table_block: parsed_superblock.record.active_dirent_table_block,
                shadow_inode_table_block: parsed_superblock.record.shadow_inode_table_block,
                shadow_dirent_table_block: parsed_superblock.record.shadow_dirent_table_block,
                generation: parsed_superblock.record.generation,
                inode_table_dirty: false,
                dirent_table_dirty: false,
                needs_shadow_sync: true,
                staging_roots: Vec::new(),
                free_inode_slots,
                parent_of,
                inode_to_entry_index,
                free_data_extents: BTreeMap::new(),
                dir_inode_indices: Vec::new(),
                undo: UndoLog::default(),
                xattrs,
                active_xattr_table_block: parsed_superblock.record.active_xattr_table_block,
                shadow_xattr_table_block: parsed_superblock.record.shadow_xattr_table_block,
                xattr_table_dirty: false,
                dedup_refcounts: BTreeMap::new(),
                dedup_hash_to_extents: BTreeMap::new(),
            }),
            case_sensitive,
            inode_table_blocks: parsed_superblock.record.inode_table_blocks,
            dirent_table_blocks: parsed_superblock.record.dirent_table_blocks,
            data_block_start: parsed_superblock.record.data_block_start,
            inode_capacity,
            dirent_capacity,
            xattr_table_blocks: parsed_superblock.record.xattr_table_blocks,
            xattr_capacity: parsed_superblock
                .format_version
                .xattr_capacity(parsed_superblock.record.xattr_table_blocks),
            profiler: FsProfiler::default(),
        });
        {
            let mut state = fs.state.lock();
            fs.rebuild_free_data_extents(&mut state);
            fs.rebuild_dir_inode_indices(&mut state);
        }

        // If the superblock we mounted from had a non-zero pending_commit,
        // the previous session crashed mid-commit.  The filesystem state is
        // consistent (we loaded from the active tables, which are never
        // written during a commit), but the stale pending_commit flag on
        // disk should be cleared by calling [`check_and_repair`].
        let _ = pending_commit_on_mount;

        Ok(fs)
    }

    pub(crate) fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        match self.format_version.persistent_security_descriptor_layout() {
            Some(_) if self.device.is_read_only() => {
                SecurityDescriptorMutationSupport::PersistentReadOnly
            }
            Some(_) => SecurityDescriptorMutationSupport::Persistent,
            None => SecurityDescriptorMutationSupport::LayoutDerivedOnly,
        }
    }

    pub(crate) fn require_persistent_security_descriptor_writes(&self) -> Result<()> {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        if self
            .format_version
            .persistent_security_descriptor_layout()
            .is_none()
        {
            return Err(Error::Unsupported);
        }

        Ok(())
    }

    // ─── block-cache helpers ───

    pub(crate) fn cached_read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        if self.device.device_health() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }
        let block_count = buffer.len() / BLOCK_SIZE;
        for i in 0..block_count {
            let offset = i * BLOCK_SIZE;
            self.cache
                .read_cached(lba + i as u64, &mut buffer[offset..offset + BLOCK_SIZE])?;
        }
        Ok(())
    }

    /// Write metadata blocks to the device (durability) and populate the block
    /// cache so that subsequent reads of the same LBA range are cache hits
    /// instead of re-fetching from the device.
    ///
    /// Each block is written through to the device immediately to preserve
    /// the crash-safety guarantees of the metadata two-phase commit protocol.
    /// Cache entries are populated as **clean** (not dirty) because the device
    /// already has the authoritative data; this avoids extra device writes
    /// from dirty evictions that would shift the call count for torn-write
    /// failure-injection tests.
    ///
    /// Prefer [`write_blocks_cached_wb`](Self::write_blocks_cached_wb) for
    /// file-data writes whose durability is deferred until the next metadata
    /// flush.
    pub(crate) fn write_blocks_cached(&self, lba: u64, data: &[u8]) -> Result<()> {
        if self.device.device_health() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }
        let block_count = data.len() / BLOCK_SIZE;
        self.device.write_blocks(lba, data)?;
        for i in 0..block_count {
            let offset = i * BLOCK_SIZE;
            self.cache
                .populate_clean(lba + i as u64, &data[offset..offset + BLOCK_SIZE]);
        }
        Ok(())
    }

    /// Write file-data blocks through the write-back cache, deferring the
    /// device write until the next [`BlockCache::flush`] call or dirty
    /// eviction.
    ///
    /// Entries are marked **dirty** in the cache; eviction of a dirty entry
    /// writes it back to the device first.  This batches small data-block
    /// writes and reduces device I/O for multi-block file operations.
    ///
    /// Currently unused — the infrastructure is in place for a future
    /// write-back optimisation.
    #[allow(dead_code)]
    pub(crate) fn write_blocks_cached_wb(&self, lba: u64, data: &[u8]) -> Result<()> {
        if self.device.device_health() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }
        let block_count = data.len() / BLOCK_SIZE;
        for i in 0..block_count {
            let offset = i * BLOCK_SIZE;
            self.cache
                .write_back(lba + i as u64, &data[offset..offset + BLOCK_SIZE])?;
        }
        Ok(())
    }

    /// Return a point-in-time snapshot of filesystem operation counters.
    /// When the `fs_profiler` feature is disabled the snapshot is all zeros.
    pub(crate) fn profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.profiler.snapshot()
    }

    /// Return a point-in-time snapshot of block-cache statistics including
    /// hits, misses, evictions, and dirty write-backs.
    #[allow(dead_code)]
    pub(crate) fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }
}

/// Read the persisted xattr records from the active xattr table slot (V4+).
///
/// Each fixed-size record is parsed from the `{inode_index:u32, name_len:u32,
/// value_len:u32, status:u32, name:[u8;XATTR_NAME_MAX], value:[u8;XATTR_VALUE_MAX]}`
/// layout written by `write_runtime_xattr_table`.  Records are written
/// contiguously from slot 0 and the remaining capacity is zeroed, so scanning
/// up to the first all-zero slot reconstructs the exact in-memory record list.
/// A written record is never all-zero: live records carry a non-zero
/// `name_len` and deleted records carry `status == XATTR_STATUS_DELETED`.
pub(crate) fn read_xattr_records(
    device: &dyn BlockDevice,
    format_version: SimpleFsFormatVersion,
    table_block: usize,
    capacity: usize,
) -> Result<Vec<XattrRecord>> {
    let table_bytes = format_version.xattr_table_bytes(capacity)?;
    let mut buffer = vec![0_u8; blocks_for(table_bytes) * BLOCK_SIZE];
    device.read_blocks(table_block as u64, &mut buffer)?;

    let mut records = Vec::with_capacity(capacity);
    for index in 0..capacity {
        let base = format_version.xattr_table_entry_offset(0, index)?;
        let end = base
            .checked_add(XATTR_RECORD_SIZE)
            .ok_or(Error::InvalidArgument)?;
        let slot = buffer.get(base..end).ok_or(Error::InvalidArgument)?;
        if slot.iter().all(|byte| *byte == 0) {
            break;
        }
        records.push(XattrRecord {
            inode_index: read_u32(slot, 0)?,
            name_len: read_u32(slot, 4)?,
            value_len: read_u32(slot, 8)?,
            status: read_u32(slot, 12)?,
            name: slot[16..16 + XATTR_NAME_MAX]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
            value: slot[16 + XATTR_NAME_MAX..16 + XATTR_NAME_MAX + XATTR_VALUE_MAX]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        });
    }

    Ok(records)
}
