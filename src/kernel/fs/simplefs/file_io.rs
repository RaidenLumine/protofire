//! src/kernel/fs/simplefs/file_io.rs
//!
//! File read/write, truncation, zero-range, and capacity management.

use alloc::vec;

use crate::{Error, Result};

use super::super::block::BLOCK_SIZE;
use super::super::vfs::NodeKind;

use super::free_fns::*;
use super::transaction::TransactionContext;
use super::types::*;
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    pub(crate) fn read_file(
        &self,
        inode_index: usize,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let _prof_start = self.profiler.tick();
        let inode = {
            let state = self.state.lock();
            *state.inodes.get(inode_index).ok_or(Error::InternalError)?
        };
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let file_size = inode.size as usize;
        let offset = offset as usize;
        if offset >= file_size {
            return Ok(0);
        }

        let count = (file_size - offset).min(buffer.len());
        let start_block = inode.data_block as usize + offset / BLOCK_SIZE;
        let in_block_offset = offset % BLOCK_SIZE;
        let last_offset = offset + count;
        let end_block_exclusive = last_offset.div_ceil(BLOCK_SIZE);
        let blocks_to_read = end_block_exclusive - (offset / BLOCK_SIZE);
        if end_block_exclusive > inode.block_count as usize {
            return Err(Error::InternalError);
        }
        let mut temp = vec![0_u8; blocks_to_read * BLOCK_SIZE];
        self.cached_read_blocks(start_block as u64, &mut temp)?;

        let start = in_block_offset;
        let end = start + count;
        buffer[..count].copy_from_slice(&temp[start..end]);

        // When reading the entire file, verify the data checksum if one was
        // stored (non-zero).  Partial reads skip this check.
        if offset == 0
            && count >= file_size
            && inode.data_checksum != 0
            && compute_data_checksum(&temp[..file_size]) != inode.data_checksum
        {
            return Err(Error::DeviceError);
        }

        self.profiler.inc_reads();
        self.profiler.record_elapsed(_prof_start);
        Ok(count)
    }

    pub(crate) fn write_file(
        &self,
        inode_index: usize,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        let _prof_start = self.profiler.tick();
        let offset = usize::try_from(offset).map_err(|_| Error::InvalidArgument)?;
        let required_len = offset
            .checked_add(buffer.len())
            .ok_or(Error::InvalidArgument)?;
        if required_len > u32::MAX as usize {
            return Err(Error::InvalidArgument);
        }

        let current_inode = {
            let state = self.state.lock();
            *state.inodes.get(inode_index).ok_or(Error::InternalError)?
        };
        if current_inode.deleted {
            return Err(Error::NotFound);
        }
        if current_inode.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        // Overwrites that touch already-visible bytes stage a replacement copy
        // first so a crash cannot expose a partially rewritten old prefix.
        // The replacement covers the whole file (max of the write extent and
        // the current size) so a partial overwrite preserves the untouched
        // tail instead of truncating the file to the write end.
        if offset < current_inode.size as usize {
            let final_len = required_len.max(current_inode.size as usize);
            self.replace_file_contents_transactionally(inode_index, final_len, |next| {
                let end = offset + buffer.len();
                next[offset..end].copy_from_slice(buffer);
                Ok(())
            })?;
            self.profiler.inc_writes();
            self.profiler.record_elapsed(_prof_start);
            return Ok(buffer.len());
        }

        let inode = self.ensure_file_capacity(inode_index, required_len)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let capacity = inode.block_count as usize * BLOCK_SIZE;
        if offset > inode.size as usize {
            self.zero_file_range(inode, inode.size as usize, offset)?;
        }

        let count = (capacity - offset).min(buffer.len());
        let start_block = inode.data_block as usize + offset / BLOCK_SIZE;
        let in_block_offset = offset % BLOCK_SIZE;
        let last_offset = offset + count;
        let end_block_exclusive = last_offset.div_ceil(BLOCK_SIZE);
        let blocks_to_write = end_block_exclusive - (offset / BLOCK_SIZE);
        if end_block_exclusive > inode.block_count as usize {
            return Err(Error::InternalError);
        }

        let mut temp = vec![0_u8; blocks_to_write * BLOCK_SIZE];
        self.cached_read_blocks(start_block as u64, &mut temp)?;

        let start = in_block_offset;
        let end = start + count;
        temp[start..end].copy_from_slice(&buffer[..count]);

        let new_size = (offset + count) as u32;
        // Compute the updated checksum on the in-memory temp buffer, which
        // will be the source of truth after the deferred write completes.
        // We incorporate the new data into a merged view of the file contents
        // to produce the post-write checksum.
        let contents_end = (offset + count).max(inode.size as usize);
        let contents_blocks = blocks_for(contents_end).max(inode.block_count as usize);
        let mut contents = vec![0_u8; contents_blocks * BLOCK_SIZE];
        self.device
            .read_blocks(inode.data_block as u64, &mut contents)?;
        // Overlay the new data into the merged view.
        contents[offset..offset + count].copy_from_slice(&buffer[..count]);
        let new_checksum = compute_data_checksum(&contents[..contents_end]);

        if new_size > inode.size {
            self.commit_metadata_update(|state| {
                // Write data blocks before metadata so the commit is atomic:
                // data goes to the device first, then the inode update is
                // committed.  If metadata fails, the data is orphaned on the
                // device but unreferenced — check_and_repair cleans it up.
                self.write_blocks_cached(start_block as u64, &temp)?;
                state.save_inode_for_undo(inode_index);
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                if new_size > inode.size {
                    inode.size = new_size;
                }
                inode.data_checksum = new_checksum;
                Ok(())
            })?;
        } else {
            self.commit_metadata_update(|state| {
                self.write_blocks_cached(start_block as u64, &temp)?;
                state.save_inode_for_undo(inode_index);
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                inode.data_checksum = new_checksum;
                Ok(())
            })?;
        }

        self.profiler.inc_writes();
        self.profiler.record_elapsed(_prof_start);
        Ok(count)
    }

    pub(crate) fn set_len_file(&self, inode_index: usize, length: u64) -> Result<()> {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        let new_len = usize::try_from(length).map_err(|_| Error::InvalidArgument)?;
        if new_len > u32::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        let inode = self.ensure_file_capacity(inode_index, new_len)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let old_len = inode.size as usize;
        if new_len == old_len {
            return Ok(());
        }

        let new_block_count = blocks_for(new_len);
        let new_block_count = u32::try_from(new_block_count).map_err(|_| Error::OutOfMemory)?;

        if new_len > old_len {
            self.zero_file_range(inode, old_len, new_len)?;
        }

        let new_checksum = if new_block_count == 0 {
            0
        } else {
            let inode = {
                let state = self.state.lock();
                *state.inodes.get(inode_index).ok_or(Error::InternalError)?
            };
            let mut contents = vec![0_u8; new_block_count as usize * BLOCK_SIZE];
            let read_len = (inode.size as usize).min(new_len);
            if read_len > 0 {
                let current_block_count = inode.block_count as usize;
                let mut current = vec![0_u8; current_block_count * BLOCK_SIZE];
                self.cached_read_blocks(inode.data_block as u64, &mut current)?;
                contents[..read_len].copy_from_slice(&current[..read_len]);
            }
            compute_data_checksum(&contents[..new_len])
        };

        self.commit_metadata_update(|state| {
            state.save_inode_for_undo(inode_index);
            let (free_start, free_count) = {
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                let old_blocks = inode.block_count as usize;
                let old_data_block = inode.data_block as usize;
                let new_blocks = new_block_count as usize;
                inode.size = new_len as u32;
                inode.block_count = new_block_count;
                if new_block_count == 0 {
                    inode.data_block = 0;
                }
                inode.data_checksum = new_checksum;
                // Compute range to free (may be zero).
                if old_blocks > new_blocks {
                    (old_data_block + new_blocks, old_blocks - new_blocks)
                } else {
                    (0, 0)
                }
            };
            if free_count > 0 {
                self.mark_extent_free(state, free_start, free_count);
            }
            Ok(())
        })
    }

    fn replace_file_contents_transactionally<F>(
        &self,
        inode_index: usize,
        new_len: usize,
        mutate: F,
    ) -> Result<OnDiskInode>
    where
        F: FnOnce(&mut [u8]) -> Result<()>,
    {
        let inode = {
            let state = self.state.lock();
            *state.inodes.get(inode_index).ok_or(Error::InternalError)?
        };
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let new_block_count = blocks_for(new_len);
        let new_block_count_u32 = u32::try_from(new_block_count).map_err(|_| Error::OutOfMemory)?;
        let mut next_contents = vec![0_u8; new_block_count * BLOCK_SIZE];
        let preserved_len = (inode.size as usize).min(new_len);

        if preserved_len != 0 {
            let current_block_count = inode.block_count as usize;
            if current_block_count == 0 {
                return Err(Error::InternalError);
            }

            let mut current_contents = vec![0_u8; current_block_count * BLOCK_SIZE];
            self.cached_read_blocks(inode.data_block as u64, &mut current_contents)?;
            next_contents[..preserved_len].copy_from_slice(&current_contents[..preserved_len]);
        }

        mutate(&mut next_contents[..new_len])?;

        let new_checksum = compute_data_checksum(&next_contents[..new_len]);

        let old_data_block = inode.data_block as usize;
        let old_block_count = inode.block_count as usize;

        self.commit_metadata_update(|state| {
            // Find free extent for the new data inside the commit so the
            // allocation is covered by the transaction.
            let next_data_block = if new_block_count == 0 {
                0
            } else {
                self.find_free_data_block_span(state, new_block_count, None)?
            };

            // Write data blocks inside the commit before the inode update
            // so the data is durable before the metadata points to it.
            if !next_contents.is_empty() {
                self.write_blocks_cached(next_data_block as u64, &next_contents)?;
            }

            state.save_inode_for_undo(inode_index);
            let result = {
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                inode.data_block = next_data_block as u32;
                inode.block_count = new_block_count_u32;
                inode.size = new_len as u32;
                inode.data_checksum = new_checksum;
                *inode
            };
            // Free the old extent and allocate the new one.
            if old_block_count > 0 && old_data_block != next_data_block {
                self.mark_extent_free(state, old_data_block, old_block_count);
            }
            if new_block_count > 0 {
                self.mark_extent_allocated(state, next_data_block, new_block_count);
            }
            Ok(result)
        })
    }

    pub(crate) fn zero_file_range(
        &self,
        inode: OnDiskInode,
        start: usize,
        end: usize,
    ) -> Result<()> {
        if start >= end {
            return Ok(());
        }

        let start_block_offset = start / BLOCK_SIZE;
        let end_block_exclusive = end.div_ceil(BLOCK_SIZE);
        if end_block_exclusive > inode.block_count as usize {
            return Err(Error::InternalError);
        }

        let start_block = inode.data_block as usize + start_block_offset;
        let blocks_to_write = end_block_exclusive - start_block_offset;
        let mut temp = vec![0_u8; blocks_to_write * BLOCK_SIZE];
        self.cached_read_blocks(start_block as u64, &mut temp)?;

        let zero_start = start % BLOCK_SIZE;
        let zero_end = zero_start + (end - start);
        temp[zero_start..zero_end].fill(0);
        self.write_blocks_cached(start_block as u64, &temp)
    }

    pub(crate) fn commit_metadata_update<T, F>(&self, mutate: F) -> Result<T>
    where
        F: FnOnce(&mut SimpleFsState) -> Result<T>,
    {
        let mut state = self.state.lock();
        state.begin_undo();
        let result = match mutate(&mut state) {
            Ok(result) => result,
            Err(error) => {
                state.rollback_undo();
                return Err(error);
            }
        };
        // Any mutation may have modified inodes directly; mark dirty here
        // so flush_metadata knows to write the inode table.  Dirent table
        // dirty tracking is handled precisely by insert/remove helpers.
        state.inode_table_dirty = true;

        if let Err(error) = self.validate_runtime_state(&state) {
            state.rollback_undo();
            return Err(error);
        }

        // Mutations write data blocks (via write_blocks_cached) before
        // updating in-memory metadata.  If flush_metadata fails, the data
        // is on the device but the metadata was rolled back — orphaned
        // data blocks are cleaned up by check_and_repair on next mount.
        if let Err(error) = self.flush_metadata(&mut state) {
            state.rollback_undo();
            return Err(error);
        }

        state.commit_undo();
        Ok(result)
    }

    /// Execute a batch of mutations inside a single atomic commit.
    /// Data-block writes are deferred via the write-back cache and flushed
    /// atomically with the metadata commit; on rollback they are discarded.
    pub fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut TransactionContext) -> Result<T>,
    {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        self.commit_metadata_update(|state| {
            self.profiler.inc_transactions();
            let mut ctx = TransactionContext { state, fs: self };
            f(&mut ctx)
        })
    }
    pub(crate) fn ensure_file_capacity(
        &self,
        inode_index: usize,
        required_len: usize,
    ) -> Result<OnDiskInode> {
        let inode = {
            let state = self.state.lock();
            *state.inodes.get(inode_index).ok_or(Error::InternalError)?
        };
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let current_blocks = inode.block_count as usize;
        let required_blocks = blocks_for(required_len);
        if required_blocks <= current_blocks {
            return Ok(inode);
        }

        let required_blocks_u32 = u32::try_from(required_blocks).map_err(|_| Error::OutOfMemory)?;
        let next_data_block = {
            let state = self.state.lock();
            self.find_free_data_block_span(&state, required_blocks, Some(inode_index))?
        };

        if current_blocks != 0 && next_data_block == inode.data_block as usize {
            let extend_by = required_blocks - current_blocks;
            let current_end = next_data_block + current_blocks;

            let zeroed = vec![0_u8; extend_by * BLOCK_SIZE];
            self.write_blocks_cached(current_end as u64, &zeroed)?;

            return self.commit_metadata_update(|state| {
                state.save_inode_for_undo(inode_index);
                let (result, extend_start, extend_count) = {
                    let inode = state
                        .inodes
                        .get_mut(inode_index)
                        .ok_or(Error::InternalError)?;
                    let old_blocks = inode.block_count as usize;
                    let new_blocks = required_blocks_u32 as usize;
                    let ext_start = inode.data_block as usize + old_blocks;
                    let ext_count = new_blocks.saturating_sub(old_blocks);
                    inode.block_count = required_blocks_u32;
                    (*inode, ext_start, ext_count)
                };
                // Allocate the additional blocks at the tail.
                if extend_count > 0 {
                    self.mark_extent_allocated(state, extend_start, extend_count);
                }
                Ok(result)
            });
        }

        let new_start = next_data_block;

        // If the file cannot grow in place, relocate the whole extent to the
        // next free span and then publish the new metadata atomically.
        let mut relocated = vec![0_u8; required_blocks * BLOCK_SIZE];
        if current_blocks != 0 {
            let current_len = current_blocks * BLOCK_SIZE;
            self.cached_read_blocks(inode.data_block as u64, &mut relocated[..current_len])?;
        }
        self.write_blocks_cached(new_start as u64, &relocated)?;

        let old_data_block = inode.data_block as usize;
        let old_block_count = current_blocks;

        self.commit_metadata_update(|state| {
            state.save_inode_for_undo(inode_index);
            let result = {
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                inode.data_block = new_start as u32;
                inode.block_count = required_blocks_u32;
                *inode
            };
            // Free the old extent and allocate the new one.
            if old_block_count > 0 {
                self.mark_extent_free(state, old_data_block, old_block_count);
            }
            self.mark_extent_allocated(state, new_start, required_blocks_u32 as usize);
            Ok(result)
        })
    }
}
