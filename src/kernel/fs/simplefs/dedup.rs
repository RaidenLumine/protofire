//! src/kernel/fs/simplefs/dedup.rs
//! Cross-file content deduplication for V4 volumes.
//!
//! Identical file content is stored once and shared by multiple inodes.
//! The invariant that keeps the in-memory hash map safe: `INODE_FLAG_DEDUPED`
//! means "this inode's extent is a member of the dedup pool" with
//! `refcount >= 1` (a sole owner is still pooled, so every future sharer and
//! every release goes through the same refcount-aware path).
//!
//! Refcounts are rebuilt at mount time from the on-disk `DEDUPED` markers
//! (grouping by `(data_block, block_count)`), so the pool survives crashes.
//! The content-hash → extent map is populated lazily as files are written and
//! is re-discovered across reboots.
//!
//! Compressed and deduped files are mutually exclusive: a compressed file's
//! extent stores an encoded stream, so it is never a dedup candidate.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Result};

use super::super::block::BLOCK_SIZE;
use super::constants::*;
use super::types::*;
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    /// FNV-1a 64-bit content hash used as the dedup lookup key.
    fn content_hash(contents: &[u8]) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for &byte in contents {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Check whether the extent at `(data_block, block_count)` holds exactly
    /// `contents` in its first `contents.len()` bytes.
    fn extent_content_matches(
        &self,
        data_block: u32,
        block_count: u32,
        contents: &[u8],
    ) -> Result<bool> {
        let block_count = block_count as usize;
        if block_count == 0 {
            return Ok(contents.is_empty());
        }
        let mut extent = vec![0_u8; block_count * BLOCK_SIZE];
        self.cached_read_blocks(data_block as u64, &mut extent)?;
        if contents.len() > extent.len() {
            return Ok(false);
        }
        Ok(&extent[..contents.len()] == contents)
    }

    /// Release a dedup-pool file's shared extent and give it a fresh private
    /// copy (copy-on-write).  Used before any write or resize that would
    /// otherwise mutate a shared extent.  Leaves `deduped = false`.
    pub(crate) fn unshare_inode_extent(&self, inode_index: usize) -> Result<()> {
        let (data_block, block_count, size, compressed) = {
            let state = self.state.lock();
            let inode = state.inodes.get(inode_index).ok_or(Error::InternalError)?;
            (
                inode.data_block as usize,
                inode.block_count as usize,
                inode.size as usize,
                inode.compressed,
            )
        };
        if block_count == 0 {
            return Ok(());
        }
        if compressed {
            // Compressed files are never deduped; nothing to unshare.
            return Ok(());
        }

        let mut contents = vec![0_u8; block_count * BLOCK_SIZE];
        self.cached_read_blocks(data_block as u64, &mut contents)?;
        let contents_len = size;

        self.commit_metadata_update(|state| {
            let next = self.find_free_data_block_span(state, block_count, None)?;
            self.write_blocks_cached(next as u64, &contents)?;
            state.save_inode_for_undo(inode_index);
            let inode = state
                .inodes
                .get_mut(inode_index)
                .ok_or(Error::InternalError)?;
            let old_data = inode.data_block as usize;
            let old_blocks = inode.block_count as usize;
            inode.data_block = next as u32;
            inode.deduped = false;
            self.release_inode_extent(state, old_data, old_blocks, true);
            self.mark_extent_allocated(state, next, block_count);
            let _ = contents_len;
            Ok(())
        })
    }

    /// After a write, opportunistically dedup the file: if its content matches
    /// a pooled extent, share it (freeing the freshly-written private extent);
    /// otherwise add its extent to the pool.  No-op outside V4, for empty or
    /// compressed files.
    pub(crate) fn maybe_dedup_inode(&self, inode_index: usize) -> Result<()> {
        if !self.format_version.supports_persistent_xattrs() {
            return Ok(());
        }
        let (size, block_count, compressed) = {
            let state = self.state.lock();
            let inode = state.inodes.get(inode_index).ok_or(Error::InternalError)?;
            (
                inode.size as usize,
                inode.block_count as usize,
                inode.compressed,
            )
        };
        if compressed || size == 0 || block_count == 0 {
            return Ok(());
        }

        let mut contents = vec![0_u8; block_count * BLOCK_SIZE];
        self.cached_read_blocks(
            {
                let state = self.state.lock();
                state
                    .inodes
                    .get(inode_index)
                    .ok_or(Error::InternalError)?
                    .data_block as u64
            },
            &mut contents,
        )?;
        let contents = contents[..size].to_vec();

        self.commit_metadata_update(|state| {
            self.dedup_share_or_pool_locked(state, inode_index, &contents)
        })
    }

    /// Decide, inside a metadata transaction, whether the inode's current
    /// private extent should be shared with a pooled candidate or added to
    /// the pool itself.
    fn dedup_share_or_pool_locked(
        &self,
        state: &mut SimpleFsState,
        inode_index: usize,
        contents: &[u8],
    ) -> Result<()> {
        let hash = Self::content_hash(contents);

        // Try to share an existing pooled extent with identical content.
        let candidates = state.dedup_hash_to_extents.get(&hash).cloned();
        if let Some(candidates) = candidates {
            for (db, bc, candidate_size) in candidates {
                if candidate_size as usize != contents.len() {
                    continue;
                }
                if !self.extent_content_matches(db, bc, contents)? {
                    continue;
                }
                let current = state
                    .inodes
                    .get(inode_index)
                    .copied()
                    .ok_or(Error::InternalError)?;
                let old_data = current.data_block as usize;
                let old_blocks = current.block_count as usize;
                // Release the freshly-written private extent if it differs
                // from the shared target.
                if old_blocks > 0 && (old_data != db as usize || old_blocks != bc as usize) {
                    self.release_inode_extent(state, old_data, old_blocks, false);
                }
                state.save_inode_for_undo(inode_index);
                let inode = state
                    .inodes
                    .get_mut(inode_index)
                    .ok_or(Error::InternalError)?;
                inode.data_block = db;
                inode.block_count = bc;
                inode.deduped = true;
                *state.dedup_refcounts.entry((db, bc)).or_insert(0) += 1;
                return Ok(());
            }
        }

        // No match: pool this inode's current extent.
        let inode = *state.inodes.get(inode_index).ok_or(Error::InternalError)?;
        if inode.block_count == 0 {
            return Ok(());
        }
        let key = (inode.data_block, inode.block_count);
        state.save_inode_for_undo(inode_index);
        let inode = state
            .inodes
            .get_mut(inode_index)
            .ok_or(Error::InternalError)?;
        inode.deduped = true;
        *state.dedup_refcounts.entry(key).or_insert(0) += 1;
        let entry = (key.0, key.1, inode.size);
        if let Some(list) = state.dedup_hash_to_extents.get_mut(&hash) {
            if !list.contains(&entry) {
                list.push(entry);
            }
        } else {
            state.dedup_hash_to_extents.insert(hash, vec![entry]);
        }
        Ok(())
    }
}
