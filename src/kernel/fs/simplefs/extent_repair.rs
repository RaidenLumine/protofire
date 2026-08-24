//! src/kernel/fs/simplefs/extent_repair.rs
//!
//! Free extent tracking, metadata flush, volume check & repair, orphan
//! cleanup, and runtime validation.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Result};

use super::super::block::{DeviceHealth, BLOCK_SIZE};
use super::super::vfs::{NodeKind, VolumeCheckReport};

use super::constants::*;
use super::free_fns::*;
use super::types::*;
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    pub(crate) fn rebuild_free_data_extents(&self, state: &mut SimpleFsState) {
        state.save_free_extents_for_undo();
        state.free_data_extents.clear();
        let data_start = self.data_block_start;
        let device_end = self.device.block_count() as usize;

        let mut extents: Vec<(usize, usize)> = state
            .inodes
            .iter()
            .filter(|inode| {
                !inode.deleted && inode.kind != NodeKind::Directory && inode.block_count > 0
            })
            .map(|inode| {
                let start = inode.data_block as usize;
                let end = start + inode.block_count as usize;
                (start, end)
            })
            .collect();
        extents.sort_unstable_by_key(|(start, _)| *start);

        let mut cursor = data_start;
        for (start, end) in extents {
            if cursor < start {
                state.free_data_extents.insert(cursor, start - cursor);
            }
            if end > cursor {
                cursor = end;
            }
        }
        if cursor < device_end {
            state.free_data_extents.insert(cursor, device_end - cursor);
        }
    }

    /// Rebuild the `dir_inode_indices` vector by scanning all inodes.
    /// Called once at mount time; thereafter maintained incrementally.
    pub(crate) fn rebuild_dir_inode_indices(&self, state: &mut SimpleFsState) {
        state.dir_inode_indices.clear();
        for (index, inode) in state.inodes.iter().enumerate() {
            if inode.kind == NodeKind::Directory && !inode.deleted {
                state.dir_inode_indices.push(index);
            }
        }
    }

    /// Release an inode's data extent, honoring the cross-file dedup pool.
    ///
    /// A non-deduped extent (or a zero-length one) is freed immediately.  A
    /// deduped extent decrements its refcount and is only freed when the last
    /// reference goes away (the hash map entry is purged at the same time).
    pub(crate) fn release_inode_extent(
        &self,
        state: &mut SimpleFsState,
        data_block: usize,
        block_count: usize,
        deduped: bool,
    ) {
        if !deduped || block_count == 0 {
            self.mark_extent_free(state, data_block, block_count);
            return;
        }
        let key = (data_block as u32, block_count as u32);
        if let Some(count) = state.dedup_refcounts.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.dedup_refcounts.remove(&key);
                state.dedup_hash_to_extents.retain(|_, extents| {
                    extents.retain(|&(db, bc, _)| (db, bc) != key);
                    !extents.is_empty()
                });
                self.mark_extent_free(state, data_block, block_count);
            }
        } else {
            // No pool entry (shouldn't happen for a deduped inode) — free the
            // extent defensively so it is never leaked.
            self.mark_extent_free(state, data_block, block_count);
        }
    }

    /// Remove `[start, start+count)` from the free extent map.
    pub(crate) fn mark_extent_allocated(
        &self,
        state: &mut SimpleFsState,
        start: usize,
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        state.save_free_extents_for_undo();
        if let Some(&free_count) = state.free_data_extents.get(&start) {
            if free_count == count {
                state.free_data_extents.remove(&start);
            } else if free_count > count {
                state.free_data_extents.remove(&start);
                state
                    .free_data_extents
                    .insert(start + count, free_count - count);
            }
        }
    }

    /// Return `[start, start+count)` to the free extent map, merging with
    /// adjacent free extents.
    pub(crate) fn mark_extent_free(&self, state: &mut SimpleFsState, start: usize, count: usize) {
        if count == 0 {
            return;
        }
        state.save_free_extents_for_undo();

        // Clamp to the data area.
        let data_start = self.data_block_start;
        let clamped_start = start.max(data_start);
        if clamped_start < data_start {
            return;
        }
        let clamped_end = start
            .saturating_add(count)
            .min(self.device.block_count() as usize);
        if clamped_end <= clamped_start {
            return;
        }
        let mut new_start = clamped_start;
        let mut new_count = clamped_end - clamped_start;

        // Merge with a preceding extent that touches us.
        let prev_key = state
            .free_data_extents
            .range(..new_start)
            .next_back()
            .filter(|(&k, &c)| k + c == new_start)
            .map(|(&k, _)| k);
        if let Some(pk) = prev_key {
            let pc = state.free_data_extents.remove(&pk).unwrap_or(0);
            new_start = pk;
            new_count += pc;
        }

        // Merge with a following extent that touches us.
        let next_key = state
            .free_data_extents
            .range(new_start..)
            .next()
            .filter(|(&k, _)| k == new_start + new_count)
            .map(|(&k, _)| k);
        if let Some(nk) = next_key {
            let nc = state.free_data_extents.remove(&nk).unwrap_or(0);
            new_count += nc;
        }

        state.free_data_extents.insert(new_start, new_count);
    }

    pub(crate) fn find_free_data_block_span(
        &self,
        state: &SimpleFsState,
        required_blocks: usize,
        skip_inode: Option<usize>,
    ) -> Result<usize> {
        if required_blocks == 0 {
            return Ok(self.data_block_start);
        }

        // Try in-place extension for an existing inode (O(log n) via BTreeMap).
        if let Some(skip_index) = skip_inode {
            if let Some(inode) = state.inodes.get(skip_index) {
                if !inode.deleted && inode.kind != NodeKind::Directory && inode.block_count > 0 {
                    let preferred_start = inode.data_block as usize;
                    let current_blocks = inode.block_count as usize;
                    let extend_start = preferred_start + current_blocks;
                    let extend_count = required_blocks.saturating_sub(current_blocks);
                    if let Some(&free_count) = state.free_data_extents.get(&extend_start) {
                        if free_count >= extend_count {
                            let preferred_end = preferred_start + required_blocks;
                            if preferred_end <= self.device.block_count() as usize {
                                return Ok(preferred_start);
                            }
                        }
                    }
                }
            }
        }

        // Best-fit: scan all free extents and pick the smallest sufficient one.
        // This reduces fragmentation by preserving larger extents for future
        // allocations that may need them.
        let device_end = self.device.block_count() as usize;
        let mut best: Option<(usize, usize)> = None;
        for (&start, &count) in &state.free_data_extents {
            if count >= required_blocks
                && start.saturating_add(required_blocks) <= device_end
                && best.is_none_or(|(_, best_count)| count < best_count)
            {
                best = Some((start, count));
            }
        }
        if let Some((start, _)) = best {
            return Ok(start);
        }

        Err(Error::OutOfMemory)
    }

    /// Flush in-memory metadata to disk using a two-phase commit protocol.
    ///
    /// Phase 1 — Mark: write `pending_commit = target_generation` to both
    /// superblock mirrors so a crash during the write is detectable on next
    /// mount.  The superblock still points to the **current** active tables.
    ///
    /// Phase 2 — Write: flush dirty shadow metadata tables (inode then dirent).
    ///
    /// Phase 3 — Publish: write both superblock mirrors with swapped
    /// active/shadow pointers, the bumped generation, and `pending_commit`
    /// cleared.  Only after both superblocks are written does the in-memory
    /// state swap.
    ///
    /// On mount, if either superblock has `pending_commit != 0`, the shadow
    /// tables may be corrupt and the active tables are used instead;
    /// [`check_and_repair`] clears the stale flag.
    pub(crate) fn flush_metadata(&self, state: &mut SimpleFsState) -> Result<()> {
        self.profiler.inc_metadata_flushes();

        let image = self.runtime_metadata_image(state);
        let next_generation = state
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidArgument)?;

        // Phase 1: Mark pending commit on both superblock mirrors (V3+ only).
        // The superblock still references the current active tables;
        // only `pending_commit` is set to signal an in-progress commit.
        // V2 does not have a pending_commit field, so we skip this phase
        // to avoid unnecessary writes and preserve the V2 write sequence.
        if self
            .format_version
            .persistent_security_descriptor_layout()
            .is_some()
        {
            let pending_record = SuperblockRecord {
                pending_commit: next_generation,
                ..self.runtime_superblock_record(state)
            };
            let mut pending_sb = [0_u8; BLOCK_SIZE];
            write_superblock(
                &mut pending_sb,
                &self.label,
                self.format_version,
                pending_record,
            );
            self.write_blocks_cached(SECONDARY_SUPERBLOCK_BLOCK as u64, &pending_sb)?;
            self.write_blocks_cached(PRIMARY_SUPERBLOCK_BLOCK as u64, &pending_sb)?;
        }

        // Phase 2: Write shadow metadata tables.
        // All tables are always written so that after the pointer swap
        // both shadow slots contain a consistent copy of the current
        // metadata.  The `inode_table_dirty` / `dirent_table_dirty` flags
        // and `needs_shadow_sync` are maintained for a future write-skipping
        // optimisation; see the field-level docs on [`SimpleFsState`].
        self.write_blocks_cached(state.shadow_inode_table_block as u64, &image.inode_table)?;
        self.write_blocks_cached(state.shadow_dirent_table_block as u64, &image.dirent_table)?;
        // V4+: the shadow xattr table is part of the same atomic slot.  It is
        // gated on the format so V2/V3 write sequences stay byte-identical
        // (crash tests hard-code the absolute write-call indices).
        if self.format_version.supports_persistent_xattrs() {
            self.write_blocks_cached(state.shadow_xattr_table_block as u64, &image.xattr_table)?;
        }

        // Phase 3: Publish — swap active/shadow, bump generation, clear
        // pending_commit.  The old active slot becomes the new shadow slot.
        {
            let publish_record = SuperblockRecord {
                active_inode_table_block: state.shadow_inode_table_block,
                active_dirent_table_block: state.shadow_dirent_table_block,
                shadow_inode_table_block: state.active_inode_table_block,
                shadow_dirent_table_block: state.active_dirent_table_block,
                generation: next_generation,
                pending_commit: 0,
                active_xattr_table_block: state.shadow_xattr_table_block,
                shadow_xattr_table_block: state.active_xattr_table_block,
                ..self.runtime_superblock_record(state)
            };
            let mut publish_sb = [0_u8; BLOCK_SIZE];
            write_superblock(
                &mut publish_sb,
                &self.label,
                self.format_version,
                publish_record,
            );
            self.write_blocks_cached(SECONDARY_SUPERBLOCK_BLOCK as u64, &publish_sb)?;
            self.write_blocks_cached(PRIMARY_SUPERBLOCK_BLOCK as u64, &publish_sb)?;
        }

        // Update in-memory state only after all writes succeed.
        core::mem::swap(
            &mut state.active_inode_table_block,
            &mut state.shadow_inode_table_block,
        );
        core::mem::swap(
            &mut state.active_dirent_table_block,
            &mut state.shadow_dirent_table_block,
        );
        core::mem::swap(
            &mut state.active_xattr_table_block,
            &mut state.shadow_xattr_table_block,
        );
        state.generation = next_generation;
        state.inode_table_dirty = false;
        state.dirent_table_dirty = false;
        state.xattr_table_dirty = false;
        state.needs_shadow_sync = false;
        Ok(())
    }

    pub(crate) fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let state = self.state.lock().clone();
        self.validate_runtime_state(&state)?;
        let health = self.inspect_runtime_health(&state);

        // Run orphan and integrity diagnostics alongside the metadata slot
        // check so the caller gets a single unified health report.
        let orphan_data_blocks = count_unreferenced_data_blocks(
            self.data_block_start,
            self.device.block_count() as usize,
            &state.inodes,
        );
        let checksum_failures = self.count_checksum_failures_locked(&state);

        // Clean up orphaned staging entries before metadata repair so that
        // any staging directories left by a crash are removed.
        let staging_orphans_cleaned = self.cleanup_staging_orphans_locked(&state);

        // Zero out orphan data blocks so stale file content cannot be
        // recovered.  This is done before the health check so the report
        // reflects what was cleaned regardless of metadata health.
        let orphan_blocks_cleaned = if orphan_data_blocks > 0 {
            self.cleanup_orphan_data_blocks_locked(&state)
        } else {
            0
        };

        // Count superblock slots that don't match the expected runtime
        // state — each mismatch represents an interrupted commit that left
        // one superblock mirror stale.  Also explicitly check the
        // pending_commit field on both superblock mirrors for V3+ formats:
        // a non-zero value means a crash occurred mid-commit (between
        // Phase 1 mark and Phase 3 publish of the two-phase protocol).
        let mut interrupted_commits = usize::from(!health.primary_superblock_matches)
            + usize::from(!health.secondary_superblock_matches);
        if self
            .format_version
            .persistent_security_descriptor_layout()
            .is_some()
        {
            interrupted_commits += self.count_pending_commit_on_disk();
        }

        if health.is_clean() {
            // Orphan data blocks were zeroed on disk but the in-memory
            // free-extent map was not updated.  Rebuild it so the freed
            // blocks are available for allocation during this mount.
            if orphan_blocks_cleaned > 0 {
                let mut live_state = self.state.lock();
                self.rebuild_free_data_extents(&mut live_state);
            }
            return Ok(health.report(
                orphan_data_blocks,
                checksum_failures,
                staging_orphans_cleaned,
                orphan_blocks_cleaned,
                interrupted_commits,
            ));
        }

        // A no-op commit republishes the current in-memory tree into the
        // inactive slot and rewrites both mirrored superblocks. Running it up
        // to twice repairs whichever slot was stale or torn.
        for _ in 0..2 {
            self.commit_metadata_update(|state| {
                // Force the metadata tables dirty so the shadow slot is fully
                // rewritten, including the V4+ xattr table.
                state.dirent_table_dirty = true;
                if self.format_version.supports_persistent_xattrs() {
                    state.xattr_table_dirty = true;
                }
                // Rebuild free extents from current inode table state so that
                // any blocks zeroed by orphan/staging cleanup are tracked.
                self.rebuild_free_data_extents(state);
                Ok(())
            })?;
            let state = self.state.lock().clone();
            let post_repair = self.inspect_runtime_health(&state);
            if post_repair.is_clean() {
                return Ok(health.repaired_report(
                    post_repair,
                    orphan_data_blocks,
                    checksum_failures,
                    staging_orphans_cleaned,
                    orphan_blocks_cleaned,
                    interrupted_commits,
                ));
            }
        }

        Err(Error::InternalError)
    }

    /// Count checksum failures without taking the state lock (caller holds
    /// the cloned state or already released the lock). Read errors are
    /// conservatively counted as failures.
    pub(crate) fn count_checksum_failures_locked(&self, state: &SimpleFsState) -> usize {
        let mut failures = 0_usize;
        for inode in &state.inodes {
            if inode.deleted || inode.kind != NodeKind::File || inode.size == 0 {
                continue;
            }
            if inode.data_checksum == 0 {
                continue;
            }
            let size = inode.size as usize;
            let block_count = inode.block_count as usize;
            if block_count == 0 {
                continue;
            }
            let mut contents = vec![0_u8; block_count * BLOCK_SIZE];
            if self
                .device
                .read_blocks(inode.data_block as u64, &mut contents)
                .is_err()
            {
                failures += 1;
                continue;
            }
            if compute_data_checksum(&contents[..size]) != inode.data_checksum {
                failures += 1;
            }
        }
        failures
    }

    /// Count superblock mirrors that carry a non-zero `pending_commit`.
    /// Only meaningful for V3+ formats; returns 0 for V2.
    pub(crate) fn count_pending_commit_on_disk(&self) -> usize {
        let mut count = 0_usize;
        for &block in &[PRIMARY_SUPERBLOCK_BLOCK, SECONDARY_SUPERBLOCK_BLOCK] {
            if let Ok((_label, parsed)) = read_superblock_record(&*self.device, block) {
                if parsed.record.pending_commit != 0 {
                    count += 1;
                }
            }
        }
        count
    }

    pub(crate) fn inspect_runtime_health(&self, state: &SimpleFsState) -> RuntimeHealthSnapshot {
        let expected = self.runtime_superblock_record(state);
        let metadata_image = self.runtime_metadata_image(state);
        RuntimeHealthSnapshot {
            primary_superblock_matches: self
                .superblock_matches_expected(PRIMARY_SUPERBLOCK_BLOCK, expected),
            secondary_superblock_matches: self
                .superblock_matches_expected(SECONDARY_SUPERBLOCK_BLOCK, expected),
            active_metadata_matches: self.metadata_slot_matches(
                state.active_inode_table_block,
                state.active_dirent_table_block,
                state.active_xattr_table_block,
                &metadata_image,
            ),
            shadow_metadata_matches: self.metadata_slot_matches(
                state.shadow_inode_table_block,
                state.shadow_dirent_table_block,
                state.shadow_xattr_table_block,
                &metadata_image,
            ),
        }
    }

    /// Count data blocks in `[data_block_start, max_referenced_end)` that are
    /// not referenced by any live (non-deleted) inode.  Blocks beyond the
    /// highest inode reference are treated as free space rather than orphans.
    ///
    /// Count unreferenced data blocks in the given range using the supplied
    /// inode list.  Only scans up to the highest live inode reference so that
    /// blocks beyond the last allocation are treated as free space.
    pub(crate) fn count_orphan_data_blocks(&self) -> usize {
        let state = self.state.lock();
        count_unreferenced_data_blocks(
            self.data_block_start,
            self.device.block_count() as usize,
            &state.inodes,
        )
    }

    /// Register a staging root path so that [`check_and_repair`] can
    /// automatically clean up orphaned staging entries on boot.
    /// Duplicate registrations are silently ignored.
    pub(crate) fn register_staging_root(&self, path: &str) {
        let mut state = self.state.lock();
        if !state.staging_roots.iter().any(|r| r == path) {
            state.staging_roots.push(path.to_string());
        }
    }

    /// Clean up orphaned staging entries across all registered staging roots.
    ///
    /// Called from [`check_and_repair`] with a cloned snapshot of the state.
    /// Uses the snapshot to enumerate orphaned entries, then removes each
    /// one via [`remove_path_recursive`] which operates on the live state.
    /// Returns the total number of orphaned entries removed.
    pub(crate) fn cleanup_staging_orphans_locked(&self, state: &SimpleFsState) -> usize {
        let mut cleaned = 0_usize;
        for root in &state.staging_roots {
            let staging_index = match self.lookup_index_locked(state, root) {
                Ok(idx) => idx,
                Err(_) => continue,
            };
            let staging_inode = match state.inodes.get(staging_index) {
                Some(inode) if inode.kind == NodeKind::Directory => inode,
                _ => continue,
            };

            // Collect names from the snapshot before any mutation.
            let entry_start = staging_inode.entry_start as usize;
            let entry_count = staging_inode.entry_count as usize;
            let names: Vec<String> = (0..entry_count)
                .filter_map(|i| state.dir_entries.get(entry_start + i))
                .map(|e| e.name.clone())
                .collect();

            for name in &names {
                let path = format!("{}/{}", root, name);
                // remove_path_recursive acquires the lock independently.
                if self.remove_path_recursive(&path).is_ok() {
                    cleaned += 1;
                }
            }
        }
        cleaned
    }

    /// Zero out orphan data blocks so that stale file content cannot be
    /// recovered.  Uses the supplied snapshot to identify unreferenced
    /// blocks, then writes zeroes to each one.
    ///
    /// Returns the number of blocks that were zeroed.
    pub(crate) fn cleanup_orphan_data_blocks_locked(&self, state: &SimpleFsState) -> usize {
        let data_start = self.data_block_start;
        let total_blocks = self.device.block_count() as usize;

        // Build a referenced bitmap using the same logic as
        // count_unreferenced_data_blocks.
        let max_referenced = state
            .inodes
            .iter()
            .filter(|inode| !inode.deleted && inode.block_count > 0)
            .map(|inode| (inode.data_block as usize).saturating_add(inode.block_count as usize))
            .max()
            .unwrap_or(data_start);

        if max_referenced <= data_start {
            return 0;
        }

        let scan_blocks = max_referenced.saturating_sub(data_start);
        let mut referenced = alloc::vec![false; scan_blocks];

        for inode in &state.inodes {
            if inode.deleted || inode.block_count == 0 {
                continue;
            }
            let start = inode.data_block as usize;
            let end = start.saturating_add(inode.block_count as usize);
            if start < data_start || end > total_blocks {
                continue;
            }
            let rel_start = start.saturating_sub(data_start);
            let rel_end = end.saturating_sub(data_start).min(scan_blocks);
            for slot in referenced.iter_mut().take(rel_end).skip(rel_start) {
                *slot = true;
            }
        }

        // Zero out each unreferenced block.
        let zero_block = vec![0_u8; BLOCK_SIZE];
        let mut cleaned = 0_usize;
        for (i, &is_ref) in referenced.iter().enumerate() {
            if !is_ref {
                let lba = (data_start + i) as u64;
                if self.device.write_blocks(lba, &zero_block).is_ok() {
                    cleaned += 1;
                }
            }
        }
        cleaned
    }

    /// Verify stored data checksums against current file content for all
    /// live non-empty file inodes. Returns a pair of (files_checked, failures).
    /// Inodes with checksum 0 (not yet computed) are skipped.
    pub(crate) fn check_data_integrity(&self) -> Result<(usize, usize)> {
        let state = self.state.lock();
        let mut files_checked = 0_usize;
        for inode in &state.inodes {
            if !inode.deleted
                && inode.kind == NodeKind::File
                && inode.size != 0
                && inode.data_checksum != 0
            {
                files_checked += 1;
            }
        }
        let failures = self.count_checksum_failures_locked(&state);
        Ok((files_checked, failures))
    }

    pub(crate) fn device_health(&self) -> DeviceHealth {
        self.device.device_health()
    }

    pub(crate) fn runtime_superblock_record(&self, state: &SimpleFsState) -> SuperblockRecord {
        SuperblockRecord {
            inode_count: state.inodes.len(),
            dirent_count: state.dir_entries.len(),
            active_inode_table_block: state.active_inode_table_block,
            active_dirent_table_block: state.active_dirent_table_block,
            shadow_inode_table_block: state.shadow_inode_table_block,
            shadow_dirent_table_block: state.shadow_dirent_table_block,
            inode_table_blocks: self.inode_table_blocks,
            dirent_table_blocks: self.dirent_table_blocks,
            data_block_start: self.data_block_start,
            generation: state.generation,
            pending_commit: 0,
            active_xattr_table_block: state.active_xattr_table_block,
            shadow_xattr_table_block: state.shadow_xattr_table_block,
            xattr_table_blocks: self.xattr_table_blocks,
            xattr_count: state.xattrs.len(),
        }
    }

    pub(crate) fn validate_runtime_state(&self, state: &SimpleFsState) -> Result<()> {
        if state.inodes.len() > self.inode_capacity
            || state.dir_entries.len() > self.dirent_capacity
        {
            return Err(Error::InternalError);
        }

        validate_superblock_record(self.runtime_superblock_record(state))
            .map_err(|_| Error::InternalError)?;
        validate_loaded_metadata(
            &state.inodes,
            &state.dir_entries,
            self.format_version,
            self.data_block_start,
            self.device.block_count() as usize,
            self.case_sensitive,
        )
        .map_err(|_| Error::InternalError)
    }

    pub(crate) fn superblock_matches_expected(
        &self,
        block_index: usize,
        expected: SuperblockRecord,
    ) -> bool {
        match read_superblock_record(&*self.device, block_index) {
            Ok((label, parsed_superblock)) => {
                label == self.label
                    && parsed_superblock.format_version == self.format_version
                    && parsed_superblock.record == expected
            }
            Err(_) => false,
        }
    }

    pub(crate) fn metadata_slot_matches(
        &self,
        inode_table_block: usize,
        dirent_table_block: usize,
        xattr_table_block: usize,
        expected: &RuntimeMetadataImage,
    ) -> bool {
        let mut actual_inode_table = vec![0_u8; expected.inode_table.len()];
        if self
            .device
            .read_blocks(inode_table_block as u64, &mut actual_inode_table)
            .is_err()
        {
            return false;
        }
        if actual_inode_table != expected.inode_table {
            return false;
        }

        let mut actual_dirent_table = vec![0_u8; expected.dirent_table.len()];
        if self
            .device
            .read_blocks(dirent_table_block as u64, &mut actual_dirent_table)
            .is_err()
        {
            return false;
        }
        if actual_dirent_table != expected.dirent_table {
            return false;
        }

        // V4+: the xattr table is part of the metadata slot.
        if !expected.xattr_table.is_empty() {
            let mut actual_xattr_table = vec![0_u8; expected.xattr_table.len()];
            if self
                .device
                .read_blocks(xattr_table_block as u64, &mut actual_xattr_table)
                .is_err()
            {
                return false;
            }
            if actual_xattr_table != expected.xattr_table {
                return false;
            }
        }

        true
    }

    pub(crate) fn runtime_metadata_image(&self, state: &SimpleFsState) -> RuntimeMetadataImage {
        let mut inode_table = vec![0_u8; self.inode_table_blocks * BLOCK_SIZE];
        write_runtime_inode_table(&mut inode_table, self.format_version, 0, &state.inodes)
            .expect("simplefs runtime inode table geometry should stay valid");

        let mut dirent_table = vec![0_u8; self.dirent_table_blocks * BLOCK_SIZE];
        write_runtime_dir_entry_table(
            &mut dirent_table,
            self.format_version,
            0,
            &state.dir_entries,
        )
        .expect("simplefs runtime dirent table geometry should stay valid");

        // V4+: serialize the xattr table into its shadow slot geometry.
        let xattr_table = if self.format_version.supports_persistent_xattrs() {
            let mut table = vec![0_u8; self.xattr_table_blocks * BLOCK_SIZE];
            write_runtime_xattr_table(&mut table, self.format_version, 0, &state.xattrs)
                .expect("simplefs runtime xattr table geometry should stay valid");
            table
        } else {
            Vec::new()
        };

        RuntimeMetadataImage {
            inode_table,
            dirent_table,
            xattr_table,
        }
    }
}
