//! src/kernel/fs/simplefs/fs.rs
//! SimpleFs core implementation: path lookup, metadata accessors, and the
//! locked directory-entry / inode-slot primitives.
//!
//! These methods are recovered from the original adastra-kernel simplefs
//! `fs.rs`; the current tree splits the original file across `path.rs`,
//! `transaction.rs`, `dir_ops.rs`, `vfs.rs`, and this file.

use alloc::string::{String, ToString};

use crate::{Error, Result};

use super::super::vfs::{Metadata, NodeKind};
use super::types::{OnDiskDirEntry, OnDiskInode};
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    /// Resolve a path to an inode index without following symlinks.
    pub(crate) fn lookup_index(&self, path: &str) -> Result<usize> {
        if path.is_empty() || path == "/" {
            return Ok(0);
        }

        let state = self.state.lock();
        let mut current = 0_usize;
        for segment in path.trim_matches('/').split('/') {
            current = self.find_child(&state, current, segment)?;
        }

        self.profiler.inc_lookups();
        Ok(current)
    }

    /// Like [`lookup_index`] but follows symlinks during path resolution.
    pub(crate) fn resolve_path(&self, path: &str) -> Result<usize> {
        let state = self.state.lock();
        self.resolve_path_locked(&state, path)
    }

    /// Build [`Metadata`] from an inode, attaching its persistent security
    /// descriptor when one is present.
    pub(crate) fn metadata_from_inode(&self, inode: OnDiskInode) -> Metadata {
        let metadata = Metadata::new(
            inode.kind,
            match inode.kind {
                NodeKind::Directory => inode.entry_count as usize,
                NodeKind::File | NodeKind::Device | NodeKind::Symlink => inode.size as usize,
            },
        );

        match inode.runtime_security_descriptor() {
            Some(security) => metadata.with_security(security),
            None => metadata,
        }
    }

    pub(crate) fn name_of(&self, index: usize) -> String {
        if index == 0 {
            return "/".to_string();
        }

        let state = self.state.lock();
        // Use the inode_to_entry_index reverse map for O(1) dirent lookup
        // instead of scanning the parent directory's entries linearly.
        if let Some(&Some(entry_idx)) = state.inode_to_entry_index.get(index) {
            if let Some(entry) = state.dir_entries.get(entry_idx) {
                return entry.name.clone();
            }
        }

        "?".to_string()
    }

    pub(crate) fn kind_of(&self, index: usize) -> NodeKind {
        self.state
            .lock()
            .inodes
            .get(index)
            .map(|inode| inode.kind)
            .unwrap_or(NodeKind::File)
    }

    pub(crate) fn size_of(&self, index: usize) -> usize {
        self.state
            .lock()
            .inodes
            .get(index)
            .map(|inode| inode.size as usize)
            .unwrap_or(0)
    }

    pub(crate) fn metadata_of(&self, index: usize) -> Result<Metadata> {
        let state = self.state.lock();
        let inode = *state.inodes.get(index).ok_or(Error::InternalError)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }

        Ok(self.metadata_from_inode(inode))
    }

    /// Resolve a path to an inode index under an already-held state lock,
    /// without following symlinks.
    pub(crate) fn lookup_index_locked(&self, state: &SimpleFsState, path: &str) -> Result<usize> {
        if path.is_empty() || path == "/" {
            return Ok(0);
        }

        let mut current = 0_usize;
        for segment in path.trim_matches('/').split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            if segment == ".." {
                // Walk up to parent, or stay at root.
                current = state.parent_of.get(current).copied().flatten().unwrap_or(0);
                continue;
            }
            current = self.find_child(state, current, segment)?;
        }

        Ok(current)
    }

    pub(crate) fn parent_index_of_locked(
        &self,
        state: &SimpleFsState,
        child_index: usize,
    ) -> Result<Option<usize>> {
        if child_index == 0 {
            return Ok(None);
        }

        state
            .parent_of
            .get(child_index)
            .copied()
            .flatten()
            .map_or(Err(Error::InternalError), |p| Ok(Some(p)))
    }

    pub(crate) fn is_descendant_index_locked(
        &self,
        state: &SimpleFsState,
        candidate_index: usize,
        ancestor_index: usize,
    ) -> Result<bool> {
        let mut current = Some(candidate_index);
        while let Some(index) = current {
            if index == ancestor_index {
                return Ok(true);
            }

            current = self.parent_index_of_locked(state, index)?;
        }

        Ok(false)
    }

    /// Insert a directory entry into a parent directory, maintaining the
    /// reverse parent index, the inode→entry reverse index, and directory
    /// `entry_start`/`entry_count` invariants.  Must be called under a
    /// metadata transaction.
    pub(crate) fn insert_dir_entry_locked(
        &self,
        state: &mut SimpleFsState,
        parent_index: usize,
        entry: OnDiskDirEntry,
    ) -> Result<()> {
        state.save_all_dirents_and_dir_inodes_for_undo();
        if state.dir_entries.len() >= self.dirent_capacity {
            return Err(Error::OutOfMemory);
        }

        let parent_inode = state
            .inodes
            .get(parent_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if parent_inode.kind != NodeKind::Directory || parent_inode.deleted {
            return Err(Error::InvalidArgument);
        }

        let insert_at = parent_inode.entry_start as usize + parent_inode.entry_count as usize;
        let child_inode_index = entry.inode_index as usize;
        state.dir_entries.insert(insert_at, entry);
        state.dirent_table_dirty = true;

        // Update the reverse parent index for the newly inserted child.
        if child_inode_index < state.parent_of.len() {
            state.save_parent_of_for_undo(child_inode_index);
            state.parent_of[child_inode_index] = Some(parent_index);
        }

        // Maintain the inode→entry reverse index: set the new entry's
        // position and shift all entries at or past the insertion point.
        if child_inode_index < state.inode_to_entry_index.len() {
            state.inode_to_entry_index[child_inode_index] = Some(insert_at);
        }
        for pos in state.inode_to_entry_index.iter_mut().flatten() {
            if *pos >= insert_at {
                *pos += 1;
            }
        }

        // Update only directory inodes — O(num_dirs) instead of O(all_inodes).
        for &dir_idx in &state.dir_inode_indices {
            let inode = &mut state.inodes[dir_idx];
            if dir_idx == parent_index {
                inode.entry_count += 1;
            } else if inode.entry_start as usize >= insert_at {
                inode.entry_start += 1;
            }
        }
        state.inode_table_dirty = true;

        Ok(())
    }

    /// Remove a directory entry, returning it, and maintain the reverse
    /// parent index / inode→entry reverse index invariants.  Must be called
    /// under a metadata transaction.
    pub(crate) fn remove_dir_entry_locked(
        &self,
        state: &mut SimpleFsState,
        parent_index: usize,
        entry_index: usize,
    ) -> Result<OnDiskDirEntry> {
        state.save_all_dirents_and_dir_inodes_for_undo();
        let parent_inode = state
            .inodes
            .get(parent_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if parent_inode.kind != NodeKind::Directory || parent_inode.deleted {
            return Err(Error::InvalidArgument);
        }
        let entry_start = parent_inode.entry_start as usize;
        let entry_end = entry_start
            .checked_add(parent_inode.entry_count as usize)
            .ok_or(Error::InternalError)?;
        if entry_index < entry_start || entry_index >= entry_end {
            return Err(Error::InternalError);
        }

        let removed = state.dir_entries.remove(entry_index);
        state.dirent_table_dirty = true;

        // Clear the reverse parent index for the removed child.
        let child_idx = removed.inode_index as usize;
        if child_idx < state.parent_of.len() {
            state.save_parent_of_for_undo(child_idx);
            state.parent_of[child_idx] = None;
        }

        // Maintain the inode→entry reverse index: clear the removed entry's
        // position and shift all entries past the removal point.
        if child_idx < state.inode_to_entry_index.len() {
            state.inode_to_entry_index[child_idx] = None;
        }
        for pos in state.inode_to_entry_index.iter_mut().flatten() {
            if *pos > entry_index {
                *pos -= 1;
            }
        }

        // Update only directory inodes — O(num_dirs) instead of O(all_inodes).
        for &dir_idx in &state.dir_inode_indices {
            let inode = &mut state.inodes[dir_idx];
            if dir_idx == parent_index {
                inode.entry_count = inode.entry_count.saturating_sub(1);
            } else if inode.entry_start as usize > entry_index {
                inode.entry_start -= 1;
            }
        }

        Ok(removed)
    }

    pub(crate) fn has_available_inode_slot(&self, state: &SimpleFsState) -> bool {
        !state.free_inode_slots.is_empty() || state.inodes.len() < self.inode_capacity
    }

    /// Allocate (or recycle) an inode slot, writing `inode` into it.  Must be
    /// called under a metadata transaction so the slot allocation is undone
    /// if the enclosing transaction rolls back.
    pub(crate) fn allocate_inode_slot(
        &self,
        state: &mut SimpleFsState,
        inode: OnDiskInode,
    ) -> Result<usize> {
        state.save_free_slots_for_undo();
        state.save_dir_indices_for_undo();
        let is_dir = inode.kind == NodeKind::Directory;
        let index = if let Some(free_idx) = state.free_inode_slots.pop() {
            // Save old inode before mutable borrow to avoid borrow conflict.
            state.save_inode_for_undo(free_idx);
            if let Some(slot) = state.inodes.get_mut(free_idx) {
                // If the recycled slot was a directory, remove it from dir_inode_indices.
                if slot.kind == NodeKind::Directory && !slot.deleted {
                    if let Some(pos) = state.dir_inode_indices.iter().position(|&i| i == free_idx) {
                        state.dir_inode_indices.remove(pos);
                    }
                }
                *slot = inode;
                state.inode_table_dirty = true;
                // Clear any stale parent_of and entry index from the previous occupant.
                if free_idx < state.parent_of.len() {
                    state.save_parent_of_for_undo(free_idx);
                    state.parent_of[free_idx] = None;
                }
                if free_idx < state.inode_to_entry_index.len() {
                    state.inode_to_entry_index[free_idx] = None;
                }
                free_idx
            } else {
                return Err(Error::InternalError);
            }
        } else {
            if state.inodes.len() >= self.inode_capacity {
                return Err(Error::OutOfMemory);
            }
            state.save_inodes_len_for_undo();
            let idx = state.inodes.len();
            state.inodes.push(inode);
            state.parent_of.push(None);
            state.inode_to_entry_index.push(None);
            state.inode_table_dirty = true;
            idx
        };

        if is_dir {
            state.dir_inode_indices.push(index);
        }
        Ok(index)
    }
}
