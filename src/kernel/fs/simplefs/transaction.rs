//! src/kernel/fs/simplefs/transaction.rs
//!
//! Undo-log based transaction support for SimpleFs metadata mutations.

use alloc::string::ToString;

use crate::{Error, Result};

use super::super::vfs::{
    NodeKind, SecurityDescriptor, DEFAULT_DIRECTORY_MODE, MAX_PERMISSION_MODE, ROOT_GROUP_ID,
    ROOT_OWNER_ID,
};

use super::free_fns::*;
use super::types::*;
use super::{SimpleFs, SimpleFsState, UndoLog};

impl SimpleFsState {
    /// Clear the undo log at the start of a commit.  Saves the current dirty
    /// flags so rollback can restore them regardless of what the closure sets.
    pub(crate) fn begin_undo(&mut self) {
        self.undo = UndoLog::default();
        self.undo.old_inode_table_dirty = Some(self.inode_table_dirty);
        self.undo.old_dirent_table_dirty = Some(self.dirent_table_dirty);
    }

    /// Save an inode's current value before mutation, for rollback on error.
    pub(crate) fn save_inode_for_undo(&mut self, index: usize) {
        if let Some(inode) = self.inodes.get(index).copied() {
            self.undo.inodes.push((index, inode));
        }
    }

    /// Save a dirent's current value before mutation, for rollback on error.
    pub(crate) fn save_dirent_for_undo(&mut self, index: usize) {
        if let Some(entry) = self.dir_entries.get(index) {
            self.undo.dirents.push((index, entry.clone()));
        }
    }

    /// Save a parent_of entry before mutation.
    pub(crate) fn save_parent_of_for_undo(&mut self, index: usize) {
        if let Some(val) = self.parent_of.get(index).copied() {
            self.undo.parent_of.push((index, val));
        }
    }

    /// Save an xattr record before mutation, for rollback on error (V4+).
    pub(crate) fn save_xattr_for_undo(&mut self, index: usize) {
        if let Some(xattr) = self.xattrs.get(index).copied() {
            self.undo.xattrs.push((index, xattr));
        }
    }

    /// Lazily save `xattrs.len()` before the first push in a commit.
    pub(crate) fn save_xattr_len_for_undo(&mut self) {
        if self.undo.xattr_len.is_none() {
            self.undo.xattr_len = Some(self.xattrs.len());
        }
    }

    /// Lazily save `free_data_extents` before the first mutation in a commit.
    pub(crate) fn save_free_extents_for_undo(&mut self) {
        if self.undo.free_data_extents.is_none() {
            self.undo.free_data_extents = Some(self.free_data_extents.clone());
        }
    }

    /// Lazily save `free_inode_slots` before the first mutation in a commit.
    pub(crate) fn save_free_slots_for_undo(&mut self) {
        if self.undo.free_inode_slots.is_none() {
            self.undo.free_inode_slots = Some(self.free_inode_slots.clone());
        }
    }

    /// Lazily save `dir_inode_indices` before the first mutation in a commit.
    pub(crate) fn save_dir_indices_for_undo(&mut self) {
        if self.undo.dir_inode_indices.is_none() {
            self.undo.dir_inode_indices = Some(self.dir_inode_indices.clone());
        }
    }

    /// Lazily save `staging_roots` length before the first push in a commit.
    #[allow(dead_code)]
    pub(crate) fn save_staging_roots_len_for_undo(&mut self) {
        if self.undo.staging_roots_len.is_none() {
            self.undo.staging_roots_len = Some(self.staging_roots.len());
        }
    }

    /// Lazily save the full `dir_entries` vector and all directory inodes
    /// before the first insert/remove within a commit.  Insert/remove shifts
    /// entries and indices, so per-entry undo isn't sufficient.
    pub(crate) fn save_all_dirents_and_dir_inodes_for_undo(&mut self) {
        if self.undo.all_dirents.is_none() {
            self.undo.all_dirents = Some(self.dir_entries.clone());
            // Also save all directory inodes whose entry_start/entry_count may
            // be shifted by the insert/remove, and the inode→entry reverse index.
            for &dir_idx in &self.dir_inode_indices {
                if let Some(inode) = self.inodes.get(dir_idx).copied() {
                    self.undo.inodes.push((dir_idx, inode));
                }
            }
            self.undo.all_inode_to_entry_index = Some(self.inode_to_entry_index.clone());
        }
    }

    /// Lazily save `inodes.len()` and `parent_of.len()` before a push (new
    /// inode allocation).  On rollback the vectors are truncated to these
    /// lengths, removing orphan allocations.
    pub(crate) fn save_inodes_len_for_undo(&mut self) {
        if self.undo.inodes_len.is_none() {
            self.undo.inodes_len = Some(self.inodes.len());
            self.undo.parent_of_len = Some(self.parent_of.len());
            self.undo.inode_to_entry_index_len = Some(self.inode_to_entry_index.len());
        }
    }

    /// Lazily save dirty flags before any modification in a commit.
    #[allow(dead_code)]
    pub(crate) fn save_dirty_flags_for_undo(&mut self) {
        if self.undo.old_inode_table_dirty.is_none() {
            self.undo.old_inode_table_dirty = Some(self.inode_table_dirty);
            self.undo.old_dirent_table_dirty = Some(self.dirent_table_dirty);
        }
    }

    /// Rollback all mutations recorded in the undo log.  LIFO order ensures
    /// that dependent mutations are unwound correctly.
    pub(crate) fn rollback_undo(&mut self) {
        // ── Full dirent-table restore (saved on first insert/remove) ──
        if let Some(ref all) = self.undo.all_dirents {
            self.dir_entries = all.clone();
        }
        if let Some(ref all) = self.undo.all_inode_to_entry_index {
            self.inode_to_entry_index = all.clone();
        }
        // ── Restore individual dirents on top (for pre-insert mutations) ──
        for (idx, old) in self.undo.dirents.iter().rev() {
            if let Some(slot) = self.dir_entries.get_mut(*idx) {
                *slot = old.clone();
            }
        }
        // ── Restore inodes (reverse order) ──
        for &(idx, old) in self.undo.inodes.iter().rev() {
            if let Some(slot) = self.inodes.get_mut(idx) {
                *slot = old;
            }
        }
        // ── Restore xattr records (reverse order, V4+) ──
        for (idx, old) in self.undo.xattrs.iter().rev() {
            if let Some(slot) = self.xattrs.get_mut(*idx) {
                *slot = *old;
            }
        }
        if let Some(len) = self.undo.xattr_len {
            self.xattrs.truncate(len);
        }
        // ── Truncate vectors that grew via push (new inode allocation) ──
        if let Some(len) = self.undo.inodes_len {
            self.inodes.truncate(len);
        }
        if let Some(len) = self.undo.parent_of_len {
            self.parent_of.truncate(len);
        }
        if let Some(len) = self.undo.inode_to_entry_index_len {
            self.inode_to_entry_index.truncate(len);
        }
        // ── Restore fixed-size auxiliary state ──
        if let Some(ref extents) = self.undo.free_data_extents {
            self.free_data_extents = extents.clone();
        }
        if let Some(ref slots) = self.undo.free_inode_slots {
            self.free_inode_slots = slots.clone();
        }
        if let Some(ref indices) = self.undo.dir_inode_indices {
            self.dir_inode_indices = indices.clone();
        }
        // Restore parent_of entries
        for &(idx, old) in self.undo.parent_of.iter().rev() {
            if let Some(slot) = self.parent_of.get_mut(idx) {
                *slot = old;
            }
        }
        // Restore inode_to_entry_index entries
        for &(idx, old) in self.undo.inode_to_entry_index.iter().rev() {
            if let Some(slot) = self.inode_to_entry_index.get_mut(idx) {
                *slot = old;
            }
        }
        // Restore staging_roots length
        if let Some(len) = self.undo.staging_roots_len {
            self.staging_roots.truncate(len);
        }
        // Restore dirty flags
        if let Some(dirty) = self.undo.old_inode_table_dirty {
            self.inode_table_dirty = dirty;
        }
        if let Some(dirty) = self.undo.old_dirent_table_dirty {
            self.dirent_table_dirty = dirty;
        }
    }

    /// Discard the undo log after a successful commit.
    pub(crate) fn commit_undo(&mut self) {
        self.undo = UndoLog::default();
    }
}

/// Context for batched metadata mutations within a single atomic commit.
/// Created by [`SimpleFs::transaction`]; all mutations are applied to the
/// in-memory state and flushed to disk once when the transaction closure
/// returns `Ok`.  Data-block writes are not supported inside transactions.
pub struct TransactionContext<'a> {
    pub(crate) state: &'a mut SimpleFsState,
    pub(crate) fs: &'a SimpleFs,
}

impl TransactionContext<'_> {
    pub(crate) fn lookup_index(&self, path: &str) -> Result<usize> {
        self.fs.lookup_index_locked(self.state, path)
    }

    pub fn create_dir(&mut self, path: &str) -> Result<()> {
        self.create_dir_with_security(path, None)
    }

    pub fn create_dir_with_security(
        &mut self,
        path: &str,
        security: Option<SecurityDescriptor>,
    ) -> Result<()> {
        if let Some(ref sec) = security {
            if sec.mode & !MAX_PERMISSION_MODE != 0 {
                return Err(Error::InvalidArgument);
            }
        }

        if path.is_empty() || path == "/" {
            return Err(Error::InvalidArgument);
        }

        validate_dir_entry_name_for_format(base_name(path), self.fs.format_version)?;

        if self.lookup_index(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        if !self.fs.has_available_inode_slot(self.state)
            || self.state.dir_entries.len() >= self.fs.dirent_capacity
        {
            return Err(Error::OutOfMemory);
        }

        let parent_path = parent_path(path).ok_or(Error::InvalidArgument)?;
        let parent_index = self.lookup_index(&parent_path)?;
        let parent_inode = *self
            .state
            .inodes
            .get(parent_index)
            .ok_or(Error::InternalError)?;
        if parent_inode.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let entry_start = self.state.dir_entries.len() as u32;
        let persistent_security = self
            .fs
            .format_version
            .persistent_security_descriptor_layout()
            .map(|_| match security {
                Some(sec) => OnDiskPersistentSecurityDescriptor {
                    owner_uid: sec.owner_uid,
                    owner_gid: sec.owner_gid,
                    mode: sec.mode,
                },
                None => {
                    let (owner_uid, owner_gid) = match parent_inode.persistent_security {
                        Some(ps) => (ps.owner_uid, ps.owner_gid),
                        None => (ROOT_OWNER_ID, ROOT_GROUP_ID),
                    };
                    OnDiskPersistentSecurityDescriptor {
                        owner_uid,
                        owner_gid,
                        mode: DEFAULT_DIRECTORY_MODE,
                    }
                }
            });
        self.fs.profiler.inc_creates();
        let new_inode_index = self.fs.allocate_inode_slot(
            self.state,
            OnDiskInode {
                kind: NodeKind::Directory,
                deleted: false,
                entry_start,
                entry_count: 0,
                data_block: 0,
                block_count: 0,
                size: 0,
                persistent_security,
                data_checksum: 0,
                compressed: false,
                deduped: false,
            },
        )?;
        self.fs.insert_dir_entry_locked(
            self.state,
            parent_index,
            OnDiskDirEntry {
                inode_index: new_inode_index as u32,
                kind: NodeKind::Directory,
                name: base_name(path).to_string(),
            },
        )?;

        Ok(())
    }

    pub fn remove_path(&mut self, path: &str) -> Result<()> {
        if path.is_empty() || path == "/" {
            return Err(Error::InvalidArgument);
        }

        self.fs.profiler.inc_deletes();
        let parent_path = parent_path(path).ok_or(Error::InvalidArgument)?;
        let parent_index = self.lookup_index(&parent_path)?;
        let parent_inode = *self
            .state
            .inodes
            .get(parent_index)
            .ok_or(Error::InternalError)?;
        if parent_inode.kind != NodeKind::Directory || parent_inode.deleted {
            return Err(Error::InvalidArgument);
        }

        let resolved =
            self.fs
                .resolve_live_child_dirent_locked(self.state, parent_index, base_name(path))?;
        if resolved.inode.kind == NodeKind::Directory && resolved.inode.entry_count != 0 {
            return Err(Error::Busy);
        }

        self.fs
            .remove_dir_entry_locked(self.state, parent_index, resolved.entry_index)?;

        let old_data_block;
        let old_block_count;
        let old_deduped;
        {
            self.state.save_inode_for_undo(resolved.inode_index);
            self.state.save_free_slots_for_undo();
            self.state.save_dir_indices_for_undo();
            let inode = self
                .state
                .inodes
                .get_mut(resolved.inode_index)
                .ok_or(Error::InternalError)?;
            let freed_index = resolved.inode_index;
            let was_dir = inode.kind == NodeKind::Directory;
            old_data_block = inode.data_block as usize;
            old_block_count = inode.block_count as usize;
            old_deduped = inode.deduped;
            inode.deleted = true;
            inode.entry_start = 0;
            inode.data_block = 0;
            inode.block_count = 0;
            inode.size = 0;
            inode.entry_count = 0;
            inode.persistent_security = None;
            self.state.inode_table_dirty = true;
            // A slot still referenced by an open handle must not be recycled;
            // it is freed by SimpleVNode's Drop once the last handle closes.
            if self
                .state
                .open_handles
                .get(&freed_index)
                .copied()
                .unwrap_or(0)
                == 0
            {
                self.state.free_inode_slots.push(freed_index);
            }
            // V4+: xattr records attached to the removed inode are released.
            self.fs.mark_inode_xattrs_deleted(self.state, freed_index);
            if was_dir {
                if let Some(pos) = self
                    .state
                    .dir_inode_indices
                    .iter()
                    .position(|&i| i == freed_index)
                {
                    self.state.dir_inode_indices.remove(pos);
                }
            }
        }
        self.fs
            .release_inode_extent(self.state, old_data_block, old_block_count, old_deduped);
        Ok(())
    }

    pub fn update_security_descriptor(
        &mut self,
        path: &str,
        security: SecurityDescriptor,
    ) -> Result<()> {
        if self
            .fs
            .format_version
            .persistent_security_descriptor_layout()
            .is_none()
        {
            return Err(Error::Unsupported);
        }

        if security.mode & !MAX_PERMISSION_MODE != 0 {
            return Err(Error::InvalidArgument);
        }

        let inode_index = self.lookup_index(path)?;
        self.state.save_inode_for_undo(inode_index);
        let inode = self
            .state
            .inodes
            .get_mut(inode_index)
            .ok_or(Error::InternalError)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }

        inode.persistent_security = Some(OnDiskPersistentSecurityDescriptor {
            owner_uid: security.owner_uid,
            owner_gid: security.owner_gid,
            mode: security.mode,
        });
        self.state.inode_table_dirty = true;
        Ok(())
    }

    /// Set an extended attribute on the node at `path` (V4+, symlinks
    /// followed), within this transaction.
    pub fn set_xattr(&mut self, path: &str, name: &[u8], value: &[u8]) -> Result<()> {
        let inode_index = self.fs.resolve_path_locked(self.state, path)?;
        self.fs
            .set_xattr_for_inode(self.state, inode_index, name, value)
    }

    /// Remove an extended attribute from the node at `path` (V4+, symlinks
    /// followed), within this transaction.
    pub fn remove_xattr(&mut self, path: &str, name: &[u8]) -> Result<()> {
        let inode_index = self.fs.resolve_path_locked(self.state, path)?;
        self.fs
            .remove_xattr_for_inode(self.state, inode_index, name)
    }
}

// ── SimpleFs core implementation ─────────────────────────────────────
