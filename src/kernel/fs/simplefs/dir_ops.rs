//! src/kernel/fs/simplefs/dir_ops.rs
//!
//! File/directory/symlink creation, deletion, rename, swap, and recursive
//! removal.

use alloc::format;
use alloc::string::ToString;
use alloc::vec;

use crate::{Error, Result};

use super::super::block::BLOCK_SIZE;
use super::super::vfs::{
    DirectoryEntry, Metadata, NodeKind, SecurityDescriptor, DEFAULT_FILE_MODE, MAX_PERMISSION_MODE,
    ROOT_GROUP_ID, ROOT_OWNER_ID,
};

use super::constants::*;
use super::free_fns::*;
use super::types::*;
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    pub(crate) fn create_file(&self, path: &str) -> Result<usize> {
        self.create_file_with_security(path, None)
    }

    pub(crate) fn create_file_with_security(
        &self,
        path: &str,
        security: Option<SecurityDescriptor>,
    ) -> Result<usize> {
        if let Some(ref sec) = security {
            if sec.mode & !MAX_PERMISSION_MODE != 0 {
                return Err(Error::InvalidArgument);
            }
        }

        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        if path.is_empty() || path == "/" {
            return Err(Error::InvalidArgument);
        }

        validate_dir_entry_name_for_format(base_name(path), self.format_version)?;

        self.commit_metadata_update(|state| {
            self.profiler.inc_creates();
            if self.lookup_index_locked(state, path).is_ok() {
                return Err(Error::AlreadyExists);
            }

            if !self.has_available_inode_slot(state)
                || state.dir_entries.len() >= self.dirent_capacity
            {
                return Err(Error::OutOfMemory);
            }

            let parent_path = parent_path(path).ok_or(Error::InvalidArgument)?;
            let parent_index = self.lookup_index_locked(state, &parent_path)?;
            let parent_inode = state
                .inodes
                .get(parent_index)
                .copied()
                .ok_or(Error::InternalError)?;
            if parent_inode.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }

            let next_data_block =
                self.find_free_data_block_span(state, INITIAL_FILE_BLOCKS as usize, None)?;

            let zeroed = vec![0_u8; INITIAL_FILE_BLOCKS as usize * BLOCK_SIZE];
            self.write_blocks_cached(next_data_block as u64, &zeroed)?;

            let persistent_security = self
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
                            mode: DEFAULT_FILE_MODE,
                        }
                    }
                });

            let new_inode_index = self.allocate_inode_slot(
                state,
                OnDiskInode {
                    kind: NodeKind::File,
                    deleted: false,
                    entry_start: 0,
                    entry_count: 0,
                    data_block: next_data_block as u32,
                    block_count: INITIAL_FILE_BLOCKS,
                    size: 0,
                    persistent_security,
                    data_checksum: 0,
                    compressed: false,
                    deduped: false,
                },
            )?;
            self.insert_dir_entry_locked(
                state,
                parent_index,
                OnDiskDirEntry {
                    inode_index: new_inode_index as u32,
                    kind: NodeKind::File,
                    name: base_name(path).to_string(),
                },
            )?;

            self.mark_extent_allocated(state, next_data_block, INITIAL_FILE_BLOCKS as usize);

            Ok(new_inode_index)
        })
    }

    pub(crate) fn create_symlink(&self, target: &str, link_path: &str) -> Result<usize> {
        if target.is_empty() {
            return Err(Error::InvalidArgument);
        }

        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        if link_path.is_empty() || link_path == "/" {
            return Err(Error::InvalidArgument);
        }

        validate_dir_entry_name_for_format(base_name(link_path), self.format_version)?;

        let target_bytes = target.as_bytes();
        let target_len = target_bytes.len();

        self.commit_metadata_update(|state| {
            self.profiler.inc_creates();
            if self.lookup_index_locked(state, link_path).is_ok() {
                return Err(Error::AlreadyExists);
            }

            if !self.has_available_inode_slot(state)
                || state.dir_entries.len() >= self.dirent_capacity
            {
                return Err(Error::OutOfMemory);
            }

            let parent_path = parent_path(link_path).ok_or(Error::InvalidArgument)?;
            let parent_index = self.lookup_index_locked(state, &parent_path)?;
            let parent_inode = state
                .inodes
                .get(parent_index)
                .copied()
                .ok_or(Error::InternalError)?;
            if parent_inode.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }

            let persistent_security = self
                .format_version
                .persistent_security_descriptor_layout()
                .map(|_| {
                    let (owner_uid, owner_gid) = match parent_inode.persistent_security {
                        Some(ps) => (ps.owner_uid, ps.owner_gid),
                        None => (ROOT_OWNER_ID, ROOT_GROUP_ID),
                    };
                    OnDiskPersistentSecurityDescriptor {
                        owner_uid,
                        owner_gid,
                        mode: DEFAULT_FILE_MODE,
                    }
                });

            // Decide inline vs external storage.
            let (entry_start, entry_count, data_block, block_count, size) =
                if target_len <= MAX_INLINE_SYMLINK_LEN {
                    // Pack target into entry_start + entry_count + data_block (12 bytes).
                    let mut buf = [0_u8; MAX_INLINE_SYMLINK_LEN];
                    buf[..target_len].copy_from_slice(target_bytes);
                    let es = u32::from_le_bytes(buf[..4].try_into().unwrap());
                    let ec = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                    let db = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                    (es, ec, db, 0_u32, target_len as u32)
                } else {
                    // Allocate a data block for the target.
                    let block = self.find_free_data_block_span(state, 1, None)?;
                    let mut block_data = vec![0_u8; BLOCK_SIZE];
                    block_data[..target_len].copy_from_slice(target_bytes);
                    self.write_blocks_cached(block as u64, &block_data)?;
                    self.mark_extent_allocated(state, block, 1);
                    (0_u32, 0_u32, block as u32, 1_u32, target_len as u32)
                };

            let new_inode_index = self.allocate_inode_slot(
                state,
                OnDiskInode {
                    kind: NodeKind::Symlink,
                    deleted: false,
                    entry_start,
                    entry_count,
                    data_block,
                    block_count,
                    size,
                    persistent_security,
                    data_checksum: 0,
                    compressed: false,
                    deduped: false,
                },
            )?;
            self.insert_dir_entry_locked(
                state,
                parent_index,
                OnDiskDirEntry {
                    inode_index: new_inode_index as u32,
                    kind: NodeKind::Symlink,
                    name: base_name(link_path).to_string(),
                },
            )?;

            Ok(new_inode_index)
        })
    }

    pub(crate) fn remove_path(&self, path: &str) -> Result<()> {
        self.transaction(|ctx| ctx.remove_path(path))
    }

    pub(crate) fn update_security_descriptor(
        &self,
        path: &str,
        security: SecurityDescriptor,
    ) -> Result<()> {
        self.require_persistent_security_descriptor_writes()?;
        if security.mode & !MAX_PERMISSION_MODE != 0 {
            return Err(Error::InvalidArgument);
        }
        self.transaction(|ctx| ctx.update_security_descriptor(path, security))
    }

    pub(crate) fn create_dir(&self, path: &str) -> Result<()> {
        self.create_dir_with_security(path, None)
    }

    pub(crate) fn create_dir_with_security(
        &self,
        path: &str,
        security: Option<SecurityDescriptor>,
    ) -> Result<()> {
        self.transaction(|ctx| ctx.create_dir_with_security(path, security))
    }

    /// Like the non-symlink-following stat, but resolves symlinks before
    /// returning metadata.
    pub(crate) fn stat_follow(&self, path: &str) -> Result<Metadata> {
        let state = self.state.lock();
        let inode_index = self.resolve_path_locked(&state, path)?;
        let inode = state
            .inodes
            .get(inode_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }

        Ok(self.metadata_from_inode(inode))
    }

    pub(crate) fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let state = self.state.lock();
        let inode_index = self.lookup_index_locked(&state, path)?;
        let inode = state
            .inodes
            .get(inode_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }
        if inode.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if index >= inode.entry_count as usize {
            return Err(Error::NotFound);
        }

        let entry_index = inode
            .entry_start
            .checked_add(index as u32)
            .ok_or(Error::InternalError)? as usize;
        let entry = state.dir_entries.get(entry_index).ok_or(Error::NotFound)?;
        let child_inode = state
            .inodes
            .get(entry.inode_index as usize)
            .copied()
            .ok_or(Error::InternalError)?;
        if child_inode.deleted {
            return Err(Error::InternalError);
        }

        let metadata = self.metadata_from_inode(child_inode);
        Ok(
            DirectoryEntry::new(metadata.kind, metadata.size, entry.name.clone())
                .with_security(metadata.security),
        )
    }

    pub(crate) fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        if old_path.is_empty() || old_path == "/" || new_path.is_empty() || new_path == "/" {
            return Err(Error::InvalidArgument);
        }

        let new_name = base_name(new_path);
        validate_dir_entry_name_for_format(new_name, self.format_version)?;

        self.commit_metadata_update(|state| {
            self.profiler.inc_renames();
            self.rename_locked(state, old_path, new_path)
        })
    }

    /// Atomically swap two paths within a single metadata transaction.
    ///
    /// This is the core primitive for rollback and version switching:
    /// after swapping, `path_a` holds what was at `path_b` and vice versa.
    /// If either path does not exist, or if a directory-descendant cycle
    /// would be created, the swap is rejected and no changes are made.
    pub(crate) fn swap_paths(&self, path_a: &str, path_b: &str) -> Result<()> {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        if path_a.is_empty()
            || path_a == "/"
            || path_b.is_empty()
            || path_b == "/"
            || path_a == path_b
        {
            return Err(Error::InvalidArgument);
        }

        // Use a unique temporary name that cannot collide with existing
        // entries.  The generation number ensures uniqueness.
        let state = self.state.lock();
        let tmp_name = format!(".swap-tmp-{}", state.generation);
        drop(state);

        self.commit_metadata_update(|state| {
            // Step 1: rename a → tmp
            let parent_a = parent_path(path_a).ok_or(Error::InvalidArgument)?;
            let tmp_path = format!("{}/{}", parent_a, tmp_name);

            // Verify a exists and b exists (or will be checked by rename).
            self.lookup_index_locked(state, path_a)?;
            self.lookup_index_locked(state, path_b)?;

            // Check for directory descendant cycles: if a is an ancestor of
            // b, swapping them would create a cycle.
            let a_idx = self.lookup_index_locked(state, path_a)?;
            let b_idx = self.lookup_index_locked(state, path_b)?;
            let a_inode = state
                .inodes
                .get(a_idx)
                .copied()
                .ok_or(Error::InternalError)?;
            let b_inode = state
                .inodes
                .get(b_idx)
                .copied()
                .ok_or(Error::InternalError)?;

            if a_inode.kind == NodeKind::Directory
                && self.is_descendant_index_locked(state, b_idx, a_idx)?
            {
                return Err(Error::InvalidArgument);
            }
            if b_inode.kind == NodeKind::Directory
                && self.is_descendant_index_locked(state, a_idx, b_idx)?
            {
                return Err(Error::InvalidArgument);
            }

            // Perform the three-way rename within the transaction.
            // rename a → tmp
            self.rename_locked(state, path_a, &tmp_path)?;
            // rename b → a
            self.rename_locked(state, path_b, path_a)?;
            // rename tmp → b
            self.rename_locked(state, &tmp_path, path_b)?;

            Ok(())
        })
    }

    /// Internal rename that operates on an already-locked state.
    pub(crate) fn rename_locked(
        &self,
        state: &mut SimpleFsState,
        old_path: &str,
        new_path: &str,
    ) -> Result<()> {
        let new_name = base_name(new_path);
        validate_dir_entry_name_for_format(new_name, self.format_version)?;

        let old_parent_path = parent_path(old_path).ok_or(Error::InvalidArgument)?;
        let new_parent_path = parent_path(new_path).ok_or(Error::InvalidArgument)?;
        let old_parent_index = self.lookup_index_locked(state, &old_parent_path)?;
        let new_parent_index = self.lookup_index_locked(state, &new_parent_path)?;

        let old_parent_inode = state
            .inodes
            .get(old_parent_index)
            .copied()
            .ok_or(Error::InternalError)?;
        let new_parent_inode = state
            .inodes
            .get(new_parent_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if old_parent_inode.deleted || new_parent_inode.deleted {
            return Err(Error::NotFound);
        }
        if old_parent_inode.kind != NodeKind::Directory
            || new_parent_inode.kind != NodeKind::Directory
        {
            return Err(Error::InvalidArgument);
        }

        let old_entry =
            self.resolve_live_child_dirent_locked(state, old_parent_index, base_name(old_path))?;

        let same_parent = old_parent_index == new_parent_index;
        match self.resolve_live_child_dirent_locked(state, new_parent_index, new_name) {
            Ok(target) if same_parent && target.entry_index == old_entry.entry_index => {
                state.save_dirent_for_undo(old_entry.entry_index);
                state.dir_entries[old_entry.entry_index].name = new_name.to_string();
                return Ok(());
            }
            Ok(_) => return Err(Error::AlreadyExists),
            Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }

        if same_parent {
            state.save_dirent_for_undo(old_entry.entry_index);
            state.dir_entries[old_entry.entry_index].name = new_name.to_string();
            return Ok(());
        }

        if old_entry.inode.kind == NodeKind::Directory
            && self.is_descendant_index_locked(state, new_parent_index, old_entry.inode_index)?
        {
            return Err(Error::InvalidArgument);
        }

        let mut entry =
            self.remove_dir_entry_locked(state, old_parent_index, old_entry.entry_index)?;
        entry.name = new_name.to_string();
        self.insert_dir_entry_locked(state, new_parent_index, entry)?;
        Ok(())
    }
    pub(crate) fn remove_path_recursive(&self, path: &str) -> Result<()> {
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if path.is_empty() || path == "/" {
            return Err(Error::InvalidArgument);
        }

        self.commit_metadata_update(|state| self.remove_path_recursive_locked(state, path))
    }

    pub(crate) fn remove_path_recursive_locked(
        &self,
        state: &mut SimpleFsState,
        path: &str,
    ) -> Result<()> {
        self.profiler.inc_deletes();
        let inode_index = self.lookup_index_locked(state, path)?;
        let inode = state
            .inodes
            .get(inode_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if inode.deleted {
            return Err(Error::NotFound);
        }

        // For directories, recursively remove children first.
        // We process children in reverse so that entry_start indices
        // of remaining siblings stay valid across remove_dir_entry_locked.
        if inode.kind == NodeKind::Directory {
            let entry_start = inode.entry_start as usize;
            let entry_count = inode.entry_count as usize;
            for i in (0..entry_count).rev() {
                let entry = state.dir_entries[entry_start + i].clone();
                let child_path = format!("{}/{}", path.trim_end_matches('/'), entry.name);
                self.remove_path_recursive_locked(state, &child_path)?;
            }
        }

        // Re-read inode — children removal may have shifted entries.
        let current = state
            .inodes
            .get(inode_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if current.kind == NodeKind::Directory && current.entry_count != 0 {
            return Err(Error::Busy);
        }

        let parent_path_str = parent_path(path).ok_or(Error::InvalidArgument)?;
        let parent_index = self.lookup_index_locked(state, &parent_path_str)?;
        let resolved =
            self.resolve_live_child_dirent_locked(state, parent_index, base_name(path))?;

        self.remove_dir_entry_locked(state, parent_index, resolved.entry_index)?;

        let old_data_block;
        let old_block_count;
        let old_deduped;
        {
            state.save_inode_for_undo(inode_index);
            state.save_free_slots_for_undo();
            state.save_dir_indices_for_undo();
            let inode = state
                .inodes
                .get_mut(inode_index)
                .ok_or(Error::InternalError)?;
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
            state.inode_table_dirty = true;
            // A slot still referenced by an open handle must not be recycled;
            // it is freed by SimpleVNode's Drop once the last handle closes.
            if state.open_handles.get(&inode_index).copied().unwrap_or(0) == 0 {
                state.free_inode_slots.push(inode_index);
            }
            // V4+: xattr records attached to the removed inode are released.
            self.mark_inode_xattrs_deleted(state, inode_index);
            if was_dir {
                if let Some(pos) = state
                    .dir_inode_indices
                    .iter()
                    .position(|&i| i == inode_index)
                {
                    state.dir_inode_indices.remove(pos);
                }
            }
        }
        self.release_inode_extent(state, old_data_block, old_block_count, old_deduped);

        Ok(())
    }
}
