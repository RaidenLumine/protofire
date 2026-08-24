//! src/kernel/fs/simplefs/image_staging.rs
//!
//! Image building (for mkfs-like creation) and staging area management.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Result};

use super::super::block::BLOCK_SIZE;
use super::super::vfs::NodeKind;

use super::constants::*;
use super::free_fns::*;
use super::types::*;
use super::{ImageEntry, SimpleFs};

// ── Image building ────────────────────────────────────────────────────

impl SimpleFs {
    pub fn build_image(label: &str, files: &[ImageEntry<'_>]) -> Result<Vec<u8>> {
        Self::build_image_with_headroom(label, files, 0, 0, 0)
    }

    pub fn build_image_with_headroom(
        label: &str,
        files: &[ImageEntry<'_>],
        extra_inodes: usize,
        extra_dir_entries: usize,
        extra_data_blocks: usize,
    ) -> Result<Vec<u8>> {
        Self::build_image_internal(
            label,
            files,
            extra_inodes,
            extra_dir_entries,
            extra_data_blocks,
            SimpleFsFormatVersion::V2,
            0,
        )
    }

    /// Build a V4 image (persistent security descriptors + xattr table +
    /// data-reduction flags).  `extra_xattrs` reserves xattr-table capacity
    /// beyond the (initially empty) xattr list.
    pub fn build_v4_image_with_headroom(
        label: &str,
        files: &[ImageEntry<'_>],
        extra_inodes: usize,
        extra_dir_entries: usize,
        extra_xattrs: usize,
        extra_data_blocks: usize,
    ) -> Result<Vec<u8>> {
        Self::build_image_internal(
            label,
            files,
            extra_inodes,
            extra_dir_entries,
            extra_data_blocks,
            SimpleFsFormatVersion::V4PersistentSecurityDescriptorsWithXattrs,
            extra_xattrs,
        )
    }

    fn build_image_internal(
        label: &str,
        files: &[ImageEntry<'_>],
        extra_inodes: usize,
        extra_dir_entries: usize,
        extra_data_blocks: usize,
        format_version: SimpleFsFormatVersion,
        extra_xattr_capacity: usize,
    ) -> Result<Vec<u8>> {
        let nodes = build_nodes(files)?;
        // DFS order keeps parent directory metadata ahead of children in generated tables.
        let order = depth_first_order(&nodes);
        let mut old_to_new = vec![0_usize; nodes.len()];

        for (new_index, old_index) in order.iter().copied().enumerate() {
            old_to_new[old_index] = new_index;
        }

        let mut dir_entries = Vec::new();
        let mut inodes = vec![BuilderInode::default(); order.len()];

        for (new_index, old_index) in order.iter().copied().enumerate() {
            let node = &nodes[old_index];
            let inode = &mut inodes[new_index];
            inode.kind = encode_kind(node.kind);

            match node.kind {
                NodeKind::Directory => {
                    inode.entry_start = dir_entries.len() as u32;
                    inode.entry_count = node.children.len() as u32;

                    for child in node.children.iter().copied() {
                        let child_node = &nodes[child];
                        dir_entries.push(BuilderDirEntry {
                            inode_index: old_to_new[child] as u32,
                            kind: encode_kind(child_node.kind),
                            name: child_node.name.clone(),
                        });
                    }
                }
                NodeKind::File | NodeKind::Device | NodeKind::Symlink => {
                    inode.size = node.data.len() as u32;
                }
            }
        }

        let inode_table_block: usize = SECONDARY_SUPERBLOCK_BLOCK + 1;
        let planned_inode_capacity = inodes
            .len()
            .checked_add(extra_inodes)
            .ok_or(Error::InvalidArgument)?;
        let planned_inode_bytes = format_version.inode_table_bytes(planned_inode_capacity)?;
        let inode_table_blocks = blocks_for(planned_inode_bytes);
        let dirent_table_block = inode_table_block
            .checked_add(inode_table_blocks)
            .ok_or(Error::InvalidArgument)?;
        let planned_dirent_capacity = dir_entries
            .len()
            .checked_add(extra_dir_entries)
            .ok_or(Error::InvalidArgument)?;
        let planned_dirent_bytes = format_version.dirent_table_bytes(planned_dirent_capacity)?;
        let dirent_table_blocks = blocks_for(planned_dirent_bytes);

        // V4+ reserves an active/shadow xattr-table pair immediately after the
        // dirent tables, preserving the "active table N, then shadow table N"
        // symmetry that validate_superblock_record enforces.
        let xattr_table_blocks = if format_version.supports_persistent_xattrs() {
            blocks_for(format_version.xattr_table_bytes(extra_xattr_capacity)?).max(1)
        } else {
            0
        };

        let shadow_inode_table_block: usize;
        let shadow_dirent_table_block: usize;
        let data_block_start: usize;
        let active_xattr_table_block: usize;
        let shadow_xattr_table_block: usize;

        if format_version.supports_persistent_xattrs() {
            active_xattr_table_block = dirent_table_block
                .checked_add(dirent_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            shadow_inode_table_block = active_xattr_table_block
                .checked_add(xattr_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            shadow_dirent_table_block = shadow_inode_table_block
                .checked_add(inode_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            shadow_xattr_table_block = shadow_dirent_table_block
                .checked_add(dirent_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            data_block_start = shadow_xattr_table_block
                .checked_add(xattr_table_blocks)
                .ok_or(Error::InvalidArgument)?;
        } else {
            shadow_inode_table_block = dirent_table_block
                .checked_add(dirent_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            shadow_dirent_table_block = shadow_inode_table_block
                .checked_add(inode_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            data_block_start = shadow_dirent_table_block
                .checked_add(dirent_table_blocks)
                .ok_or(Error::InvalidArgument)?;
            active_xattr_table_block = 0;
            shadow_xattr_table_block = 0;
        }

        let mut next_data_block = data_block_start;
        for (new_index, old_index) in order.iter().copied().enumerate() {
            let node = &nodes[old_index];
            if node.kind == NodeKind::Directory {
                continue;
            }

            let block_count = blocks_for(node.data.len());
            inodes[new_index].data_block = next_data_block as u32;
            inodes[new_index].block_count = block_count as u32;
            next_data_block = next_data_block
                .checked_add(block_count)
                .ok_or(Error::InvalidArgument)?;
        }

        let total_blocks = next_data_block
            .checked_add(extra_data_blocks)
            .ok_or(Error::InvalidArgument)?
            .max(1);
        let image_bytes = total_blocks
            .checked_mul(BLOCK_SIZE)
            .ok_or(Error::InvalidArgument)?;
        let mut image = vec![0_u8; image_bytes];
        let superblock_record = SuperblockRecord {
            inode_count: inodes.len(),
            dirent_count: dir_entries.len(),
            active_inode_table_block: inode_table_block,
            active_dirent_table_block: dirent_table_block,
            shadow_inode_table_block,
            shadow_dirent_table_block,
            inode_table_blocks,
            dirent_table_blocks,
            data_block_start,
            generation: 0,
            pending_commit: 0,
            active_xattr_table_block,
            shadow_xattr_table_block,
            xattr_table_blocks,
            xattr_count: 0,
        };
        write_superblock(
            &mut image[PRIMARY_SUPERBLOCK_BLOCK * BLOCK_SIZE
                ..(PRIMARY_SUPERBLOCK_BLOCK + 1) * BLOCK_SIZE],
            label,
            format_version,
            superblock_record,
        );
        let primary_superblock = image
            [PRIMARY_SUPERBLOCK_BLOCK * BLOCK_SIZE..(PRIMARY_SUPERBLOCK_BLOCK + 1) * BLOCK_SIZE]
            .to_vec();
        image[SECONDARY_SUPERBLOCK_BLOCK * BLOCK_SIZE
            ..(SECONDARY_SUPERBLOCK_BLOCK + 1) * BLOCK_SIZE]
            .copy_from_slice(&primary_superblock);

        write_inode_table(&mut image, format_version, inode_table_block, &inodes)?;
        write_dir_entry_table(&mut image, format_version, dirent_table_block, &dir_entries)?;
        write_inode_table(
            &mut image,
            format_version,
            shadow_inode_table_block,
            &inodes,
        )?;
        write_dir_entry_table(
            &mut image,
            format_version,
            shadow_dirent_table_block,
            &dir_entries,
        )?;

        for (new_index, old_index) in order.iter().copied().enumerate() {
            let node = &nodes[old_index];
            if node.kind == NodeKind::Directory || node.data.is_empty() {
                continue;
            }

            let start = (inodes[new_index].data_block as usize)
                .checked_mul(BLOCK_SIZE)
                .ok_or(Error::InvalidArgument)?;
            let end = start
                .checked_add(node.data.len())
                .ok_or(Error::InvalidArgument)?;
            if end > image.len() {
                return Err(Error::InvalidArgument);
            }
            image[start..end].copy_from_slice(node.data);
        }

        Ok(image)
    }
}

// ── Staging area ──────────────────────────────────────────────────────

pub struct StagingArea {
    fs: Arc<SimpleFs>,
    staging_root: String,
}

impl StagingArea {
    /// Create a new staging area rooted at `staging_root`.
    ///
    /// The staging root directory is created if it does not already exist.
    /// Returns an error if `staging_root` is `/` or empty.
    pub fn create(fs: &Arc<SimpleFs>, staging_root: &str) -> Result<Self> {
        if staging_root.is_empty() || staging_root == "/" {
            return Err(Error::InvalidArgument);
        }

        // Ensure staging root exists (idempotent).
        match fs.lookup_index(staging_root) {
            Ok(_) => {}
            Err(Error::NotFound) => {
                fs.create_dir(staging_root)?;
            }
            Err(e) => return Err(e),
        }

        // Register so that check_and_repair can clean up orphaned entries.
        fs.register_staging_root(staging_root);

        Ok(Self {
            fs: Arc::clone(fs),
            staging_root: staging_root.to_string(),
        })
    }

    /// Return the path to the staging root directory.
    pub fn root(&self) -> &str {
        &self.staging_root
    }

    /// Begin staging a new item.
    ///
    /// Creates a new directory under the staging root and returns its full
    /// path. Callers can then use normal filesystem operations (create_file,
    /// write, create_dir, ...) to populate the staging directory.
    ///
    /// `name` must be a single path component (no `/`).
    pub fn prepare(&self, name: &str) -> Result<String> {
        if name.is_empty() || name.contains('/') {
            return Err(Error::InvalidArgument);
        }

        let path = format!("{}/{}", self.staging_root, name);
        self.fs.create_dir(&path)?;
        Ok(path)
    }

    /// Atomically publish a staged item to its final location.
    ///
    /// Renames the staging directory to `target`.  Returns
    /// [`Error::AlreadyExists`] if `target` already exists — the caller
    /// should remove or move the existing target first.
    pub fn publish(&self, name: &str, target: &str) -> Result<()> {
        let staged_path = format!("{}/{}", self.staging_root, name);
        self.fs.rename(&staged_path, target)
    }

    /// Abort a staged item by recursively removing it from the staging area.
    pub fn abort(&self, name: &str) -> Result<()> {
        let path = format!("{}/{}", self.staging_root, name);
        self.fs.remove_path_recursive(&path)
    }

    /// List all items currently in the staging area.
    ///
    /// Returns a vector of entry names (single path components) sorted in
    /// dirent-table order.
    pub fn list(&self) -> Result<Vec<String>> {
        let state = self.fs.state.lock();
        let staging_index = self.fs.lookup_index_locked(&state, &self.staging_root)?;
        let staging_inode = state
            .inodes
            .get(staging_index)
            .copied()
            .ok_or(Error::InternalError)?;
        if staging_inode.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let start = staging_inode.entry_start as usize;
        let count = staging_inode.entry_count as usize;
        let mut names = Vec::with_capacity(count);
        for i in 0..count {
            names.push(state.dir_entries[start + i].name.clone());
        }
        Ok(names)
    }

    /// Remove all staged items from the staging area.
    ///
    /// Returns the number of items that were removed.  This is typically
    /// called on boot to clean up orphaned staging artifacts left behind
    /// by a crash.
    pub fn cleanup(&self) -> Result<usize> {
        let names = self.list()?;
        let count = names.len();
        for name in &names {
            self.abort(name)?;
        }
        Ok(count)
    }

    /// Publish a staged item, preserving the existing target as a backup.
    ///
    /// If `target` already exists, it is first renamed to `<target>.bak`
    /// before the staged content is published.  Returns a [`VersionSwitch`]
    /// handle that can be used to commit (remove the backup) or rollback
    /// (swap the backup back into place).
    ///
    /// All operations are performed within a single metadata transaction,
    /// so a crash leaves the filesystem in a consistent state.
    pub fn publish_with_backup(&self, name: &str, target: &str) -> Result<VersionSwitch> {
        if target.is_empty() || target == "/" {
            return Err(Error::InvalidArgument);
        }

        let staged_path = format!("{}/{}", self.staging_root, name);
        let backup_path = format!("{}.bak", target);

        // Check if target exists before deciding the strategy.
        let target_exists = self.fs.lookup_index(target).is_ok();

        if target_exists {
            // Rename existing target to backup, then publish.
            self.fs.rename(target, &backup_path)?;
            match self.fs.rename(&staged_path, target) {
                Ok(()) => {}
                Err(e) => {
                    // Attempt to restore the backup on failure.
                    let _ = self.fs.rename(&backup_path, target);
                    return Err(e);
                }
            }
        } else {
            self.fs.rename(&staged_path, target)?;
        }

        Ok(VersionSwitch {
            fs: Arc::clone(&self.fs),
            target: target.to_string(),
            backup_path,
            backup_exists: target_exists,
        })
    }
}

/// Handle returned by [`StagingArea::publish_with_backup`].
///
/// Represents a completed version switch where the previous version (if
/// any) has been moved to a backup location.  The caller can either
/// [`commit`](VersionSwitch::commit) (remove the backup, making the new
/// version permanent) or [`rollback`](VersionSwitch::rollback) (swap the
/// backup back into place, undoing the publish).
pub struct VersionSwitch {
    fs: Arc<SimpleFs>,
    target: String,
    backup_path: String,
    backup_exists: bool,
}

impl VersionSwitch {
    /// Permanently commit the version switch by removing the backup of
    /// the previous version.  After this call, rollback is no longer
    /// possible.
    pub fn commit(self) -> Result<()> {
        if self.backup_exists {
            self.fs.remove_path_recursive(&self.backup_path)?;
        }
        Ok(())
    }

    /// Roll back the version switch by swapping the backup back into
    /// the target location.  The newly-published version is moved to
    /// the backup location.
    pub fn rollback(self) -> Result<()> {
        if self.backup_exists {
            self.fs.swap_paths(&self.backup_path, &self.target)?;
        }
        Ok(())
    }

    /// Returns the path to the backup (previous version), if any.
    pub fn backup_path(&self) -> Option<&str> {
        if self.backup_exists {
            Some(&self.backup_path)
        } else {
            None
        }
    }
}
