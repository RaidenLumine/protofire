//! src/kernel/fs/simplefs/path.rs
//! Path resolution and symlink following for SimpleFs.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Result};

use super::super::block::BLOCK_SIZE;
use super::super::vfs::NodeKind;

use super::constants::*;
use super::format_io::names_match;
use super::types::*;
use super::{SimpleFs, SimpleFsState};

impl SimpleFs {
    pub(crate) fn find_child(
        &self,
        state: &SimpleFsState,
        parent_index: usize,
        segment: &str,
    ) -> Result<usize> {
        Ok(self
            .resolve_live_child_dirent_locked(state, parent_index, segment)?
            .inode_index)
    }

    pub(crate) fn resolve_live_child_dirent_locked(
        &self,
        state: &SimpleFsState,
        parent_index: usize,
        segment: &str,
    ) -> Result<ResolvedChildEntry> {
        let inode = state.inodes.get(parent_index).ok_or(Error::InternalError)?;
        if inode.kind != NodeKind::Directory || inode.deleted {
            return Err(Error::NotFound);
        }

        let start = inode.entry_start as usize;
        let end = start + inode.entry_count as usize;
        let entries = state
            .dir_entries
            .get(start..end)
            .ok_or(Error::InternalError)?;

        // Path and mutation lookup share the same live-child resolution rule:
        // names must match under the current case policy and deleted targets
        // are skipped as if absent.
        entries
            .iter()
            .enumerate()
            .find_map(|(offset, entry)| {
                if !names_match(entry.name.as_str(), segment, self.case_sensitive) {
                    return None;
                }

                let inode_index = entry.inode_index as usize;
                let inode = *state.inodes.get(inode_index)?;
                if inode.deleted {
                    return None;
                }

                Some(ResolvedChildEntry {
                    entry_index: start + offset,
                    inode_index,
                    inode,
                })
            })
            .ok_or(Error::NotFound)
    }

    /// Read the target path from a symlink inode.
    ///
    /// For short targets (≤ [`MAX_INLINE_SYMLINK_LEN`] bytes), the target is
    /// packed into `entry_start` + `entry_count` + `data_block` and
    /// `block_count` is 0.
    ///
    /// For longer targets, `block_count` is 1 and the target is stored in a
    /// single data block pointed to by `data_block`.
    pub(crate) fn read_symlink_target(&self, inode: &OnDiskInode) -> Result<Vec<u8>> {
        let len = inode.size as usize;
        if len == 0 {
            return Err(Error::InvalidArgument);
        }

        if inode.block_count == 0 {
            // Inline: target bytes packed into entry_start (4) + entry_count (4)
            // + data_block (4), read left-to-right.
            let mut buf = [0_u8; 12];
            buf[..4].copy_from_slice(&inode.entry_start.to_le_bytes());
            buf[4..8].copy_from_slice(&inode.entry_count.to_le_bytes());
            buf[8..12].copy_from_slice(&inode.data_block.to_le_bytes());
            let actual_len = len.min(MAX_INLINE_SYMLINK_LEN);
            Ok(buf[..actual_len].to_vec())
        } else {
            // External: target stored in a data block.
            let mut temp = vec![0_u8; BLOCK_SIZE];
            self.cached_read_blocks(inode.data_block as u64, &mut temp)?;
            let actual_len = len.min(BLOCK_SIZE);
            Ok(temp[..actual_len].to_vec())
        }
    }

    /// Resolve a path, following symlinks component by component.
    ///
    /// Returns the final inode index after resolving all symlinks encountered
    /// along the path.  Symlink resolution depth is bounded by
    /// [`MAX_SYMLINK_DEPTH`].
    pub(crate) fn resolve_path_locked(&self, state: &SimpleFsState, path: &str) -> Result<usize> {
        self.resolve_path_locked_depth(state, path, 0)
    }

    /// Internal recursive implementation that tracks symlink depth across
    /// recursive calls to prevent stack overflow from loops.
    pub(crate) fn resolve_path_locked_depth(
        &self,
        state: &SimpleFsState,
        path: &str,
        depth: usize,
    ) -> Result<usize> {
        if path.is_empty() || path == "/" {
            return Ok(0);
        }

        if depth > MAX_SYMLINK_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let components: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current = 0_usize;
        let mut i = 0;
        // Track the literal path walked so far (excluding the component that
        // turned out to be a symlink).  Used for relative-symlink resolution.
        let mut walked = String::new();

        while i < components.len() {
            let segment = components[i];
            if segment.is_empty() || segment == "." {
                i += 1;
                continue;
            }
            if segment == ".." {
                current = state.parent_of.get(current).copied().flatten().unwrap_or(0);
                // Truncate walked path back to the parent.
                if let Some(pos) = walked.rfind('/') {
                    walked.truncate(pos);
                }
                i += 1;
                continue;
            }
            current = self.find_child(state, current, segment)?;
            walked.push('/');
            walked.push_str(segment);
            i += 1;

            // Check whether the resolved component is a symlink.
            let inode = state
                .inodes
                .get(current)
                .copied()
                .ok_or(Error::InternalError)?;
            if inode.kind == NodeKind::Symlink {
                let target = self.read_symlink_target(&inode)?;
                let target_str =
                    core::str::from_utf8(&target).map_err(|_| Error::InvalidArgument)?;

                // Build the remaining path suffix (components after this symlink).
                let suffix: String = if i < components.len() {
                    let rest: Vec<&str> = components[i..].to_vec();
                    format!("/{}", rest.join("/"))
                } else {
                    String::new()
                };

                // Resolve the target: absolute targets stand on their own,
                // relative targets resolve against the parent of the symlink
                // (drop the symlink's own name from the walked prefix).
                let resolved = if target_str.starts_with('/') {
                    format!("{}{}", target_str, suffix)
                } else {
                    let walked_parent = walked
                        .rsplit_once('/')
                        .map(|(prefix, _)| prefix)
                        .unwrap_or("/");
                    format!("{}/{}", walked_parent, target_str) + &suffix
                };

                // Recursively resolve the combined path.
                return self.resolve_path_locked_depth(state, &resolved, depth + 1);
            }
        }

        self.profiler.inc_lookups();
        Ok(current)
    }
}
