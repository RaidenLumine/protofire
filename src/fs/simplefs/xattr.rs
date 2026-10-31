//! src/fs/simplefs/xattr.rs
//!
//! Persistent extended-attribute (xattr) table operations for V4 volumes.
//!
//! Xattrs are stored in a fixed-capacity xattr table (an active/shadow pair
//! tracked in the superblock, flushed through the same two-phase commit as
//! the inode/dirent tables).  Each record is fixed-size
//! [`XattrRecord`] and is attached to exactly one inode by `inode_index`.
//! Removed records are marked `XATTR_STATUS_DELETED` and their slots reused;
//! [`check_and_repair`] keeps the table compact.

use alloc::vec::Vec;

use crate::fs::vfs::XattrEntry;
use crate::Error;
use crate::Result;

use super::constants::*;
use super::types::*;
use super::SimpleFs;
use super::SimpleFsState;

impl SimpleFs {
    /// Index of the live xattr record for `(inode_index, name)`, if any.
    fn find_live_xattr(state: &SimpleFsState, inode_index: usize, name: &[u8]) -> Option<usize> {
        state.xattrs.iter().position(|record| {
            record.status == XATTR_STATUS_LIVE
                && record.inode_index as usize == inode_index
                && record.name_len as usize == name.len()
                && &record.name[..name.len()] == name
        })
    }

    /// Set an xattr on an inode.  Creates a new record or overwrites the
    /// existing live record in place.  Runs inside a metadata transaction.
    pub(crate) fn set_xattr_for_inode(
        &self,
        state: &mut SimpleFsState,
        inode_index: usize,
        name: &[u8],
        value: &[u8],
    ) -> Result<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if value.len() > XATTR_VALUE_MAX {
            return Err(Error::InvalidArgument);
        }
        if inode_index >= state.inodes.len() {
            return Err(Error::InvalidArgument);
        }

        // Overwrite an existing live record.
        if let Some(index) = Self::find_live_xattr(state, inode_index, name) {
            state.save_xattr_for_undo(index);
            let mut record = state.xattrs[index];
            record.value_len = value.len() as u32;
            record.value.fill(0);
            record.value[..value.len()].copy_from_slice(value);
            state.xattrs[index] = record;
            return Ok(());
        }

        // Reuse a deleted slot, otherwise append within capacity.
        let slot = state
            .xattrs
            .iter()
            .position(|record| record.status == XATTR_STATUS_DELETED);
        let index = match slot {
            Some(index) => {
                state.save_xattr_for_undo(index);
                index
            }
            None => {
                if state.xattrs.len() >= self.xattr_capacity {
                    return Err(Error::OutOfMemory);
                }
                state.save_xattr_len_for_undo();
                state.xattrs.push(XattrRecord::default());
                state.xattrs.len() - 1
            }
        };

        let mut record = XattrRecord {
            inode_index: inode_index as u32,
            status: XATTR_STATUS_LIVE,
            name_len: name.len() as u32,
            value_len: value.len() as u32,
            ..Default::default()
        };
        record.name[..name.len()].copy_from_slice(name);
        record.value[..value.len()].copy_from_slice(value);
        state.xattrs[index] = record;
        Ok(())
    }

    /// Return the value of an xattr, or `None` when it is not present.
    pub(crate) fn get_xattr_for_inode(
        &self,
        state: &SimpleFsState,
        inode_index: usize,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let Some(index) = Self::find_live_xattr(state, inode_index, name) else {
            return Ok(None);
        };
        let record = &state.xattrs[index];
        Ok(Some(record.value[..record.value_len as usize].to_vec()))
    }

    /// Remove an xattr.  The record is marked deleted and its payload
    /// zeroed so stale data cannot be recovered.  Returns `NotFound` when the
    /// attribute does not exist.
    pub(crate) fn remove_xattr_for_inode(
        &self,
        state: &mut SimpleFsState,
        inode_index: usize,
        name: &[u8],
    ) -> Result<()> {
        let Some(index) = Self::find_live_xattr(state, inode_index, name) else {
            return Err(Error::NotFound);
        };
        state.save_xattr_for_undo(index);
        let record = &mut state.xattrs[index];
        record.status = XATTR_STATUS_DELETED;
        record.name_len = 0;
        record.value_len = 0;
        record.name.fill(0);
        record.value.fill(0);
        Ok(())
    }

    /// List all live xattrs attached to an inode.
    pub(crate) fn list_xattrs_for_inode(
        &self,
        state: &SimpleFsState,
        inode_index: usize,
    ) -> Vec<XattrEntry> {
        state
            .xattrs
            .iter()
            .filter(|record| {
                record.status == XATTR_STATUS_LIVE && record.inode_index as usize == inode_index
            })
            .map(|record| {
                XattrEntry::new(
                    record.name[..record.name_len as usize].to_vec(),
                    record.value[..record.value_len as usize].to_vec(),
                )
            })
            .collect()
    }

    /// Mark every xattr attached to `inode_index` deleted (inode removal).
    pub(crate) fn mark_inode_xattrs_deleted(&self, state: &mut SimpleFsState, inode_index: usize) {
        let indices: Vec<usize> = state
            .xattrs
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.status == XATTR_STATUS_LIVE && record.inode_index as usize == inode_index
            })
            .map(|(index, _)| index)
            .collect();
        if indices.is_empty() {
            return;
        }
        for index in indices {
            state.save_xattr_for_undo(index);
            let record = &mut state.xattrs[index];
            record.status = XATTR_STATUS_DELETED;
            record.name_len = 0;
            record.value_len = 0;
            record.name.fill(0);
            record.value.fill(0);
        }
    }
}

/// Per-file data-reduction flags (`FILE_FLAG_*`), and setting them.
///
/// The two bits are on the inode's flags byte, which every format has; what
/// only V4 has is a promise that the byte reaches the disk.  A V2 volume
/// would accept a set and lose it at the next mount, so the setter refuses
/// there rather than answering `Ok` for something it cannot keep — the read
/// side still answers, because a record parsed from a V4 volume may carry the
/// bits even when this driver cannot set them.
impl SimpleFs {
    /// The flags a node's inode carries, as `FILE_FLAG_*`.
    pub(crate) fn file_flags_for_inode(
        &self,
        state: &SimpleFsState,
        inode_index: usize,
    ) -> Result<u32> {
        let inode = state
            .inodes
            .get(inode_index)
            .ok_or(Error::InvalidArgument)?;
        let mut flags = 0u32;
        if inode.compressed {
            flags |= crate::abi::fs::FILE_FLAG_COMPRESSED;
        }
        if inode.deduped {
            flags |= crate::abi::fs::FILE_FLAG_DEDUPED;
        }
        Ok(flags)
    }

    /// Turn `set` on and `clear` off, for the node at `inode_index`.
    ///
    /// Refuses on a format that does not persist the flags byte, so a caller
    /// learns its flag will not survive a remount instead of being told the
    /// call worked.
    pub(crate) fn set_file_flags_for_inode(
        &self,
        state: &mut SimpleFsState,
        inode_index: usize,
        set: u32,
        clear: u32,
    ) -> Result<()> {
        if !self.format_version.supports_persistent_xattrs() {
            return Err(Error::Unsupported);
        }
        // The dedup bit is the filesystem's bookkeeping — it says an extent is
        // in the pool and the refcount map agrees — so a caller clearing it
        // would leave the two disagreeing.  Only compression is the program's.
        let mutable = crate::abi::fs::FILE_FLAG_COMPRESSED;
        if set & !mutable != 0 || clear & !mutable != 0 {
            return Err(Error::InvalidArgument);
        }
        if set & clear != 0 {
            return Err(Error::InvalidArgument);
        }
        if inode_index >= state.inodes.len() {
            return Err(Error::InvalidArgument);
        }

        state.save_inode_for_undo(inode_index);
        let inode = state
            .inodes
            .get_mut(inode_index)
            .ok_or(Error::InternalError)?;
        if set & crate::abi::fs::FILE_FLAG_COMPRESSED != 0 {
            inode.compressed = true;
        }
        if clear & crate::abi::fs::FILE_FLAG_COMPRESSED != 0 {
            inode.compressed = false;
        }
        Ok(())
    }
}
