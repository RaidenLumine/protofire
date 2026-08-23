//! src/kernel/fs/filesystem/xattr.rs
//! FileSystem extended-attribute (xattr) and per-file data-reduction flag
//! access, dispatched through the mounted filesystem's VNode.

use alloc::vec::Vec;

use crate::kernel::process::{SecurityToken, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::{Error, Result};

use super::super::vfs::XattrEntry;
use super::super::FileSystem;

impl FileSystem {
    /// Set (create or overwrite) an extended attribute on the file at
    /// `normalized`.
    pub(crate) fn set_xattr_for_normalized_path(
        &self,
        normalized: &str,
        name: &[u8],
        value: &[u8],
        security_token: SecurityToken,
    ) -> Result<()> {
        if normalized == "/" {
            return Err(Error::PermissionDenied);
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_WRITE, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.set_xattr(name, value)
    }

    /// Read the value of an extended attribute on the file at `normalized`.
    /// Returns `Ok(None)` when the attribute is not present.
    pub(crate) fn get_xattr_for_normalized_path(
        &self,
        normalized: &str,
        name: &[u8],
        security_token: SecurityToken,
    ) -> Result<Option<Vec<u8>>> {
        if normalized == "/" {
            return Ok(None);
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_READ, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.get_xattr(name)
    }

    /// List the extended attributes attached to the file at `normalized`.
    pub(crate) fn list_xattrs_for_normalized_path(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<Vec<XattrEntry>> {
        if normalized == "/" {
            return Ok(Vec::new());
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_READ, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.list_xattrs()
    }

    /// Remove an extended attribute from the file at `normalized`.
    pub(crate) fn remove_xattr_for_normalized_path(
        &self,
        normalized: &str,
        name: &[u8],
        security_token: SecurityToken,
    ) -> Result<()> {
        if normalized == "/" {
            return Err(Error::PermissionDenied);
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_WRITE, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.remove_xattr(name)
    }

    /// Toggle per-file data-reduction flags (`set` bits on, `clear` bits off)
    /// on the file at `normalized`.
    pub(crate) fn set_file_flags_for_normalized_path(
        &self,
        normalized: &str,
        set: u32,
        clear: u32,
        security_token: SecurityToken,
    ) -> Result<()> {
        if normalized == "/" {
            return Err(Error::PermissionDenied);
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_WRITE, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.set_file_flags(set, clear)
    }

    /// Read the per-file data-reduction flags for the file at `normalized`.
    pub(crate) fn get_file_flags_for_normalized_path(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<u32> {
        if normalized == "/" {
            return Ok(0);
        }
        self.authorize_existing_open(normalized, HANDLE_RIGHT_READ, security_token)?;
        let (fs, relative_path) = self.require_mount(normalized)?;
        let vnode = fs.lookup(&relative_path)?;
        vnode.get_file_flags()
    }
}
