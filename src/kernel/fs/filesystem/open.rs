//! src/kernel/fs/filesystem/open.rs
//!
//! FileSystem open and create file methods.

use crate::kernel::process::SecurityToken;
use crate::Result;

use super::super::FileHandle;
use super::super::FileSystem;
use super::super::CREATE_NEW;
use super::super::OPEN_ALWAYS;
use super::super::OPEN_EXISTING;

impl FileSystem {
    pub fn open(&self, path: &str, flags: u32) -> Result<FileHandle> {
        self.create_file(path, flags, 0, 0)
    }

    pub fn open_from(&self, path: &str, cwd: &str, flags: u32) -> Result<FileHandle> {
        self.create_file_from(path, cwd, flags, 0, 0)
    }

    pub fn create_file(
        &self,
        path: &str,
        desired_access: u32,
        share_mode: u32,
        _creation_disposition: u32,
    ) -> Result<FileHandle> {
        let normalized = self.normalize_path(path)?;
        self.create_file_normalized(
            &normalized,
            desired_access,
            share_mode,
            _creation_disposition,
        )
    }

    pub fn create_file_from(
        &self,
        path: &str,
        cwd: &str,
        desired_access: u32,
        share_mode: u32,
        creation_disposition: u32,
    ) -> Result<FileHandle> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.create_file_normalized(
            &normalized,
            desired_access,
            share_mode,
            creation_disposition,
        )
    }

    pub(crate) fn create_file_normalized(
        &self,
        normalized: &str,
        desired_access: u32,
        share_mode: u32,
        creation_disposition: u32,
    ) -> Result<FileHandle> {
        self.create_file_normalized_with_security_token(
            normalized,
            desired_access,
            share_mode,
            creation_disposition,
            SecurityToken::system(),
        )
    }

    pub(crate) fn create_file_normalized_with_security_token(
        &self,
        normalized: &str,
        desired_access: u32,
        share_mode: u32,
        creation_disposition: u32,
        security_token: SecurityToken,
    ) -> Result<FileHandle> {
        let vnode = match creation_disposition {
            OPEN_EXISTING => {
                self.open_existing_file_node(normalized, desired_access, security_token)?
            }
            CREATE_NEW => self.create_new_file_node(normalized, security_token)?,
            OPEN_ALWAYS => {
                self.open_or_create_file_node(normalized, desired_access, security_token)?
            }
            _ => return Err(crate::Error::InvalidArgument),
        };
        let metadata = self.stat_normalized_path(normalized)?;
        let mount_flags = self
            .resolve_mount_entry(normalized)
            .map(|(mount, _relative_path)| mount.flags)
            .unwrap_or(0);
        let security_source =
            self.security_descriptor_mutation_support_for_normalized_path(normalized);
        let handle = {
            let mut next = self.next_handle.lock();
            let handle = *next;
            *next += 1;
            handle
        };

        Ok(FileHandle {
            handle,
            vnode,
            security: metadata.security,
            security_source,
            mount_flags,
            position: 0,
            flags: desired_access,
            share_mode,
        })
    }

    pub(crate) fn authorize_open_normalized_path_with_security_token(
        &self,
        normalized: &str,
        desired_access: u32,
        security_token: SecurityToken,
    ) -> Result<()> {
        self.authorize_existing_open(normalized, desired_access, security_token)
    }
}
