//! src/kernel/fs/filesystem/dir.rs
//!
//! FileSystem directory create, remove, stat, read methods.
use crate::kernel::process::SecurityToken;
use crate::Result;

use super::super::vfs::{DirectoryEntry, Metadata as FileMetadata};
use super::super::FileSystem;

impl FileSystem {
    pub fn create_dir(&self, path: &str) -> Result<()> {
        let normalized = self.normalize_path(path)?;
        self.create_dir_normalized(&normalized)
    }

    pub fn create_dir_from(&self, path: &str, cwd: &str) -> Result<()> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.create_dir_normalized(&normalized)
    }

    pub(crate) fn create_dir_normalized(&self, normalized: &str) -> Result<()> {
        self.create_dir_normalized_with_security_token(normalized, SecurityToken::system())
    }

    pub(crate) fn create_dir_normalized_with_security_token(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        self.with_authorized_namespace_mutation(
            normalized,
            security_token,
            |mount, relative_path| mount.fs.create_dir(relative_path),
        )
    }

    pub fn remove_path(&self, path: &str) -> Result<()> {
        let normalized = self.normalize_path(path)?;
        self.remove_normalized_path(&normalized)
    }

    pub fn remove_path_from(&self, path: &str, cwd: &str) -> Result<()> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.remove_normalized_path(&normalized)
    }

    pub(crate) fn remove_normalized_path(&self, normalized: &str) -> Result<()> {
        self.remove_normalized_path_with_security_token(normalized, SecurityToken::system())
    }

    pub(crate) fn remove_normalized_path_with_security_token(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        self.with_authorized_namespace_mutation(
            normalized,
            security_token,
            |mount, relative_path| mount.fs.remove_path(relative_path),
        )
    }

    // Kept crash-recovery / security-token primitive; the install pipeline moved
    // out of the kernel and will consume this when re-added.
    #[allow(dead_code)]
    pub(crate) fn remove_normalized_path_if_exists_with_security_token(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        match self.remove_normalized_path_with_security_token(normalized, security_token) {
            Ok(()) | Err(crate::Error::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn stat_path(&self, path: &str) -> Result<FileMetadata> {
        let normalized = self.normalize_path(path)?;
        self.stat_normalized_path(&normalized)
    }

    pub fn stat_path_from(&self, path: &str, cwd: &str) -> Result<FileMetadata> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.stat_normalized_path(&normalized)
    }

    pub fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let normalized = self.normalize_path(path)?;
        self.read_dir_normalized(&normalized, index)
    }

    pub fn read_dir_from(&self, path: &str, cwd: &str, index: usize) -> Result<DirectoryEntry> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.read_dir_normalized(&normalized, index)
    }

    pub(crate) fn read_dir_normalized(
        &self,
        normalized: &str,
        index: usize,
    ) -> Result<DirectoryEntry> {
        self.merged_directory_entries(normalized)?
            .get(index)
            .cloned()
            .ok_or(crate::Error::NotFound)
    }
}
