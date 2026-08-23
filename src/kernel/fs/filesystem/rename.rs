//! src/kernel/fs/filesystem/rename.rs
//! filesystem/rename — FileSystem rename methods.

use crate::kernel::process::SecurityToken;
use crate::Result;

use super::super::FileSystem;

impl FileSystem {
    pub fn rename_path(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (normalized_old, normalized_new) =
            self.normalize_path_pair_from(old_path, new_path, &self.current_working_dir())?;
        self.rename_normalized_paths(&normalized_old, &normalized_new)
    }

    pub fn rename_path_from(&self, old_path: &str, new_path: &str, cwd: &str) -> Result<()> {
        let (normalized_old, normalized_new) =
            self.normalize_path_pair_from(old_path, new_path, cwd)?;
        self.rename_normalized_paths(&normalized_old, &normalized_new)
    }

    pub(crate) fn rename_normalized_paths(
        &self,
        normalized_old: &str,
        normalized_new: &str,
    ) -> Result<()> {
        self.rename_normalized_paths_with_security_token(
            normalized_old,
            normalized_new,
            SecurityToken::system(),
        )
    }

    pub(crate) fn rename_normalized_paths_with_security_token(
        &self,
        normalized_old: &str,
        normalized_new: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        if normalized_old == "/" || normalized_new == "/" {
            return Err(crate::Error::InvalidArgument);
        }

        if normalized_old == normalized_new {
            return Ok(());
        }

        let ((old_mount, old_relative_path), (_new_mount, new_relative_path)) =
            self.resolve_same_mount_rename_entries(normalized_old, normalized_new)?;
        self.authorize_namespace_mutation_targets(
            &[normalized_old, normalized_new],
            security_token,
        )?;
        old_mount.fs.rename(&old_relative_path, &new_relative_path)
    }
}
