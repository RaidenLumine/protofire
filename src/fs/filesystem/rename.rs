//! src/fs/filesystem/rename.rs
//!
//! filesystem/rename — FileSystem rename methods.

use crate::kernel::security::SecurityToken;
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

    /// Exchange two paths within one mount, under `security_token`.
    ///
    /// The caller learns nothing about the moment in between because there is
    /// not one: a version switch that renamed one file and then the other would
    /// leave a window where the name it is switching points at nothing, and a
    /// crash would take that window.
    // The install path (`user::program::install`) is the caller, and it is
    // compiled only with a demo disk or in tests; a plain kernel build has none.
    #[cfg_attr(not(any(feature = "demo-disk", test)), allow(dead_code))]
    pub(crate) fn swap_normalized_paths_with_security_token(
        &self,
        normalized_a: &str,
        normalized_b: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        if normalized_a == "/" || normalized_b == "/" || normalized_a == normalized_b {
            return Err(crate::Error::InvalidArgument);
        }

        let ((mount_a, relative_a), (_mount_b, relative_b)) =
            self.resolve_same_mount_rename_entries(normalized_a, normalized_b)?;
        self.authorize_namespace_mutation_targets(&[normalized_a, normalized_b], security_token)?;
        mount_a.fs.swap_paths(&relative_a, &relative_b)
    }
}
