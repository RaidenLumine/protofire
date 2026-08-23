//! src/kernel/fs/filesystem/io.rs
//! FileSystem read, write, replace methods.
use crate::kernel::process::{SecurityToken, HANDLE_RIGHT_WRITE};
use crate::Result;

use super::super::vfs::NodeKind;
use super::super::{FileHandle, FileSystem, OPEN_ALWAYS};
use super::path_helpers::*;

impl FileSystem {
    pub fn read(&self, file: &mut FileHandle, buffer: &mut [u8]) -> Result<usize> {
        file.read(buffer)
    }

    pub fn write(&self, file: &mut FileHandle, buffer: &[u8]) -> Result<usize> {
        file.write(buffer)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn replace_file_contents_normalized_with_security_token(
        &self,
        normalized: &str,
        bytes: &[u8],
        security_token: SecurityToken,
    ) -> Result<()> {
        let mut file = self.create_file_normalized_with_security_token(
            normalized,
            HANDLE_RIGHT_WRITE,
            0,
            OPEN_ALWAYS,
            security_token,
        )?;
        let _ = file.set_len(0)?;
        let written = self.write(&mut file, bytes)?;
        if written != bytes.len() {
            return Err(crate::Error::InternalError);
        }

        Ok(())
    }

    // Kept crash-recovery / security-token primitive; the install pipeline moved
    // out of the kernel and will consume this when re-added.
    #[allow(dead_code)]
    pub(crate) fn probe_directory_writable_normalized_with_security_token(
        &self,
        normalized_dir: &str,
        probe_name: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        let probe_path = probe_child_normalized_path(normalized_dir, probe_name)?;
        // Preflight writability before committing larger catalog/package
        // mutations so callers fail before partially mutating live state.
        self.remove_normalized_path_if_exists_with_security_token(&probe_path, security_token)?;
        self.replace_file_contents_normalized_with_security_token(
            &probe_path,
            b"probe\n",
            security_token,
        )?;
        self.remove_normalized_path_if_exists_with_security_token(&probe_path, security_token)
    }

    // Kept crash-recovery / security-token primitive; the install pipeline moved
    // out of the kernel and will consume this when re-added.
    #[allow(dead_code)]
    pub(crate) fn probe_nearest_existing_directory_writable_normalized_with_security_token(
        &self,
        normalized_path: &str,
        probe_name: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        let mut current = normalized_path;
        loop {
            match self.stat_normalized_path(current) {
                Ok(metadata) if metadata.kind == NodeKind::Directory => {
                    return self.probe_directory_writable_normalized_with_security_token(
                        current,
                        probe_name,
                        security_token,
                    );
                }
                Ok(_) => return Err(crate::Error::InvalidArgument),
                Err(crate::Error::NotFound) => {
                    let parent = parent_normalized_path(current).ok_or(crate::Error::NotFound)?;
                    current = parent;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
