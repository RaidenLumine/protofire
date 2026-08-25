//! src/kernel/fs/filesystem/mount.rs
//!
//! FileSystem mount, register, unmount methods.

use alloc::string::ToString;
use alloc::sync::Arc;

use super::types::MountPoint;
use crate::Result;

use super::super::block::BlockDevice;
use super::super::path;
use super::super::vfs::FileSystem as VfsTrait;
use super::super::FileSystem;

impl FileSystem {
    pub fn register(&mut self, name: &str, fs: Arc<dyn VfsTrait>) {
        self.filesystems.insert(name.to_string(), fs);
    }

    pub fn register_block_device(&mut self, name: &str, device: Arc<dyn BlockDevice>) {
        self.block_devices.insert(name.to_string(), device);
    }

    pub fn mount(&mut self, device: &str, path: &str, fs_name: &str, flags: u32) -> Result<()> {
        let mount_path = path::normalize_path(path, "/")?;
        let fs = self
            .filesystems
            .get(fs_name)
            .cloned()
            .ok_or(crate::Error::NotFound)?;

        self.mounted_fs.insert(
            mount_path,
            MountPoint {
                fs_name: fs.name().to_string(),
                fs,
                device: device.to_string(),
                flags,
            },
        );

        Ok(())
    }

    /// Remove a mount point at `path`.
    ///
    /// Returns [`Error::NotFound`] if no filesystem is mounted at the
    /// normalised path.
    pub fn unmount(&mut self, path: &str) -> Result<()> {
        let mount_path = path::normalize_path(path, "/")?;
        self.mounted_fs
            .remove(&mount_path)
            .map(|_| ())
            .ok_or(crate::Error::NotFound)
    }
}
