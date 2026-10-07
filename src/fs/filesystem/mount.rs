//! src/fs/filesystem/mount.rs
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

    /// The handle a device was registered under, for a caller that needs the
    /// device itself rather than its geometry.
    ///
    /// The handle is the *wrapped* one a zone was mounted through — the
    /// wrapper the boot-work counters sit in — so a caller that reads through
    /// it is counted exactly once, the same way the zone's own reads are.
    pub fn block_device(&self, name: &str) -> Option<Arc<dyn BlockDevice>> {
        self.block_devices.get(name).cloned()
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

        crate::fs::publish_mount_snapshot(self.mount_points());

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
            .ok_or(crate::Error::NotFound)?;
        crate::fs::publish_mount_snapshot(self.mount_points());
        Ok(())
    }
}
