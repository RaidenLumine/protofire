//! src/kernel/fs/simplefs/vfs.rs
//!
//! VFS integration: SimpleFsVolume wrapper, VfsFileSystem trait implementation,
//! and SimpleVNode implementation.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::Result;

use super::super::block::DeviceHealth;
use super::super::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, XattrEntry,
};
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;

use super::{SimpleFs, SimpleFsVolume, SimpleVNode};

impl SimpleFsVolume {
    pub fn new(inner: Arc<SimpleFs>) -> Self {
        Self { inner }
    }
}

impl VfsFileSystem for SimpleFsVolume {
    fn name(&self) -> &str {
        self.inner.label.as_str()
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let inode_index = self.inner.resolve_path(path)?;
        self.inner.track_handle(inode_index);
        Ok(Arc::new(SimpleVNode {
            name: self.inner.name_of(inode_index),
            fs: self.inner.clone(),
            inode_index,
        }))
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let inode_index = self.inner.create_file(path)?;
        self.inner.track_handle(inode_index);
        Ok(Arc::new(SimpleVNode {
            name: self.inner.name_of(inode_index),
            fs: self.inner.clone(),
            inode_index,
        }))
    }

    fn create_symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn VNode>> {
        let inode_index = self.inner.create_symlink(target, link_path)?;
        self.inner.track_handle(inode_index);
        Ok(Arc::new(SimpleVNode {
            name: self.inner.name_of(inode_index),
            fs: self.inner.clone(),
            inode_index,
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.inner.stat_follow(path)
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.inner.read_dir(path, index)
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.inner.rename(old_path, new_path)
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        self.inner.create_dir(path)
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        self.inner.remove_path(path)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        self.inner.security_descriptor_mutation_support()
    }

    fn update_security_descriptor(&self, path: &str, security: SecurityDescriptor) -> Result<()> {
        self.inner.update_security_descriptor(path, security)
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        self.inner.check_and_repair()
    }

    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.inner.profiler_snapshot()
    }

    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        self.lookup(path)?.list_xattrs()
    }

    fn get_xattr(&self, path: &str, name: &[u8]) -> Result<Option<Vec<u8>>> {
        self.lookup(path)?.get_xattr(name)
    }
}
impl SimpleFsVolume {
    /// Return the number of data blocks that are not referenced by any live
    /// inode. This is a diagnostic helper; results may include blocks that
    /// were never allocated on V2 images.
    pub fn count_orphan_data_blocks(&self) -> usize {
        self.inner.count_orphan_data_blocks()
    }

    /// Verify stored data checksums against current file content.
    /// Returns `(files_checked, failures)`.
    pub fn check_data_integrity(&self) -> (usize, usize) {
        self.inner
            .check_data_integrity()
            .expect("check data integrity")
    }

    /// Return the health of the underlying block device.
    pub fn device_health(&self) -> DeviceHealth {
        self.inner.device_health()
    }

    /// Return a point-in-time snapshot of filesystem operation counters.
    pub fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.inner.profiler_snapshot()
    }
}

/// Manages a staging area within the filesystem for atomic install operations.
///
/// A staging area is a directory (typically `.staging`) where new content can
/// be prepared, verified, and atomically published via rename.  Orphaned
/// staging entries — left behind after a crash — can be cleaned up on next
/// mount by calling [`cleanup`](StagingArea::cleanup).
///
/// # Lifecycle
///
/// ```text
/// prepare("myapp")  →  /system/.staging/myapp/
///   (write files into the staging directory via normal FS operations)
/// verify            →  check checksums, metadata, etc.
/// publish(target)   →  atomically rename to target path
///   — or —
/// abort("myapp")    →  recursively remove the staging directory
/// ```
impl VNode for SimpleVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.fs.kind_of(self.inode_index)
    }

    fn size(&self) -> usize {
        self.fs.size_of(self.inode_index)
    }

    fn metadata(&self) -> Result<Metadata> {
        self.fs.metadata_of(self.inode_index)
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.fs.read_file(self.inode_index, offset, buffer)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        self.fs.write_file(self.inode_index, _offset, _buffer)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        self.fs.set_len_file(self.inode_index, length)
    }

    fn sync(&self) -> Result<()> {
        // Flush dirty cached blocks before the device-level flush so that
        // any deferred write-back data reaches the device.
        self.fs.cache.flush()?;
        self.fs.device.flush()
    }

    fn list_xattrs(&self) -> Result<Vec<XattrEntry>> {
        let state = self.fs.state.lock();
        Ok(self.fs.list_xattrs_for_inode(&state, self.inode_index))
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let state = self.fs.state.lock();
        self.fs.get_xattr_for_inode(&state, self.inode_index, name)
    }
}
