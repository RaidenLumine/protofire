//! src/kernel/fs/devfs.rs
//! Device filesystem (devfs): exposes the kernel device registry as VFS nodes.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::kernel::device;
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem, Metadata, NodeKind, SecurityDescriptor, VNode,
};
use crate::{Error, Result};

/// Device filesystem.
pub struct DevFs;

/// A directory node for the devfs root.
pub struct DevDirVNode;

/// A VNode backed by a registered device descriptor.
pub struct DevVNode {
    name: String,
}

impl VNode for DevDirVNode {
    fn name(&self) -> &str {
        "/"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn size(&self) -> usize {
        0
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

impl VNode for DevVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Device
    }

    fn size(&self) -> usize {
        device::device_metadata(&self.name)
            .map(|meta| meta.size)
            .unwrap_or(0)
    }

    fn metadata(&self) -> Result<Metadata> {
        match device::device_metadata(&self.name) {
            Some(meta) => Ok(Metadata {
                kind: NodeKind::Device,
                size: meta.size,
                security: SecurityDescriptor::root_for_kind(NodeKind::Device),
                created: 0,
                modified: 0,
                accessed: 0,
            }),
            None => Err(Error::NotFound),
        }
    }

    fn read(&self, _offset: u64, buffer: &mut [u8]) -> Result<usize> {
        device::dispatch_device_read(&self.name, buffer, 0)
    }

    fn write(&self, _offset: u64, buffer: &[u8]) -> Result<usize> {
        device::dispatch_device_write(&self.name, buffer)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        // Device nodes are addressed by name through the registry; report a
        // stable (0, 0) major/minor pair since devfs has no block numbering.
        Ok((0, 0))
    }
}

impl FileSystem for DevFs {
    fn name(&self) -> &str {
        "devfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        if path == "/" || path.is_empty() || device::is_virtual_device_directory(path) {
            return Ok(Arc::new(DevDirVNode));
        }
        if device::virtual_device_node(path).is_some() {
            return Ok(Arc::new(DevVNode {
                name: path.to_string(),
            }));
        }
        // Allow lookup by bare device name (mount-relative, e.g. "console").
        let bare = path.strip_prefix('/').unwrap_or(path);
        if device::device_descriptor(bare).is_some() {
            return Ok(Arc::new(DevVNode {
                name: bare.to_string(),
            }));
        }
        Err(Error::NotFound)
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let device_name = path.strip_prefix('/').unwrap_or(path);

        if device_name.is_empty() || device_name.contains('/') {
            // Root of devfs — return directory metadata.
            return Ok(Metadata {
                kind: NodeKind::Directory,
                size: 0,
                security: SecurityDescriptor::root_for_kind(NodeKind::Directory),
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }

        self.lookup(path).and_then(|vnode| vnode.metadata())
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        if path == "/" || path.is_empty() || device::is_virtual_device_directory(path) {
            return device::virtual_device_directory_entry(index).ok_or(Error::InvalidArgument);
        }
        Err(Error::NotFound)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::Unsupported)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Register and mount devfs at `mount_path`.
pub fn mount_devfs(mount_path: &str) -> Result<()> {
    let fs = crate::kernel::fs::global().ok_or(Error::InternalError)?;
    let mut fs_guard = fs.lock();
    fs_guard.register("devfs", Arc::new(DevFs));
    fs_guard.mount("/dev/adastra-devfs", mount_path, "devfs", 0)
}
