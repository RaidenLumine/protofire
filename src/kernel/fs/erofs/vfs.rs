//! src/kernel/fs/erofs/vfs.rs
//!
//! EROFS VFS glue: mounting, lookup, reading directories.
//! VFS integration: [`EroFsVolume`] wrapper, [`FileSystem`] trait impl,
//! [`EroVNode`] implementation.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::super::block::BlockDevice;
use super::super::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, ROOT_GROUP_ID, ROOT_OWNER_ID,
};

use super::fs::EroFs;
use super::types::*;

// ─── EroFsVolume ───────────────────────────────────────────────────────

/// A mounted EROFS volume that implements [`VfsFileSystem`].
///
/// Created via [`EroFsVolume::open`], then registered with the kernel's
/// VFS and mounted at a path.
pub struct EroFsVolume {
    name: String,
    fs: Arc<EroFs>,
}

impl EroFsVolume {
    /// Open an EROFS volume from the given block device.
    ///
    /// Reads and validates the superblock.  Returns an error if the
    /// superblock magic does not match or the feature set is
    /// unsupported.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let vol_name = device.name().rsplit(':').next().unwrap_or(device.name());
        let name = format!("erofs:{}", vol_name);
        let fs = Arc::new(EroFs::open(device)?);
        Ok(Self { name, fs })
    }
}

// ─── VfsFileSystem implementation ─────────────────────────────────────

impl VfsFileSystem for EroFsVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (nid, inode) = self.fs.walk_path(path)?;
        let name = path
            .rsplit_once('/')
            .map(|(_, leaf)| {
                if leaf.is_empty() {
                    self.fs.sb.volume_name_string()
                } else {
                    leaf.to_string()
                }
            })
            .unwrap_or_else(|| self.fs.sb.volume_name_string());
        Ok(Arc::new(EroVNode {
            name,
            nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (_nid, inode) = self.fs.walk_path(path)?;
        Ok(metadata_from_inode(&inode))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (dir_nid, dir_inode) = self.fs.walk_path(path)?;
        let kind = erofs_mode_to_kind(dir_inode.mode());
        if kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let entries = self.fs.read_dir_entries(dir_nid)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        let child_nid = entry.nid as u32;

        // Try to read the child inode for size information.
        let child_kind = erofs_ft_to_kind(entry.file_type);
        let child_size = match self.fs.read_inode(child_nid) {
            Ok(child_inode) => child_inode.i_size as usize,
            Err(_) => 0,
        };

        Ok(DirectoryEntry::new(
            child_kind,
            child_size,
            entry.name.clone(),
        ))
    }

    // ── Mutating operations — all return PermissionDenied ──────────

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        if self.fs.sb.magic != EROFS_MAGIC {
            issues += 1;
        }

        if self.fs.sb.block_size() == 0 {
            issues += 1;
        }

        if self.lookup("/").is_err() {
            issues += 1;
        }

        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }
}

// ─── VNode implementation ─────────────────────────────────────────────

struct EroVNode {
    name: String,
    nid: u32,
    inode: Mutex<ErofsInodeCompact>,
    fs: Arc<EroFs>,
}

impl VNode for EroVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        // Re-read from disk to avoid stale cached data.
        self.fs
            .read_inode(self.nid)
            .map(|inode| erofs_mode_to_kind(inode.mode()))
            .unwrap_or_else(|_| erofs_mode_to_kind(self.inode.lock().mode()))
    }

    fn size(&self) -> usize {
        self.fs
            .read_inode(self.nid)
            .map(|inode| inode.i_size as usize)
            .unwrap_or_else(|_| self.inode.lock().i_size as usize)
    }

    fn metadata(&self) -> Result<Metadata> {
        let inode = self.fs.read_inode(self.nid)?;
        Ok(metadata_from_inode(&inode))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.fs.read_file_data(self.nid, offset, buffer)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    fn set_len(&self, _length: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn sync(&self) -> Result<()> {
        // Read-only volume — nothing to sync.
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn readlink(&self) -> Result<alloc::vec::Vec<u8>> {
        self.fs.read_symlink_target(self.nid)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────

fn metadata_from_inode(inode: &ErofsInodeCompact) -> Metadata {
    let kind = erofs_mode_to_kind(inode.mode());
    let size = inode.i_size as usize;
    let perm = inode.perm();
    // EROFS compact inodes don't store UID/GID directly — default to
    // root:root with the mode from i_format.
    Metadata::new(kind, size).with_security(SecurityDescriptor::new(
        ROOT_OWNER_ID,
        ROOT_GROUP_ID,
        perm,
    ))
}

impl ErofsSuperblock {
    /// Return the volume name as a String, truncating at the first NUL
    /// byte or using the full 16 bytes.
    fn volume_name_string(&self) -> String {
        let end = self
            .volume_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.volume_name.len());
        String::from_utf8_lossy(&self.volume_name[..end]).to_string()
    }
}
