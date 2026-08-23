//! src/kernel/fs/f2fs/vfs.rs
//! VFS integration: [`F2fsVolume`] wrapper, [`VfsFileSystem`] trait impl,
//! [`F2VNode`] implementation, and path helpers.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::super::block::BlockDevice;
use super::super::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, ROOT_GROUP_ID, ROOT_OWNER_ID,
};

use super::constants::*;
use super::types::*;
use super::F2fsFs;
use super::F2fsVolume;

// ─── F2fsVolume implementation ────────────────────────────────────────

impl F2fsVolume {
    /// Open an F2FS volume from the given block device.
    ///
    /// Reads and validates the superblock and checkpoint, then initialises
    /// the in-memory NAT and SIT caches.  Returns an error if the
    /// superblock magic does not match.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let name = format!(
            "f2fs:{}",
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        let fs = Arc::new(F2fsFs::open(device)?);
        Ok(Self { name, fs })
    }
}

// ─── VfsFileSystem implementation ─────────────────────────────────────

impl VfsFileSystem for F2fsVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (nid, inode) = self.fs.walk_path(path)?;
        let fname = path
            .rsplit_once('/')
            .map(|(_, leaf)| if leaf.is_empty() { "root" } else { leaf })
            .unwrap_or("root");
        Ok(Arc::new(F2VNode {
            name: fname.to_string(),
            nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (nid, inode) = self.fs.walk_path(path)?;
        Ok(self.fs.stat_inode(nid, &inode))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (_nid, dir_inode) = self.fs.walk_path(path)?;
        let kind = dir_inode.kind();
        if kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let entries = self.fs.read_dir_entries(&dir_inode)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        let child_nid = entry.ino;

        // Try to read the child inode for size/kind information.
        let child_kind = f2fs_ft_to_kind(entry.file_type);
        let child_size = match self.fs.read_inode(child_nid) {
            Ok(child_inode) => child_inode.file_size() as usize,
            Err(_) => 0,
        };

        Ok(DirectoryEntry::new(
            child_kind,
            child_size,
            entry.name.clone(),
        ))
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.fs.check_writable()?;

        // Walk old path to get the inode to rename.
        let (old_nid, old_inode) = self.fs.walk_path(old_path)?;

        let (old_parent_path, old_name) = split_path(old_path)?;
        let (old_parent_nid, _) = self.fs.walk_path(&old_parent_path)?;

        let (new_parent_path, new_name) = split_path(new_path)?;
        let (new_parent_nid, _) = self.fs.walk_path(&new_parent_path)?;

        // If the destination already exists, remove it.
        if let Ok((existing_nid, existing_inode)) = self.fs.walk_path(new_path) {
            if existing_nid == old_nid {
                // Renaming to the same name is a no-op.
                if old_path == new_path {
                    return Ok(());
                }
                // Same inode, different path — just remove old entry.
            } else if existing_inode.kind() == NodeKind::Directory {
                let entries = self.fs.read_dir_entries(&existing_inode)?;
                let non_dot_entries = entries
                    .iter()
                    .filter(|e| e.name != "." && e.name != "..")
                    .count();
                if non_dot_entries > 0 {
                    return Err(Error::Busy);
                }
            }
            self.fs.remove_dir_entry(new_parent_nid, &new_name)?;
            self.fs.free_inode_blocks(existing_nid)?;
            self.fs.nat_free_nid(existing_nid)?;
        }

        // Remove the old directory entry.
        self.fs.remove_dir_entry(old_parent_nid, &old_name)?;

        // Add the new directory entry pointing to the same inode.
        let file_type = match old_inode.kind() {
            NodeKind::Directory => F2FS_FT_DIR,
            NodeKind::File => F2FS_FT_REG_FILE,
            NodeKind::Device => F2FS_FT_CHRDEV,
            NodeKind::Symlink => F2FS_FT_SYMLINK,
        };
        self.fs
            .add_dir_entry(new_parent_nid, old_nid, &new_name, file_type)?;

        // When renaming a directory across parents, update links_count.
        if old_inode.kind() == NodeKind::Directory && old_parent_nid != new_parent_nid {
            let mut old_parent_inode = self.fs.read_inode(old_parent_nid)?;
            old_parent_inode.i_links = old_parent_inode.i_links.saturating_sub(1);
            self.fs.write_inode(old_parent_nid, &old_parent_inode)?;

            let mut new_parent_inode = self.fs.read_inode(new_parent_nid)?;
            new_parent_inode.i_links = new_parent_inode.i_links.saturating_add(1);
            self.fs.write_inode(new_parent_nid, &new_parent_inode)?;
        }

        self.fs.flush_all()
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        // Allocate a NID for the new file.
        let file_nid = self.fs.nat_alloc_nid()?;

        // Build a file inode.
        let file_inode = F2fsInode {
            i_mode: F2FS_S_IFREG | 0o644,
            i_uid: ROOT_OWNER_ID,
            i_gid: ROOT_GROUP_ID,
            i_links: 1,
            i_size: 0,
            i_blocks: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_atime_nsec: 0,
            i_ctime_nsec: 0,
            i_mtime_nsec: 0,
            i_xattr_nid: 0,
            i_flags: 0,
            i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
        };

        // Write the inode to get a physical block and bind it.
        self.fs.write_inode(file_nid, &file_inode)?;

        // Add directory entry in parent.
        self.fs
            .add_dir_entry(parent_nid, file_nid, &child_name, F2FS_FT_REG_FILE)?;

        self.fs.flush_all()?;

        let inode = self.fs.read_inode(file_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: file_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        let dir_nid = self.fs.nat_alloc_nid()?;
        let block_size = self.fs.block_size();

        // Build a data block with "." and ".." entries.
        let mut data_block = vec![0u8; block_size];
        let mut offset = 0usize;
        offset += write_f2fs_dir_entry(dir_nid, ".", F2FS_FT_DIR, 0, &mut data_block[offset..]);
        write_f2fs_dir_entry(parent_nid, "..", F2FS_FT_DIR, 0, &mut data_block[offset..]);

        // Allocate the data block.
        let data_phys = self.fs.segment_alloc_block(&data_block)?;

        // Build directory inode.
        let dir_inode = F2fsInode {
            i_mode: F2FS_S_IFDIR | 0o755,
            i_uid: ROOT_OWNER_ID,
            i_gid: ROOT_GROUP_ID,
            i_links: 2,
            i_size: (dir_entry_size(1) + dir_entry_size(2)) as u64,
            i_blocks: (block_size as u64).div_ceil(512),
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_atime_nsec: 0,
            i_ctime_nsec: 0,
            i_mtime_nsec: 0,
            i_xattr_nid: 0,
            i_flags: 0,
            i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
        };
        let mut dir_inode = dir_inode;
        dir_inode.i_addr[0] = data_phys;

        // Write the directory inode.
        self.fs.write_inode(dir_nid, &dir_inode)?;

        // Bump parent's link count.
        {
            let mut parent_inode = self.fs.read_inode(parent_nid)?;
            parent_inode.i_links = parent_inode.i_links.saturating_add(1);
            self.fs.write_inode(parent_nid, &parent_inode)?;
        }

        // Add entry in parent.
        self.fs
            .add_dir_entry(parent_nid, dir_nid, &child_name, F2FS_FT_DIR)?;

        self.fs.flush_all()
    }

    fn create_symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let target_bytes = target.as_bytes();
        // Only fast symlinks: target must fit inline in i_addr.
        let max_fast = F2FS_ADDRS_PER_INODE * 4; // 923 * 4 = 3692 bytes
        if target_bytes.len() > max_fast {
            return Err(Error::InvalidArgument);
        }

        let (parent_path, child_name) = split_path(link_path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        let sym_nid = self.fs.nat_alloc_nid()?;

        let mut sym_inode = F2fsInode {
            i_mode: F2FS_S_IFLNK | 0o777,
            i_uid: ROOT_OWNER_ID,
            i_gid: ROOT_GROUP_ID,
            i_links: 1,
            i_size: target_bytes.len() as u64,
            i_blocks: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_atime_nsec: 0,
            i_ctime_nsec: 0,
            i_mtime_nsec: 0,
            i_xattr_nid: 0,
            i_flags: 0,
            i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
        };

        // Write the target path inline into i_addr as raw bytes.
        let addr_bytes: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                sym_inode.i_addr.as_mut_ptr() as *mut u8,
                F2FS_ADDRS_PER_INODE * 4,
            )
        };
        addr_bytes[..target_bytes.len()].copy_from_slice(target_bytes);

        self.fs.write_inode(sym_nid, &sym_inode)?;
        self.fs
            .add_dir_entry(parent_nid, sym_nid, &child_name, F2FS_FT_SYMLINK)?;
        self.fs.flush_all()?;

        let inode = self.fs.read_inode(sym_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: sym_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn create_device(&self, path: &str, major: u32, minor: u32) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        let dev_nid = self.fs.nat_alloc_nid()?;

        let mut dev_inode = F2fsInode {
            i_mode: F2FS_S_IFCHR | 0o660,
            i_uid: ROOT_OWNER_ID,
            i_gid: ROOT_GROUP_ID,
            i_links: 1,
            i_size: 0,
            i_blocks: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_atime_nsec: 0,
            i_ctime_nsec: 0,
            i_mtime_nsec: 0,
            i_xattr_nid: 0,
            i_flags: 0,
            i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
        };
        // Store (major << 8) | minor in i_addr[0] as the device ID.
        dev_inode.i_addr[0] = (major << 8) | minor;

        self.fs.write_inode(dev_nid, &dev_inode)?;
        self.fs
            .add_dir_entry(parent_nid, dev_nid, &child_name, F2FS_FT_CHRDEV)?;
        self.fs.flush_all()?;

        let inode = self.fs.read_inode(dev_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: dev_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;

        // Path must not be "/".
        if path == "/" {
            return Err(Error::Busy);
        }

        let (nid, inode) = self.fs.walk_path(path)?;

        // Recursively remove children for directories.
        if inode.kind() == NodeKind::Directory {
            let entries = self.fs.read_dir_entries(&inode)?;
            for entry in &entries {
                if entry.name != "." && entry.name != ".." {
                    let child_path = if path.ends_with('/') {
                        format!("{}{}", path, entry.name)
                    } else {
                        format!("{}/{}", path, entry.name)
                    };
                    self.remove_path(&child_path)?;
                }
            }
        }

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, mut parent_inode) = self.fs.walk_path(&parent_path)?;

        self.fs.remove_dir_entry(parent_nid, &child_name)?;
        self.fs.free_inode_blocks(nid)?;
        self.fs.nat_free_nid(nid)?;

        // Decrement parent's link count if removing a directory.
        if inode.kind() == NodeKind::Directory {
            parent_inode.i_links = parent_inode.i_links.saturating_sub(1);
            self.fs.write_inode(parent_nid, &parent_inode)?;
        }

        self.fs.flush_all()
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        // No repair implemented for v1.
        Ok(VolumeCheckReport::default())
    }
}

// ─── F2VNode implementation ───────────────────────────────────────────

/// Private VNode handle for an F2FS inode.
struct F2VNode {
    name: String,
    nid: u32,
    inode: Mutex<F2fsInode>,
    fs: Arc<F2fsFs>,
}

impl VNode for F2VNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.fs
            .read_inode(self.nid)
            .map(|inode| inode.kind())
            .unwrap_or_else(|_| self.inode.lock().kind())
    }

    fn size(&self) -> usize {
        self.fs
            .read_inode(self.nid)
            .map(|inode| inode.file_size() as usize)
            .unwrap_or_else(|_| self.inode.lock().file_size() as usize)
    }

    fn metadata(&self) -> Result<Metadata> {
        let inode = self.fs.read_inode(self.nid)?;
        let kind = inode.kind();
        let size = inode.file_size() as usize;
        let perm = inode.permission_mode();
        Ok(
            Metadata::new(kind, size).with_security(SecurityDescriptor::new(
                inode.i_uid,
                inode.i_gid,
                perm,
            )),
        )
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let inode = self.fs.read_inode(self.nid)?;
        self.fs.read_file_data(&inode, offset, buffer)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        let written = self.fs.write_file_data(self.nid, offset, buffer)?;
        // Refresh the cached inode.
        if let Ok(fresh) = self.fs.read_inode(self.nid) {
            *self.inode.lock() = fresh;
        }
        Ok(written)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        self.fs.check_writable()?;
        let mut inode = self.fs.read_inode(self.nid)?;

        if length < inode.i_size {
            // Truncate: free blocks beyond the new end.
            let block_size = self.fs.block_size() as u64;
            let new_end_block = if length == 0 {
                0
            } else {
                length.div_ceil(block_size) as usize
            };
            for i in new_end_block..F2FS_ADDRS_PER_INODE {
                if inode.i_addr[i] != F2FS_NULL_ADDR && inode.i_addr[i] != F2FS_NEW_ADDR {
                    // Free this individual block.
                    let phys = inode.i_addr[i];
                    let blocks_per_seg = self.fs.sb.blocks_per_seg();
                    let segment0 = self.fs.sb.segment0_blkaddr;
                    if phys >= segment0 {
                        let rel = phys - segment0;
                        let segno = rel / blocks_per_seg;
                        let off = (rel % blocks_per_seg) as u16;
                        let mut sit = self.fs.sit_cache.lock();
                        if (segno as usize) < sit.entries.len() {
                            sit.entries[segno as usize].mark_invalid(off);
                        }
                    }
                    inode.i_addr[i] = F2FS_NULL_ADDR;
                }
            }
        }

        inode.i_size = length;
        inode.i_blocks = length.div_ceil(512);
        self.fs.write_inode(self.nid, &inode)?;
        *self.inode.lock() = inode;
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.fs.flush_all()
    }

    fn sync_data(&self) -> Result<()> {
        self.fs.cache.flush()
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        let inode = self.fs.read_inode(self.nid)?;
        self.fs.read_symlink_target(&inode)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        let inode = self.fs.read_inode(self.nid)?;
        if inode.kind() != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }
        let encoded = inode.i_addr[0];
        let major = (encoded >> 8) & 0xFF;
        let minor = encoded & 0xFF;
        Ok((major, minor))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────

/// Split a path into `(parent_path, leaf_name)`.
///
/// E.g. `"/foo/bar/baz"` → `("/foo/bar", "baz")`.
/// E.g. `"/hello"` → `("/", "hello")`.
pub(crate) fn split_path(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    let (parent, leaf) = trimmed.rsplit_once('/').ok_or(Error::InvalidArgument)?;
    if leaf.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let parent = if parent.is_empty() { "/" } else { parent };
    Ok((parent.to_string(), leaf.to_string()))
}

/// Convert an F2FS file-type code to a [`NodeKind`].
pub(crate) fn f2fs_ft_to_kind(ft: u8) -> NodeKind {
    match ft {
        F2FS_FT_DIR => NodeKind::Directory,
        F2FS_FT_REG_FILE => NodeKind::File,
        F2FS_FT_CHRDEV | F2FS_FT_BLKDEV => NodeKind::Device,
        F2FS_FT_SYMLINK => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}
