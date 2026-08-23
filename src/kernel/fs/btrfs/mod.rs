//! src/kernel/fs/btrfs/mod.rs
//! Btrfs read-only filesystem driver.
//!
//! ## Supported features
//!
//! - Superblock parsing at standard offset (64K)
//! - B-tree traversal (binary search, leaf read)
//! - Root tree → FS tree / subvolume tree resolution
//! - Inode lookup via INODE_ITEM
//! - Directory enumeration via DIR_ITEM
//! - File reading via EXTENT_DATA items (regular extents)
//! - CRC32C checksum verification on all B-tree nodes
//! - Subvolume traversal (automatic tree switching on subvolume boundaries)
//! - Multi-device support (chunk tree logical→physical address translation)
//!
//! ## Limitations
//!
//! - Read-only (all mutating operations return [`Error::PermissionDenied`]).
//! - No RAID striping (single-device chunks only).
//! - No journal / log-tree replay.

mod fs;
pub(crate) mod types;

#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::filesystem::profiler::{FsProfiler, FsProfilerSnapshot};
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport,
};
use crate::{Error, Result};

use fs::ChunkMap;
use types::{ExtentData, InodeItem, RootItem, Superblock, FS_TREE_OBJECTID};

// ── BtrfsVolume ─────────────────────────────────────────────────────────

pub struct BtrfsVolume {
    devices: Vec<Arc<dyn BlockDevice>>,
    sb: Superblock,
    fs_tree_root: u64,
    chunk_map: ChunkMap,
    /// Discovered subvolumes: (tree_objectid, RootItem).
    subvolumes: Vec<(u64, RootItem)>,
    profiler: Arc<FsProfiler>,
}

impl BtrfsVolume {
    /// Open a Btrfs filesystem spanning one or more block devices.
    ///
    /// The first device must contain the primary superblock at offset 64 KiB.
    /// Additional devices are discovered by parsing the chunk tree and are
    /// indexed by their device ID (devid) as recorded in each stripe.
    pub fn open(devices: Vec<Arc<dyn BlockDevice>>) -> Result<Self> {
        let device = &devices[0];
        let sb = fs::read_superblock(device)?;
        let fs_tree_root =
            fs::find_tree_root(device, &sb, FS_TREE_OBJECTID)?.ok_or(Error::InvalidArgument)?;

        // Build the chunk map for logical→physical address translation.
        let chunk_map = if devices.len() == 1 {
            ChunkMap::identity()
        } else {
            ChunkMap::from_chunk_tree(device, sb.chunk_tree_root, sb.node_size, devices.len())
                .unwrap_or_else(|_| ChunkMap::identity())
        };

        let subvolumes = fs::discover_subvolumes(device, &sb).unwrap_or_default();

        Ok(Self {
            devices,
            sb,
            fs_tree_root,
            chunk_map,
            subvolumes,
            profiler: Arc::new(FsProfiler::default()),
        })
    }

    /// Returns the primary device (device 0).
    fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.devices[0]
    }

    /// Resolve a path, returning `(tree_root_bytenr, inode_number)`.
    ///
    /// When a path component crosses a subvolume boundary (i.e. a DIR_ITEM
    /// points to an inode that lives in a different tree), this function
    /// automatically switches to the target subvolume's tree root.
    fn resolve_path(&self, path: &str) -> Result<(u64, u64)> {
        let clean = clean_path(path);
        if clean.is_empty() || clean == "/" {
            return Ok((self.fs_tree_root, self.sb.root_dir_objectid));
        }

        let segments: Vec<&str> = clean
            .strip_prefix('/')
            .unwrap_or(&clean)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_tree = self.fs_tree_root;
        let mut current_ino = self.sb.root_dir_objectid;

        for name in &segments {
            let entries =
                fs::read_dir_entries(self.device(), current_tree, self.sb.node_size, current_ino)?;
            let entry = entries
                .iter()
                .find(|e| String::from_utf8_lossy(&e.name) == *name)
                .ok_or(Error::NotFound)?;

            let child_ino = entry.inode;

            // Try to find the inode in the current tree.
            match fs::lookup_inode(self.device(), current_tree, self.sb.node_size, child_ino)? {
                Some(_) => {
                    current_ino = child_ino;
                }
                None => {
                    // Not in the current tree — check if this inode is the
                    // root directory of a known subvolume.
                    if let Some((_tree_id, ri)) = self
                        .subvolumes
                        .iter()
                        .find(|(_, ri)| ri.root_dirid == child_ino)
                    {
                        current_tree = ri.root_bytenr;
                        current_ino = child_ino;
                    } else {
                        return Err(Error::NotFound);
                    }
                }
            }
        }

        Ok((current_tree, current_ino))
    }
}

impl VfsFileSystem for BtrfsVolume {
    fn name(&self) -> &str {
        "btrfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.profiler.inc_lookups();
        let (tree_root, ino) = self.resolve_path(path)?;
        let inode = fs::lookup_inode(self.device(), tree_root, self.sb.node_size, ino)?
            .ok_or(Error::NotFound)?;

        let kind = if inode.is_dir() {
            NodeKind::Directory
        } else if inode.is_symlink() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        let extents = if inode.is_file() {
            fs::read_extents(self.device(), tree_root, self.sb.node_size, ino).unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(Arc::new(BtrfsVNode {
            name: extract_name(path),
            kind,
            size: inode.size as usize,
            extents,
            devices: self.devices.clone(),
            chunk_map: self.chunk_map.clone(),
            profiler: self.profiler.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.profiler.inc_lookups();
        let (tree_root, ino) = self.resolve_path(path)?;
        let entries = fs::read_dir_entries(self.device(), tree_root, self.sb.node_size, ino)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;

        // Try the current tree first; fall back to scanning subvolumes
        // if the child inode is a subvolume root directory.
        let child_tree =
            fs::lookup_inode(self.device(), tree_root, self.sb.node_size, entry.inode)?
                .map(|_| tree_root)
                .or_else(|| {
                    self.subvolumes
                        .iter()
                        .find(|(_, ri)| ri.root_dirid == entry.inode)
                        .map(|(_, ri)| ri.root_bytenr)
                })
                .unwrap_or(tree_root);

        let child_inode =
            fs::lookup_inode(self.device(), child_tree, self.sb.node_size, entry.inode)?.unwrap_or(
                InodeItem {
                    generation: 0,
                    transid: 0,
                    size: 0,
                    nbytes: 0,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    nlink: 0,
                    flags: 0,
                },
            );

        let kind = if child_inode.is_dir() {
            NodeKind::Directory
        } else if child_inode.is_symlink() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        Ok(DirectoryEntry {
            kind,
            size: child_inode.size as usize,
            name: String::from_utf8_lossy(&entry.name).into_owned(),
            security: SecurityDescriptor {
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o555,
            },
        })
    }

    fn rename(&self, _o: &str, _n: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn create_file(&self, _p: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn create_dir(&self, _p: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn create_symlink(&self, _t: &str, _p: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn create_device(&self, _p: &str, _m: u32, _n: u32) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn remove_path(&self, _p: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }
    fn update_security_descriptor(&self, _p: &str, _s: SecurityDescriptor) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        if self.sb.node_size == 0 {
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
    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.profiler.snapshot()
    }
}

// ── BtrfsVNode ──────────────────────────────────────────────────────────

struct BtrfsVNode {
    name: String,
    kind: NodeKind,
    size: usize,
    extents: Vec<ExtentData>,
    devices: Vec<Arc<dyn BlockDevice>>,
    chunk_map: ChunkMap,
    profiler: Arc<FsProfiler>,
}

impl VNode for BtrfsVNode {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> NodeKind {
        self.kind
    }
    fn size(&self) -> usize {
        self.size
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            kind: self.kind,
            size: self.size,
            security: SecurityDescriptor {
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o555,
            },
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.profiler.inc_reads();
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        fs::read_file(
            &self.devices,
            &self.chunk_map,
            &self.extents,
            self.size as u64,
            offset,
            buffer,
        )
    }

    fn write(&self, _o: u64, _b: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
    fn set_len(&self, _l: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        if self.extents.len() == 1 && self.extents[0].extent_type == 0 {
            let mut buf = vec![0u8; self.size];
            fs::read_file(
                &self.devices,
                &self.chunk_map,
                &self.extents,
                self.size as u64,
                0,
                &mut buf,
            )?;
            Ok(buf)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn clean_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn extract_name(path: &str) -> String {
    let clean = clean_path(path);
    if clean == "/" {
        return "/".into();
    }
    clean
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}
