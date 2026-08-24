//! src/kernel/fs/squashfs/mod.rs
//!
//! SquashFS read-only filesystem driver with LZ4 and ZSTD decompression.
//!
//! ## Supported features
//!
//! - Superblock parsing and validation
//! - Compressed metadata block reading (LZ4, ZSTD)
//! - Inode table caching
//! - Directory traversal
//! - File data reading with compression support (LZ4, ZSTD)
//! - Fragment table support
//!
//! ## Limitations
//!
//! - Read-only (all mutating operations return [`Error::PermissionDenied`]).
//! - No XZ compression support.

mod fs;
pub(crate) mod types;

#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, XattrEntry,
};
use crate::{Error, Result};

use types::{
    parse_extended_inode_xattr_idx, parse_inode, parse_squashfs_xattrs, Inode, Superblock,
    SQUASHFS_MAGIC, XATTR_ID_TABLE_ENTRY_SIZE,
};

// ── SquashfsVolume ─────────────────────────────────────────────────────────

pub struct SquashfsVolume {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
    inodes: Vec<u8>, // decompressed inode table
}

impl SquashfsVolume {
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let sb = fs::read_superblock(&device)?;
        let inodes = fs::load_inode_table(&device, &sb)?;

        // Validate root inode exists.
        if sb.root_inode_offset as usize >= inodes.len() {
            return Err(Error::InvalidArgument);
        }

        Ok(Self { device, sb, inodes })
    }

    /// Resolve a clean path to an inode index (offset into inode table).
    fn resolve(&self, clean_path: &str) -> Result<u32> {
        if clean_path.is_empty() || clean_path == "/" {
            return Ok(self.sb.root_inode_offset);
        }

        let segments: Vec<&str> = clean_path
            .strip_prefix('/')
            .unwrap_or(clean_path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_off = self.sb.root_inode_offset;

        for name in &segments {
            let (inode, _) =
                parse_inode(&self.inodes, current_off).ok_or(Error::InvalidArgument)?;
            let dir_inode = match &inode {
                Inode::Directory(d) => d,
                _ => return Err(Error::NotFound),
            };
            let entries = fs::read_dir_entries(&self.device, &self.sb, dir_inode)?;
            let found = entries
                .iter()
                .find(|e| e.name == *name)
                .ok_or(Error::NotFound)?;
            current_off = found.inode_offset;
        }

        Ok(current_off)
    }
}

impl VfsFileSystem for SquashfsVolume {
    fn name(&self) -> &str {
        "squashfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_path(path);
        let inode_off = self.resolve(&clean)?;
        let (inode, _) = parse_inode(&self.inodes, inode_off).ok_or(Error::InvalidArgument)?;

        let (kind, size) = match &inode {
            Inode::Directory(_) => (NodeKind::Directory, 0usize),
            Inode::File(f) => (NodeKind::File, f.file_size as usize),
            Inode::Symlink(_) => (NodeKind::Symlink, 0usize),
        };

        Ok(Arc::new(SquashfsVNode {
            name: extract_name(&clean),
            kind,
            size,
            inode_offset: inode_off,
            device: self.device.clone(),
            sb: self.sb.clone(),
            inodes: self.inodes.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let clean = clean_path(path);
        let inode_off = self.resolve(&clean)?;
        let (inode, _) = parse_inode(&self.inodes, inode_off).ok_or(Error::InvalidArgument)?;
        let dir_inode = match &inode {
            Inode::Directory(d) => d,
            _ => return Err(Error::InvalidArgument),
        };
        let entries = fs::read_dir_entries(&self.device, &self.sb, dir_inode)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;

        let (child_inode, _) = parse_inode(&self.inodes, entry.inode_offset).unwrap_or_else(|| {
            // Return a dummy kind on error.
            (
                Inode::Symlink(types::SymlinkInode {
                    nlink: 0,
                    target: Vec::new(),
                }),
                0,
            )
        });

        let (kind, size) = match &child_inode {
            Inode::Directory(_) => (NodeKind::Directory, 0usize),
            Inode::File(f) => (NodeKind::File, f.file_size as usize),
            Inode::Symlink(_) => (NodeKind::Symlink, 0usize),
        };

        Ok(DirectoryEntry {
            kind,
            size,
            name: entry.name.clone(),
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
    fn update_security_descriptor(&self, _path: &str, _security: SecurityDescriptor) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        if self.sb.magic != SQUASHFS_MAGIC {
            issues += 1;
        }

        if self.sb.block_size == 0 {
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
        FsProfilerSnapshot::default()
    }

    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        self.lookup(path)?.list_xattrs()
    }
}

// ── SquashfsVNode ──────────────────────────────────────────────────────────

struct SquashfsVNode {
    name: String,
    kind: NodeKind,
    size: usize,
    inode_offset: u32,
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
    inodes: Vec<u8>,
}

impl VNode for SquashfsVNode {
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
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let (inode, _) =
            parse_inode(&self.inodes, self.inode_offset).ok_or(Error::InvalidArgument)?;
        match &inode {
            Inode::File(f) => fs::read_file(&self.device, &self.sb, f, offset, buffer),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn write(&self, _o: u64, _b: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
    fn set_len(&self, _l: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        let (inode, _) =
            parse_inode(&self.inodes, self.inode_offset).ok_or(Error::InvalidArgument)?;
        match &inode {
            Inode::Symlink(s) => Ok(s.target.clone()),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn list_xattrs(&self) -> Result<Vec<XattrEntry>> {
        // Determine inode type code from the raw inode table to detect extended types.
        let inode_type = self
            .inodes
            .get(self.inode_offset as usize)
            .copied()
            .unwrap_or(0);

        // Extract xattr_idx if this is an extended inode (types 8, 9, 10).
        let xattr_idx = if inode_type >= 8 {
            parse_extended_inode_xattr_idx(&self.inodes, self.inode_offset, inode_type)
                .map(|(idx, _)| idx)
                .unwrap_or(0xFFFF_FFFF)
        } else {
            return Ok(Vec::new());
        };

        if xattr_idx == 0xFFFF_FFFF {
            return Ok(Vec::new());
        }

        // Read the xattr ID table (compressed metadata block).
        if self.sb.xattr_id_table_start == 0 {
            return Ok(Vec::new());
        }

        let id_table_uncompressed = (self.sb.inode_count as usize + 1) * XATTR_ID_TABLE_ENTRY_SIZE;
        let id_table_data = match fs::read_metadata_block(
            &self.device,
            &self.sb,
            self.sb.xattr_id_table_start,
            id_table_uncompressed,
        ) {
            Ok(data) => data,
            Err(_) => return Ok(Vec::new()),
        };

        // Look up the entry for this xattr_idx.
        let entry_off = xattr_idx as usize * XATTR_ID_TABLE_ENTRY_SIZE;
        if entry_off + XATTR_ID_TABLE_ENTRY_SIZE > id_table_data.len() {
            return Ok(Vec::new());
        }

        let xattr_pos = u64::from_le_bytes([
            id_table_data[entry_off],
            id_table_data[entry_off + 1],
            id_table_data[entry_off + 2],
            id_table_data[entry_off + 3],
            id_table_data[entry_off + 4],
            id_table_data[entry_off + 5],
            id_table_data[entry_off + 6],
            id_table_data[entry_off + 7],
        ]);
        let xattr_count = u32::from_le_bytes([
            id_table_data[entry_off + 8],
            id_table_data[entry_off + 9],
            id_table_data[entry_off + 10],
            id_table_data[entry_off + 11],
        ]);
        let xattr_size = u32::from_le_bytes([
            id_table_data[entry_off + 12],
            id_table_data[entry_off + 13],
            id_table_data[entry_off + 14],
            id_table_data[entry_off + 15],
        ]);

        if xattr_pos == 0xFFFF_FFFF_FFFF_FFFF || xattr_count == 0 {
            return Ok(Vec::new());
        }

        // Read and decompress the xattr data block.
        let xattr_data =
            match fs::read_metadata_block(&self.device, &self.sb, xattr_pos, xattr_size as usize) {
                Ok(data) => data,
                Err(_) => return Ok(Vec::new()),
            };

        Ok(parse_squashfs_xattrs(&xattr_data, xattr_count)
            .into_iter()
            .map(|(name, value)| XattrEntry::new(name, value))
            .collect())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

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
