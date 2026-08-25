//! src/kernel/fs/xfs/mod.rs
//!
//! XFS read-only filesystem driver (phase 1).
//!
//! ## Supported features (phase 1)
//!
//! - Superblock parsing (v4/v5)
//! - Inode lookup via AG addressing
//! - Shortform and block-format directories
//! - Extent-based file reading
//! - Symlinks (inline, fast path)
//!
//! ## Limitations
//!
//! - Read-only (all mutating operations return [`Error::PermissionDenied`]).
//! - No B+tree-format directories (large dirs only partially supported).
//! - No B+tree-format data fork (files with >~20 extents).
//! - No journal replay (mounting a dirty FS may show stale data).
//! - No extended attributes.
//! - Attribute fork is ignored.
//!
//! ## Architecture
//!
//! [`XfsVolume`] wraps a block device. Inodes and directory blocks are read
//! on demand. File data is read via extent lists. No inode cache is maintained.

mod btree;
mod fs;
mod journal;
pub(crate) mod types;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::kernel::fs::vfs::DirectoryEntry;
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::vfs::Metadata;
use crate::kernel::fs::vfs::NodeKind;
use crate::kernel::fs::vfs::SecurityDescriptor;
use crate::kernel::fs::vfs::SecurityDescriptorMutationSupport;
use crate::kernel::fs::vfs::VNode;
use crate::kernel::fs::vfs::VolumeCheckReport;
use crate::kernel::fs::vfs::XattrEntry;
use crate::Error;
use crate::Result;

use types::Extent;
use types::InodeCore;
use types::Superblock;

// ── XfsVolume ─────────────────────────────────────────────────────────────

pub struct XfsVolume {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
}

impl XfsVolume {
    /// Open an XFS volume on the given block device.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let sb = fs::read_superblock(&device)?;
        Ok(Self { device, sb })
    }

    /// Resolve a path to a (ino, core, full_inode_buf) triple.
    fn resolve(&self, path: &str) -> Result<(u64, InodeCore, Vec<u8>)> {
        let clean = clean_xfs_path(path);
        let (ino, core, buf) = if clean.is_empty() || clean == "/" {
            let ino = self.sb.root_ino;
            let (core, buf) = fs::read_inode_buf(&self.device, &self.sb, ino)?;
            (ino, core, buf)
        } else {
            let segments: Vec<&str> = clean
                .strip_prefix('/')
                .unwrap_or(&clean)
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();

            let mut current_ino = self.sb.root_ino;

            for name in &segments {
                let (dc, db) = fs::read_inode_buf(&self.device, &self.sb, current_ino)?;
                current_ino = fs::lookup_dir_entry_by_name(
                    &self.device,
                    &self.sb,
                    &dc,
                    &db,
                    name.as_bytes(),
                )?
                .ok_or(Error::NotFound)?;
            }

            let (core, buf) = fs::read_inode_buf(&self.device, &self.sb, current_ino)?;
            (current_ino, core, buf)
        };

        Ok((ino, core, buf))
    }
}

impl VfsFileSystem for XfsVolume {
    fn name(&self) -> &str {
        "xfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_xfs_path(path);
        let ino = if clean.is_empty() || clean == "/" {
            self.sb.root_ino
        } else {
            let segments: Vec<&str> = clean
                .strip_prefix('/')
                .unwrap_or(&clean)
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            let mut cur = self.sb.root_ino;
            for name in &segments {
                let (dc, db) = fs::read_inode_buf(&self.device, &self.sb, cur)?;
                cur = fs::lookup_dir_entry_by_name(
                    &self.device,
                    &self.sb,
                    &dc,
                    &db,
                    name.as_bytes(),
                )?
                .ok_or(Error::NotFound)?;
            }
            cur
        };

        let (core, buf) = fs::read_inode_buf(&self.device, &self.sb, ino)?;

        let kind = if core.is_dir() {
            NodeKind::Directory
        } else if core.file_type() == 0o120000 {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        let extents = fs::get_extents(&self.device, &self.sb, &core, &buf).unwrap_or_default();

        let name = extract_name(path);

        Ok(Arc::new(XfsVNode {
            name,
            kind,
            ino,
            size: core.size as usize,
            format: core.format,
            extents,
            buf,
            device: self.device.clone(),
            sb: self.sb.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let clean = clean_xfs_path(path);
        let ino = if clean.is_empty() || clean == "/" {
            self.sb.root_ino
        } else {
            let segments: Vec<&str> = clean
                .strip_prefix('/')
                .unwrap_or(&clean)
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            let mut cur = self.sb.root_ino;
            for name in &segments {
                let (dc, db) = fs::read_inode_buf(&self.device, &self.sb, cur)?;
                cur = fs::lookup_dir_entry_by_name(
                    &self.device,
                    &self.sb,
                    &dc,
                    &db,
                    name.as_bytes(),
                )?
                .ok_or(Error::NotFound)?;
            }
            cur
        };

        let entries = fs::read_directory(&self.device, &self.sb, ino)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;

        let name = String::from_utf8_lossy(&entry.name).into_owned();
        let child_core = fs::read_inode_buf(&self.device, &self.sb, entry.inode)
            .map(|(c, _)| c)
            .unwrap_or_else(|_| InodeCore {
                magic: 0,
                mode: 0,
                version: 0,
                format: 0,
                attr_format: 0,
                uid: 0,
                gid: 0,
                nlink: 0,
                size: 0,
                num_extents: 0,
                attr_num_extents: 0,
                fork_offset: 0,
                is_v5: false,
            });

        let kind = if child_core.is_dir() {
            NodeKind::Directory
        } else if child_core.file_type() == 0o120000 {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        Ok(DirectoryEntry {
            kind,
            size: child_core.size as usize,
            name,
            security: SecurityDescriptor {
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o555,
            },
        })
    }

    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        let (_ino, core, buf) = self.resolve(path)?;
        fs::list_xattrs_for_inode(
            &self.device,
            &self.sb,
            &core,
            &buf,
            self.sb.inode_size as usize,
        )
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
        // A dirty journal (unclean unmount) means a metadata commit was
        // interrupted by a crash.  Replay the log when dirty so the on-disk
        // metadata is brought back up to date.
        let dirty = fs::check_journal(&self.sb).is_dirty;
        let mut repairs_applied = 0;
        if dirty && journal::replay_xfs_journal(&self.device, &self.sb).is_ok() {
            repairs_applied = 1;
        }
        Ok(VolumeCheckReport {
            issues_detected: usize::from(dirty),
            repairs_applied,
            orphan_data_blocks: 0,
            checksum_failures: 0,
            staging_orphans_cleaned: 0,
            orphan_blocks_cleaned: 0,
            interrupted_commits: usize::from(dirty),
        })
    }
    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        FsProfilerSnapshot::default()
    }
}

// ── XfsVNode ──────────────────────────────────────────────────────────────

struct XfsVNode {
    name: String,
    kind: NodeKind,
    #[allow(dead_code)]
    ino: u64,
    size: usize,
    format: u8,
    #[allow(dead_code)]
    extents: Vec<Extent>,
    #[allow(dead_code)]
    buf: Vec<u8>,
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
}

impl VNode for XfsVNode {
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
        if self.format == XFS_DINODE_FMT_LOCAL {
            fs::read_inline_file(
                &InodeCore {
                    magic: 0,
                    mode: 0,
                    version: 0,
                    format: self.format,
                    attr_format: 0,
                    uid: 0,
                    gid: 0,
                    nlink: 0,
                    size: self.size as u64,
                    num_extents: 0,
                    attr_num_extents: 0,
                    fork_offset: 0,
                    is_v5: false,
                },
                &self.buf,
                offset,
                buffer,
            )
        } else {
            fs::read_file(
                &self.device,
                &self.sb,
                &self.extents,
                self.size as u64,
                offset,
                buffer,
            )
        }
    }
    fn write(&self, _o: u64, _b: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
    fn set_len(&self, _l: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn readlink(&self) -> Result<Vec<u8>> {
        if self.format == XFS_DINODE_FMT_LOCAL {
            // Symlink target stored inline in data fork.
            let data = &self.buf[96..];
            let len = self.size.min(data.len());
            Ok(data[..len].to_vec())
        } else {
            // Symlink via extents — read the target.
            let mut target = vec![0u8; self.size.min(4096)];
            fs::read_file(
                &self.device,
                &self.sb,
                &self.extents,
                self.size as u64,
                0,
                &mut target,
            )?;
            Ok(target)
        }
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn clean_xfs_path(path: &str) -> String {
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
    let clean = clean_xfs_path(path);
    if clean == "/" {
        return "/".into();
    }
    clean
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}

use types::XFS_DINODE_FMT_LOCAL;
