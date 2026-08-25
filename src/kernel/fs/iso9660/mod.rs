//! src/kernel/fs/iso9660/mod.rs
//!
//! ISO 9660 (CD-ROM) read-only filesystem with Rock Ridge, Joliet, and El
//! Torito.
//!
//! ## Supported features
//!
//! - Primary Volume Descriptor (PVD) parsing
//! - Directory record traversal (Level 1, 2, 3)
//! - Contiguous extent-based file reading
//! - Rock Ridge: NM (POSIX names), PX (permissions), SL (symlinks)
//! - Case-insensitive path lookup (ISO 9660 native behavior)
//!
//! ## Limitations
//!
//! - Read-only (all mutating operations return [`Error::PermissionDenied`]).
//! - No El Torito boot catalog support.
//! - No multi-extent files (ISO 9660 Level 3 interleave).
//! - XA attributes are ignored.
//! - Sector size is always assumed to be 2048 bytes.
//!
//! ## Architecture
//!
//! [`Iso9660Volume`] wraps a block device and PVD-derived state. Lookup
//! reads directory contents on the fly; intermediate directory reads are
//! discarded after path traversal. File reading pulls data directly from
//! contiguous extents on the device.

mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;

use alloc::string::String;
use alloc::sync::Arc;
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
use crate::Error;
use crate::Result;

use types::DirRecord;

// ── Volume label helper ────────────────────────────────────────────────────

/// Extract the volume label from the PVD's volume_id field.
fn pvd_volume_label(pvd: &types::Pvd) -> String {
    let raw = &pvd.volume_id;
    let end = raw
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(raw.len());
    let mut label = String::with_capacity(end);
    for &b in &raw[..end] {
        if b.is_ascii_graphic() || b == b' ' {
            label.push(b as char);
        } else {
            label.push('_');
        }
    }
    label.trim_end().into()
}

// ── Iso9660Volume ─────────────────────────────────────────────────────────

/// A mounted ISO 9660 volume implementing the VFS [`VfsFileSystem`] trait.
pub struct Iso9660Volume {
    device: Arc<dyn BlockDevice>,
    block_size: u16,
    volume_label: String,
    /// Joliet SVD root directory record, if present.
    joliet_root: Option<DirRecord>,
    /// Whether Joliet UCS-2BE filenames should be used.
    has_joliet: bool,
}

impl Iso9660Volume {
    /// Open an ISO 9660 volume on the given block device.
    ///
    /// Reads the PVD and validates the ISO 9660 signature.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let pvd = fs::read_pvd(&device)?;
        let block_size = pvd.block_size();
        if block_size == 0 || !(block_size as usize).is_multiple_of(types::SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }

        // Try to detect a Joliet Supplementary Volume Descriptor.
        let (joliet_label, joliet_root, has_joliet) = if let Some(svd) = fs::read_svd(&device) {
            let (joliet_root_rec, _) =
                DirRecord::parse_joliet(&svd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
            (pvd_volume_label(&svd), Some(joliet_root_rec), true)
        } else {
            (pvd_volume_label(&pvd), None, false)
        };

        Ok(Self {
            device,
            block_size,
            volume_label: joliet_label,
            joliet_root,
            has_joliet,
        })
    }

    /// Return the volume label.
    pub fn volume_label(&self) -> &str {
        &self.volume_label
    }

    /// Return El Torito boot catalog entries, if this is a bootable image.
    pub fn boot_entries(&self) -> Vec<types::BootEntry> {
        if let Some(catalog_lba) = fs::find_boot_catalog_lba(&self.device) {
            fs::read_boot_catalog(&self.device, catalog_lba).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Read directory entries from an extent, using Joliet if enabled.
    fn read_dir_extent(&self, extent_location: u32, extent_size: u32) -> Result<Vec<DirRecord>> {
        if self.has_joliet {
            fs::read_joliet_directory(&self.device, self.block_size, extent_location, extent_size)
        } else {
            fs::read_directory(&self.device, self.block_size, extent_location, extent_size)
        }
    }

    /// Read the root directory entries, preferring Joliet when available.
    fn read_root_entries(&self) -> Result<Vec<DirRecord>> {
        if let Some(ref joliet_root) = self.joliet_root {
            return fs::read_joliet_directory(
                &self.device,
                self.block_size,
                joliet_root.extent_location,
                joliet_root.extent_size,
            );
        }
        let pvd = fs::read_pvd(&self.device)?;
        let (root_record, _next) =
            DirRecord::parse(&pvd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
        fs::read_directory(
            &self.device,
            self.block_size,
            root_record.extent_location,
            root_record.extent_size,
        )
    }

    /// Resolve a clean path to a `(DirRecord, Option<Vec<DirRecord>>)` pair.
    /// The second element is populated for directories.
    fn resolve(&self, clean_path: &str) -> Result<(DirRecord, Option<Vec<DirRecord>>)> {
        if clean_path.is_empty() || clean_path == "/" {
            let entries = self.read_root_entries()?;
            let pvd = fs::read_pvd(&self.device)?;
            let (root_rec, _) =
                DirRecord::parse(&pvd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
            return Ok((root_rec, Some(entries)));
        }

        let segments: Vec<&str> = clean_path
            .strip_prefix('/')
            .unwrap_or(clean_path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_entries = self.read_root_entries()?;

        for (i, name) in segments.iter().enumerate() {
            let record = find_in_dir(&current_entries, name).ok_or(Error::NotFound)?;

            if i == segments.len() - 1 {
                let sub = if record.is_dir() {
                    Some(self.read_dir_extent(record.extent_location, record.extent_size)?)
                } else {
                    None
                };
                return Ok((record.clone(), sub));
            }

            if record.is_dir() {
                current_entries =
                    self.read_dir_extent(record.extent_location, record.extent_size)?;
            } else {
                return Err(Error::NotFound);
            }
        }

        Err(Error::NotFound)
    }
}

impl VfsFileSystem for Iso9660Volume {
    fn name(&self) -> &str {
        &self.volume_label
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_path(path);
        let (record, _entries) = self.resolve(&clean)?;

        let kind = if record.is_dir() {
            NodeKind::Directory
        } else if record.rr_symlink.is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        Ok(Arc::new(Iso9660VNode {
            name: record.best_name(),
            kind,
            extent_location: record.extent_location,
            extent_size: record.extent_size,
            rr_posix: record.rr_posix,
            rr_symlink: record.rr_symlink,
            device: self.device.clone(),
            block_size: self.block_size,
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let clean = clean_path(path);
        let (_, entries) = self.resolve(&clean)?;
        let entries = entries.ok_or(Error::InvalidArgument)?;
        let record = entries.get(index).ok_or(Error::NotFound)?;

        let kind = if record.is_dir() {
            NodeKind::Directory
        } else if record.rr_symlink.is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };

        Ok(DirectoryEntry {
            kind,
            size: record.extent_size as usize,
            name: record.best_name(),
            security: rr_to_security(&record.rr_posix),
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

        if self.block_size == 0 {
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
}

// ── Iso9660VNode ───────────────────────────────────────────────────────────

struct Iso9660VNode {
    name: String,
    kind: NodeKind,
    extent_location: u32,
    extent_size: u32,
    rr_posix: Option<(u32, u32, u32, u32)>,
    rr_symlink: Option<Vec<u8>>,
    device: Arc<dyn BlockDevice>,
    block_size: u16,
}

impl VNode for Iso9660VNode {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> NodeKind {
        self.kind
    }
    fn size(&self) -> usize {
        self.extent_size as usize
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            kind: self.kind,
            size: self.extent_size as usize,
            security: rr_to_security(&self.rr_posix),
            created: 0,
            modified: 0,
            accessed: 0,
        })
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        fs::read_extent(
            &self.device,
            self.block_size,
            self.extent_location,
            self.extent_size,
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
        match &self.rr_symlink {
            Some(data) => Ok(data.clone()),
            None => Err(Error::InvalidArgument),
        }
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
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

fn find_in_dir<'a>(entries: &'a [DirRecord], name: &str) -> Option<&'a DirRecord> {
    let lower = name.to_lowercase();
    // First try case-insensitive match on best_name.
    entries.iter().find(|e| {
        let ename = e.best_name();
        ename.to_lowercase() == lower || ename == *name
    })
}

fn rr_to_security(rr: &Option<(u32, u32, u32, u32)>) -> SecurityDescriptor {
    match rr {
        Some((mode, _links, uid, gid)) => SecurityDescriptor {
            owner_uid: *uid,
            owner_gid: *gid,
            mode: *mode as u16,
        },
        None => SecurityDescriptor {
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o555,
        },
    }
}
