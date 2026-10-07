//! src/fs/iso9660/mod.rs
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
//! - File data, length and space are writable ([RFC
//!   0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)): an ISO
//!   9660 file is one raw contiguous extent whose two fields — where it starts
//!   and how long it is — are in its directory record, so writing bytes, or a
//!   length inside the block the file has, touches nothing else.  Growing past
//!   that block takes blocks from an **append-only** allocator, which grows the
//!   volume's own declared size over them; a file with something after it
//!   *moves* to the end rather than growing where it is, because an extent is
//!   one contiguous run.  Creating, removing and renaming still return
//!   [`Error::PermissionDenied`], and a write to a read-only *device* is
//!   refused by the device.
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
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use crate::fs::block::BlockDevice;
use crate::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::fs::vfs::DirectoryEntry;
use crate::fs::vfs::FileSystem as VfsFileSystem;
use crate::fs::vfs::Metadata;
use crate::fs::vfs::NodeKind;
use crate::fs::vfs::SecurityDescriptor;
use crate::fs::vfs::SecurityDescriptorMutationSupport;
use crate::fs::vfs::VNode;
use crate::fs::vfs::VolumeCheckReport;
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

    /// Read the root directory, and say which extent it came from.
    fn read_root(&self) -> Result<(u32, Vec<DirRecord>)> {
        if let Some(ref joliet_root) = self.joliet_root {
            let entries = fs::read_joliet_directory(
                &self.device,
                self.block_size,
                joliet_root.extent_location,
                joliet_root.extent_size,
            )?;
            return Ok((joliet_root.extent_location, entries));
        }
        let pvd = fs::read_pvd(&self.device)?;
        let (root_record, _next) =
            DirRecord::parse(&pvd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
        let entries = fs::read_directory(
            &self.device,
            self.block_size,
            root_record.extent_location,
            root_record.extent_size,
        )?;
        Ok((root_record.extent_location, entries))
    }

    /// Resolve a clean path to its record, its directory's entries when it is a
    /// directory, and where its own record sits on the volume.
    ///
    /// The third element is what a resize rewrites: a directory record carries
    /// the length of the file it describes, and the record's position is not
    /// something a lookup can recover later without walking the path again.
    fn resolve(&self, clean_path: &str) -> Result<(DirRecord, Option<Vec<DirRecord>>, u64)> {
        if clean_path.is_empty() || clean_path == "/" {
            let (_, entries) = self.read_root()?;
            let pvd = fs::read_pvd(&self.device)?;
            let (root_rec, _) =
                DirRecord::parse(&pvd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
            // The root's record lives in the PVD, not in an extent, and a
            // directory is not resizable; zero is the honest answer.
            return Ok((root_rec, Some(entries), 0));
        }

        let segments: Vec<&str> = clean_path
            .strip_prefix('/')
            .unwrap_or(clean_path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let (mut entries_extent, mut current_entries) = self.read_root()?;

        for (i, name) in segments.iter().enumerate() {
            let record = find_in_dir(&current_entries, name).ok_or(Error::NotFound)?;
            // The parser recorded the offset it found the record at *inside
            // the extent it walked*; the volume is what knows where that
            // extent is.
            let record_offset =
                entries_extent as u64 * self.block_size as u64 + record.source_offset as u64;

            if i == segments.len() - 1 {
                let sub = if record.is_dir() {
                    Some(self.read_dir_extent(record.extent_location, record.extent_size)?)
                } else {
                    None
                };
                return Ok((record.clone(), sub, record_offset));
            }

            if record.is_dir() {
                entries_extent = record.extent_location;
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
        let (record, _entries, record_offset) = self.resolve(&clean)?;

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
            extent_location: AtomicU32::new(record.extent_location),
            extent_size: AtomicU32::new(record.extent_size),
            record_offset,
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
        let (_, entries, _) = self.resolve(&clean)?;
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
    /// The file's first logical block, as its record says.
    ///
    /// Atomic because a growth that has to move the file rewrites it: an
    /// extent is one contiguous run, so a file with something after it moves
    /// to new space rather than growing in place.
    extent_location: AtomicU32,
    /// The length the file's directory record carries.
    ///
    /// Atomic because [`VNode::set_len`] changes it: the record on the volume
    /// is the authority, and this is the copy the node answers with while it
    /// lives.
    extent_size: AtomicU32,
    /// Where this node's own directory record sits on the volume, in bytes.
    ///
    /// A resize rewrites the length *in that record*, and nothing else on the
    /// volume knows the file's size.
    record_offset: u64,
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
        self.extent_size.load(Ordering::Relaxed) as usize
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            kind: self.kind,
            size: self.size(),
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
            self.extent_location.load(Ordering::Relaxed),
            self.extent_size.load(Ordering::Relaxed),
            offset,
            buffer,
        )
    }

    /// Overwrite bytes the file already has.
    ///
    /// A write inside the file's length changes no metadata at all.  One that
    /// runs past the end grows the file first — the same `set_len` a caller
    /// could ask for — so a caller can create a file and write it the way it
    /// writes any other.  When the file cannot grow, the write is **short**
    /// rather than failing, which is the answer this call has always given for
    /// a byte it could not take.
    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let end = offset.saturating_add(buffer.len() as u64);
        if end > self.size() as u64 {
            // A refusal here is not this write's answer: the short write below
            // is.
            let _ = self.set_len(end);
        }
        fs::write_extent(
            &self.device,
            self.block_size,
            self.extent_location.load(Ordering::Relaxed),
            self.extent_size.load(Ordering::Relaxed),
            offset,
            buffer,
        )
    }

    /// Change the length the file's directory record carries.
    ///
    /// The record is the file's only metadata — its extent start and its
    /// length, both fields of the record — so a resize in place is one 16-byte
    /// write that covers both.
    ///
    /// A file's extent starts on a logical block boundary and its blocks are
    /// its own, so a length up to the end of the block the current one ends in
    /// needs no allocation: growing into that block's tail is free, and
    /// shrinking is free.  Past that block the file needs more blocks, and a
    /// file's extent is **one contiguous run**, so there are two ways to get
    /// them: take the blocks that follow, when the file is the last thing the
    /// volume holds, or move the file to the end of the volume, which is what
    /// happens when something else is in the way.  The allocator is
    /// append-only, so neither way reuses a block the image already wrote.
    fn set_len(&self, length: u64) -> Result<()> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let length = u32::try_from(length).map_err(|_| Error::InvalidArgument)?;
        let block_size = self.block_size as u32;
        let current = self.extent_size.load(Ordering::Relaxed);
        if length == current {
            return Ok(());
        }

        let mut extent_location = self.extent_location.load(Ordering::Relaxed);
        let last_block_end = current.div_ceil(block_size) * block_size;
        if length > last_block_end {
            let old_blocks = current.div_ceil(block_size);
            let new_blocks = length.div_ceil(block_size);
            let volume_end = fs::volume_blocks(&self.device)?;

            if volume_end != 0 && extent_location + old_blocks == volume_end {
                // The file is the last thing on the volume: the blocks it
                // needs are the ones that follow it, and the volume grows over
                // them.  Growing the volume first is what keeps a crash from
                // leaving a record that claims blocks the volume does not own.
                fs::set_volume_blocks(&self.device, volume_end + (new_blocks - old_blocks))?;
            } else {
                // Something follows it.  An extent is one run, so the file
                // moves to the end of the volume — data first, then the record
                // that points at it, so a crash before the record leaves the
                // old file whole.
                let first = fs::allocate_blocks(&self.device, self.block_size, new_blocks)?;
                let mut data = alloc::vec![0u8; current as usize];
                fs::read_extent(
                    &self.device,
                    self.block_size,
                    extent_location,
                    current,
                    0,
                    &mut data,
                )?;
                fs::write_extent(
                    &self.device,
                    self.block_size,
                    first,
                    length,
                    0,
                    &data[..current as usize],
                )?;
                extent_location = first;
            }
        }

        // Where the file is and how long it is, in one write: the two fields
        // are adjacent in the record and each is stored twice.
        fs::rewrite_record_placement(&self.device, self.record_offset, extent_location, length)?;

        self.extent_location
            .store(extent_location, Ordering::Relaxed);
        self.extent_size.store(length, Ordering::Relaxed);
        Ok(())
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
