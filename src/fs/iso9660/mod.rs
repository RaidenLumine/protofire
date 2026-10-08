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
//! - Rock Ridge: NM (POSIX names), PX (permissions), SL (symlinks) — read, and
//!   NM/PX written for an entry this driver creates or renames
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
//!   one contiguous run.  A regular file can be created — empty, in the
//!   directory it names — and removed, which is a record appended to that
//!   directory or shifted out of it; a **directory** can be created and removed
//!   too, and that is what moves the path tables, which are rebuilt from the
//!   tree rather than edited in place.  A directory that still holds something
//!   refuses to go, and an entry can be renamed or moved: its record leaves one
//!   directory and joins another, a directory's ".." follows it, and the tables
//!   are rebuilt.
//! - A created or renamed entry carries a Rock Ridge **name** entry, so its
//!   name is the caller's — lower case, spaces, anything a record has room for
//!   — and the identifier beside it is the mangled form a reader that ignores
//!   Rock Ridge sees.  No `ER` entry is written yet, so such a reader is
//!   entitled to ignore the name entry; a name too long for the 255-byte record
//!   that has to hold it is refused rather than stored in part.
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

use alloc::collections::VecDeque;
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
use crate::fs::vfs::MAX_PERMISSION_MODE;
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

    /// Read the root directory: its own record, and its entries.
    fn read_root(&self) -> Result<(DirRecord, Vec<DirRecord>)> {
        if let Some(ref joliet_root) = self.joliet_root {
            let entries = fs::read_joliet_directory(
                &self.device,
                self.block_size,
                joliet_root.extent_location,
                joliet_root.extent_size,
            )?;
            return Ok((joliet_root.clone(), entries));
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
        Ok((root_record, entries))
    }

    /// Every directory the volume has, in the order a path table keeps them.
    ///
    /// The standard's order is by hierarchy level, then by the parent's number,
    /// then by identifier.  A level-order walk gives the first two for free —
    /// a parent is always numbered before its children — so this walks the
    /// levels in turn and sorts each directory's children by identifier.
    fn path_table_entries(&self) -> Result<Vec<fs::PathTableEntry>> {
        let (root, root_entries) = self.read_root()?;
        let mut entries = alloc::vec![fs::PathTableEntry {
            identifier: alloc::vec![0x00],
            extent_location: root.extent_location,
            number: 1,
            parent_number: 1,
        }];

        let mut pending: VecDeque<(u16, Vec<DirRecord>)> = VecDeque::new();
        pending.push_back((1, root_entries));
        while let Some((parent_number, records)) = pending.pop_front() {
            let mut children: Vec<DirRecord> = records
                .into_iter()
                .filter(|record| record.is_dir() && !is_self_or_parent(record))
                .collect();
            children.sort_by(|left, right| left.identifier.cmp(&right.identifier));

            for child in children {
                let number = u16::try_from(entries.len() + 1).map_err(|_| Error::NoSpace)?;
                entries.push(fs::PathTableEntry {
                    identifier: child.identifier.clone(),
                    extent_location: child.extent_location,
                    number,
                    parent_number,
                });
                let sub = self.read_dir_extent(child.extent_location, child.extent_size)?;
                pending.push_back((number, sub));
            }
        }
        Ok(entries)
    }

    /// Rebuild both path tables from the tree and write them.
    ///
    /// The tables are *derived* rather than edited: a directory's number is its
    /// position, so inserting one renumbers everything after it, and rebuilding
    /// the list is the same work with fewer ways to be wrong.  Two are
    /// required — one per byte order — and a volume may also carry optional
    /// copies, which are rewritten to the same content because a reader is
    /// allowed to follow them.
    fn rewrite_path_tables(&self) -> Result<()> {
        let entries = self.path_table_entries()?;
        let little = fs::build_path_table(&entries, false);
        let big = fs::build_path_table(&entries, true);
        debug_assert_eq!(little.len(), big.len());
        let size = u32::try_from(little.len()).map_err(|_| Error::NoSpace)?;

        let pvd = fs::read_pvd(&self.device)?;
        let old_size = u32::from_le_bytes(
            pvd.path_table_size[..4]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let blocks = |bytes: u32| (bytes as u64).div_ceil(self.block_size as u64) as u32;

        let mut l_location = fs::field_le(pvd.l_path_table_loc);
        let mut m_location = fs::field_be(pvd.m_path_table_loc);
        if blocks(size) > blocks(old_size) {
            // A path table is one contiguous extent like any other, so more
            // room than it has means moving it to the end of the volume.
            l_location = fs::allocate_blocks(&self.device, self.block_size, blocks(size))?;
            m_location = fs::allocate_blocks(&self.device, self.block_size, blocks(size))?;
        }

        let write_at = |location: u32, table: &[u8]| -> Result<()> {
            fs::write_exact(
                &self.device,
                location as u64 * self.block_size as u64,
                table,
            )
        };
        write_at(l_location, &little)?;
        write_at(m_location, &big)?;
        let opt_l = if pvd.opt_l_path_table_loc == 0 {
            0
        } else {
            write_at(l_location, &little)?;
            l_location
        };
        let opt_m = if pvd.opt_m_path_table_loc == 0 {
            0
        } else {
            write_at(m_location, &big)?;
            m_location
        };

        fs::rewrite_path_table_fields(&self.device, size, l_location, opt_l, m_location, opt_m)
    }

    /// Resolve a clean path to its record, its directory's entries when it is a
    /// directory, and where its own record sits on the volume.
    ///
    /// The third element is what a resize rewrites: a directory record carries
    /// the length of the file it describes, and the record's position is not
    /// something a lookup can recover later without walking the path again.
    fn resolve(&self, clean_path: &str) -> Result<(DirRecord, Option<Vec<DirRecord>>, u64)> {
        if clean_path.is_empty() || clean_path == "/" {
            let (root_rec, entries) = self.read_root()?;
            // The root's record is a field of the PVD, and a root that grows
            // or shrinks rewrites its length there.
            return Ok((root_rec, Some(entries), fs::root_record_offset()));
        }

        let segments: Vec<&str> = clean_path
            .strip_prefix('/')
            .unwrap_or(clean_path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let (root_record, root_entries) = self.read_root()?;
        let mut entries_extent = root_record.extent_location;
        let mut current_entries = root_entries;

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

    /// The directory a path names a child of, and the child's own name.
    ///
    /// A path is resolved one segment at a time, and a create or a remove needs
    /// the *parent*: its extent is where a child's record goes, and its own
    /// record is where the directory's length lives.
    fn resolve_child(&self, clean_path: &str) -> Result<(DirRecord, u64, String)> {
        let (parent_path, child) = match clean_path.rfind('/') {
            Some(index) => (&clean_path[..index], &clean_path[index + 1..]),
            None => ("", clean_path),
        };
        if child.is_empty() {
            // The root has no parent to add it to or take it from.
            return Err(Error::InvalidArgument);
        }

        let parent_path = if parent_path.is_empty() {
            "/"
        } else {
            parent_path
        };
        let (parent, _entries, record_offset) = self.resolve(parent_path)?;
        if !parent.is_dir() {
            return Err(Error::InvalidArgument);
        }
        Ok((parent, record_offset, String::from(child)))
    }

    /// Where a directory's own ".." record sits on the volume.
    ///
    /// It is the second record in the directory's extent, and the parser finds
    /// it by its identifier — one byte, `0x01` — so this does not have to
    /// assume how long the first record is.
    fn parent_record_of(&self, extent_location: u32, extent_size: u32) -> Result<u64> {
        let mut data = alloc::vec![0u8; extent_size as usize];
        fs::read_extent(
            &self.device,
            self.block_size,
            extent_location,
            extent_size,
            0,
            &mut data,
        )?;

        let mut at = 0usize;
        while let Some((record, next)) = DirRecord::parse(&data, at) {
            if record.identifier == [0x01] {
                return Ok(extent_location as u64 * self.block_size as u64 + at as u64);
            }
            at = next;
        }
        Err(Error::InvalidArgument)
    }

    /// Add a record to a directory, and answer where it landed.
    ///
    /// A directory that has to grow can **move**: an extent is one contiguous
    /// run, and the blocks after it may be taken.  When it does, its children's
    /// own ".." records — which name it by where it was — are stale, so they
    /// are rewritten here, at the one place a directory grows.
    ///
    /// The children are read out of the extent the directory *left*, which the
    /// move copied rather than changed: that copy is the directory as it was
    /// before this record joined it, which is exactly the list to correct.
    ///
    /// Three things name a directory by its address, and a move leaves all
    /// three behind: its parent's record for it, its children's "..", and both
    /// path tables.  Correcting them here is what keeps a create that happens
    /// to fill a full directory from writing a volume whose tree and whose
    /// tables disagree.
    fn append_to_directory(
        &self,
        parent: &DirRecord,
        parent_record_offset: u64,
        record: &[u8],
    ) -> Result<u64> {
        let (location, new_size, record_offset) = fs::append_record(
            &self.device,
            self.block_size,
            parent.extent_location,
            parent.extent_size,
            record,
        )?;

        if location != parent.extent_location {
            let children = self.read_dir_extent(parent.extent_location, parent.extent_size)?;
            for child in children.iter().filter(|child| child.is_dir()) {
                let child_parent =
                    self.parent_record_of(child.extent_location, child.extent_size)?;
                fs::rewrite_record_placement(&self.device, child_parent, location, new_size)?;
            }
            fs::rewrite_record_placement(&self.device, parent_record_offset, location, new_size)?;
            // Last, because the tables are rebuilt from the tree: the walk that
            // derives them starts at the root's record, which the line above
            // just moved when the directory that grew *is* the root.
            self.rewrite_path_tables()?;
            return Ok(record_offset);
        }

        fs::rewrite_record_placement(&self.device, parent_record_offset, location, new_size)?;
        Ok(record_offset)
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

    /// Move or rename an entry.
    ///
    /// This is a removal and a create the caller sees as one: the record leaves
    /// its directory, and an identical one — the same extent and the same
    /// length — joins the destination's under the new name.  A directory also
    /// carries ".." pointing at its parent, so a move rewrites that, and both
    /// path tables are rebuilt because a directory's level and number are
    /// properties of where it sits.
    fn rename(&self, old: &str, new: &str) -> Result<()> {
        let old_clean = clean_path(old);
        let new_clean = clean_path(new);
        if old_clean == new_clean {
            return Ok(());
        }

        let (record, _entries, record_offset) = self.resolve(&old_clean)?;
        if self.resolve(&new_clean).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (old_parent, old_parent_record_offset, _old_name) = self.resolve_child(&old_clean)?;
        let new_name = self.resolve_child(&new_clean)?.2;

        if record.is_dir() {
            // A directory cannot move inside itself: the records a move would
            // rewrite are the ones it is made of.
            let old_prefix = alloc::format!("{old_clean}/");
            let new_parent_path = parent_path_of(&new_clean);
            if new_parent_path == old_clean || new_parent_path.starts_with(&old_prefix) {
                return Err(Error::InvalidArgument);
            }
        }

        // Out of the old directory first, and then the destination is resolved
        // again: when both are the same directory, the removal shortened it and
        // the append has to see the length that leaves.
        remove_child_record(
            &self.device,
            self.block_size,
            old_parent.extent_location,
            old_parent.extent_size,
            old_parent_record_offset,
            record_offset,
            record.record_len,
        )?;
        let (new_parent, new_parent_record_offset, _new_name) = self.resolve_child(&new_clean)?;

        let entries = self.read_dir_extent(new_parent.extent_location, new_parent.extent_size)?;
        let identifier = identifier_for(&new_name, record.is_dir(), &identifiers_in(&entries))?;
        // The entry keeps everything its record said about it — its POSIX
        // attributes, a symlink's target, whatever else its System Use area
        // holds — except the name entries, which are the one thing a rename
        // changes.
        let bytes = directory_record(
            &identifier,
            record.extent_location,
            record.extent_size,
            record.is_dir(),
            &types::susp_with_name(&record.system_use, new_name.as_bytes()),
        )?;
        let _record_offset =
            self.append_to_directory(&new_parent, new_parent_record_offset, &bytes)?;

        if record.is_dir() {
            if old_parent.extent_location != new_parent.extent_location {
                // ".." is the directory's own record of its parent, and this is
                // the one thing about it that a move changes.
                let parent_record =
                    self.parent_record_of(record.extent_location, record.extent_size)?;
                fs::rewrite_record_placement(
                    &self.device,
                    parent_record,
                    new_parent.extent_location,
                    new_parent.extent_size,
                )?;
            }
            self.rewrite_path_tables()?;
        }
        Ok(())
    }

    /// Add a regular file to a directory.
    ///
    /// The file is *empty*: its record points at where the volume's space ends
    /// and says its length is zero, so creating one costs the record and
    /// nothing else, and the first write is what gives it blocks
    /// ([RFC 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
    ///
    /// The name the caller used is what its record's `NM` entry holds, so a
    /// name the identifier cannot spell — lower case, spaces, anything — is
    /// stored as itself and read back as itself, while the identifier is the
    /// mangled form a reader without Rock Ridge sees.
    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_path(path);
        if self.resolve(&clean).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(&clean)?;
        let entries = self.read_dir_extent(parent.extent_location, parent.extent_size)?;
        let identifier = identifier_for(&child, false, &identifiers_in(&entries))?;

        let extent_location = fs::volume_blocks(&self.device)?;
        let record = directory_record(
            &identifier,
            extent_location,
            0,
            false,
            &rock_ridge_area(&child, default_posix(false)),
        )?;
        let record_offset = self.append_to_directory(&parent, parent_record_offset, &record)?;

        Ok(Arc::new(Iso9660VNode {
            // The record's name entry holds what the caller asked for, so the
            // node is named that and a second mount agrees.
            name: child,
            kind: NodeKind::File,
            extent_location: AtomicU32::new(extent_location),
            extent_size: AtomicU32::new(0),
            record_offset,
            // The attributes are what the record this call wrote carries, so
            // the node answers with them rather than with the default a record
            // without them would get.
            rr_posix: Some(default_posix(false)),
            rr_symlink: None,
            device: self.device.clone(),
            block_size: self.block_size,
        }))
    }
    fn create_dir(&self, path: &str) -> Result<()> {
        let clean = clean_path(path);
        if self.resolve(&clean).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(&clean)?;
        let entries = self.read_dir_extent(parent.extent_location, parent.extent_size)?;
        let identifier = identifier_for(&child, true, &identifiers_in(&entries))?;

        // A directory's extent holds its own two records before anything else:
        // "." is itself and ".." is its parent, and they are what makes it a
        // directory at all.
        let extent_location = fs::allocate_blocks(&self.device, self.block_size, 1)?;
        let mut extent = DirRecord::new_directory(&[0x00], extent_location, EMPTY_DIRECTORY_BYTES);
        extent.extend_from_slice(&DirRecord::new_directory(
            &[0x01],
            parent.extent_location,
            parent.extent_size,
        ));
        debug_assert_eq!(extent.len(), EMPTY_DIRECTORY_BYTES as usize);
        fs::write_exact(
            &self.device,
            extent_location as u64 * self.block_size as u64,
            &extent,
        )?;

        // The parent's own record for it, appended to the parent's extent the
        // way any other child is.
        let record = directory_record(
            &identifier,
            extent_location,
            EMPTY_DIRECTORY_BYTES,
            true,
            &rock_ridge_area(&child, default_posix(true)),
        )?;
        let _record_offset = self.append_to_directory(&parent, parent_record_offset, &record)?;

        // And the path tables, which are how a reader finds a directory without
        // walking the tree.  They come last on purpose: a crash between the two
        // leaves a directory the *tree* has and the table does not, which a
        // walk still finds, rather than an entry for a directory that is not
        // there at all.
        self.rewrite_path_tables()
    }
    fn create_symlink(&self, _t: &str, _p: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn create_device(&self, _p: &str, _m: u32, _n: u32) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    /// Take a regular file out of its directory.
    ///
    /// The records after it move down over it rather than being re-serialised:
    /// a record carries whatever its writer put in the System Use area, and
    /// this driver does not parse all of it, so the bytes are the only honest
    /// copy.  What the file's blocks were is not reclaimed — the allocator
    /// appends, and a free-space scan is what would change that.
    fn remove_path(&self, path: &str) -> Result<()> {
        let clean = clean_path(path);
        let (record, _entries, record_offset) = self.resolve(&clean)?;
        if record.is_dir() {
            // A directory that still holds something cannot go: its children's
            // records would be pointing at a parent nothing names, and the
            // path tables would have to lose their entries one by one.  An
            // empty one is exactly its own two records.
            if record.extent_size != EMPTY_DIRECTORY_BYTES {
                return Err(Error::Busy);
            }
        }
        let (parent, parent_record_offset, _child) = self.resolve_child(&clean)?;
        remove_child_record(
            &self.device,
            self.block_size,
            parent.extent_location,
            parent.extent_size,
            parent_record_offset,
            record_offset,
            record.record_len,
        )?;

        if record.is_dir() {
            // The tables still name it, and a table that names a directory the
            // tree does not have is the worse half of the same crash.
            self.rewrite_path_tables()?;
        }
        Ok(())
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
        let current = self.extent_size.load(Ordering::Relaxed);
        if length == current {
            return Ok(());
        }

        let extent_location = self.extent_location.load(Ordering::Relaxed);
        // Past the block the file has, the extent needs blocks; `place_extent`
        // takes them where it can and moves the file where it cannot.
        let extent_location = fs::place_extent(
            &self.device,
            self.block_size,
            extent_location,
            current,
            length,
        )?;

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

/// The ISO 9660 identifier for a file a caller names.
fn is_self_or_parent(record: &DirRecord) -> bool {
    record.identifier.len() == 1 && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01)
}

/// The bytes an empty directory's extent holds: its own two records, which
/// have one-byte identifiers and so are 34 bytes each.
const EMPTY_DIRECTORY_BYTES: u32 = 2 * (33 + 1);

/// Take one record out of a directory's extent.
///
/// The records after it move down over it and the tail is zeroed, rather than
/// the survivors being re-serialised: a record carries whatever its writer put
/// in its System Use area, and this driver does not parse all of it, so the
/// bytes are the only honest copy.  The directory's own record is rewritten to
/// the length that leaves.
fn remove_child_record(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    dir_extent: u32,
    dir_size: u32,
    dir_record_offset: u64,
    child_record_offset: u64,
    child_len: usize,
) -> Result<()> {
    let mut data = alloc::vec![0u8; dir_size as usize];
    fs::read_extent(device, block_size, dir_extent, dir_size, 0, &mut data)?;

    let at = child_record_offset
        .checked_sub(dir_extent as u64 * block_size as u64)
        .ok_or(Error::InvalidArgument)? as usize;
    if at + child_len > data.len() {
        return Err(Error::InvalidArgument);
    }
    data.copy_within(at + child_len.., at);
    let new_size = dir_size - child_len as u32;
    data[new_size as usize..].fill(0);
    fs::write_extent(device, block_size, dir_extent, dir_size, 0, &data)?;

    // The directory is that much shorter, and nothing else about it moved.
    fs::rewrite_record_placement(device, dir_record_offset, dir_extent, new_size)
}

/// The path of the directory a path names a child of.
fn parent_path_of(clean_path: &str) -> &str {
    match clean_path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &clean_path[..index],
    }
}

/// The identifier a directory record carries for the name a caller used.
///
/// The identifier is what a reader **without** Rock Ridge sees, and the rule
/// for one is level 2: upper case letters, digits, underscores and at most one
/// dot, inside thirty bytes, with the `;1` version a file has and a directory
/// does not.  The name itself is kept instead in the record's `NM` entry
/// ([`types::susp_name`]), so the identifier is only the fallback a reader
/// that ignores Rock Ridge falls back to: a name with none of those characters
/// in it is *mangled* to the nearest identifier rather than refused.
///
/// Mangling is many-to-one — `a b` and `a_b` both want `A_B` — and two records
/// with one identifier are two entries only one of which a lookup can reach,
/// so the identifiers the directory already holds decide a numbered suffix.
fn identifier_for(name: &str, directory: bool, taken: &[Vec<u8>]) -> Result<Vec<u8>> {
    /// A level-2 identifier is at most thirty bytes, version included.
    const MAX_IDENTIFIER: usize = 30;
    /// How many suffixes a collision is worth trying before giving up.
    const SUFFIX_LIMIT: u32 = 9999;

    let room = if directory {
        MAX_IDENTIFIER
    } else {
        MAX_IDENTIFIER - 2 // the ";1" every file identifier carries
    };

    let mut stem = Vec::with_capacity(name.len().min(room));
    let mut dotted = false;
    for character in name.chars() {
        match character.to_ascii_uppercase() {
            upper @ ('A'..='Z' | '0'..='9' | '_') => stem.push(upper as u8),
            '.' if !dotted => {
                dotted = true;
                stem.push(b'.');
            }
            _ => stem.push(b'_'),
        }
    }
    if stem.is_empty() {
        stem.push(b'_');
    }
    stem.truncate(room);

    let versioned = |stem: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(stem.len() + 2);
        out.extend_from_slice(stem);
        if !directory {
            out.extend_from_slice(b";1");
        }
        out
    };
    let taken_holds = |candidate: &[u8]| taken.iter().any(|held| held == candidate);

    let candidate = versioned(&stem);
    if !taken_holds(&candidate) {
        return Ok(candidate);
    }

    // A suffix has to fit inside the identifier too, so the stem gives back as
    // many bytes as the number takes.
    for suffix in 1..=SUFFIX_LIMIT {
        let text = alloc::format!("_{suffix}");
        let keep = room.saturating_sub(text.len()).min(stem.len());
        let mut numbered = stem[..keep].to_vec();
        numbered.extend_from_slice(text.as_bytes());
        let candidate = versioned(&numbered);
        if !taken_holds(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::NoSpace)
}

/// The identifiers a directory holds, which is what a name is mangled against.
fn identifiers_in(entries: &[types::DirRecord]) -> Vec<Vec<u8>> {
    entries
        .iter()
        .map(|entry| entry.identifier.clone())
        .collect()
}

/// The attributes a created entry gets out of the POSIX entry.
///
/// The mode is a POSIX one, file type included, which is what Rock Ridge
/// records and what a POSIX reader applies whole: a file its owner may write,
/// a directory it may enter, and everyone else may read.
fn default_posix(directory: bool) -> (u32, u32, u32, u32) {
    if directory {
        (0o040755, 2, 0, 0)
    } else {
        (0o100644, 1, 0, 0)
    }
}

/// The System Use area a created entry carries.
///
/// `PX` gives it the attributes a POSIX reader reports, `NM` the name its
/// caller used, and `ST` ends the area — which is what says the entries are
/// complete rather than truncated by the record that holds them.
fn rock_ridge_area(name: &str, posix: (u32, u32, u32, u32)) -> Vec<u8> {
    let (mode, links, uid, gid) = posix;
    let mut area = types::susp_posix(mode, links, uid, gid);
    area.extend_from_slice(&types::susp_name(name.as_bytes()));
    area.extend_from_slice(&types::susp_terminator());
    area
}

/// Assemble a directory record from its parts, refusing one too long to write.
///
/// A record's own length is a single byte, so its identifier, its padding and
/// its System Use area together have to fit in 255 of them.  The name a caller
/// chose is in that area and is the part they control, so a name too long to
/// fit is refused — rather than written in part, which a reader would read
/// back as a different name.
fn directory_record(
    identifier: &[u8],
    extent_location: u32,
    extent_size: u32,
    directory: bool,
    system_use: &[u8],
) -> Result<Vec<u8>> {
    let record = types::DirRecord::new_entry_with(
        identifier,
        extent_location,
        extent_size,
        directory,
        system_use,
    );
    if record.len() > u8::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    Ok(record)
}

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
        // A Rock Ridge `PX` mode is a POSIX one, file type included, and the
        // VFS's is the permission bits alone (`MAX_PERMISSION_MODE`), which is
        // what every other filesystem here reports.
        Some((mode, _links, uid, gid)) => SecurityDescriptor {
            owner_uid: *uid,
            owner_gid: *gid,
            mode: (*mode & u32::from(MAX_PERMISSION_MODE)) as u16,
        },
        None => SecurityDescriptor {
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o555,
        },
    }
}
