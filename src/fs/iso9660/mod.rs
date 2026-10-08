//! src/fs/iso9660/mod.rs
//!
//! ISO 9660 (CD-ROM) with Rock Ridge, Joliet and El Torito: readable as it
//! comes, and writable in the places the format and the volume allow.
//!
//! ## Supported features
//!
//! - Primary Volume Descriptor (PVD) parsing
//! - Directory record traversal (Level 1, 2, 3)
//! - Contiguous extent-based file reading
//! - Rock Ridge: NM (POSIX names), PX (permissions), SL (symlinks) — read, and
//!   NM/PX written for an entry this driver creates or renames
//! - Case-insensitive path lookup (ISO 9660 native behavior)
//! - A volume with more than one descriptor is read through the tree the reader
//!   is meant to see — Joliet's, when there is one — and an entry only another
//!   tree names is not found from here
//!
//! ## Limitations
//!
//! - File data, length and space are writable ([RFC
//!   0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)): an ISO
//!   9660 file is one raw contiguous extent whose two fields — where it starts
//!   and how long it is — are in its directory record, so writing bytes, or a
//!   length inside the block the file has, touches nothing else.  Growing past
//!   that block takes blocks from the volume's **free space**, which is what
//!   its structures do not name: a block map is built by walking the whole
//!   volume, and a volume with anything this driver cannot account for — a
//!   descriptor it does not know, an extended attribute record, no terminator
//!   on the descriptor set — is one it appends to instead, because handing a
//!   block out is not a thing to guess at.  A file with something after it
//!   *moves* into that free space rather than growing where it is, because an
//!   extent is one contiguous run.  A regular file can be created — empty, in
//!   the directory it names — and removed, which is a record appended to that
//!   directory or shifted out of it; a **directory** can be created and removed
//!   too, and that is what moves the path tables, which are rebuilt from the
//!   tree rather than edited in place.  A directory that still holds something
//!   refuses to go, and an entry can be renamed or moved: its record leaves one
//!   directory and joins another, a directory's ".." follows it, and the tables
//!   are rebuilt.
//! - A volume with **two trees** — a Joliet one beside the primary — is written
//!   only where the two agree, which is the file's data: an overwrite inside
//!   its length is the same bytes under both records.  A length change and
//!   everything structural is refused, because each would have to appear in
//!   both trees and the trees spell a name differently by design, so nothing on
//!   the volume says which record in the other tree is the same file's ([RFC
//!   0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md) draws the
//!   line where a write would otherwise be a guess).
//! - A created or renamed entry carries a Rock Ridge **name** entry, so its
//!   name is the caller's — lower case, spaces, anything a record has room for
//!   — and the identifier beside it is the mangled form a reader that ignores
//!   Rock Ridge sees.  A *writable* volume is given the `ER` entry those
//!   entries need when it is opened, which is the only moment the root's own
//!   record can move without invalidating an offset a node already holds; a
//!   name too long for the 255-byte record that has to hold it is refused
//!   rather than stored in part.
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

/// One of a volume's directory trees.
///
/// ISO 9660 lets a volume carry more than one: the primary descriptor's tree,
/// whose identifiers are upper case and versioned, and a supplementary tree —
/// Joliet's, when the descriptor's escape sequence says so — whose identifiers
/// are UCS-2BE.  The trees share the files' *data*, but not their directories:
/// each has its own root, its own directory extents, and its own path tables.
/// A record in every tree names that shared data, which is what makes a file's
/// length something every tree has an opinion about.
#[derive(Clone, Copy)]
struct Tree {
    /// Whether identifiers in this tree are UCS-2BE.
    joliet: bool,
    /// The descriptor that names this tree and carries its path tables.
    descriptor_sector: u64,
}

/// A mounted ISO 9660 volume implementing the VFS [`VfsFileSystem`] trait.
pub struct Iso9660Volume {
    device: Arc<dyn BlockDevice>,
    block_size: u16,
    volume_label: String,
    /// The size the volume declared when it was opened.
    ///
    /// It is the floor a **shrink** may not take the volume's end below: the
    /// blocks the image came with are the image's, and the one rule this
    /// driver can apply without knowing what is on the volume is that
    /// everything past the size it declares belongs to nobody.
    ///
    /// It is *not* a floor on what the allocator may hand out: a block inside
    /// the volume is free when the block map says nothing names it, and the map
    /// is what lets a hole left by a removal be reused — see [`Allocator`].
    volume_floor: u32,
    /// The primary descriptor's tree, and the supplementary one when the
    /// volume has it.
    primary: Tree,
    joliet: Option<Tree>,
}

impl Iso9660Volume {
    /// Every tree the volume has, the primary one first.
    fn trees(&self) -> impl Iterator<Item = &Tree> {
        core::iter::once(&self.primary).chain(self.joliet.iter())
    }

    /// The tree a read answers from.
    ///
    /// Joliet's, when the volume has one: it is the tree whose names are meant
    /// to be read, and the primary tree's are the fallback spelling of them.
    fn reading_tree(&self) -> &Tree {
        self.joliet.as_ref().unwrap_or(&self.primary)
    }

    /// How many trees the volume has, which is what says whether a length is
    /// one record's to change.
    fn tree_count(&self) -> u8 {
        u8::try_from(self.trees().count()).unwrap_or(u8::MAX)
    }

    /// Refuse a change that would alter a *directory* on a volume with two
    /// trees.
    ///
    /// A create, a removal and a rename each add or take away a record in a
    /// directory, and a volume's trees do not share their directories: the
    /// entry would have to be made in every tree, with an identifier encoded
    /// for each, and this driver makes it in one.  A *length* is a field of a
    /// record every tree has, so that one is kept in step; anything structural
    /// is not, and a change that would half-happen is refused instead ([RFC
    /// 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
    fn refuse_a_change_to_one_of_two_trees(&self) -> Result<()> {
        if self.joliet.is_some() {
            return Err(Error::Unsupported);
        }
        Ok(())
    }

    /// Open an ISO 9660 volume on the given block device.
    ///
    /// Reads the PVD and validates the ISO 9660 signature.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let pvd = fs::read_pvd(&device)?;
        let block_size = pvd.block_size();
        if block_size == 0 || !(block_size as usize).is_multiple_of(types::SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }
        // Before the upgrade below, which is the first thing that grows it.
        let volume_floor = fs::volume_blocks(&device)?;

        // Try to detect a Joliet Supplementary Volume Descriptor — wherever in
        // the descriptor set it is, which is not a fixed sector when the
        // volume is bootable.
        let (volume_label, joliet) =
            if let Some((sector, svd)) = fs::find_joliet_descriptor(&device) {
                (
                    pvd_volume_label(&svd),
                    Some(Tree {
                        joliet: true,
                        descriptor_sector: sector,
                    }),
                )
            } else {
                (pvd_volume_label(&pvd), None)
            };

        let volume = Self {
            device,
            block_size,
            volume_label,
            volume_floor,
            primary: Tree {
                joliet: false,
                descriptor_sector: types::PVD_SECTOR,
            },
            joliet,
        };

        // A volume this driver is going to write entries into has to say which
        // extension they belong to, and a read-only device is not one to do it
        // on (`declare_extension` explains why it happens here).
        if !volume.device.is_read_only() {
            let _ = volume.declare_extension();
        }

        Ok(volume)
    }

    /// Read the area a `CE` entry continues into.
    ///
    /// The three numbers are a logical block, a byte offset into it, and how
    /// many bytes of continuation there are.  The entry that names it is the
    /// volume's, not this driver's, so its length is bounded the way a
    /// directory's is: a broken one must not become an allocation.
    fn continuation(&self, block: u32, offset: u32, size: u32) -> Option<Vec<u8>> {
        if u64::from(size) > fs::MAX_DIRECTORY_BYTES {
            return None;
        }
        let end = offset.checked_add(size)?;
        let mut bytes = alloc::vec![0u8; size as usize];
        fs::read_extent(
            &self.device,
            self.block_size,
            block,
            end,
            u64::from(offset),
            &mut bytes,
        )
        .ok()?;
        Some(bytes)
    }

    /// Make a writable volume say which extension its entries belong to.
    ///
    /// A volume whose System Use areas carry Rock Ridge entries is required to
    /// name the extension in an `ER` entry, or a reader is entitled to ignore
    /// every one of them — and this driver has been *writing* such entries
    /// since names stopped having to be ISO 9660 identifiers.  The entry's own
    /// mandated text makes it 237 bytes, and a directory record's length is one
    /// byte, so the root's own "." record carries an `SP` marker and a `CE`
    /// naming a **continuation area** in a block of its own, where the entry
    /// goes.
    ///
    /// This runs **at open**, because the root's "." record grows by the area
    /// above and every record after it moves: a node that had already been
    /// handed a record offset would then point at the wrong bytes, and at open
    /// no node exists yet.
    ///
    /// The root is built **elsewhere** and the volume repointed at it — the
    /// descriptor first, then the path tables, which name it too — so a crash
    /// leaves either the old root or the new one, whole.  That is the shape a
    /// file takes when it grows by moving, and it costs the same thing: the
    /// blocks the old root held are not reclaimed, because the allocator
    /// appends.  A failure between those two writes leaves the tables naming
    /// the extent the root left, which still holds exactly the entries it
    /// held, so a reader that follows a table reads the old list rather than a
    /// broken one ([RFC
    /// 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
    ///
    /// It is best-effort.  A volume this cannot be written to still mounts:
    /// reading the disc is the larger thing not to lose, and an entry written
    /// without the reference is still one this driver's own reader reads.
    fn declare_extension(&self) -> Result<()> {
        let pvd = fs::read_pvd(&self.device)?;
        let (root, _next) =
            DirRecord::parse(&pvd.root_dir_record, 0).ok_or(Error::InvalidArgument)?;
        if u64::from(root.extent_size) > fs::MAX_DIRECTORY_BYTES {
            return Err(Error::InvalidArgument);
        }
        let mut extent = alloc::vec![0u8; root.extent_size as usize];
        fs::read_extent(
            &self.device,
            self.block_size,
            root.extent_location,
            root.extent_size,
            0,
            &mut extent,
        )?;
        let (first, first_len) = DirRecord::parse(&extent, 0).ok_or(Error::InvalidArgument)?;

        let declared = types::susp_names_extension(&first.system_use, |block, offset, size| {
            self.continuation(block, offset, size)
        });
        if declared {
            return Ok(());
        }

        // The continuation area first: nothing names it until the record below
        // does, so a failure or a crash here changes nothing that is read.
        let reference = types::susp_extensions_reference();
        let mut allocate = fs::Allocator::of(&self.device, self.block_size);
        let continuation = allocate.take(1)?;
        fs::write_exact(
            &self.device,
            continuation as u64 * self.block_size as u64,
            &reference,
        )?;

        // The root, rebuilt whole: its "." record grows by the area above and
        // every record after it moves, so the extent is written somewhere else
        // rather than edited where it is.
        let area = root_extension_area(continuation, reference.len() as u32);
        let tail = &extent[first_len..];
        // A record's length does not depend on the length it reports, so one
        // built with no size is what says how long the real one will be.
        let first_record_len =
            directory_record(&[0x00], root.extent_location, 0, true, &area)?.len();
        let new_size = u32::try_from(first_record_len + tail.len()).map_err(|_| Error::NoSpace)?;
        let new_blocks = (new_size as u64).div_ceil(self.block_size as u64) as u32;
        let location = allocate.take(new_blocks)?;

        let record = directory_record(&[0x00], location, new_size, true, &area)?;
        let mut rebuilt = Vec::with_capacity(new_size as usize);
        rebuilt.extend_from_slice(&record);
        rebuilt.extend_from_slice(tail);
        debug_assert_eq!(rebuilt.len(), new_size as usize);

        // The root's own ".." names the root, and the root has moved: the copy
        // above took the record that said the old address.
        let placement = fs::placement_field(location, new_size);
        let mut at = record.len();
        while let Some((entry, next)) = DirRecord::parse(&rebuilt, at) {
            if entry.identifier == [0x01] {
                rebuilt[at + types::DIR_RECORD_EXTENT_LOCATION_OFFSET..][..16]
                    .copy_from_slice(&placement);
                break;
            }
            at = next;
        }

        fs::write_exact(
            &self.device,
            location as u64 * self.block_size as u64,
            &rebuilt,
        )?;

        // Every directory the root holds names it in its own ".." record too,
        // and those records are in *other* extents — the copy above did not
        // touch them.  This is the same work [`Iso9660Volume::append_to_directory`]
        // does when a directory grows into a move, and for the same reason.
        for child in subdirectories(&extent, first_len) {
            let child_parent = self.parent_record_of(child.extent_location, child.extent_size)?;
            fs::rewrite_record_placement(&self.device, child_parent, location, new_size)?;
        }

        // The commit: one write of the descriptor's own root record, which is
        // the thing that says where the root is.
        fs::rewrite_record_placement(
            &self.device,
            types::PVD_SECTOR * self.block_size as u64
                + core::mem::offset_of!(types::Pvd, root_dir_record) as u64,
            location,
            new_size,
        )?;
        // The tables name the root too, and a reader may follow them instead of
        // walking the tree; rebuilding them is what the tree above decides.
        self.rewrite_path_tables()
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

    /// Read directory entries from an extent, in one tree's encoding.
    fn read_dir_extent(
        &self,
        tree: &Tree,
        extent_location: u32,
        extent_size: u32,
    ) -> Result<Vec<DirRecord>> {
        if tree.joliet {
            fs::read_joliet_directory(&self.device, self.block_size, extent_location, extent_size)
        } else {
            fs::read_directory(&self.device, self.block_size, extent_location, extent_size)
        }
    }

    /// Read a tree's root directory: its own record, and its entries.
    ///
    /// The record is read from the descriptor every time rather than kept,
    /// because a writable volume's root can *move* — the extension reference
    /// rebuilds it — and a copy taken at open would name the extent it left.
    fn read_root(&self, tree: &Tree) -> Result<(DirRecord, Vec<DirRecord>)> {
        let root_record = fs::descriptor_root(&self.device, tree.descriptor_sector, tree.joliet)?;
        let entries =
            self.read_dir_extent(tree, root_record.extent_location, root_record.extent_size)?;
        Ok((root_record, entries))
    }

    /// Every directory the volume has, in the order a path table keeps them.
    ///
    /// The standard's order is by hierarchy level, then by the parent's number,
    /// then by identifier.  A level-order walk gives the first two for free —
    /// a parent is always numbered before its children — so this walks the
    /// levels in turn and sorts each directory's children by identifier.
    fn path_table_entries(&self, tree: &Tree) -> Result<Vec<fs::PathTableEntry>> {
        let (root, root_entries) = self.read_root(tree)?;
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
                .filter(|record| record.is_dir() && !fs::names_self_or_parent(record, tree.joliet))
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
                let sub = self.read_dir_extent(tree, child.extent_location, child.extent_size)?;
                pending.push_back((number, sub));
            }
        }
        Ok(entries)
    }

    /// Rebuild the path tables of every tree the volume has.
    fn rewrite_path_tables(&self) -> Result<()> {
        for tree in self.trees() {
            self.rewrite_path_tables_in(tree)?;
        }
        Ok(())
    }

    /// Rebuild one tree's path tables from that tree, and write them.
    ///
    /// The tables are *derived* rather than edited: a directory's number is its
    /// position, so inserting one renumbers everything after it, and rebuilding
    /// the list is the same work with fewer ways to be wrong.  Two are
    /// required — one per byte order — and a volume may also carry optional
    /// copies, which are rewritten to the same content because a reader is
    /// allowed to follow them.  Every one of them goes in the descriptor that
    /// names the tree: a second tree's tables are its own, and a reader that
    /// follows them must not be handed the first tree's directories.
    fn rewrite_path_tables_in(&self, tree: &Tree) -> Result<()> {
        let entries = self.path_table_entries(tree)?;
        let little = fs::build_path_table(&entries, false);
        let big = fs::build_path_table(&entries, true);
        debug_assert_eq!(little.len(), big.len());
        let size = u32::try_from(little.len()).map_err(|_| Error::NoSpace)?;

        let descriptor = fs::read_descriptor(&self.device, tree.descriptor_sector)?;
        let old_size = u32::from_le_bytes(
            descriptor.path_table_size[..4]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let blocks = |bytes: u32| (bytes as u64).div_ceil(self.block_size as u64) as u32;

        let mut l_location = fs::field_le(descriptor.l_path_table_loc);
        let mut m_location = fs::field_be(descriptor.m_path_table_loc);
        if blocks(size) > blocks(old_size) {
            // A path table is one contiguous extent like any other, so more
            // room than it has means moving it to free blocks — one allocator
            // for both, so the second table cannot be handed the first's.
            let mut allocate = fs::Allocator::of(&self.device, self.block_size);
            l_location = allocate.take(blocks(size))?;
            m_location = allocate.take(blocks(size))?;
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
        let opt_l = if descriptor.opt_l_path_table_loc == 0 {
            0
        } else {
            write_at(l_location, &little)?;
            l_location
        };
        let opt_m = if descriptor.opt_m_path_table_loc == 0 {
            0
        } else {
            write_at(m_location, &big)?;
            m_location
        };

        fs::rewrite_path_table_fields(
            &self.device,
            tree.descriptor_sector,
            size,
            l_location,
            opt_l,
            m_location,
            opt_m,
        )
    }

    /// Resolve a clean path to its record, its directory's entries when it is a
    /// directory, and where its own record sits on the volume.
    ///
    /// The third element is what a resize rewrites: a directory record carries
    /// the length of the file it describes, and the record's position is not
    /// something a lookup can recover later without walking the path again.
    fn resolve(&self, clean_path: &str) -> Result<(DirRecord, Option<Vec<DirRecord>>, u64)> {
        self.resolve_in(self.reading_tree(), clean_path)
    }

    /// The same, in one named tree.
    fn resolve_in(
        &self,
        tree: &Tree,
        clean_path: &str,
    ) -> Result<(DirRecord, Option<Vec<DirRecord>>, u64)> {
        if clean_path.is_empty() || clean_path == "/" {
            let (root_rec, entries) = self.read_root(tree)?;
            // A root's record is a field of the descriptor that names it, and
            // a root that grows or shrinks rewrites its length there.
            return Ok((
                root_rec,
                Some(entries),
                fs::root_record_offset(tree.descriptor_sector),
            ));
        }

        let segments: Vec<&str> = clean_path
            .strip_prefix('/')
            .unwrap_or(clean_path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let (root_record, root_entries) = self.read_root(tree)?;
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
                    Some(self.read_dir_extent(tree, record.extent_location, record.extent_size)?)
                } else {
                    None
                };
                return Ok((record.clone(), sub, record_offset));
            }

            if record.is_dir() {
                entries_extent = record.extent_location;
                current_entries =
                    self.read_dir_extent(tree, record.extent_location, record.extent_size)?;
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
            &mut fs::Allocator::of(&self.device, self.block_size),
        )?;

        if location != parent.extent_location {
            let children = self.read_dir_extent(
                self.reading_tree(),
                parent.extent_location,
                parent.extent_size,
            )?;
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
            trees: self.tree_count(),
            volume_floor: self.volume_floor,
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
        self.refuse_a_change_to_one_of_two_trees()?;

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

        let entries = self.read_dir_extent(
            self.reading_tree(),
            new_parent.extent_location,
            new_parent.extent_size,
        )?;
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
        self.refuse_a_change_to_one_of_two_trees()?;
        let clean = clean_path(path);
        if self.resolve(&clean).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(&clean)?;
        let entries = self.read_dir_extent(
            self.reading_tree(),
            parent.extent_location,
            parent.extent_size,
        )?;
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
            trees: self.tree_count(),
            volume_floor: self.volume_floor,
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
        self.refuse_a_change_to_one_of_two_trees()?;
        let clean = clean_path(path);
        if self.resolve(&clean).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(&clean)?;
        let entries = self.read_dir_extent(
            self.reading_tree(),
            parent.extent_location,
            parent.extent_size,
        )?;
        let identifier = identifier_for(&child, true, &identifiers_in(&entries))?;

        // A directory's extent holds its own two records before anything else:
        // "." is itself and ".." is its parent, and they are what makes it a
        // directory at all.
        let extent_location = fs::Allocator::of(&self.device, self.block_size).take(1)?;
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
    /// copy.  What the file's blocks were are free again the moment its record
    /// is gone: the volume's declared size comes down over them when they were
    /// its last, and the block map finds them wherever they are.
    fn remove_path(&self, path: &str) -> Result<()> {
        self.refuse_a_change_to_one_of_two_trees()?;
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

        // The record is gone, so whatever the entry held is free — and if it
        // was the last thing the volume held, its blocks are the volume's last
        // and it takes them back.  A removal in the middle gives nothing back,
        // because what is free there is not something this driver can see
        // without walking every extent on the volume.
        fs::release_volume_tail(
            &self.device,
            self.block_size,
            self.volume_floor,
            record.extent_location,
            record.extent_size,
            0,
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
    /// How many directory trees the volume has.
    ///
    /// One means the record above is the only copy of the file's length.  More
    /// than one means every tree has a copy, and the trees do not spell the
    /// file's name the same way — so which record in the other tree is *this*
    /// file's is not a question the volume answers, and a length is not
    /// something to write into a guess ([`Iso9660Volume`]'s
    /// `refuse_a_change_to_one_of_two_trees` is the whole argument).
    trees: u8,
    /// The size the volume declared when it was opened, which is the floor a
    /// shrink may not take blocks back below — see [`Iso9660Volume`].
    volume_floor: u32,
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
    /// volume holds, or move the file — into the free space the allocator
    /// finds, which is where a hole a removal left is handed out again.
    fn set_len(&self, length: u64) -> Result<()> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let length = u32::try_from(length).map_err(|_| Error::InvalidArgument)?;
        let current = self.extent_size.load(Ordering::Relaxed);
        if length == current {
            return Ok(());
        }
        // A file's *length* is a field of a record in every tree, and a
        // volume's trees do not spell the file's name the same way: which
        // record in the other tree is this file's is not something the volume
        // says.  What a change to the length would leave behind is one tree
        // that has it and one that does not, so it is refused — and an
        // overwrite *inside* the length is not, because the data both trees
        // point at is the same data.
        if self.trees > 1 {
            return Err(Error::Unsupported);
        }

        let extent_location = self.extent_location.load(Ordering::Relaxed);
        // Past the block the file has, the extent needs blocks; `place_extent`
        // grows it where the volume ends and moves it to free blocks where it
        // cannot — which is what puts a moved file into a hole a removal left.
        let mut allocate = fs::Allocator::of(&self.device, self.block_size);
        let extent_location = fs::place_extent(
            &self.device,
            self.block_size,
            extent_location,
            current,
            length,
            &mut allocate,
        )?;

        // Where the file is and how long it is, in one write: the two fields
        // are adjacent in the record and each is stored twice.
        fs::rewrite_record_placement(&self.device, self.record_offset, extent_location, length)?;

        // A shrink that gives up whole blocks at the very end of the volume
        // hands them back to it, which is the one place this driver can tell
        // what is free without walking the tree.
        if length < current {
            fs::release_volume_tail(
                &self.device,
                self.block_size,
                self.volume_floor,
                extent_location,
                current,
                length,
            )?;
        }

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

/// The directories an extent holds, read out of bytes already in memory.
///
/// A directory's own "." and ".." are not children of it, so they are not
/// among the records a move has to correct.
fn subdirectories(extent: &[u8], from: usize) -> Vec<DirRecord> {
    let mut children = Vec::new();
    let mut at = from;
    while let Some((record, next)) = DirRecord::parse(extent, at) {
        if record.is_dir() && !is_self_or_parent(&record) {
            children.push(record);
        }
        at = next;
    }
    children
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

/// The System Use area the root directory's own "." record carries.
///
/// It is the one record that declares what the volume's areas are: `SP` says
/// they are SUSP's at all, `PX` gives the root its attributes, and `CE` names
/// the block the extension reference continues in — because that entry does
/// not fit in a record, whose own length is one byte.
fn root_extension_area(continuation: u32, reference_size: u32) -> Vec<u8> {
    let (mode, links, uid, gid) = default_posix(true);
    let mut area = types::susp_sharing_protocol();
    area.extend_from_slice(&types::susp_posix(mode, links, uid, gid));
    area.extend_from_slice(&types::susp_continuation(continuation, 0, reference_size));
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
    types::DirRecord::new_entry_with(
        identifier,
        extent_location,
        extent_size,
        directory,
        system_use,
    )
    .ok_or(Error::InvalidArgument)
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
