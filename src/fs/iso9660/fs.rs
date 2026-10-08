//! src/fs/iso9660/fs.rs
//!
//! Low-level ISO 9660 operations: read PVD, parse directories, read files.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::block::BlockDevice;
use crate::Error;

use super::types::parse_boot_catalog;
use super::types::BootEntry;
use super::types::DirRecord;
use super::types::Pvd;
use super::types::DIR_RECORD_EXTENT_LOCATION_OFFSET;
use super::types::PVD_ROOT_RECORD_OFFSET;
use super::types::PVD_SECTOR;
use super::types::SECTOR_SIZE;
use super::types::SVD_SECTOR;

// ---------------------------------------------------------------------------
// PVD reading
// ---------------------------------------------------------------------------

/// Read and validate the Primary Volume Descriptor.
pub fn read_pvd(device: &Arc<dyn BlockDevice>) -> Result<Pvd, Error> {
    let mut buf = [0u8; SECTOR_SIZE];
    let offset = PVD_SECTOR * SECTOR_SIZE as u64;
    read_exact(device, offset, &mut buf)?;

    // The PVD is a packed struct — transmute requires the same size.
    // SAFETY: `Pvd` is `#[repr(C, packed)]`, so it needs no alignment the byte
    // buffer cannot give, and a sector is wider than the descriptor it starts
    // with.
    let pvd_ref: &Pvd = unsafe { &*buf.as_ptr().cast::<Pvd>() };

    if !pvd_ref.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // Read the bytes into a new Pvd safely.
    // SAFETY: as above — the descriptor the validated sector holds, copied out
    // rather than borrowed.
    let pvd = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) };
    Ok(pvd)
}

/// Read the Joliet Supplementary Volume Descriptor (SVD), if present.
///
/// The Joliet SVD is a type-2 volume descriptor ("CD001", version 1) whose
/// escape sequence at offset 88 identifies the UCS-2BE character set ("%/@").
/// Returns `None` when the descriptor is absent or not a Joliet SVD.
pub fn read_svd(device: &Arc<dyn BlockDevice>) -> Option<Pvd> {
    let mut buf = [0u8; SECTOR_SIZE];
    let offset = SVD_SECTOR * SECTOR_SIZE as u64;
    read_exact(device, offset, &mut buf).ok()?;

    // Validate the descriptor header and the Joliet escape sequence.
    // SAFETY: as `read_pvd` — a packed descriptor at the start of a full
    // sector buffer.
    let pvd_ref: &Pvd = unsafe { &*buf.as_ptr().cast::<Pvd>() };
    if pvd_ref.desc_type != 0x02
        || &pvd_ref.std_identifier != b"CD001"
        || pvd_ref.desc_version != 0x01
    {
        return None;
    }
    if &buf[88..91] != b"%/@" {
        return None;
    }

    // SAFETY: as above — the sector's own descriptor, copied out.
    Some(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Pvd) })
}

// ---------------------------------------------------------------------------
// Directory reading
// ---------------------------------------------------------------------------

/// The most bytes of directory this driver will hold in memory at once.
///
/// A directory's size is a field of its record, and the thing that wrote the
/// record is not this driver: a corrupt one must not be able to ask for an
/// allocation the size of the address space.  Sixteen mebibytes is far more
/// than any directory a disc this driver writes has.
pub const MAX_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;

/// Read the records an extent holds, with or without its own "." and "..".
///
/// A block map needs the two: a record's System Use area can continue into a
/// block of its own, the entry that says so is in the record, and the root
/// directory's own "." record is where a volume declares its extension — so a
/// walk that skipped it would leave that block looking free.
fn read_records(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    joliet: bool,
    with_the_dots: bool,
) -> Result<Vec<DirRecord>, Error> {
    let block_size = block_size as u64;
    let extent_size = extent_size as u64;

    if extent_size > MAX_DIRECTORY_BYTES {
        return Err(Error::InvalidArgument);
    }

    let mut data = alloc::vec![0u8; extent_size as usize];
    let extent_offset = extent_location as u64 * block_size;
    read_exact(device, extent_offset, &mut data)?;

    let mut records = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let parsed = if joliet {
            DirRecord::parse_joliet(&data, offset)
        } else {
            DirRecord::parse(&data, offset)
        };
        match parsed {
            Some((record, next)) => {
                if with_the_dots || !names_self_or_parent(&record, joliet) {
                    records.push(record);
                }
                offset = next;
                if offset >= data.len() {
                    break;
                }
            }
            None => {
                // dr_len == 0: end of directory. Advance to next sector boundary.
                let block_end = ((offset / SECTOR_SIZE) + 1) * SECTOR_SIZE;
                offset = block_end;
                if offset >= data.len() {
                    break;
                }
            }
        }
    }

    Ok(records)
}

/// Whether a record is a directory's own "." or its "..".
pub fn names_self_or_parent(record: &DirRecord, joliet: bool) -> bool {
    if !joliet {
        return record.identifier.len() == 1
            && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01);
    }
    // A Joliet identifier is UCS-2BE, where "." is the code unit 0x0000 and
    // ".." is 0x0001 — so *both* bytes are what says so.  A name whose first
    // byte is zero is any name starting below U+0100, which is most of them.
    record.identifier.len() == 2
        && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01)
        && record.identifier[1] == 0x00
}

/// Read all directory entries from an extent.
pub fn read_directory(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
) -> Result<Vec<DirRecord>, Error> {
    read_records(
        device,
        block_size,
        extent_location,
        extent_size,
        false,
        false,
    )
}

/// Read every record an extent holds, its own "." and ".." included.
pub fn read_all_records(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    joliet: bool,
) -> Result<Vec<DirRecord>, Error> {
    read_records(
        device,
        block_size,
        extent_location,
        extent_size,
        joliet,
        true,
    )
}

/// Read all directory entries from a Joliet extent (UCS-2BE filenames).
///
/// Identical to [`read_directory`] but parses records with
/// [`DirRecord::parse_joliet`], so the UCS-2BE identifiers are decoded into
/// human-readable names.
pub fn read_joliet_directory(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
) -> Result<Vec<DirRecord>, Error> {
    read_records(
        device,
        block_size,
        extent_location,
        extent_size,
        true,
        false,
    )
}

// ---------------------------------------------------------------------------
// File reading
// ---------------------------------------------------------------------------

/// Read file data from an extent.
///
/// Extent data is contiguous on ISO 9660 — no fragmentation.
pub fn read_extent(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    file_offset: u64,
    buffer: &mut [u8],
) -> Result<usize, Error> {
    if file_offset >= extent_size as u64 {
        return Ok(0);
    }

    let block_size = block_size as u64;
    let extent_start = extent_location as u64 * block_size;
    let read_start = extent_start + file_offset;
    let available = (extent_size as u64).saturating_sub(file_offset);
    let n = (buffer.len() as u64).min(available) as usize;

    read_exact(device, read_start, &mut buffer[..n])?;
    Ok(n)
}

/// Write file data into an extent, and answer how much of `buffer` was taken.
///
/// The mirror of [`read_extent`], and it is deliberately clamped to the
/// extent's recorded size: a file's length is a field of its directory record,
/// so *growing* one is a metadata change and not a data write.  A write that
/// runs past the end is therefore a short write, which is what the VFS
/// contract says a write that cannot take everything should be.
pub fn write_extent(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    file_offset: u64,
    buffer: &[u8],
) -> Result<usize, Error> {
    if file_offset >= extent_size as u64 {
        return Ok(0);
    }

    let block_size = block_size as u64;
    let available = (extent_size as u64).saturating_sub(file_offset);
    let n = (buffer.len() as u64).min(available) as usize;
    if n == 0 {
        return Ok(0);
    }

    let start = extent_location as u64 * block_size + file_offset;
    write_exact(device, start, &buffer[..n])?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// El Torito boot catalog
// ---------------------------------------------------------------------------

/// Scan the volume descriptor sequence for a Boot Record (type 0) and return
/// the boot catalog LBA it references, if any.
pub fn find_boot_catalog_lba(device: &Arc<dyn BlockDevice>) -> Option<u32> {
    for sector in (PVD_SECTOR..).take(32) {
        let mut buf = [0u8; SECTOR_SIZE];
        read_exact(device, sector * SECTOR_SIZE as u64, &mut buf).ok()?;

        let desc_type = buf[0];
        if desc_type == 0xFF {
            // Volume Descriptor Set Terminator — stop scanning.
            break;
        }

        if desc_type == 0x00 && &buf[1..6] == b"CD001" && buf[6] == 0x01 {
            // Boot Record: catalog LBA at bytes 71-74 (LE u32).
            let catalog_lba = u32::from_le_bytes([buf[71], buf[72], buf[73], buf[74]]);
            if catalog_lba > 0 {
                return Some(catalog_lba);
            }
        }
    }
    None
}

/// Read and parse the El Torito Boot Catalog from the given LBA.
pub fn read_boot_catalog(
    device: &Arc<dyn BlockDevice>,
    catalog_lba: u32,
) -> Result<Vec<BootEntry>, Error> {
    let mut buf = [0u8; SECTOR_SIZE];
    let offset = catalog_lba as u64 * SECTOR_SIZE as u64;
    read_exact(device, offset, &mut buf)?;
    Ok(parse_boot_catalog(&buf))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read exactly `n` bytes from the device at the given byte offset.
fn read_exact(device: &Arc<dyn BlockDevice>, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
    if buf.is_empty() {
        return Ok(());
    }

    let dev_bs = device.block_size() as u64;
    let start_lba = offset / dev_bs;
    let start_off = (offset % dev_bs) as usize;
    let end_byte = offset + buf.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);

    let total_blocks = (end_lba - start_lba) as usize;
    let mut scratch = alloc::vec![0u8; total_blocks * dev_bs as usize];

    for i in 0..total_blocks {
        let lba = start_lba + i as u64;
        let block_buf = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, block_buf)?;
    }

    buf.copy_from_slice(&scratch[start_off..start_off + buf.len()]);
    Ok(())
}

/// Write `buf` at a byte offset, through whole-block device writes.
///
/// A device writes blocks, so each sector the range touches is classified
/// first: one the range covers in full is written without being read, and one
/// it only partly covers is read, patched and written back — the bytes the
/// caller is not replacing have to survive, and on ISO 9660 a file's last
/// sector is where that matters, since its neighbours there are padding and
/// whatever the image put after it.
pub(crate) fn write_exact(
    device: &Arc<dyn BlockDevice>,
    offset: u64,
    buf: &[u8],
) -> Result<(), Error> {
    if buf.is_empty() {
        return Ok(());
    }

    let dev_bs = device.block_size() as u64;
    let bs = dev_bs as usize;
    let start_lba = offset / dev_bs;
    let start_off = (offset % dev_bs) as usize;

    // The range's own bounds inside the scratch, which spans exactly the
    // sectors it touches.
    let covered_from = start_off;
    let covered_to = start_off + buf.len();
    let total_blocks = covered_to.div_ceil(bs);

    let mut scratch = alloc::vec![0u8; total_blocks * bs];
    for i in 0..total_blocks {
        let sector_from = i * bs;
        let sector_to = sector_from + bs;
        if covered_from > sector_from || sector_to > covered_to {
            device.read_blocks(start_lba + i as u64, &mut scratch[sector_from..sector_to])?;
        }
    }
    scratch[covered_from..covered_to].copy_from_slice(buf);

    for i in 0..total_blocks {
        let sector_from = i * bs;
        device.write_blocks(
            start_lba + i as u64,
            &scratch[sector_from..sector_from + bs],
        )?;
    }
    Ok(())
}

/// Specialized trait needed for read_extent.
use alloc;

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

/// One directory, as a path table describes it.
///
/// A path table is how a reader finds a directory without walking the tree
/// from the root: every directory the volume has, in level order, each naming
/// its parent by number.  A directory's number *is* its position in the table,
/// so a table is built from the whole list at once and never edited in place.
pub struct PathTableEntry {
    pub identifier: Vec<u8>,
    pub extent_location: u32,
    /// This directory's number, and its parent's — both 1-based.
    pub number: u16,
    pub parent_number: u16,
}

/// Serialise a path table.
///
/// Two are required — one little-endian and one big-endian — and they are
/// identical apart from the byte order of the numbers a record carries, which
/// is why the order is an argument.
pub fn build_path_table(entries: &[PathTableEntry], big_endian: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (position, entry) in entries.iter().enumerate() {
        // A directory's number is where it sits; a table whose numbers do not
        // say that is a table a reader cannot follow.
        debug_assert_eq!(entry.number as usize, position + 1);

        let len_di = entry.identifier.len();
        let extent = if big_endian {
            entry.extent_location.to_be_bytes()
        } else {
            entry.extent_location.to_le_bytes()
        };
        let parent = if big_endian {
            entry.parent_number.to_be_bytes()
        } else {
            entry.parent_number.to_le_bytes()
        };

        out.push(len_di as u8);
        out.push(0); // extended attribute record length
        out.extend_from_slice(&extent);
        out.extend_from_slice(&parent);
        out.extend_from_slice(&entry.identifier);
        if len_di % 2 == 1 {
            // A record's length is even, so an odd identifier takes a pad byte.
            out.push(0);
        }
    }
    out
}

/// Rewrite the four descriptor fields that describe the path tables.
///
/// The size is stored twice; the little-endian table's locations are
/// little-endian and the big-endian table's are big-endian.  That is the
/// format, not a choice.  The two optional copies are rewritten too, because a
/// reader is allowed to follow them and a stale copy is a wrong answer.
///
/// The descriptor is a parameter because a volume has one per tree: the
/// primary descriptor's tables name the primary tree's directories and the
/// supplementary descriptor's name its own.
pub fn rewrite_path_table_fields(
    device: &Arc<dyn BlockDevice>,
    descriptor_sector: u64,
    size: u32,
    l_location: u32,
    opt_l_location: u32,
    m_location: u32,
    opt_m_location: u32,
) -> Result<(), Error> {
    let at = |field: usize| descriptor_sector * SECTOR_SIZE as u64 + field as u64;

    let mut size_field = [0u8; 8];
    size_field[..4].copy_from_slice(&size.to_le_bytes());
    size_field[4..].copy_from_slice(&size.to_be_bytes());
    write_exact(
        device,
        at(core::mem::offset_of!(Pvd, path_table_size)),
        &size_field,
    )?;
    write_exact(
        device,
        at(core::mem::offset_of!(Pvd, l_path_table_loc)),
        &l_location.to_le_bytes(),
    )?;
    write_exact(
        device,
        at(core::mem::offset_of!(Pvd, opt_l_path_table_loc)),
        &opt_l_location.to_le_bytes(),
    )?;
    write_exact(
        device,
        at(core::mem::offset_of!(Pvd, m_path_table_loc)),
        &m_location.to_be_bytes(),
    )?;
    write_exact(
        device,
        at(core::mem::offset_of!(Pvd, opt_m_path_table_loc)),
        &opt_m_location.to_be_bytes(),
    )
}

/// How many logical blocks the volume says it has.
///
/// The descriptor's own statement of the volume's extent, stored twice.  Zero
/// means the image never said.
/// Where a descriptor's root directory record lives.
///
/// The root is the one directory that is not a record inside another, and its
/// length lives in the descriptor that names it — one per tree.
pub fn root_record_offset(descriptor_sector: u64) -> u64 {
    descriptor_sector * SECTOR_SIZE as u64 + PVD_ROOT_RECORD_OFFSET as u64
}

/// A descriptor field whose on-disk bytes are little-endian.
///
/// The descriptor is read as bytes and its fields have whatever byte order the
/// format gives them, which is not always the machine's — the big-endian path
/// table's location is stored big-endian on a little-endian machine, and
/// reading it as an integer gives a number that addresses nothing.
pub fn field_le(value: u32) -> u32 {
    u32::from_le_bytes(value.to_ne_bytes())
}

/// A descriptor field whose on-disk bytes are big-endian.
pub fn field_be(value: u32) -> u32 {
    u32::from_be_bytes(value.to_ne_bytes())
}

/// How many logical blocks the volume says it has.
pub fn volume_blocks(device: &Arc<dyn BlockDevice>) -> Result<u32, Error> {
    let pvd = read_pvd(device)?;
    let bytes: [u8; 4] = pvd.volume_space_size[..4]
        .try_into()
        .map_err(|_| Error::InvalidArgument)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Declare the volume to be `blocks` logical blocks long.
pub fn set_volume_blocks(device: &Arc<dyn BlockDevice>, blocks: u32) -> Result<(), Error> {
    // The room has to be there in the device's own block size, not the
    // volume's — a volume that claimed blocks the medium does not have would
    // be a volume whose last files cannot be read.
    let needed = blocks as u64 * SECTOR_SIZE as u64;
    let available = device.block_count() * device.block_size() as u64;
    if needed > available {
        return Err(Error::NoSpace);
    }

    let mut field = [0u8; 8];
    field[..4].copy_from_slice(&blocks.to_le_bytes());
    field[4..].copy_from_slice(&blocks.to_be_bytes());
    let at = PVD_SECTOR * SECTOR_SIZE as u64 + core::mem::offset_of!(Pvd, volume_space_size) as u64;
    write_exact(device, at, &field)
}

/// Give back the blocks an extent no longer holds.
///
/// `held` is the size the extent had and `kept` the size it has now; the
/// blocks between them are the ones it gave up.  An extent that was the last
/// thing the volume held can lower the size the volume declares over them, and
/// nothing else has to be consulted: a block past that size belongs to nobody
/// by definition.  That is the one property a volume this driver *cannot*
/// account for still has, which is why this needs no map.
///
/// The middle of a volume is [`Allocator`]'s business: this is a **tail** rule
/// and lowering the declared size is all it does
/// ([RFC 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
pub fn release_volume_tail(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    floor: u32,
    extent_location: u32,
    held: u32,
    kept: u32,
) -> Result<(), Error> {
    let blocks = |bytes: u32| (bytes as u64).div_ceil(block_size as u64) as u32;
    let held_blocks = blocks(held);
    let kept_blocks = blocks(kept);
    if kept_blocks >= held_blocks {
        return Ok(());
    }

    let volume_end = volume_blocks(device)?;
    if extent_location.checked_add(held_blocks) != Some(volume_end) {
        return Ok(());
    }
    // Never below what the image itself declared: the blocks it came with are
    // the image's, whatever a file's record says about them.
    let new_end = extent_location + kept_blocks;
    if new_end < floor {
        return Ok(());
    }
    set_volume_blocks(device, new_end)
}

// ---------------------------------------------------------------------------
// What the volume holds
// ---------------------------------------------------------------------------

/// The blocks the standard reserves for a volume's system area.
pub const SYSTEM_AREA_BLOCKS: u32 = 16;

/// The most volume descriptors this driver will walk before giving up.
///
/// A descriptor set is a handful of sectors and ends in a terminator; a volume
/// that has not reached one within this many is not one whose structures this
/// driver can name.
const MAX_DESCRIPTORS: u32 = 32;

/// How deep a directory tree may go before the walk gives up.
const MAX_TREE_DEPTH: u32 = 64;

/// The catalog block, and the sectors El Torito may continue it into.
///
/// Claiming more than a catalog uses costs space, and claiming less costs the
/// catalog, so this is generous on purpose.
const BOOT_CATALOG_BLOCKS: u32 = 8;

/// How many logical blocks `bytes` takes.
fn blocks_of(bytes: u32, block_size: u16) -> u32 {
    (u64::from(bytes).div_ceil(u64::from(block_size))) as u32
}

/// The blocks a volume's structures occupy, as sorted, disjoint runs.
///
/// A block is free when nothing in here names it, so what the map has to be is
/// **complete**: a volume with anything this driver cannot account for gives
/// no map at all, and then allocations append, because handing a block to a
/// file that a structure already holds is the one thing that must not happen.
pub struct Occupied {
    runs: Vec<(u32, u32)>,
    /// Whether `runs` is sorted and merged, which is what a gap search needs
    /// and what marking a block breaks.
    settled: bool,
}

impl Occupied {
    fn new() -> Self {
        Self {
            runs: Vec::new(),
            settled: true,
        }
    }

    /// Claim `blocks` logical blocks beginning at `start`.
    fn mark(&mut self, start: u32, blocks: u32) {
        let end = start.saturating_add(blocks);
        if end > start {
            self.runs.push((start, end));
            self.settled = false;
        }
    }

    /// Sort and merge the runs, so that what is free is the gaps between them.
    fn settle(&mut self) {
        if self.settled {
            return;
        }
        self.runs.sort_unstable_by_key(|run| run.0);
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.runs.len());
        for &(start, end) in &self.runs {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.runs = merged;
        self.settled = true;
    }

    /// The first run of `blocks` logical blocks nothing here claims.
    ///
    /// The answer may be past the space the volume declares, which is free by
    /// definition; a caller that takes it has to grow the volume over it.
    fn first_free_run(&mut self, blocks: u32) -> Option<u32> {
        self.settle();
        if blocks == 0 {
            return Some(0);
        }
        let mut at = 0u32;
        for &(start, end) in &self.runs {
            if start.saturating_sub(at) >= blocks {
                return Some(at);
            }
            at = at.max(end);
        }
        at.checked_add(blocks).map(|_| at)
    }
}

/// The packed descriptor a sector holds.
fn descriptor_of(bytes: &[u8; SECTOR_SIZE]) -> &Pvd {
    // SAFETY: `Pvd` is `#[repr(C, packed)]`, so it needs no alignment the byte
    // buffer cannot give, and a sector is wider than the descriptor it starts
    // with.
    unsafe { &*bytes.as_ptr().cast::<Pvd>() }
}

/// The root record a descriptor carries.
///
/// A volume's trees are each named by a descriptor — the primary one, and the
/// supplementary one when the volume has it — and their root records are the
/// same field of the same structure, so this is what says where a tree starts.
pub fn descriptor_root(
    device: &Arc<dyn BlockDevice>,
    descriptor_sector: u64,
    joliet: bool,
) -> Result<DirRecord, Error> {
    let mut bytes = [0u8; SECTOR_SIZE];
    read_exact(device, descriptor_sector * SECTOR_SIZE as u64, &mut bytes)?;
    let descriptor = descriptor_of(&bytes);
    let parsed = if joliet {
        DirRecord::parse_joliet(&descriptor.root_dir_record, 0)
    } else {
        DirRecord::parse(&descriptor.root_dir_record, 0)
    };
    let (root, _next) = parsed.ok_or(Error::InvalidArgument)?;
    Ok(root)
}

/// Read one of a volume's descriptors, whichever tree it names.
pub fn read_descriptor(
    device: &Arc<dyn BlockDevice>,
    descriptor_sector: u64,
) -> Result<Pvd, Error> {
    let mut bytes = [0u8; SECTOR_SIZE];
    read_exact(device, descriptor_sector * SECTOR_SIZE as u64, &mut bytes)?;
    if &bytes[1..6] != b"CD001" || bytes[6] != 0x01 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: as `read_pvd` — a packed descriptor at the start of a full
    // sector buffer, copied out rather than borrowed.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Pvd) })
}

/// Where every structure a volume holds is, or an error when this driver
/// cannot account for all of them.
///
/// The structures a well-formed volume can have are a closed list: the system
/// area, the descriptor set, the path tables a descriptor names (with their
/// optional copies), the boot catalog a Boot Record names and the images its
/// entries point at, the directory trees of the primary and the Joliet
/// descriptors, and the continuation areas a record's `CE` entry names.  Every
/// one of them is claimed here — and anything else, from a descriptor this
/// driver does not know to an extended attribute record it does not read,
/// gives an error rather than a map with a hole in it.
pub fn occupied_blocks(device: &Arc<dyn BlockDevice>, block_size: u16) -> Result<Occupied, Error> {
    let mut occupied = Occupied::new();
    occupied.mark(0, SYSTEM_AREA_BLOCKS);

    let mut trees: Vec<(DirRecord, bool)> = Vec::new();
    let mut terminated = false;
    for offset in 0..MAX_DESCRIPTORS {
        let sector = PVD_SECTOR as u32 + offset;
        let mut bytes = [0u8; SECTOR_SIZE];
        read_exact(
            device,
            u64::from(sector) * u64::from(block_size),
            &mut bytes,
        )?;
        if &bytes[1..6] != b"CD001" || bytes[6] != 0x01 {
            return Err(Error::InvalidArgument);
        }
        occupied.mark(sector, 1);

        match bytes[0] {
            0xFF => {
                terminated = true;
                break;
            }
            0x01 | 0x02 => {
                // There is exactly one supplementary descriptor this driver
                // reads, and a volume with another is one whose other tree it
                // cannot account for.
                let joliet = &bytes[88..91] == b"%/@";
                if bytes[0] == 0x02 && !joliet {
                    return Err(Error::Unsupported);
                }
                let descriptor = descriptor_of(&bytes);
                mark_path_tables(&mut occupied, block_size, descriptor);
                let parsed = if joliet {
                    DirRecord::parse_joliet(&descriptor.root_dir_record, 0)
                } else {
                    DirRecord::parse(&descriptor.root_dir_record, 0)
                };
                let (root, _next) = parsed.ok_or(Error::InvalidArgument)?;
                trees.push((root, joliet));
            }
            0x00 => mark_boot_record(&mut occupied, block_size, &bytes),
            _ => return Err(Error::Unsupported),
        }
    }
    if !terminated {
        return Err(Error::InvalidArgument);
    }

    for (root, joliet) in &trees {
        mark_tree(device, block_size, &mut occupied, root, *joliet, 0)?;
    }
    Ok(occupied)
}

/// Claim the path tables a descriptor names, and any optional copies of them.
fn mark_path_tables(occupied: &mut Occupied, block_size: u16, descriptor: &Pvd) {
    let size = u32::from_le_bytes(
        descriptor.path_table_size[..4]
            .try_into()
            .unwrap_or_default(),
    );
    let blocks = blocks_of(size, block_size);
    for location in [
        field_le(descriptor.l_path_table_loc),
        field_be(descriptor.m_path_table_loc),
        field_le(descriptor.opt_l_path_table_loc),
        field_be(descriptor.opt_m_path_table_loc),
    ] {
        if location != 0 {
            occupied.mark(location, blocks);
        }
    }
}

/// Claim the boot catalog a Boot Record names, and the images its entries do.
fn mark_boot_record(occupied: &mut Occupied, block_size: u16, bytes: &[u8; SECTOR_SIZE]) {
    let catalog = u32::from_le_bytes([bytes[71], bytes[72], bytes[73], bytes[74]]);
    if catalog == 0 {
        return;
    }
    occupied.mark(catalog, BOOT_CATALOG_BLOCKS);
    for entry in parse_boot_catalog(bytes) {
        // An entry counts its image in the 512-byte sectors a boot loader
        // reads, not in the volume's logical blocks.
        let image = (u64::from(entry.sector_count) * 512).div_ceil(u64::from(block_size)) as u32;
        occupied.mark(entry.load_rba, image);
    }
}

/// Claim every extent a directory tree names, from its root down.
fn mark_tree(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    occupied: &mut Occupied,
    root: &DirRecord,
    joliet: bool,
    depth: u32,
) -> Result<(), Error> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::InvalidArgument);
    }
    if root.extended_attribute_blocks != 0 {
        // The root's own attributes sit in front of the extent below, and what
        // this walk is about to read is not where the record says the entries
        // are.
        return Err(Error::Unsupported);
    }
    // Every record, its own "." and ".." included: those two are records like
    // any other here, and the root's "." is where a volume's extension
    // reference is, whose continuation is a block of its own.
    let records = read_all_records(
        device,
        block_size,
        root.extent_location,
        root.extent_size,
        joliet,
    )?;
    occupied.mark(
        root.extent_location,
        blocks_of(root.extent_size, block_size),
    );

    for record in &records {
        mark_record(occupied, block_size, record)?;
        // "." is this directory and ".." is its parent: neither is a child,
        // and following them would walk the tree in circles.
        if record.is_dir() && !names_self_or_parent(record, joliet) {
            mark_tree(device, block_size, occupied, record, joliet, depth + 1)?;
        }
    }
    Ok(())
}

/// Claim what one record names.
fn mark_record(occupied: &mut Occupied, block_size: u16, record: &DirRecord) -> Result<(), Error> {
    if record.extended_attribute_blocks != 0 {
        // The attributes sit in front of the data and this driver does not
        // read them, so what the record says is not the whole of what the
        // entry holds.
        return Err(Error::Unsupported);
    }
    occupied.mark(
        record.extent_location,
        blocks_of(record.extent_size, block_size),
    );
    mark_continuations(occupied, block_size, &record.system_use);
    Ok(())
}

/// Claim the bytes a record's System Use area says it continues into.
fn mark_continuations(occupied: &mut Occupied, block_size: u16, system_use: &[u8]) {
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        if &rest[..2] == b"CE" && len >= 28 {
            let number =
                |at: usize| u32::from_le_bytes(rest[at..at + 4].try_into().unwrap_or_default());
            // The continuation begins at a byte offset inside that block, so
            // what it takes is however many blocks its bytes fall in.
            let bytes = u64::from(number(12)) + u64::from(number(20));
            let blocks = bytes.div_ceil(u64::from(block_size)) as u32;
            occupied.mark(number(4), blocks);
        }
        rest = &rest[len..];
    }
}

/// Where a new extent comes from.
///
/// The volume's free blocks are everything its structures do not name, and
/// finding them means walking the whole volume — so it happens once per
/// operation, and the blocks are claimed here as they are handed out.
pub struct Allocator<'a> {
    device: &'a Arc<dyn BlockDevice>,
    block_size: u16,
    /// The volume's structures, when this driver can account for all of them;
    /// `None` is a volume it cannot, and then every allocation appends.
    free: Option<Occupied>,
}

impl<'a> Allocator<'a> {
    /// An allocator for a volume, which hands out the blocks that are free and
    /// appends when it cannot account for what is on the volume.
    pub fn of(device: &'a Arc<dyn BlockDevice>, block_size: u16) -> Self {
        Self {
            device,
            block_size,
            free: occupied_blocks(device, block_size).ok(),
        }
    }

    /// Take `blocks` logical blocks, and answer where they are.
    pub fn take(&mut self, blocks: u32) -> Result<u32, Error> {
        let Some(free) = self.free.as_mut() else {
            return allocate_blocks(self.device, self.block_size, blocks);
        };
        let start = free.first_free_run(blocks).ok_or(Error::NoSpace)?;
        free.mark(start, blocks);
        // The run may be past the space the volume declares, which is free by
        // definition; taking it means the volume grows over it.
        let end = start.checked_add(blocks).ok_or(Error::NoSpace)?;
        if end > volume_blocks(self.device)? {
            set_volume_blocks(self.device, end)?;
        }
        Ok(start)
    }
}

/// Take `count` logical blocks for a file, and grow the volume to hold them.
///
/// This is the **fallback** the allocator above uses for a volume whose
/// structures this driver cannot account for: the blocks begin where the
/// volume's declared extent ends, and the one metadata field it moves is the
/// volume's own size.  It never hands out a block the image already wrote,
/// which is what makes it correct without knowing what is on the volume — and
/// what it costs is that nothing in the middle is ever handed out again
/// ([RFC 0011](../../docs/rfcs/0011-make-iso9660-file-data-writable.md)).
pub fn allocate_blocks(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    count: u32,
) -> Result<u32, Error> {
    let first = volume_blocks(device)?;
    if first == 0 {
        // The image never declared its size, so there is no end to append to.
        return Err(Error::NoSpace);
    }
    let _ = block_size;
    let end = first.checked_add(count).ok_or(Error::NoSpace)?;

    set_volume_blocks(device, end)?;
    Ok(first)
}

/// Give an extent the blocks `new_size` bytes need, and answer where it is.
///
/// An extent is **one contiguous run**, so there are two ways to make it
/// bigger and this picks by where it is.  When it is the last thing the volume
/// holds, the blocks it needs follow it and the volume grows over them — no
/// copy.  Otherwise something is in the way, and the extent **moves** to the
/// free blocks the allocator gives it: the data first, and the caller writes
/// the record that points at it afterwards, so a crash before that leaves the
/// old record pointing at the old content.
///
/// A size that fits in the blocks the extent already has allocates nothing and
/// moves nothing.
pub fn place_extent(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    new_size: u32,
    allocate: &mut Allocator,
) -> Result<u32, Error> {
    let bs = block_size as u32;
    let old_blocks = extent_size.div_ceil(bs);
    let new_blocks = new_size.div_ceil(bs);
    if new_blocks <= old_blocks {
        return Ok(extent_location);
    }

    let volume_end = volume_blocks(device)?;
    if volume_end != 0 && extent_location + old_blocks == volume_end {
        // The extent is the last thing on the volume: grow the volume over the
        // blocks that follow it, which keeps a crash from leaving a record
        // that claims blocks the volume does not own.
        set_volume_blocks(device, volume_end + (new_blocks - old_blocks))?;
        return Ok(extent_location);
    }

    let first = allocate.take(new_blocks)?;
    if extent_size > 0 {
        let mut data = alloc::vec![0u8; extent_size as usize];
        read_extent(
            device,
            block_size,
            extent_location,
            extent_size,
            0,
            &mut data,
        )?;
        write_extent(device, block_size, first, new_size, 0, &data)?;
    }
    Ok(first)
}

/// Add `record` to the end of a directory's extent, and answer where it went.
///
/// A directory record may not straddle a logical block boundary, so a record
/// that does not fit in the block the directory's records end in starts the
/// next one.  The bytes it skips are left as the image had them — a reader
/// reads a zero-length record as "no more records in this block" and continues
/// at the next one, which is what [`read_directory`] does.
///
/// The directory's own record is the caller's to rewrite: it says where the
/// extent is and how long it is, and nothing here touches it.
pub fn append_record(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    dir_extent: u32,
    dir_size: u32,
    record: &[u8],
    allocate: &mut Allocator,
) -> Result<(u32, u32, u64), Error> {
    let bs = block_size as u64;
    let mut at = dir_size as u64;
    if at % bs + record.len() as u64 > bs {
        at = at.div_ceil(bs) * bs;
    }

    let new_size = u32::try_from(at + record.len() as u64).map_err(|_| Error::NoSpace)?;
    let location = place_extent(device, block_size, dir_extent, dir_size, new_size, allocate)?;

    // The record goes into the extent's own byte space, which the move above
    // preserved, so `at` is where it is either way.
    write_exact(device, location as u64 * bs + at, record)?;
    Ok((location, new_size, location as u64 * bs + at))
}

/// The bytes a record's extent-location and data-length fields hold.
///
/// The two fields are adjacent in the record and each is stored twice —
/// little-endian then big-endian — so a reader that checks either half sees
/// the same thing.
pub fn placement_field(extent_location: u32, length: u32) -> [u8; 16] {
    let mut field = [0u8; 16];
    field[..4].copy_from_slice(&extent_location.to_le_bytes());
    field[4..8].copy_from_slice(&extent_location.to_be_bytes());
    field[8..12].copy_from_slice(&length.to_le_bytes());
    field[12..].copy_from_slice(&length.to_be_bytes());
    field
}

/// Point a file's record at a new extent, and give it a new length.
pub fn rewrite_record_placement(
    device: &Arc<dyn BlockDevice>,
    record_offset: u64,
    extent_location: u32,
    length: u32,
) -> Result<(), Error> {
    let field = placement_field(extent_location, length);
    write_exact(
        device,
        record_offset + DIR_RECORD_EXTENT_LOCATION_OFFSET as u64,
        &field,
    )
}
