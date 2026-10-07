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

/// Read all directory entries from an extent.
pub fn read_directory(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
) -> Result<Vec<DirRecord>, Error> {
    let block_size = block_size as u64;
    let extent_size = extent_size as u64;

    // Cap to a reasonable maximum to avoid OOM on corrupt images.
    if extent_size > 16 * 1024 * 1024 {
        return Err(Error::InvalidArgument);
    }

    let mut data = alloc::vec![0u8; extent_size as usize];
    let extent_offset = extent_location as u64 * block_size;
    read_exact(device, extent_offset, &mut data)?;

    let mut records = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match DirRecord::parse(&data, offset) {
            Some((record, next)) => {
                // Skip "." and ".." entries for cleaner listing.
                let skip = record.identifier.len() == 1
                    && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01);

                if !skip {
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
    let block_size = block_size as u64;
    let extent_size = extent_size as u64;

    // Cap to a reasonable maximum to avoid OOM on corrupt images.
    if extent_size > 16 * 1024 * 1024 {
        return Err(Error::InvalidArgument);
    }

    let mut data = alloc::vec![0u8; extent_size as usize];
    let extent_offset = extent_location as u64 * block_size;
    read_exact(device, extent_offset, &mut data)?;

    let mut records = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match DirRecord::parse_joliet(&data, offset) {
            Some((record, next)) => {
                // Skip "." and ".." entries (UCS-2BE encoded as 0x0000 / 0x0001).
                let skip = record.identifier.len() == 2
                    && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01);

                if !skip {
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

/// How many logical blocks the volume says it has.
///
/// The descriptor's own statement of the volume's extent, stored twice.  Zero
/// means the image never said.
/// Where the root directory's record lives: a field of the PVD.
///
/// The root is the one directory that is not a record inside another, and its
/// length lives in the descriptor.
pub fn root_record_offset() -> u64 {
    PVD_SECTOR * SECTOR_SIZE as u64 + PVD_ROOT_RECORD_OFFSET as u64
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

/// Take `count` logical blocks for a file, and grow the volume to hold them.
///
/// This is an **append-only** allocator: the blocks it hands out begin where
/// the volume's declared extent ends, and the one metadata field it moves is
/// the volume's own size.  It never hands out a block the image already wrote,
/// which is what makes it correct without a free-space scan — and what it
/// costs is that a removal reclaims nothing, and a file grows either where the
/// blocks after it happen to be free or by moving.  A scan of every extent is
/// what reclaiming would take, and it is the next step
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
/// end of the volume: the data first, and the caller writes the record that
/// points at it afterwards, so a crash before that leaves the old record
/// pointing at the old content.
///
/// A size that fits in the blocks the extent already has allocates nothing and
/// moves nothing.
pub fn place_extent(
    device: &Arc<dyn BlockDevice>,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    new_size: u32,
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

    let first = allocate_blocks(device, block_size, new_blocks)?;
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
) -> Result<(u32, u32, u64), Error> {
    let bs = block_size as u64;
    let mut at = dir_size as u64;
    if at % bs + record.len() as u64 > bs {
        at = at.div_ceil(bs) * bs;
    }

    let new_size = u32::try_from(at + record.len() as u64).map_err(|_| Error::NoSpace)?;
    let location = place_extent(device, block_size, dir_extent, dir_size, new_size)?;

    // The record goes into the extent's own byte space, which the move above
    // preserved, so `at` is where it is either way.
    write_exact(device, location as u64 * bs + at, record)?;
    Ok((location, new_size, location as u64 * bs + at))
}

/// Point a file's record at a new extent, and give it a new length.
///
/// The two fields are adjacent in the record and each is stored twice —
/// little-endian then big-endian — so one write covers both, and a reader that
/// checks either half sees the same file.
pub fn rewrite_record_placement(
    device: &Arc<dyn BlockDevice>,
    record_offset: u64,
    extent_location: u32,
    length: u32,
) -> Result<(), Error> {
    let mut field = [0u8; 16];
    field[..4].copy_from_slice(&extent_location.to_le_bytes());
    field[4..8].copy_from_slice(&extent_location.to_be_bytes());
    field[8..12].copy_from_slice(&length.to_le_bytes());
    field[12..].copy_from_slice(&length.to_be_bytes());
    write_exact(
        device,
        record_offset + DIR_RECORD_EXTENT_LOCATION_OFFSET as u64,
        &field,
    )
}
