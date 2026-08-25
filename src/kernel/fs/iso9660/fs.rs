//! src/kernel/fs/iso9660/fs.rs
//!
//! Low-level ISO 9660 operations: read PVD, parse directories, read files.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::parse_boot_catalog;
use super::types::BootEntry;
use super::types::DirRecord;
use super::types::Pvd;
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
    let pvd_ref: &Pvd = unsafe { &*buf.as_ptr().cast::<Pvd>() };

    if !pvd_ref.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // Read the bytes into a new Pvd safely.
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

/// Specialized trait needed for read_extent.
use alloc;
