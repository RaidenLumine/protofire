//! src/kernel/fs/ntfs/fs.rs
//!
//! NTFS low-level operations: cluster I/O, MFT record reading, directory
//! traversal, file reads.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::{
    BootSector, DataRun, FileName, MftRecordHeader, ParsedAttr, StandardInfoAttr,
    ATTR_TYPE_FILENAME, ATTR_TYPE_STANDARD_INFO, BLOCK_SIZE,
};

// ── Boot sector ─────────────────────────────────────────────────────────

/// Read and parse the NTFS boot sector at LBA 0.
pub fn read_boot_sector(device: &Arc<dyn BlockDevice>) -> Result<BootSector, Error> {
    let mut buf = [0u8; 512];
    read_device_bytes(device, 0, &mut buf)?;
    BootSector::parse(&buf).ok_or(Error::InvalidArgument)
}

// ── Volume info ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct NtfsInfo {
    pub bs: BootSector,
    pub cluster_size: u32,
    pub mft_record_size: u32,
    pub index_block_size: u32,
}

impl NtfsInfo {
    pub fn new(bs: BootSector) -> Self {
        let cluster_size = bs.bytes_per_sector as u32 * bs.sectors_per_cluster as u32;
        let mft_record_size = bs.clusters_per_mft_record * cluster_size;
        let index_block_size = bs.clusters_per_index_buffer * cluster_size;
        Self {
            bs,
            cluster_size,
            mft_record_size,
            index_block_size,
        }
    }
}

// ── Cluster I/O ──────────────────────────────────────────────────────────

/// Read `count` clusters at LCN into `buf`. Kept as a convenience primitive;
/// the driver currently reaches the device through `read_device_bytes`.
#[allow(dead_code)]
pub fn read_clusters(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    lcn: u64,
    count: u64,
    buf: &mut [u8],
) -> Result<usize, Error> {
    if lcn == u64::MAX {
        // Sparse region: fill with zeros.
        let n = (count * info.cluster_size as u64).min(buf.len() as u64) as usize;
        buf[..n].fill(0);
        return Ok(n);
    }

    let byte_off = lcn * info.cluster_size as u64;
    let total = (count * info.cluster_size as u64) as usize;
    let n = total.min(buf.len());
    read_device_bytes(device, byte_off, &mut buf[..n])?;
    Ok(n)
}

/// Read a byte range by following data runs.
pub fn read_from_runs(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    runs: &[DataRun],
    file_size: u64,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, Error> {
    if offset >= file_size || buf.is_empty() {
        return Ok(0);
    }

    let cluster_size = info.cluster_size as u64;
    let end = (offset + buf.len() as u64).min(file_size);
    let mut total = 0usize;
    let mut cluster_start: u64 = 0;

    for run in runs {
        let run_end = cluster_start + run.cluster_count * cluster_size;
        if cluster_start >= end {
            break;
        }
        if run_end <= offset {
            cluster_start = run_end;
            continue;
        }

        let seg_start = offset.max(cluster_start);
        let seg_end = end.min(run_end);
        let seg_len = (seg_end - seg_start) as usize;
        let phys_lcn = if run.lcn >= 0 {
            run.lcn as u64
        } else {
            u64::MAX
        };
        let phys_off = if phys_lcn != u64::MAX {
            phys_lcn * cluster_size + (seg_start - cluster_start)
        } else {
            u64::MAX
        };

        let dest = (seg_start - offset) as usize;
        if phys_off == u64::MAX {
            buf[dest..dest + seg_len].fill(0);
        } else {
            read_device_bytes(device, phys_off, &mut buf[dest..dest + seg_len])?;
        }
        total += seg_len;
        cluster_start = run_end;
    }
    Ok(total)
}

// ── MFT record reading ──────────────────────────────────────────────────

/// Read an MFT record by number, applying the USA fixup. Kept as a free
/// primitive; [`super::NtfsFs::read_mft_record`] is the cache-aware wrapper.
#[allow(dead_code)]
pub fn read_mft_record(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    record_number: u64,
) -> Result<(MftRecordHeader, Vec<u8>), Error> {
    let byte_off =
        info.bs.mft_lcn * info.cluster_size as u64 + record_number * info.mft_record_size as u64;
    let mut buf = vec![0u8; info.mft_record_size as usize];
    read_device_bytes(device, byte_off, &mut buf)?;

    // USA fixup: restore original sector-end bytes from fixup array.
    let header = MftRecordHeader::parse(&buf).ok_or(Error::InvalidArgument)?;
    if header.usa_count > 1 {
        let usa_off = header.usa_offset as usize;
        let usa_len = header.usa_count as usize * 2;
        if usa_off + usa_len > buf.len() {
            return Err(Error::InvalidArgument);
        }
        // Read fixup sequence value once (first u16 of the USA array; only
        // needed to validate sector-end markers, which we skip).
        let _fixup_seq = u16::from_le_bytes([buf[usa_off], buf[usa_off + 1]]);
        for i in 1..header.usa_count as usize {
            let sector_end = i * BLOCK_SIZE;
            if sector_end >= 2 && sector_end <= buf.len() && usa_off + i * 2 + 1 < buf.len() {
                // Read original last-2-bytes from the fixup array.
                let orig_lo = buf[usa_off + i * 2];
                let orig_hi = buf[usa_off + i * 2 + 1];
                buf[sector_end - 2] = orig_lo;
                buf[sector_end - 1] = orig_hi;
            }
        }
    }

    Ok((header, buf))
}

/// Parse all attributes in an MFT record.
pub fn parse_attributes(buf: &[u8]) -> Vec<ParsedAttr> {
    let mut attrs = Vec::new();
    let mut offset = 0;

    while offset + 24 <= buf.len() {
        let attr_type = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let attr_len = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        if attr_type == 0xFFFFFFFF || attr_len == 0 {
            break;
        }

        if offset + attr_len as usize > buf.len() {
            break;
        }

        let non_resident = buf[offset + 8] != 0;
        // The remaining header fields are read for completeness; the current
        // reader does not need them (no named attributes are resolved).
        let _name_len = buf[offset + 9] as usize;
        let _name_offset = u16::from_le_bytes([buf[offset + 10], buf[offset + 11]]) as usize;
        let _flags = u16::from_le_bytes([buf[offset + 12], buf[offset + 13]]);
        let _instance = u16::from_le_bytes([buf[offset + 14], buf[offset + 15]]);

        let content_offset = if non_resident {
            24 + 8 // Resident header + start VCN + data runs length
        } else {
            24 + 4 // Resident header + content size
        };

        let content_size = if non_resident {
            // Non-resident: the real data size is stored in the attribute
            // header at +48 (u64), not derivable from the data runs alone.
            u64::from_le_bytes([
                buf[offset + 48],
                buf[offset + 49],
                buf[offset + 50],
                buf[offset + 51],
                buf[offset + 52],
                buf[offset + 53],
                buf[offset + 54],
                buf[offset + 55],
            ]) as u32
        } else {
            u32::from_le_bytes([
                buf[offset + 16],
                buf[offset + 17],
                buf[offset + 18],
                buf[offset + 19],
            ])
        };

        let mut content = Vec::new();
        if content_offset + content_size as usize <= buf.len() {
            content.extend_from_slice(&buf[content_offset..content_offset + content_size as usize]);
        }

        let data_runs_offset = if non_resident {
            // Non-resident: the data-runs array begins at header +32.
            let runs_off = u16::from_le_bytes([buf[offset + 32], buf[offset + 33]]) as usize;
            if runs_off > 0 && runs_off + 2 <= buf.len() {
                Some(runs_off)
            } else {
                None
            }
        } else {
            None
        };

        let data_runs = match data_runs_offset {
            Some(runs_off) => parse_data_runs(&buf[runs_off..]),
            None => Vec::new(),
        };

        attrs.push(ParsedAttr {
            attr_type,
            content,
            data_runs_offset,
            data_runs,
            data_size: content_size,
        });

        offset += attr_len as usize;
        if offset >= buf.len() {
            break;
        }
    }

    attrs
}

/// Parse data runs from a buffer.
///
/// Each run stores its LCN as a signed delta from the previous run's LCN (so
/// a file spanning several extents must accumulate the deltas).  A zero delta
/// marks a sparse run (-1 LCN).  The `DataRun.lcn` values are absolute.
pub fn parse_data_runs(buf: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut offset = 0usize;
    let mut prev_lcn: i64 = 0;

    while offset < buf.len() {
        let header = buf[offset];
        if header == 0 {
            break; // run-list terminator
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        offset += 1;

        if offset + len_bytes + off_bytes > buf.len() {
            break;
        }

        let mut cluster_count = 0u64;
        for i in 0..len_bytes {
            cluster_count |= (buf[offset + i] as u64) << (i * 8);
        }
        offset += len_bytes;

        let mut off_delta: i64 = 0;
        for i in 0..off_bytes {
            off_delta |= (buf[offset + i] as i64) << (i * 8);
        }
        // Sign-extend a partial-width delta.
        if off_bytes > 0 && off_bytes < 8 {
            let sign_bit = 1i64 << (off_bytes * 8 - 1);
            if off_delta & sign_bit != 0 {
                off_delta |= !((1i64 << (off_bytes * 8)) - 1);
            }
        }
        offset += off_bytes;

        if cluster_count > 0 {
            let lcn = if off_delta == 0 {
                -1 // Sparse run
            } else {
                prev_lcn + off_delta
            };
            prev_lcn = lcn;
            runs.push(DataRun { lcn, cluster_count });
        }
    }

    runs
}

/// Parse filename attributes.
#[allow(dead_code)]
pub fn parse_filename_attributes(attrs: &[ParsedAttr]) -> Vec<FileName> {
    let mut filenames = Vec::new();

    for attr in attrs {
        if attr.attr_type == ATTR_TYPE_FILENAME {
            if let Some(filename) = FileName::parse(&attr.content) {
                filenames.push(filename);
            }
        }
    }

    filenames
}

/// Find the best filename for a file (prefers Win32 over DOS).
#[allow(dead_code)]
pub fn get_best_filename(attrs: &[ParsedAttr]) -> Option<FileName> {
    let mut best = None;

    for attr in attrs {
        if attr.attr_type == ATTR_TYPE_FILENAME {
            if let Some(filename) = FileName::parse(&attr.content) {
                match &best {
                    None => best = Some(filename),
                    Some(cur) => {
                        let replace = (filename.preferred_namespace()
                            && !cur.preferred_namespace())
                            || (cur.namespace == 2 && filename.namespace != 2);
                        if replace {
                            best = Some(filename);
                        }
                    }
                }
            }
        }
    }

    best
}

/// Read the resident `$STANDARD_INFORMATION` attribute, if present.
#[allow(dead_code)]
pub fn get_standard_info(attrs: &[ParsedAttr]) -> Option<StandardInfoAttr> {
    for attr in attrs {
        if attr.attr_type == ATTR_TYPE_STANDARD_INFO {
            if let Some(si) = StandardInfoAttr::parse(&attr.content) {
                return Some(si);
            }
        }
    }
    None
}

// ── Directory operations ──────────────────────────────────────────────────

/// Parse index entries to get directory contents.
///
/// The buffer is the resident content of an `$INDEX_ROOT` attribute: a
/// 16-byte index header (first-entry offset at +8, total size at +10)
/// followed by index entries.  Each entry carries an embedded `$FILE_NAME`
/// key:
///   u64  MFT reference       (offset +0)
///   u16  entry length        (offset +8)
///   u16  content offset      (offset +10)
///   u32  flags               (offset +12, 0x02 = last entry in node)
#[allow(dead_code)]
pub fn parse_index_entries(buf: &[u8]) -> Result<Vec<(String, u64)>, Error> {
    if buf.len() < 16 {
        return Ok(Vec::new());
    }

    let start_offset = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let end_offset = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    if start_offset >= buf.len() || end_offset > buf.len() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<(u64, FileName)> = Vec::new();
    let mut offset = start_offset;
    while offset + 16 <= end_offset {
        let entry_length = u16::from_le_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        if entry_length == 0 || offset + entry_length > end_offset {
            break;
        }
        let content_offset = u16::from_le_bytes([buf[offset + 10], buf[offset + 11]]) as usize;
        let mft_ref = u64::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let flags = u32::from_le_bytes([
            buf[offset + 12],
            buf[offset + 13],
            buf[offset + 14],
            buf[offset + 15],
        ]);

        let content_start = offset + content_offset;
        if content_start < buf.len() {
            if let Some(name) = FileName::parse(&buf[content_start..]) {
                // Keep only the 48-bit MFT record number (the upper 16 bits
                // hold a sequence number).
                entries.push((mft_ref & 0x0000_FFFF_FFFF_FFFF, name));
            }
        }

        offset += entry_length;
        if flags & 0x02 != 0 {
            // Last entry in this node; skip the 8-byte alignment padding.
            offset = (offset + 7) & !7;
        }
    }

    // NTFS stores one `$FILE_NAME` index entry per namespace for the same
    // file (POSIX=0, Win32=1, DOS=2, Win32&DOS=3).  Deduplicate by MFT
    // record, keeping the preferred spelling and dropping pure-DOS 8.3
    // duplicates while preserving first-seen order.
    let mut best: Vec<(u64, FileName)> = Vec::new();
    let mut by_ref: BTreeMap<u64, usize> = BTreeMap::new();
    for (mft, name) in entries {
        match by_ref.get(&mft).copied() {
            Some(idx) => {
                let existing = &best[idx].1;
                // Prefer a Win32/Win32&DOS name over a POSIX one, and replace
                // a pure-DOS 8.3 entry with any better namespace.
                if (name.preferred_namespace() && !existing.preferred_namespace())
                    || (existing.namespace == 2 && name.namespace != 2)
                {
                    best[idx] = (mft, name);
                }
            }
            None => {
                by_ref.insert(mft, best.len());
                best.push((mft, name));
            }
        }
    }

    Ok(best
        .into_iter()
        .map(|(mft, name)| (name.name, mft))
        .collect())
}

// ── Byte I/O ──────────────────────────────────────────────────────────────

fn read_device_bytes(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    buf: &mut [u8],
) -> Result<(), Error> {
    if buf.is_empty() {
        return Ok(());
    }

    let dev_bs = device.block_size() as u64;
    let start_lba = byte_offset / dev_bs;
    let start_off = (byte_offset % dev_bs) as usize;
    let end_byte = byte_offset + buf.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);

    let total = (end_lba - start_lba) as usize;
    let mut scratch = vec![0u8; total * dev_bs as usize];

    for i in 0..total {
        let lba = start_lba + i as u64;
        let out = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, out)?;
    }

    buf.copy_from_slice(&scratch[start_off..start_off + buf.len()]);
    Ok(())
}

/// Write clusters to the NTFS volume.
pub fn write_clusters(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    lcn: u64,
    count: u64,
    buf: &[u8],
) -> Result<usize, Error> {
    if lcn == u64::MAX {
        // Cannot write to sparse regions.
        return Err(Error::InvalidArgument);
    }

    let byte_off = lcn * info.cluster_size as u64;
    let total = (count * info.cluster_size as u64) as usize;
    let n = total.min(buf.len());
    write_device_bytes(device, byte_off, &buf[..n])?;
    Ok(n)
}

/// Write a byte range to the device.
pub fn write_device_bytes(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    data: &[u8],
) -> Result<(), Error> {
    let mut offset = byte_offset;
    let mut remaining = data.len();
    let mut data_ptr = data.as_ptr();

    while remaining > 0 {
        let block_offset = offset % BLOCK_SIZE as u64;
        let block_bytes = BLOCK_SIZE.min(remaining - (offset as usize % BLOCK_SIZE));
        let block_lba = offset / BLOCK_SIZE as u64;

        let mut block_data = [0u8; BLOCK_SIZE];
        // Read existing block to preserve other data
        if read_device_bytes(device, block_lba * BLOCK_SIZE as u64, &mut block_data).is_err() {
            // If read fails (e.g., invalid LBA), create a new block
            block_data.fill(0);
        }

        // Copy new data into the block
        let start_pos = block_offset as usize;
        block_data[start_pos..start_pos + block_bytes]
            .copy_from_slice(unsafe { core::slice::from_raw_parts(data_ptr, block_bytes) });

        // Write the modified block back
        write_device_block(device, block_lba, &block_data)?;

        offset += block_bytes as u64;
        remaining -= block_bytes;
        unsafe {
            data_ptr = data_ptr.add(block_bytes);
        }
    }

    Ok(())
}

/// Write a single block to the device.
fn write_device_block(device: &Arc<dyn BlockDevice>, lba: u64, data: &[u8]) -> Result<(), Error> {
    if data.len() != BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }
    device.write_blocks(lba, data)?;
    Ok(())
}
