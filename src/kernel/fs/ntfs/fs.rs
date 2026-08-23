//! src/kernel/fs/ntfs/fs.rs
//! NTFS low-level operations: cluster I/O, MFT record reading, directory traversal, file reads.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::{
    parse_attributes, BootSector, DataRun, FileName, MftRecordHeader, ParsedAttr, StandardInfoAttr,
    ATTR_TYPE_DATA, ATTR_TYPE_FILENAME, ATTR_TYPE_INDEX_ROOT, ATTR_TYPE_STANDARD_INFO, BLOCK_SIZE,
};

// ── Volume info ──────────────────────────────────────────────────────────

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
        // Read fixup sequence value once.
        let fixup_seq = u16::from_le_bytes([buf[usa_off], buf[usa_off + 1]]);
        for i in 1..header.usa_count as usize {
            let sector_end = i * BLOCK_SIZE;
            if sector_end >= 2 && sector_end <= buf.len() && usa_off + i * 2 + 1 < buf.len() {
                // Read original last-2-bytes from the fixup array.
                let orig_lo = buf[usa_off + i * 2];
                let orig_hi = buf[usa_off + i * 2 + 1];
                // Restore original end-of-sector bytes.
                buf[sector_end - 2] = orig_lo;
                buf[sector_end - 1] = orig_hi;
                // Verify the on-disk sequence value matches (optional, skip if not).
                let _disk_seq = u16::from_le_bytes([orig_lo, orig_hi]);
                let _expected = fixup_seq;
            }
        }
    }

    Ok((header, buf))
}

// ── Attribute helpers ────────────────────────────────────────────────────

pub fn find_attr(attrs: &[ParsedAttr], attr_type: u32) -> Option<&ParsedAttr> {
    attrs.iter().find(|a| a.attr_type == attr_type)
}

pub fn get_file_size(attrs: &[ParsedAttr]) -> u64 {
    if let Some(data) = find_attr(attrs, ATTR_TYPE_DATA) {
        data.data_size
    } else {
        0
    }
}

#[allow(dead_code)]
pub fn parse_filename(attrs: &[ParsedAttr]) -> Option<FileName> {
    for attr in attrs {
        if attr.attr_type == ATTR_TYPE_FILENAME {
            if let Some(fn_) = FileName::parse(&attr.content) {
                return Some(fn_);
            }
        }
    }
    None
}

// ── Directory enumeration ────────────────────────────────────────────────

pub fn read_dir_entries(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    record_number: u64,
) -> Result<Vec<(String, u64)>, Error> {
    let (header, buf) = read_mft_record(device, info, record_number)?;
    let attrs = parse_attributes(&buf, header.first_attr_offset as usize);

    // Try INDEX_ROOT first.
    for attr in &attrs {
        if attr.attr_type == ATTR_TYPE_INDEX_ROOT {
            if let Some(entries) = parse_index_root(&attr.content) {
                return Ok(entries);
            }
        }
    }

    // Fallback: no entries.
    Ok(Vec::new())
}

fn parse_index_root(content: &[u8]) -> Option<Vec<(String, u64)>> {
    if content.len() < 16 {
        return None;
    }
    // Index root: 4 bytes type, 4 bytes collation, 4 bytes index_block_size,
    // 1 byte clusters_per_block, 2 bytes padding.
    let entries_start = 16usize; // after index header
    parse_index_entries(&content[entries_start..])
}

pub fn parse_index_entries(buf: &[u8]) -> Option<Vec<(String, u64)>> {
    let mut entries: Vec<(u64, FileName)> = Vec::new();
    let mut offset = 0usize;

    while offset + 16 <= buf.len() {
        // Index entry: 8 bytes MFT ref, 2 bytes entry_len, 2 bytes content_off,
        // 4 bytes flags.
        let entry_len = u16::from_le_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        if entry_len == 0 || offset + entry_len > buf.len() {
            break;
        }
        let content_off = u16::from_le_bytes([buf[offset + 10], buf[offset + 11]]) as usize;
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

        // Filename attribute at content offset (embedded in index entry).
        let content_start = offset + content_off;
        if content_start + 8 < buf.len() {
            if let Some(fn_) = FileName::parse(&buf[content_start..]) {
                // Keep only the 48-bit MFT record number (upper 16 bits are a
                // sequence number).
                entries.push((mft_ref & 0x0000_FFFF_FFFF_FFFF, fn_));
            }
        }

        if flags & 0x02 != 0 {
            // Last entry in this node.
            offset += entry_len;
            // Skip padding to 8-byte boundary.
            offset = (offset + 7) & !7;
            continue;
        }

        offset += entry_len;
    }

    // NTFS stores one $FILE_NAME index entry per namespace for the same file
    // (POSIX=0, Win32=1, DOS=2, Win32&DOS=3).  Deduplicate by MFT record,
    // keeping the preferred spelling (Win32/Win32&DOS > POSIX > DOS) and
    // dropping pure-DOS 8.3 duplicates, while preserving first-seen order.
    let mut best: Vec<(u64, FileName)> = Vec::new();
    let mut by_ref: BTreeMap<u64, usize> = BTreeMap::new();
    for (mft, name) in entries {
        match by_ref.get(&mft).copied() {
            Some(idx) => {
                let existing = &best[idx].1;
                if name.preferred_namespace() && !existing.preferred_namespace() {
                    best[idx] = (mft, name);
                } else if existing.namespace == 2 && name.namespace != 2 {
                    // Replace a pure-DOS entry with any better namespace.
                    best[idx] = (mft, name);
                }
            }
            None => {
                by_ref.insert(mft, best.len());
                best.push((mft, name));
            }
        }
    }

    Some(
        best.into_iter()
            .map(|(mft, name)| (name.name, mft))
            .collect(),
    )
}

/// Select the preferred (longest, most human-friendly) `$FILE_NAME` spelling
/// from a record's attribute list, per NTFS namespace preference
/// (Win32/Win32&DOS > POSIX > DOS).
pub fn get_best_filename(attrs: &[ParsedAttr]) -> Option<FileName> {
    let mut best: Option<FileName> = None;
    for attr in attrs {
        if attr.attr_type == ATTR_TYPE_FILENAME {
            if let Some(fn_) = FileName::parse(&attr.content) {
                match &best {
                    None => best = Some(fn_),
                    Some(cur) => {
                        let replace = (fn_.preferred_namespace() && !cur.preferred_namespace())
                            || (cur.namespace == 2 && fn_.namespace != 2);
                        if replace {
                            best = Some(fn_);
                        }
                    }
                }
            }
        }
    }
    best
}

/// Read the resident `$STANDARD_INFORMATION` attribute, if present.
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
