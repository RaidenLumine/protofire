//! src/fs/ntfs/fs.rs
//!
//! NTFS low-level operations: cluster I/O, MFT record reading, directory
//! traversal, file reads.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::block::BlockDevice;
use crate::Error;

use super::types::size_from_exponent;
use super::types::BootSector;
use super::types::DataRun;
use super::types::FileName;
use super::types::MftRecordHeader;
use super::types::ParsedAttr;
use super::types::StandardInfoAttr;
use super::types::ATTR_TYPE_DATA;
use super::types::ATTR_TYPE_FILENAME;
use super::types::ATTR_TYPE_STANDARD_INFO;
use super::types::BLOCK_SIZE;

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
    /// The MFT's own data runs, once something has asked for a record.
    ///
    /// The MFT is a file like any other: its `$DATA` says where its records
    /// are, and record 0 is the one whose address the boot sector names — so
    /// reading record 0 is what answers where the rest of them are.  A stride
    /// from the first cluster is right only for a volume whose MFT never grew.
    pub mft_runs: Option<Vec<DataRun>>,
    /// How long the MFT's own `$DATA` says it is.
    pub mft_data_size: u64,
}

impl NtfsInfo {
    pub fn new(bs: BootSector) -> Self {
        let cluster_size = bs.bytes_per_sector as u32 * bs.sectors_per_cluster as u32;
        let mft_record_size = size_from_exponent(bs.mft_record_exponent, cluster_size);
        let index_block_size = size_from_exponent(bs.index_buffer_exponent, cluster_size);
        Self {
            bs,
            cluster_size,
            mft_record_size,
            index_block_size,
            mft_runs: None,
            mft_data_size: 0,
        }
    }

    /// The MFT's own data runs, resolved once.
    pub fn resolve_mft_runs(
        &mut self,
        device: &Arc<dyn BlockDevice>,
    ) -> Result<Vec<DataRun>, Error> {
        if let Some(runs) = &self.mft_runs {
            return Ok(runs.clone());
        }

        let record_size = self.mft_record_size as usize;
        let mut record = alloc::vec![0u8; record_size];
        read_device_bytes(
            device,
            self.bs.mft_lcn * self.cluster_size as u64,
            &mut record,
        )?;

        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.usa_count > 0 {
            apply_usa_fixup(
                &mut record,
                header.usa_offset as usize,
                header.usa_count as usize,
                self.bs.bytes_per_sector as usize,
            );
        }
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::InvalidArgument)?;

        self.mft_data_size = data.data_size as u64;
        self.mft_runs = Some(data.data_runs.clone());
        Ok(data.data_runs.clone())
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

/// Write a byte range by following data runs — the mirror of
/// [`read_from_runs`].
///
/// A sparse run names no cluster, so a write that would land in one has
/// nowhere to go: this refuses rather than reporting bytes it did not store.
pub fn write_to_runs(
    device: &Arc<dyn BlockDevice>,
    info: &NtfsInfo,
    runs: &[DataRun],
    offset: u64,
    buf: &[u8],
) -> Result<usize, Error> {
    if buf.is_empty() {
        return Ok(0);
    }

    let cluster_size = info.cluster_size as u64;
    let end = offset + buf.len() as u64;
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
        if run.lcn < 0 {
            return Err(Error::Unsupported);
        }

        let phys_off = run.lcn as u64 * cluster_size + (seg_start - cluster_start);
        let source = (seg_start - offset) as usize;
        write_device_bytes(device, phys_off, &buf[source..source + seg_len])?;

        total += seg_len;
        cluster_start = run_end;
    }
    Ok(total)
}

/// Where a byte offset inside a run list lands on the volume.
///
/// The inverse of what [`read_from_runs`] does, for a caller that has to say
/// where a field it is about to change *lives*: a record's own position on the
/// volume is what its number and the MFT's runs give.
pub fn byte_offset_in_runs(runs: &[DataRun], cluster_size: u32, offset: u64) -> Option<u64> {
    let cluster_size = cluster_size as u64;
    let mut cluster_start: u64 = 0;
    for run in runs {
        let run_end = cluster_start + run.cluster_count * cluster_size;
        if offset < run_end {
            if run.lcn < 0 {
                return None;
            }
            return Some(run.lcn as u64 * cluster_size + (offset - cluster_start));
        }
        cluster_start = run_end;
    }
    None
}

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
        // An attribute's name and its instance number are how an
        // `$ATTRIBUTE_LIST` names it in another record.
        let name_len = buf[offset + 9] as usize;
        let name_offset = u16::from_le_bytes([buf[offset + 10], buf[offset + 11]]) as usize;
        let name = if name_len > 0 && offset + name_offset + name_len * 2 <= buf.len() {
            let bytes = &buf[offset + name_offset..offset + name_offset + name_len * 2];
            Some(String::from_utf16_lossy(
                &bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<u16>>(),
            ))
        } else {
            None
        };
        let _flags = u16::from_le_bytes([buf[offset + 12], buf[offset + 13]]);
        let instance = u16::from_le_bytes([buf[offset + 14], buf[offset + 15]]);

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

        // A resident attribute's value begins where its own header says it
        // does, at `value_offset` from the attribute's start — which is 24 for
        // an unnamed one and further along when the attribute carries a name
        // (`$INDEX_ROOT` is named "$I30", so its value starts at 32).
        let mut content = Vec::new();
        if !non_resident {
            let value_offset = u16::from_le_bytes([buf[offset + 20], buf[offset + 21]]) as usize;
            let start = offset + value_offset;
            if start + content_size as usize <= buf.len() {
                content.extend_from_slice(&buf[start..start + content_size as usize]);
            }
        }

        let data_runs_offset = if non_resident {
            // Non-resident: the data-runs array begins at header +32.
            let runs_off = u16::from_le_bytes([buf[offset + 32], buf[offset + 33]]) as usize;
            // The field is an offset from the *attribute's* own start, not
            // from the buffer the attribute sits in: for the first attribute
            // of a record the two coincide, and for every later one they do
            // not.
            let at = offset + runs_off;
            if runs_off > 0 && at + 2 <= buf.len() {
                Some(at)
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
            instance,
            name,
            holder: u64::MAX,
            offset,
            value_offset: u16::from_le_bytes([buf[offset + 20], buf[offset + 21]]) as usize,
            attr_len: attr_len as usize,
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

/// Encode data runs, the way [`parse_data_runs`] reads them.
///
/// A run's header byte says how many bytes its length and its *delta* take,
/// and the delta is signed and always measured from the run before it — so a
/// list of runs has one spelling and a reader accumulates the same addresses
/// back.  A zero header ends the list.
pub fn encode_runs(runs: &[DataRun]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous: i64 = 0;
    for run in runs {
        if run.cluster_count == 0 {
            continue;
        }

        let mut length = Vec::new();
        let mut count = run.cluster_count;
        while count > 0 {
            length.push((count & 0xff) as u8);
            count >>= 8;
        }

        // A sparse run names no cluster, so it has no delta to write and does
        // not move the place the next run measures from.
        let mut offset = Vec::new();
        if run.lcn >= 0 {
            let delta = run.lcn - previous;
            previous = run.lcn;
            let mut value = delta;
            loop {
                offset.push((value & 0xff) as u8);
                value >>= 8;
                let done = (delta >= 0 && value == 0) || (delta < 0 && value == -1);
                if done {
                    break;
                }
            }
        }

        out.push(((offset.len() as u8) << 4) | length.len() as u8);
        out.extend_from_slice(&length);
        out.extend_from_slice(&offset);
    }
    out.push(0);
    out
}

/// Put the update sequence array back, which is what makes a rewritten record
/// one a reader can unpack.
///
/// [`apply_usa_fixup`] is the other direction.  The two are not the same task:
/// a reader unpacks the record it read, and a writer that rewrites the
/// record's bytes — a relocation inside it — has to pack them again, with the
/// sequence at every sector's end and the bytes it replaced in the array.
pub fn pack_usa(buf: &mut [u8], usa_offset: usize, usa_count: usize, sector_size: usize) {
    if sector_size == 0 || usa_count == 0 || usa_offset + usa_count * 2 > buf.len() {
        return;
    }
    let sequence = u16::from_le_bytes([buf[usa_offset], buf[usa_offset + 1]]);
    for i in 1..usa_count {
        let sector_end = i * sector_size;
        if sector_end >= 2 && sector_end <= buf.len() && usa_offset + i * 2 + 1 < buf.len() {
            let low = buf[sector_end - 2];
            let high = buf[sector_end - 1];
            buf[usa_offset + i * 2] = low;
            buf[usa_offset + i * 2 + 1] = high;
            buf[sector_end - 2..sector_end].copy_from_slice(&sequence.to_le_bytes());
        }
    }
}

/// Undo an update sequence array, so the bytes a record's sectors end with are
/// the ones they held before the write that put the sequence number there.
///
/// The sector size is the *volume's*, from the boot sector, not the device's:
/// an NTFS record's sectors are `bytes_per_sector` bytes, and a volume whose
/// sectors are not 512 would otherwise have its records unpacked at the wrong
/// offsets.
pub fn apply_usa_fixup(buf: &mut [u8], usa_offset: usize, usa_count: usize, sector_size: usize) {
    if sector_size == 0 || usa_count == 0 || usa_offset + usa_count * 2 > buf.len() {
        return;
    }
    for i in 1..usa_count {
        let sector_end = i * sector_size;
        if sector_end >= 2 && sector_end <= buf.len() && usa_offset + i * 2 + 1 < buf.len() {
            let low = buf[usa_offset + i * 2];
            let high = buf[usa_offset + i * 2 + 1];
            buf[sector_end - 2] = low;
            buf[sector_end - 1] = high;
        }
    }
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

/// One entry of an `$ATTRIBUTE_LIST`: an attribute, and the record that holds
/// it.
///
/// The entry's header is 26 bytes — a type, the entry's own length, the name's
/// length and where in the entry it begins, the lowest virtual cluster number
/// this part of the attribute covers, the record that holds the part, and the
/// attribute's instance number — and the name follows it.  An entry is padded
/// to eight bytes, and the length is what says so; the list is a run of them
/// with no count in front.
pub struct AttributeListEntry {
    pub attr_type: u32,
    pub name: Option<String>,
    pub instance: u16,
    /// The first virtual cluster number this entry's part of the attribute
    /// covers: a non-resident attribute whose mapping pairs did not fit one
    /// record is *split*, and the parts are put back together in this order.
    pub lowest_vcn: u64,
    /// The record that holds this part, and its sequence number.
    pub holder: u64,
    pub sequence: u16,
}

/// Write one `$ATTRIBUTE_LIST` entry: an attribute, and the record that holds
/// it.
///
/// The entry is 26 bytes and padded to eight — the type, the entry's own
/// length, the name's length and where it begins, the lowest virtual cluster
/// number this part of the attribute covers, the record that holds it and the
/// attribute's instance number — and the name follows the header.
pub fn list_entry(
    attr_type: u32,
    name: &str,
    instance: u16,
    lowest_vcn: u64,
    holder: u64,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut entry = vec![0u8; 26];
    put_u32_le(&mut entry, 0, attr_type);
    entry[6] = (name_bytes.len() / 2) as u8;
    entry[7] = 26; // where a name begins
    put_u64_le(&mut entry, 8, lowest_vcn);
    put_u64_le(&mut entry, 16, holder);
    put_u16_le(&mut entry, 24, instance);
    entry.extend_from_slice(&name_bytes);
    let length = entry.len().div_ceil(8) * 8;
    entry.resize(length, 0);
    put_u16_le(&mut entry, 4, length as u16);
    entry
}

/// Read the entries of an `$ATTRIBUTE_LIST` value.
pub fn parse_attribute_list(buf: &[u8]) -> Vec<AttributeListEntry> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at + 26 <= buf.len() {
        let attr_type = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        let length = u16::from_le_bytes([buf[at + 4], buf[at + 5]]) as usize;
        if length < 26 || at + length > buf.len() {
            break;
        }
        let name_len = buf[at + 6] as usize;
        let name_offset = buf[at + 7] as usize;
        let name = if name_len > 0 && at + name_offset + name_len * 2 <= buf.len() {
            let bytes = &buf[at + name_offset..at + name_offset + name_len * 2];
            Some(String::from_utf16_lossy(
                &bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<u16>>(),
            ))
        } else {
            None
        };
        let reference = u64::from_le_bytes([
            buf[at + 16],
            buf[at + 17],
            buf[at + 18],
            buf[at + 19],
            buf[at + 20],
            buf[at + 21],
            buf[at + 22],
            buf[at + 23],
        ]);
        entries.push(AttributeListEntry {
            attr_type,
            name,
            instance: u16::from_le_bytes([buf[at + 24], buf[at + 25]]),
            lowest_vcn: u64::from_le_bytes([
                buf[at + 8],
                buf[at + 9],
                buf[at + 10],
                buf[at + 11],
                buf[at + 12],
                buf[at + 13],
                buf[at + 14],
                buf[at + 15],
            ]),
            holder: reference & 0x0000_FFFF_FFFF_FFFF,
            sequence: (reference >> 48) as u16,
        });
        at += length;
    }
    entries
}

/// One entry of an index node.
pub struct IndexEntry {
    /// The record the entry's key names, or zero when the entry has no key.
    pub reference: u64,
    /// The child node this entry points at, when it does: the child's virtual
    /// cluster number is the entry's *last* eight bytes, which is where the
    /// format puts it, and an internal node's entry carries a key *and* a
    /// child.
    pub child: Option<u64>,
    /// The key the entry carries, when it has one: a leaf's name, or an
    /// internal node's separator.
    pub name: Option<FileName>,
    /// Where the entry begins in the buffer it was parsed from, and how long
    /// it is: an entry is rebuilt from the bytes it already has, so a writer
    /// has to be able to name them.
    pub offset: usize,
    pub length: usize,
}

/// One index node: its entries, and whether it has children at all.
pub struct IndexNode {
    pub entries: Vec<IndexEntry>,
    /// Whether the node has a child to descend into: its last entry then
    /// points at one.
    pub has_children: bool,
}

/// Read the entries of one index node.
///
/// `node` is where the node's own header begins inside `buf`, because the two
/// places a node lives put it at different offsets: an index *root*'s value
/// carries it after the root header (the indexed attribute's type, the
/// collation rule and the buffer size, 16 bytes), and an allocation block
/// carries it after `INDX`, the block's update sequence array and its virtual
/// cluster number — 24 bytes.
///
/// Each entry is a 16-byte header and the `$FILE_NAME` it is keyed by.  The
/// value beside the entry's length is the *length* of that name and not an
/// offset to it: they look alike only while a name is 16 bytes long, which is
/// how a reader can be wrong about every other one.
pub fn parse_index_node(buf: &[u8], node: usize) -> IndexNode {
    let mut entries = Vec::new();
    let mut has_children = false;

    if node + 16 > buf.len() {
        return IndexNode {
            entries,
            has_children,
        };
    }
    // The node header's fields are 32 bits wide — an entry offset, the length
    // the entries use, the length the node *has*, and the flags — and reading
    // them as 16 worked only while every value fit in one.
    let entries_offset =
        u32::from_le_bytes([buf[node], buf[node + 1], buf[node + 2], buf[node + 3]]) as usize;
    let length =
        u32::from_le_bytes([buf[node + 4], buf[node + 5], buf[node + 6], buf[node + 7]]) as usize;
    let flags = u32::from_le_bytes([
        buf[node + 12],
        buf[node + 13],
        buf[node + 14],
        buf[node + 15],
    ]);
    has_children = flags & 0x01 != 0;

    let mut at = node + entries_offset;
    let end = (node + length).min(buf.len());
    while at + 16 <= end {
        let entry_length = u16::from_le_bytes([buf[at + 8], buf[at + 9]]) as usize;
        if entry_length == 0 || at + entry_length > end {
            break;
        }
        let stream_length = u16::from_le_bytes([buf[at + 10], buf[at + 11]]) as usize;
        let flags = u32::from_le_bytes([buf[at + 12], buf[at + 13], buf[at + 14], buf[at + 15]]);
        let reference = u64::from_le_bytes([
            buf[at],
            buf[at + 1],
            buf[at + 2],
            buf[at + 3],
            buf[at + 4],
            buf[at + 5],
            buf[at + 6],
            buf[at + 7],
        ]);

        let points_at_a_node = flags & 0x01 != 0;
        // A child's virtual cluster number *ends* the entry, where the format
        // puts it — the padding a key of any length leaves sits between the
        // key and it — and the reference field is the *key's* record, which a
        // keyless last entry leaves zero.  An internal node's entry therefore
        // carries a key and a child, and that child holds the keys less than
        // the one the entry carries.
        let child = (points_at_a_node && entry_length >= 24).then(|| {
            u64::from_le_bytes([
                buf[at + entry_length - 8],
                buf[at + entry_length - 7],
                buf[at + entry_length - 6],
                buf[at + entry_length - 5],
                buf[at + entry_length - 4],
                buf[at + entry_length - 3],
                buf[at + entry_length - 2],
                buf[at + entry_length - 1],
            ])
        });
        // The upper sixteen bits of a reference are a sequence number.
        let reference = reference & 0x0000_FFFF_FFFF_FFFF;
        let name = if stream_length >= 66 && at + 16 + stream_length <= buf.len() {
            FileName::parse(&buf[at + 16..at + 16 + stream_length])
        } else {
            None
        };
        entries.push(IndexEntry {
            reference,
            child,
            name,
            offset: at,
            length: entry_length,
        });

        if flags & 0x02 != 0 {
            break;
        }
        at += entry_length;
    }

    IndexNode {
        entries,
        has_children,
    }
}

/// Rewrite an index node's entries in the buffer the node lives in.
///
/// `entries` are the entries as bytes, in the order they are to lie, with the
/// node's own terminator last — a node is a run of entries whose last one
/// says so, and an entry that is not there cannot be patched, so the whole
/// run is written.  `room` is how much of the buffer the node may use: an
/// index *root*'s node has the resident value's room, and a block's has
/// whatever follows its own header.
///
/// A node that does not have the room refuses rather than writing past it,
/// which is the direction a caller can act on: the alternative is a node
/// whose length field describes bytes it does not own.
pub fn write_index_entries(
    buf: &mut [u8],
    node: usize,
    room: usize,
    entries: &[Vec<u8>],
) -> Result<(), Error> {
    if node + 16 > buf.len() || node + room > buf.len() {
        return Err(Error::InvalidArgument);
    }
    let entries_offset =
        u32::from_le_bytes([buf[node], buf[node + 1], buf[node + 2], buf[node + 3]]) as usize;
    if entries_offset < 16 || entries_offset > room {
        return Err(Error::InvalidArgument);
    }

    let used = entries_offset
        + entries
            .iter()
            .try_fold(0usize, |total, entry| total.checked_add(entry.len()))
            .ok_or(Error::InvalidArgument)?;
    if used > room {
        return Err(Error::NoSpace);
    }

    let mut at = node + entries_offset;
    for entry in entries {
        buf[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    buf[at..node + room].fill(0);

    // The node says how much it uses and how much it has; the flags (whether
    // it has children) are the node's own and are left as they were.
    buf[node + 4..node + 8].copy_from_slice(&(used as u32).to_le_bytes());
    buf[node + 8..node + 12].copy_from_slice(&(room as u32).to_le_bytes());
    Ok(())
}

/// The bytes of a `$FILE_NAME` value, as an index entry's key.
///
/// The value is what a name is stored as wherever it is stored: a record's
/// own name and an index entry's key are the same structure, so the two are
/// built here once.  A new file's timestamps are zero — the volume has no
/// clock to ask — and its size is whatever the caller says.
pub fn file_name_value(parent: u64, name: &str, directory: bool, size: u64) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut value = vec![0u8; 66];
    put_u64_le(&mut value, 0, parent);
    put_u64_le(&mut value, 40, size); // allocated size
    put_u64_le(&mut value, 48, size); // real size
                                      // FILE_ATTRIBUTE_ARCHIVE, and the bit that says a directory is one: a real
                                      // volume writes both for a directory's name.
    put_u32_le(&mut value, 56, if directory { 0x1000_0020 } else { 0x20 });
    value[64] = (name_bytes.len() / 2) as u8;
    value[65] = 3; // Win32 & DOS
    value.extend_from_slice(&name_bytes);
    value
}

/// The value a directory's `$INDEX_ROOT` holds while it has no children.
///
/// It is the `$FILE_NAME` index's own header — the attribute it indexes, the
/// collation rule, the size of a block — and then a node with nothing but its
/// terminator.  A directory's entries are its *children*: the "." and ".." a
/// listing shows are the reader's own, and a volume may carry a "." of its own
/// (the one `mkntfs` makes does), which is why a reader skips one rather than
/// expecting it.
pub fn empty_index_root(index_block_size: u32, cluster_size: u32) -> Vec<u8> {
    let mut value = vec![0u8; 16];
    put_u32_le(&mut value, 0, ATTR_TYPE_FILENAME);
    put_u32_le(&mut value, 4, 1); // COLLATION_FILENAME
    put_u32_le(&mut value, 8, index_block_size);
    value[12] = (index_block_size / cluster_size.max(1)) as u8;

    let node = {
        let mut node = vec![0u8; 16];
        put_u32_le(&mut node, 0, 16); // where the entries begin
        put_u32_le(&mut node, 4, 32); // what they use: the terminator
        put_u32_le(&mut node, 8, 32); // and what the node has
        put_u32_le(&mut node, 12, 0); // no children
        node
    };
    value.extend_from_slice(&node);
    value.extend_from_slice(&index_terminator());
    value
}

/// The entry an index node ends with: no name, and the last-entry flag.
pub fn index_terminator() -> Vec<u8> {
    let mut terminator = vec![0u8; 16];
    put_u16_le(&mut terminator, 8, 16); // its own length
    put_u32_le(&mut terminator, 12, 0x0000_0002); // the last entry
    terminator
}

/// One index entry: its sixteen-byte header and the name it is keyed by.
///
/// `reference` is a record number with its sequence number in the top sixteen
/// bits, which is what makes a removed record's number unusable: the entry is
/// looked up by number *and* sequence.
pub fn index_entry(name: &str, reference: u64, parent: u64, directory: bool, size: u64) -> Vec<u8> {
    let value = file_name_value(parent, name, directory, size);
    let mut entry = vec![0u8; 16];
    put_u64_le(&mut entry, 0, reference);
    // The field beside the entry's length is the *name's* length, not an
    // offset to it.
    put_u16_le(&mut entry, 10, value.len() as u16);
    entry.extend_from_slice(&value);
    let length = entry.len().div_ceil(8) * 8;
    entry.resize(length, 0);
    put_u16_le(&mut entry, 8, length as u16);
    entry
}

/// The entry a node ends with when it has a child: no name, the last-entry
/// flag, and the child block's virtual cluster number — which is the entry's
/// *last* eight bytes, where the format puts it, and not the reference field
/// a name entry keeps its record in: a real volume's pointer entries leave
/// that zero.
pub fn index_child_pointer(vcn: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 24];
    put_u16_le(&mut entry, 8, 24); // its own length
    put_u32_le(&mut entry, 12, 0x0000_0003); // points at a node, and is last
    put_u64_le(&mut entry, 16, vcn);
    entry
}

/// A non-resident attribute, named or not, whose value lies in runs.
///
/// This is what a `$DATA` with runs, an `$INDEX_ALLOCATION`, or a list that
/// is a file of its own is: a sixty-four-byte header, the name between it and
/// the mapping pairs, and the three sizes that say how much of the value is
/// spoken for.  The last virtual cluster number is what the runs add up to,
/// less one — the number of the last cluster the attribute covers.
pub fn non_resident_attribute(
    attr_type: u32,
    name: &str,
    instance: u16,
    runs: &[DataRun],
    allocated: u64,
    data_size: u64,
    initialized: u64,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let name_offset = 64usize;
    let runs_offset = name_offset + name_bytes.len();
    let mut attr = vec![0u8; runs_offset];
    put_u32_le(&mut attr, 0, attr_type);
    attr[8] = 1; // non-resident
    attr[9] = (name_bytes.len() / 2) as u8;
    put_u16_le(&mut attr, 10, name_offset as u16);
    put_u16_le(&mut attr, 14, instance);
    let clusters: u64 = runs.iter().map(|run| run.cluster_count).sum();
    put_u64_le(&mut attr, 24, clusters.saturating_sub(1)); // last VCN
    put_u16_le(&mut attr, 32, runs_offset as u16);
    put_u64_le(&mut attr, 40, allocated);
    put_u64_le(&mut attr, 48, data_size);
    put_u64_le(&mut attr, 56, initialized);
    // The name's own bytes, between the header and the mapping pairs: a
    // named attribute keeps them there, and a list entry that names it is
    // matched by them.
    attr[name_offset..runs_offset].copy_from_slice(&name_bytes);
    attr.extend_from_slice(&encode_runs(runs));
    let length = attr.len().div_ceil(8) * 8;
    attr.resize(length, 0);
    put_u32_le(&mut attr, 4, length as u32);
    attr
}

/// An index allocation block: `INDX`, its own update sequence array, the
/// virtual cluster number it sits at, and the entries the node inside it
/// holds.
///
/// The node begins twenty-four bytes in, and its entries begin forty bytes
/// into *the node* — the room the block's update sequence array takes, which
/// an entries offset of sixteen would write the entries into.  The node's
/// allocated size is what the block has past its own header, which is what
/// [`write_index_entries`] fills and what a real volume's blocks declare.
/// A set of entries that does not fit one block refuses (`NoSpace`): the
/// format's answer to a full block is a split, which is not built.
pub fn index_allocation_block(
    index_block_size: usize,
    sector_size: usize,
    vcn: u64,
    entries: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    if index_block_size <= 64 {
        return Err(Error::InvalidArgument);
    }
    let mut block = vec![0u8; index_block_size];
    block[..4].copy_from_slice(b"INDX");
    put_u16_le(&mut block, 4, 40); // where the update sequence array is
    let usa_count = 1 + index_block_size / sector_size.max(1);
    put_u16_le(&mut block, 6, usa_count as u16);
    put_u64_le(&mut block, 16, vcn);
    put_u32_le(&mut block, 24, 40); // where the node's entries begin
    write_index_entries(&mut block, 24, index_block_size - 24, entries)?;

    put_u16_le(&mut block, 40, 0x0401); // the update sequence's own number
    pack_usa(&mut block, 40, usa_count, sector_size);
    Ok(block)
}

/// A resident attribute, with the value its own header points at.
///
/// `instance` is the attribute's instance number, which a record's attributes
/// are each given; the reader this driver has does not consult it, and a real
/// NTFS does.
pub fn resident_attribute(attr_type: u32, name: &str, instance: u16, value: &[u8]) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let name_offset = 24;
    let value_offset = name_offset + name_bytes.len();

    let mut attr = vec![0u8; value_offset];
    attr[name_offset..name_offset + name_bytes.len()].copy_from_slice(&name_bytes);
    attr.extend_from_slice(value);
    put_u32_le(&mut attr, 0, attr_type);
    attr[8] = 0; // resident
    attr[9] = (name_bytes.len() / 2) as u8;
    put_u16_le(&mut attr, 10, name_offset as u16);
    put_u16_le(&mut attr, 14, instance);
    put_u16_le(&mut attr, 20, value_offset as u16);
    put_u32_le(&mut attr, 16, value.len() as u32);
    let length = attr.len().div_ceil(8) * 8;
    attr.resize(length, 0);
    put_u32_le(&mut attr, 4, length as u32);
    attr
}

/// A record, from the attributes it holds: its header, their end marker, and
/// its update sequence array packed.
///
/// This is what a *new* record is: the bytes a volume holds for one, with the
/// sizes the record's own content gives — which is the same shape the reader
/// takes apart, and the reason a record is written whole rather than field by
/// field.
pub fn build_record(
    record_size: usize,
    sector_size: usize,
    number: u64,
    sequence: u16,
    flags: u16,
    link_count: u16,
    attributes: &[Vec<u8>],
) -> Vec<u8> {
    let mut record = vec![0u8; record_size];
    record[..4].copy_from_slice(&super::types::MFT_MAGIC);
    put_u16_le(&mut record, 4, 48); // where the update sequence array is
    let usa_count = 1 + record_size / sector_size.max(1);
    put_u16_le(&mut record, 6, usa_count as u16);
    put_u16_le(&mut record, 16, sequence);
    put_u16_le(&mut record, 18, link_count);
    put_u16_le(&mut record, 20, 56); // where the attributes begin
    put_u16_le(&mut record, 22, flags);
    put_u32_le(&mut record, 28, record_size as u32);
    put_u32_le(&mut record, 44, number as u32);

    let mut at = 56;
    for attribute in attributes {
        record[at..at + attribute.len()].copy_from_slice(attribute);
        at += attribute.len();
    }
    put_u32_le(&mut record, at, 0xFFFF_FFFF); // the end marker
    put_u32_le(&mut record, 24, (at + 8) as u32); // bytes in use

    // The update sequence number is the record's own; the array holds the
    // bytes it replaced, which is what makes the sector ends a reader's to
    // check.
    let sequence_word = 0x0401u16;
    put_u16_le(&mut record, 48, sequence_word);
    for i in 1..usa_count {
        let sector_end = i * sector_size;
        if sector_end >= 2 && sector_end <= record.len() {
            let low = record[sector_end - 2];
            let high = record[sector_end - 1];
            put_u16_le(&mut record, 48 + i * 2, u16::from_le_bytes([low, high]));
            put_u16_le(&mut record, sector_end - 2, sequence_word);
        }
    }
    record
}

fn put_u16_le(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

// ── Byte I/O ──────────────────────────────────────────────────────────────

pub fn read_device_bytes(
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

/// Write a byte range to the device.
pub fn write_device_bytes(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }

    // A block at a time, each read before it is patched: a field is a few bytes
    // inside a block, and the bytes around them are not this write's to lose.
    // A block that cannot be read is an error rather than something to fill
    // with zeros, which would be the same loss by another route.
    let device_bs = device.block_size();
    let mut offset = byte_offset;
    let mut written = 0usize;
    while written < data.len() {
        let lba = offset / device_bs as u64;
        let within = (offset % device_bs as u64) as usize;
        let take = (device_bs - within).min(data.len() - written);

        let mut block = vec![0u8; device_bs];
        read_device_bytes(device, lba * device_bs as u64, &mut block)?;
        block[within..within + take].copy_from_slice(&data[written..written + take]);
        device.write_blocks(lba, &block)?;

        offset += take as u64;
        written += take;
    }
    Ok(())
}
