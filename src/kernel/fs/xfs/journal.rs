//! src/kernel/fs/xfs/journal.rs
//!
//! XFS log (journal) replay for v4 and v5 filesystems.
//!
//! Reads the internal log from `sb.log_start` for `sb.log_blocks` blocks,
//! walks log records, and replays buffer items (inode, data, dquot) so the
//! filesystem reaches a consistent state after an unclean unmount.

use alloc::sync::Arc;
use alloc::vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::{be32, be64, Superblock};

// ─── XFS log constants ──────────────────────────────────────────────────────

/// Log record header magic (v2/v5).
const XLOG_HEADER_MAGIC: u32 = 0xFE03_AD0B;
/// XFS log item type — buffer (metadata block).
const XLOG_TYPE_BUFFER: u8 = 1;
/// XFS log item type — inode (also replayed as buffer).
#[allow(dead_code)]
const XLOG_TYPE_INODE: u8 = 2;
/// XFS log item type — dquot (also replayed as buffer).
#[allow(dead_code)]
const XLOG_TYPE_DQUOT: u8 = 3;
/// XFS log item type — trans header (skip).
#[allow(dead_code)]
const XLOG_TYPE_TRANS_HDR: u8 = 8;

/// Buffer log item format type magic.
const XFS_LI_BUF: u16 = 0x3132;

/// Header size of a v2 log record (256 bytes).
const XLOG_REC_HDR_SIZE: usize = 256;
/// Size of a v2 operation header (16 bytes).
const XLOG_OP_HDR_SIZE: usize = 16;
/// Size of the buffer log format structure (32 bytes for v2).
const XFS_BLF_HDR_SIZE: usize = 32;

// ─── Parsing helpers ───────────────────────────────────────────────────────

/// Log record magic at offset 0 (u32 BE).
fn xlog_magic(buf: &[u8], off: usize) -> u32 {
    be32(buf, off)
}
/// Log record cycle number at offset 24 (u64 BE).
fn xlog_cycle(buf: &[u8], off: usize) -> u64 {
    be64(buf, off + 24)
}
/// Number of log operations at offset 16 (u32 BE).
fn xlog_num_ops(buf: &[u8], off: usize) -> u32 {
    be32(buf, off + 16)
}
/// Operation data length at op header offset 0 (u16 BE).
fn xop_length(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}
/// Operation type at op header offset 3 (u8).
fn xop_type(buf: &[u8], off: usize) -> u8 {
    buf[off + 3]
}
/// Buffer format: target block number at offset 4 (u64 BE).
fn blf_blkno(buf: &[u8], off: usize) -> u64 {
    be64(buf, off + 4)
}
/// Buffer format: flags at offset 16 (u16 BE).
fn blf_flags(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off + 16], buf[off + 17]])
}
/// Buffer format: bitmap size in u32 words at offset 18 (u16 BE).
fn blf_map_size(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off + 18], buf[off + 19]])
}
/// Buffer format: total entry size at offset 2 (u16 BE).
#[allow(dead_code)]
fn blf_total_size(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off + 2], buf[off + 3]])
}

// ─── Public interface ───────────────────────────────────────────────────────

/// Replay the XFS journal if it is dirty.
///
/// Scans the log area, finds valid log records, and replays buffer items to
/// bring the filesystem metadata up to date.  Returns `Ok(())` even if no
/// log records are found (clean journal).
pub(crate) fn replay_xfs_journal(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
) -> Result<(), Error> {
    // Bail out if the device is read-only — we cannot replay.
    if device.is_read_only() {
        crate::println!("[XFS] Journal replay skipped: device is read-only");
        return Ok(());
    }

    let bs = device.block_size() as u64;
    let log_start_byte = sb.log_start * bs;
    let log_byte_len = sb.log_blocks as u64 * bs;

    if log_byte_len < XLOG_REC_HDR_SIZE as u64 {
        return Ok(());
    }

    let log_bytes = log_byte_len as usize;
    let mut log_buf = vec![0u8; log_bytes];
    read_device(device, log_start_byte, &mut log_buf)?;

    // Phase 1: find the highest cycle number (active region of the circular log).
    let step = bs.max(512) as usize;
    // Round step up to a multiple of the minimum header size for proper alignment.
    let step = step.div_ceil(XLOG_REC_HDR_SIZE) * XLOG_REC_HDR_SIZE;

    let mut best_cycle: u64 = 0;
    let mut best_offset: usize = 0;
    let mut pos = 0usize;
    while pos + XLOG_REC_HDR_SIZE <= log_bytes {
        if xlog_magic(&log_buf, pos) == XLOG_HEADER_MAGIC {
            let cycle = xlog_cycle(&log_buf, pos);
            if cycle >= best_cycle {
                best_cycle = cycle;
                best_offset = pos;
            }
        }
        pos = pos.saturating_add(step);
    }

    if best_cycle == 0 {
        return Ok(());
    }

    // Phase 2: walk log records forward from best_offset, replaying ops.
    pos = best_offset;
    let max_iter = (sb.log_blocks as usize).clamp(256, 4096);

    for _ in 0..max_iter {
        if pos + XLOG_REC_HDR_SIZE > log_bytes {
            break;
        }
        if xlog_magic(&log_buf, pos) != XLOG_HEADER_MAGIC {
            break;
        }

        let num_ops = xlog_num_ops(&log_buf, pos) as usize;
        if num_ops == 0 || num_ops > 4096 {
            // Advance past this header and continue.
            pos = (pos + step).min(log_bytes.saturating_sub(XLOG_REC_HDR_SIZE));
            continue;
        }

        // Data starts at the next step-aligned offset after the header block.
        let ops_start = (pos + step).div_ceil(step) * step;
        if ops_start + XLOG_OP_HDR_SIZE > log_bytes {
            break;
        }

        let mut op_pos = ops_start;
        let mut ops_remaining = num_ops;

        while ops_remaining > 0 && op_pos + XLOG_OP_HDR_SIZE <= log_bytes {
            let olen = xop_length(&log_buf, op_pos) as usize;
            let otype = xop_type(&log_buf, op_pos);
            let data_start = op_pos + XLOG_OP_HDR_SIZE;

            match otype {
                XLOG_TYPE_BUFFER | XLOG_TYPE_INODE | XLOG_TYPE_DQUOT
                    if olen >= XFS_BLF_HDR_SIZE
                        && data_start + XFS_BLF_HDR_SIZE <= log_buf.len() =>
                {
                    replay_buffer_item(device, &log_buf, data_start, olen)?;
                }
                _ => {}
            }

            let aligned = (olen + 3) & !3;
            op_pos += XLOG_OP_HDR_SIZE + aligned;
            ops_remaining -= 1;
        }

        // Advance to the next record boundary.
        let next = op_pos.div_ceil(step) * step;
        if next <= pos {
            break;
        }
        pos = next;
    }

    Ok(())
}

/// Replay a single buffer item: write the logged block data back to the
/// filesystem at the target block number.
fn replay_buffer_item(
    device: &Arc<dyn BlockDevice>,
    log_buf: &[u8],
    data_start: usize,
    data_len: usize,
) -> Result<(), Error> {
    // Validate the buffer log item format type: every replayable buffer
    // item begins with the XFS_LI_BUF magic.  Anything else means we've
    // misaligned the op stream — skip rather than corrupting blocks.
    if data_start + 2 <= log_buf.len()
        && u16::from_be_bytes([log_buf[data_start], log_buf[data_start + 1]]) != XFS_LI_BUF
    {
        return Ok(());
    }

    let blkno = blf_blkno(log_buf, data_start);
    let bflags = blf_flags(log_buf, data_start);
    let map_size = blf_map_size(log_buf, data_start) as usize;

    // Reject obviously invalid block numbers.
    if blkno == 0 {
        return Ok(());
    }

    // If BLF_CANCEL (0x10) flag is set, this buffer was cancelled; skip.
    if bflags & 0x10 != 0 {
        return Ok(());
    }

    // After the header and bitmap, the full block data follows.
    let bitmap_bytes = map_size * 4;
    let hdr_plus_bitmap = XFS_BLF_HDR_SIZE + bitmap_bytes;

    let block_data_start = data_start + hdr_plus_bitmap;
    let dev_bs = device.block_size();
    if block_data_start + dev_bs > data_start + data_len {
        return Ok(());
    }
    if block_data_start + dev_bs > log_buf.len() {
        return Ok(());
    }

    let block_data = &log_buf[block_data_start..block_data_start + dev_bs];
    let byte_offset = blkno * device.block_size() as u64;
    write_device(device, byte_offset, block_data)
}

// ─── Device I/O ─────────────────────────────────────────────────────────────

/// Read bytes from the device at a byte-aligned offset.
fn read_device(
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

/// Write bytes to the device at a byte-aligned offset (read-modify-write for
/// partial sector boundaries).
fn write_device(device: &Arc<dyn BlockDevice>, byte_offset: u64, data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }
    let dev_bs = device.block_size() as u64;
    let start_lba = byte_offset / dev_bs;
    let start_off = (byte_offset % dev_bs) as usize;
    let end_byte = byte_offset + data.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);
    let total = (end_lba - start_lba) as usize;

    let mut scratch = vec![0u8; total * dev_bs as usize];
    for i in 0..total {
        let lba = start_lba + i as u64;
        let out = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, out)?;
    }

    scratch[start_off..start_off + data.len()].copy_from_slice(data);

    for i in 0..total {
        let lba = start_lba + i as u64;
        let chunk = &scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.write_blocks(lba, chunk)?;
    }

    Ok(())
}
