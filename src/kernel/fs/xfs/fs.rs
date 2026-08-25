//! src/kernel/fs/xfs/fs.rs
//!
//! XFS low-level operations: superblock, inode reading, directory, extents,
//! file I/O.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::btree::read_device_bytes;
use super::btree::{
    lookup_leaf_dir_by_hash, lookup_node_dir_by_hash, parse_leaf_dir, read_extent_btree,
    read_node_dir_entries, xfs_dir_hash,
};
use super::types::{
    parse_block_dir, parse_extents, parse_shortform_dir, DirEntry, Extent, InodeCore, JournalInfo,
    Superblock, XFS_DA_NODE_MAGIC, XFS_DINODE_FMT_BTREE, XFS_DINODE_FMT_EXTENTS,
    XFS_DINODE_FMT_LOCAL, XFS_DIR2_LEAF1_MAGIC, XFS_DIR2_LEAFN_MAGIC,
};
use crate::kernel::fs::vfs::XattrEntry;

// ── Superblock ──────────────────────────────────────────────────────────────

pub fn read_superblock(device: &Arc<dyn BlockDevice>) -> Result<Superblock, Error> {
    let mut buf = vec![0u8; 512];
    read_device_bytes(device, 0, &mut buf)?;
    Superblock::parse(&buf).ok_or(Error::InvalidArgument)
}

/// Inspect the superblock's journal fields and report whether the journal
/// needs replay (dirty unmount).  This is detection only — no recovery is
/// attempted on a read-only driver.
pub fn check_journal(sb: &Superblock) -> JournalInfo {
    let has_journal = sb.log_blocks > 0 && sb.log_start != 0;

    // Determine the log format version.
    // v4: features2 bits 16-19 encode the log version (0 = v1, 1 = v2).
    // v5: features_log encodes the version directly.
    let is_v5 = sb.versionnum & 0x0008 != 0; // V5 superblock has bit 3 set
    let log_version = if is_v5 {
        (sb.features_log & 0xF) as u8
    } else {
        ((sb.features2 >> 16) & 0xF) as u8
    };

    // Dirty check: v4 log version 2 has a clean-unmount flag in
    // features_log bit 0.  v5 log checks features_log & 0x2.
    let is_dirty = if !has_journal {
        false
    } else if is_v5 {
        // v5: check if XFS_SB_FEAT_INCOMPAT_LOG is set and log is dirty
        sb.features_incompat & 1 != 0 && sb.features_log & 0x2 == 0
    } else {
        // v4 log v2: features_log bit 0 set = clean unmount
        log_version >= 2 && sb.features_log & 0x1 == 0
    };

    JournalInfo {
        has_journal,
        is_dirty,
        log_start: sb.log_start,
        log_blocks: sb.log_blocks,
        log_version,
    }
}

// ── Inode I/O ───────────────────────────────────────────────────────────────

/// Compute the byte offset of an inode on disk.
pub fn inode_addr(sb: &Superblock, ino: u64) -> (u64, u32) {
    let ag = ino >> 32; // upper bits = AG number
    let rel = ino & 0xFFFF_FFFF; // lower bits = inode within AG
    let ag_start = ag * sb.blocks_per_ag as u64;
    if sb.inode_size == 0 || sb.block_size == 0 {
        return (0, rel as u32);
    }
    let inodes_per_block = sb.block_size as u64 / sb.inode_size as u64;
    if inodes_per_block == 0 {
        return (0, rel as u32);
    }
    let block_off = ag_start + rel / inodes_per_block;
    let offset_in_block = (rel % inodes_per_block) * sb.inode_size as u64;
    let byte_off = block_off * sb.block_size as u64 + offset_in_block;
    (byte_off, rel as u32)
}

/// Read the raw bytes of an inode from disk.
pub fn read_inode_buf(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    ino: u64,
) -> Result<(InodeCore, Vec<u8>), Error> {
    let (byte_off, _rel) = inode_addr(sb, ino);
    let inode_size = sb.inode_size as usize;
    let mut buf = vec![0u8; inode_size];
    read_device_bytes(device, byte_off, &mut buf)?;
    let core = InodeCore::parse(&buf, inode_size).ok_or(Error::InvalidArgument)?;
    Ok((core, buf))
}

// ── Directory reading ───────────────────────────────────────────────────────

/// Read directory entries from an inode (supports shortform and block formats).
pub fn read_dir_from_inode(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
) -> Result<Vec<DirEntry>, Error> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_LOCAL => Ok(parse_shortform_dir(buf, data_fork_off)),
        XFS_DINODE_FMT_EXTENTS => {
            let extents = parse_extents(buf, data_fork_off, core.num_extents);
            read_block_dir_entries(device, sb, &extents, core.size)
        }
        XFS_DINODE_FMT_BTREE => {
            let extents = read_extent_btree(device, sb, buf, data_fork_off)?;
            read_block_dir_entries(device, sb, &extents, core.size)
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Public wrapper used by read_dir.
pub fn read_directory(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    ino: u64,
) -> Result<Vec<DirEntry>, Error> {
    let (core, buf) = read_inode_buf(device, sb, ino)?;
    read_dir_from_inode(device, sb, &core, &buf)
}

/// Look up a single directory entry by name using the hash index.
///
/// When the directory uses hash-indexed (leaf or node) format, this
/// computes the name hash and binary-searches the B+tree / leaf entries
/// to read only the matched data entry instead of the entire directory.
///
/// For shortform (LOCAL) directories the list is small enough that a
/// linear scan is equally fast; for block-format directories the hash
/// index isn't available so we fall back to a full read.
///
/// Returns `Ok(Some(ino))` on match, `Ok(None)` if not found.
pub(crate) fn lookup_dir_entry_by_name(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
    name: &[u8],
) -> Result<Option<u64>, Error> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_LOCAL => {
            let entries = parse_shortform_dir(buf, data_fork_off);
            Ok(entries.iter().find(|e| e.name == name).map(|e| e.inode))
        }
        XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE => {
            let extents = match core.format {
                XFS_DINODE_FMT_EXTENTS => parse_extents(buf, data_fork_off, core.num_extents),
                XFS_DINODE_FMT_BTREE => read_extent_btree(device, sb, buf, data_fork_off)?,
                _ => unreachable!(),
            };

            if extents.is_empty() {
                return Ok(None);
            }

            let target_hash = xfs_dir_hash(name);

            // Check the first block's magic to decide dispatch.
            if let Some(first_ext) = extents.first() {
                if first_ext.block_count > 0 {
                    let bs = sb.block_size as u64;
                    let first_block = first_ext.start_block * bs;
                    let mut first_buf = vec![0u8; bs as usize];
                    read_device_bytes(device, first_block, &mut first_buf)?;
                    if first_buf.len() >= 10 {
                        let magic = u16::from_be_bytes([first_buf[8], first_buf[9]]);
                        if magic == XFS_DA_NODE_MAGIC {
                            return lookup_node_dir_by_hash(
                                device,
                                sb,
                                &extents,
                                target_hash,
                                name,
                            );
                        }
                        if magic == XFS_DIR2_LEAF1_MAGIC || magic == XFS_DIR2_LEAFN_MAGIC {
                            return lookup_leaf_dir_by_hash(
                                device,
                                sb,
                                &extents,
                                target_hash,
                                name,
                            );
                        }
                    }
                }
            }

            // Block-format (no hash index) — fall back to full read.
            let entries = read_block_dir_entries(device, sb, &extents, core.size)?;
            Ok(entries.iter().find(|e| e.name == name).map(|e| e.inode))
        }
        _ => Ok(None),
    }
}

/// Read directory entries from extent-mapped directory blocks.
///
/// Dispatches to the appropriate parser based on the first block's magic:
/// - [`XFS_DA_NODE_MAGIC`] → node-format B+tree traversal
/// - [`XFS_DIR2_LEAF1_MAGIC`] / [`XFS_DIR2_LEAFN_MAGIC`] → leaf-format
/// - otherwise → block-format
fn read_block_dir_entries(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    dir_size: u64,
) -> Result<Vec<DirEntry>, Error> {
    // Check the first block to determine the directory format.
    // Node-format directories have a root node block (XFS_DA_NODE_MAGIC)
    // as the first block.  Their tree structure requires different traversal.
    if let Some(first_ext) = extents.first() {
        if first_ext.block_count > 0 {
            let bs = sb.block_size as u64;
            let first_block = first_ext.start_block * bs;
            let mut first_buf = vec![0u8; bs as usize];
            read_device_bytes(device, first_block, &mut first_buf)?;
            if first_buf.len() >= 10 {
                let magic = u16::from_be_bytes([first_buf[8], first_buf[9]]);
                if magic == XFS_DA_NODE_MAGIC {
                    return read_node_dir_entries(device, sb, extents);
                }
            }
        }
    }

    let mut entries = Vec::new();
    let mut bytes_read = 0u64;

    for ext in extents {
        if bytes_read >= dir_size {
            break;
        }
        let blocks = ext.block_count;
        let bs = sb.block_size as u64;
        for i in 0..blocks {
            if bytes_read >= dir_size {
                break;
            }
            let block_addr = (ext.start_block + i) * bs;
            let mut block_buf = vec![0u8; bs as usize];
            read_device_bytes(device, block_addr, &mut block_buf)?;

            // Check block magic for leaf-format directory (hash-indexed).
            // Magic is a u16 at offset 8 in xfs_da_blkinfo_t.
            if block_buf.len() >= 16 {
                let da_magic = u16::from_be_bytes([block_buf[8], block_buf[9]]);
                if da_magic == XFS_DIR2_LEAF1_MAGIC || da_magic == XFS_DIR2_LEAFN_MAGIC {
                    entries.extend(parse_leaf_dir(&block_buf));
                    bytes_read += bs;
                    continue;
                }
            }
            entries.extend(parse_block_dir(&block_buf));
            bytes_read += bs;
        }
    }
    Ok(entries)
}

// ── Extent / File reading ──────────────────────────────────────────────────

/// Get extent list for a file inode.
pub fn get_extents(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
) -> Result<Vec<Extent>, Error> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_EXTENTS => Ok(parse_extents(buf, data_fork_off, core.num_extents)),
        XFS_DINODE_FMT_BTREE => {
            // B+tree extent format: root is inline in the inode data fork.
            super::btree::read_extent_btree(device, sb, buf, data_fork_off)
        }
        _ => Ok(Vec::new()),
    }
}

/// Read file data from extent list.
pub fn read_file(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    file_size: u64,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, Error> {
    if offset >= file_size || buffer.is_empty() {
        return Ok(0);
    }

    let bs = sb.block_size as u64;
    let end_off = (offset + buffer.len() as u64).min(file_size);
    let mut total = 0usize;

    for ext in extents {
        let ext_start = ext.start_offset;
        let ext_end = ext_start + ext.block_count * bs;

        if offset >= ext_end || end_off <= ext_start {
            continue;
        }

        let seg_start = offset.max(ext_start);
        let seg_end = end_off.min(ext_end);
        let seg_len = (seg_end - seg_start) as usize;
        let phys = ext.start_block * bs + (seg_start - ext_start);
        let dest_off = (seg_start - offset) as usize;

        read_device_bytes(device, phys, &mut buffer[dest_off..dest_off + seg_len])?;
        total += seg_len;
    }

    Ok(total)
}

/// Read inline file data (for local format inodes).
pub fn read_inline_file(
    core: &InodeCore,
    buf: &[u8],
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, Error> {
    // For inline files, the inode version doesn't matter — the data always
    // starts right after the inode core at byte 100 (v4) or 176 (v5).
    // However, the caller (XfsVNode::read) doesn't have access to the
    // superblock, so we use core.is_v5 as a heuristic.  Inline files are
    // uncommon under v5, but this keeps the code correct.
    let data_offset = if core.is_v5 { 176usize } else { 100usize };
    if buf.len() < data_offset {
        return Err(Error::InvalidArgument);
    }
    let inline_data = &buf[data_offset..];
    let file_size = core.size as usize;
    let off = offset as usize;
    if off >= file_size || buffer.is_empty() {
        return Ok(0);
    }
    let n = buffer.len().min(file_size - off);
    let avail = inline_data
        .len()
        .saturating_sub(off)
        .min(file_size.saturating_sub(off));
    let n = n.min(avail);
    if off + n > inline_data.len() {
        return Ok(0);
    }
    buffer[..n].copy_from_slice(&inline_data[off..off + n]);
    Ok(n)
}

// ── Extended attributes ──────────────────────────────────────────────────────

/// List extended attributes for an inode.
///
/// Dispatches by the attribute fork format (stored in `core.attr_format`):
/// - `FMT_LOCAL` → parses shortform attribute entries directly.
/// - `FMT_EXTENTS` → walks extent-mapped attribute leaf blocks.
/// - `FMT_BTREE` → walks the attribute B+tree.
pub fn list_xattrs_for_inode(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
    inode_size: usize,
) -> Result<Vec<XattrEntry>, Error> {
    // No attribute fork at all.
    let attr_range = match core.attr_fork_range(inode_size) {
        Some(range) => range,
        None => return Ok(Vec::new()),
    };
    let (fork_off, _fork_end) = attr_range;

    // Gather raw (name, value) byte vectors from the attribute fork.
    let pairs = match core.attr_format {
        XFS_DINODE_FMT_LOCAL => {
            // Shortform: attrs are inline after the fork offset.
            super::btree::parse_attr_sf_entries(buf, fork_off, inode_size)
        }
        XFS_DINODE_FMT_EXTENTS => {
            let num_extents = core.attr_num_extents as usize;
            if num_extents == 0 || fork_off + num_extents * 16 > buf.len() {
                return Ok(Vec::new());
            }
            let extents = parse_extents(buf, fork_off, num_extents as u32);
            super::btree::walk_attr_tree(device, sb, &extents, 0).unwrap_or_default()
        }
        XFS_DINODE_FMT_BTREE => {
            let extents = super::btree::read_extent_btree(device, sb, buf, fork_off)?;
            super::btree::walk_attr_tree(device, sb, &extents, 0).unwrap_or_default()
        }
        _ => return Ok(Vec::new()),
    };

    Ok(pairs
        .into_iter()
        .map(|(name, value)| XattrEntry::new(name, value))
        .collect())
}

// ── Byte I/O ────────────────────────────────────────────────────────────────
// read_device_bytes is shared via super::btree::read_device_bytes
