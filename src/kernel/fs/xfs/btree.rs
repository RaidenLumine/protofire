//! src/kernel/fs/xfs/btree.rs
//!
//! Generic XFS B+tree reader for 32-bit and 64-bit-key btrees.
//!
//! XFS uses B+trees extensively: free-space btrees, inode-allocation btrees,
//! and file-extent btrees (64-bit keys). This module provides readers for
//! 32-bit-key btrees (AGF free-space, AGI inode) and 64-bit-key extent
//! btrees (BMAP), plus a reusable [`BtreeReader64`] for any 64-bit-key
//! B+tree.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use super::types::Extent;
use super::types::{
    be32, be64, parse_block_dir, parse_btree_records, parse_data_entry_at, BtreeBlock, BtreeRecord,
    DirEntry, XFS_DA_NODE_MAGIC, XFS_DIR2_LEAF1_MAGIC, XFS_DIR2_LEAFN_MAGIC,
};

/// Maximum B+tree depth to guard against infinite loops on corrupted metadata.
const XFS_BTREE_MAX_DEPTH: usize = 8;

/// A generic B+tree reader for 32-bit-key btrees.
#[allow(dead_code)]
pub struct BtreeReader {
    device: Arc<dyn BlockDevice>,
    root_block: u32,
    block_size: u32,
    ag_start: u64, // absolute block offset of this AG
    rec_size: usize,
}

#[allow(dead_code)]
impl BtreeReader {
    pub fn new(
        device: Arc<dyn BlockDevice>,
        root_block: u32,
        block_size: u32,
        ag_start: u64,
        rec_size: usize,
    ) -> Self {
        Self {
            device,
            root_block,
            block_size,
            ag_start,
            rec_size,
        }
    }

    /// Search for a record with the given key. Returns the record if found.
    pub fn search(&self, key: u32) -> Result<Option<BtreeRecord>, Error> {
        let mut block_num = self.root_block as u64 + self.ag_start;

        loop {
            let byte_off = block_num * self.block_size as u64;
            let mut buf = vec![0u8; self.block_size as usize];
            read_device_bytes(&self.device, byte_off, &mut buf)?;

            let node = BtreeBlock::parse(&buf).ok_or(Error::InvalidArgument)?;

            if !node.is_btree_node() {
                return Err(Error::InvalidArgument);
            }

            if node.is_leaf() {
                let records =
                    parse_btree_records(&node.data, node.num_recs as usize, self.rec_size);
                for rec in records {
                    if rec.key == key {
                        return Ok(Some(rec));
                    }
                }
                return Ok(None);
            }

            // Internal node: find the appropriate child block.
            let records = parse_btree_records(&node.data, node.num_recs as usize, self.rec_size);
            let mut child = None;
            for rec in &records {
                if key < rec.key {
                    break;
                }
                child = Some(rec.block as u64 + self.ag_start);
            }
            // If no child found, use the last key's right child.
            if child.is_none() && !records.is_empty() {
                child = Some(records.last().unwrap().block as u64 + self.ag_start);
            }
            match child {
                Some(b) => block_num = b,
                None => return Ok(None),
            }
        }
    }
}

// ── 64-bit-key extent B+tree reader ──────────────────────────────────────

/// Parse BMAP leaf records (24 bytes each) into Extent structs.
pub(crate) fn parse_bmap_leaf(data: &[u8], num_recs: usize) -> Vec<Extent> {
    let mut extents = Vec::with_capacity(num_recs);
    for i in 0..num_recs {
        let off = i * 24;
        if off + 24 > data.len() {
            break;
        }
        let start_offset = be64(data, off);
        let start_block = be64(data, off + 8);
        let block_count = be32(data, off + 16) as u64;
        extents.push(Extent {
            start_offset,
            start_block,
            block_count,
        });
    }
    extents
}

/// Parse BMAP internal node records (16 bytes each) into (key, block) pairs.
pub(crate) fn parse_bmap_internal(data: &[u8], num_recs: usize) -> Vec<(u64, u64)> {
    let mut recs = Vec::with_capacity(num_recs);
    for i in 0..num_recs {
        let off = i * 16;
        if off + 16 > data.len() {
            break;
        }
        let key = be64(data, off);
        let block = be64(data, off + 8);
        recs.push((key, block));
    }
    recs
}

// ── Directory hash ─────────────────────────────────────────────────────────

/// XFS directory name hash (xfs_da_hashname).
///
/// Fold a filename into a 32-bit hash used as the lookup key in XFS
/// directory B+trees (leaf and node formats).  The algorithm is:
///
/// ```text
/// hash = 0
/// for each byte b in name:
///     hash = (hash << 4) + b
///     if high = hash & 0xF000_0000:
///         hash ^= high >> 24
///         hash &= ~high
/// return hash
/// ```
pub(crate) fn xfs_dir_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(byte as u32);
        let high = hash & 0xF000_0000;
        if high != 0 {
            hash ^= high >> 24;
            hash &= !high;
        }
    }
    hash
}

// ── 64-bit-key B+tree reader ──────────────────────────────────────────────

/// A generic B+tree reader for XFS 64-bit-key btrees.
///
/// Supports both BMAP extent trees and directory B+trees.  Use
/// [`collect_extents`] to gather all leaf records from an extent tree, or
/// [`search_dir`] to look up a directory entry by hash.
pub(crate) struct BtreeReader64 {
    device: Arc<dyn BlockDevice>,
    block_size: u32,
    /// Byte offset where B+tree records start in a long-format block:
    /// 32 for v4, 56 for v5.
    rec_offset: usize,
    /// BMAP B+tree block magic for this filesystem version:
    /// 0x424D_4150 ("BMAP") for v4, 0x424D_4133 ("BMA3") for v5.
    bmap_magic: u32,
}

impl BtreeReader64 {
    pub fn new(
        device: Arc<dyn BlockDevice>,
        block_size: u32,
        rec_offset: usize,
        bmap_magic: u32,
    ) -> Self {
        Self {
            device,
            block_size,
            rec_offset,
            bmap_magic,
        }
    }

    /// Collect all extent records from a BMAP B+tree given the inode data
    /// fork root.  This is the generalized version of the free function
    /// `read_extent_btree`.
    ///
    /// `fork_off` is the byte offset of the data fork within the inode
    /// buffer `buf`.  The data fork contains a BMDR root header:
    ///
    /// ```text
    /// u16 level
    /// u16 numrecs
    /// … numrecs × (16 bytes internal / 24 bytes leaf)
    /// ```
    pub fn collect_extents(&self, buf: &[u8], fork_off: usize) -> Result<Vec<Extent>, Error> {
        // Bounds check: need at least 4 bytes for the BMDR header.
        if fork_off + 4 > buf.len() {
            return Err(Error::InvalidArgument);
        }
        let root_level = u16::from_be_bytes([buf[fork_off], buf[fork_off + 1]]);
        let root_numrecs = u16::from_be_bytes([buf[fork_off + 2], buf[fork_off + 3]]) as usize;
        let root_data = &buf[fork_off + 4..];

        if root_level == 0 {
            // Root is a leaf: records are extent records (24 bytes each).
            return Ok(parse_bmap_leaf(root_data, root_numrecs));
        }

        // Root is an internal node — descend to collect all leaf extents.
        // Push children in reverse so leftmost is processed first (LIFO stack).
        // Depth starts at 1 since we are one level below the BMDR root.
        let root_recs = parse_bmap_internal(root_data, root_numrecs);
        let mut stack: Vec<(u64, usize)> = root_recs
            .iter()
            .rev()
            .map(|(_, block)| (*block, 1))
            .collect();

        let mut all_extents = Vec::new();
        let block_size = self.block_size as u64;
        let rec_offset = self.rec_offset;
        let bmap_magic = self.bmap_magic;

        while let Some((block_num, depth)) = stack.pop() {
            // Guard against infinite loops from corrupted metadata cycles.
            if depth > XFS_BTREE_MAX_DEPTH {
                continue;
            }

            let byte_off = block_num * block_size;
            let mut node_buf = vec![0u8; block_size as usize];
            read_device_bytes(&self.device, byte_off, &mut node_buf)?;

            // Bounds check: need at least the long-format header.
            if node_buf.len() < rec_offset {
                continue;
            }
            let magic = be32(&node_buf, 0);
            if magic != bmap_magic {
                // BMAP magic — skip blocks that aren't BMAP B+tree nodes
                // (corruption or non-BMAP tree; safe to skip in read-only mode).
                continue;
            }
            let level = u16::from_be_bytes([node_buf[4], node_buf[5]]);
            let numrecs = u16::from_be_bytes([node_buf[6], node_buf[7]]) as usize;
            // Records start after the long-format block header.
            let data = &node_buf[rec_offset..];

            if level == 0 {
                all_extents.extend(parse_bmap_leaf(data, numrecs));
            } else {
                for (_, child_block) in parse_bmap_internal(data, numrecs).iter().rev() {
                    stack.push((*child_block, depth + 1));
                }
            }
        }

        Ok(all_extents)
    }
}

// read_extent_btree kept as a thin wrapper for compatibility with the
// existing call-sites in fs.rs.  It delegates to BtreeReader64.

/// Parse a directory B+tree leaf record (xfs_dir2_leaf_entry, 8 bytes).
///
/// Each leaf entry maps a directory name hash to a data-block address.
/// Returns `(hash, address)` pairs.
pub(crate) fn parse_dir_leaf_entries(data: &[u8], num_entries: usize) -> Vec<(u32, u32)> {
    let mut entries = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let off = i * 8;
        if off + 8 > data.len() {
            break;
        }
        let hash = be32(data, off);
        let address = be32(data, off + 4);
        entries.push((hash, address));
    }
    entries
}

/// Parse a leaf-format XFS directory block.
///
/// A leaf-format directory uses hash-indexed [`xfs_dir2_leaf_entry`] records
/// to locate [`xfs_dir2_data_entry`] records within the same block.
///
/// ## Block layout (v4)
///
/// ```text
/// Offset  0: u32 forw         — forward sibling pointer
/// Offset  4: u32 back         — back sibling pointer
/// Offset  8: u16 magic        — 0x4449_524C ("DIRL") for v4
/// Offset 10: u16 pad
/// Offset 12: u16 count        — number of leaf entries
/// Offset 14: u16 stale        — number of stale entries
/// Offset 16: xfs_dir2_leaf_entry[count]  — 8 bytes each (hash u32 + address u32)
/// Then:      xfs_dir2_free[count]        — best-free table (not needed for read)
/// Then:      free space
/// Near end:  xfs_dir2_data_entry records — indexed by leaf entry addresses
/// ```
///
/// For v5 (magic 0x5844_3244 "XD2D") the `xfs_da3_blkinfo` header is 56 bytes,
/// with `count` at offset 56 and leaf entries at offset 64.
#[allow(dead_code)]
pub(crate) fn parse_leaf_dir(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    // Need at least the v4 leaf header: 12 (blkinfo) + 2 (count) + 2 (stale) = 16
    if data.len() < 16 {
        return entries;
    }

    // Magic is at offset 8 as u16 in xfs_da_blkinfo_t.
    let magic = u16::from_be_bytes([data[8], data[9]]);

    let (count, leaf_entries_start): (usize, usize) = match magic {
        XFS_DIR2_LEAF1_MAGIC | XFS_DIR2_LEAFN_MAGIC => {
            // v4: xfs_da_blkinfo is 12 bytes; count at offset 12, entries at 16
            let cnt = u16::from_be_bytes([data[12], data[13]]) as usize;
            (cnt, 16)
        }
        _ => return entries,
    };

    if count == 0 {
        return entries;
    }

    // Parse leaf entries.
    let leaf_data = &data[leaf_entries_start..];
    let leaf_entries = parse_dir_leaf_entries(leaf_data, count);

    for (_hash, address) in leaf_entries {
        let addr = address as usize;
        if addr >= data.len() {
            continue;
        }
        if let Some(entry) = super::types::parse_data_entry_at(data, addr) {
            entries.push(entry);
        }
    }

    entries
}

/// Read all extents from a file whose data fork is in B+tree (FMT_BTREE) format.
///
/// This is a convenience wrapper around [`BtreeReader64::collect_extents`].
pub fn read_extent_btree(
    device: &Arc<dyn BlockDevice>,
    sb: &super::types::Superblock,
    buf: &[u8],
    fork_off: usize,
) -> Result<Vec<Extent>, Error> {
    let reader = BtreeReader64::new(
        Arc::clone(device),
        sb.block_size,
        sb.btree_lblock_rec_offset(),
        sb.bmap_magic(),
    );
    reader.collect_extents(buf, fork_off)
}

// ── Node-format directory B+tree traversal ─────────────────────────────────

/// Map a directory logical block number to a physical byte offset on disk.
///
/// Directory blocks are addressed by logical block number (index into the
/// extent list).  This helper walks the extent list and returns the absolute
/// byte offset of the given logical block.
fn logical_block_to_phys(lbn: u32, extents: &[Extent], bs: u64) -> Option<u64> {
    let mut remaining = lbn as u64;
    for ext in extents {
        if remaining < ext.block_count {
            return Some((ext.start_block + remaining) * bs);
        }
        remaining -= ext.block_count;
    }
    None
}

/// Parse a node-format XFS directory node block (xfs_da_intnode).
///
/// Returns `(level, entries)` where each entry is `(hashval, before)`:
/// - `level` is the tree level (0 means children are leaves).
/// - `hashval` is the name hash key.
/// - `before` is the logical block number of the child.
fn parse_node_block(data: &[u8]) -> Option<(u16, Vec<(u32, u32)>)> {
    if data.len() < 16 {
        return None;
    }
    let magic = u16::from_be_bytes([data[8], data[9]]);
    if magic != XFS_DA_NODE_MAGIC {
        return None;
    }
    let count = u16::from_be_bytes([data[12], data[13]]) as usize;
    let level = u16::from_be_bytes([data[14], data[15]]);

    let node_data = &data[16..];
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 8;
        if off + 8 > node_data.len() {
            break;
        }
        let hash = be32(node_data, off);
        let before = be32(node_data, off + 4);
        entries.push((hash, before));
    }
    Some((level, entries))
}

/// Traverse a node-format directory B+tree and collect all directory entries.
///
/// Node-format directories use a B+tree with `xfs_da_intnode` internal blocks
/// and `xfs_dir2_leaf` (LEAFN) leaf blocks.  Each LEAFN leaf entry's address
/// encodes a data logical block number (upper 16 bits) and byte offset (lower
/// 16 bits) where the actual `xfs_dir2_data_entry` resides.
///
/// The root is always at logical block 0.  This function walks the tree
/// depth-first and resolves every entry back to its data block.
pub(crate) fn read_node_dir_entries(
    device: &Arc<dyn BlockDevice>,
    sb: &super::types::Superblock,
    extents: &[Extent],
) -> Result<Vec<DirEntry>, Error> {
    let bs = sb.block_size as u64;
    let mut entries = Vec::new();
    // Stack holds logical block numbers still to visit.
    let mut stack: Vec<u32> = vec![0]; // root

    while let Some(lbn) = stack.pop() {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs as usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            continue;
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                // Internal node: extract children and push onto stack.
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    let children: Vec<u32> =
                        node_entries.iter().map(|&(_, before)| before).collect();
                    // Push in reverse for left-to-right (hash-ordered) traversal.
                    for child in children.iter().rev() {
                        stack.push(*child);
                    }
                }
            }
            XFS_DIR2_LEAFN_MAGIC => {
                // LEAFN leaf block: entries point to separate data blocks.
                let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
                let leaf_data = &buf[16..];
                let leaf_entries = parse_dir_leaf_entries(leaf_data, count);

                for (_hash, address) in leaf_entries {
                    // LEAFN address: upper 16 bits = data logical block,
                    //                lower 16 bits = byte offset within data block.
                    let data_lbn = address >> 16;
                    let byte_off = (address & 0xFFFF) as usize;

                    let data_phys = logical_block_to_phys(data_lbn, extents, bs)
                        .ok_or(Error::InvalidArgument)?;
                    let mut data_buf = vec![0u8; bs as usize];
                    read_device_bytes(device, data_phys, &mut data_buf)?;

                    if let Some(entry) = parse_data_entry_at(&data_buf, byte_off) {
                        entries.push(entry);
                    }
                }
            }
            XFS_DIR2_LEAF1_MAGIC => {
                // LEAF1 in a node tree is unusual but handle it gracefully.
                entries.extend(parse_leaf_dir(&buf));
            }
            _ => {
                // Fallback: try block-format for unknown block types.
                entries.extend(parse_block_dir(&buf));
            }
        }
    }

    Ok(entries)
}

// ── Hash-indexed directory lookup ─────────────────────────────────────────

/// Map a byte offset within a directory's data area to a physical disk byte
/// offset and the offset within that block.
///
/// Unlike [`logical_block_to_phys`] which operates on logical block numbers,
/// this helper works with byte-granularity addresses as stored in
/// [`XFS_DIR2_LEAF1_MAGIC`] leaf entries.
fn dir_byte_to_phys(byte_off: u64, extents: &[Extent], bs: u64) -> Option<(u64, usize)> {
    let mut remaining = byte_off;
    for ext in extents {
        let ext_bytes = ext.block_count * bs;
        if remaining < ext_bytes {
            let block_idx = remaining / bs;
            let block_off = (remaining % bs) as usize;
            let phys = (ext.start_block + block_idx) * bs;
            return Some((phys, block_off));
        }
        remaining -= ext_bytes;
    }
    None
}

/// Look up an inode by name in a **leaf-format** directory.
///
/// Walks all extent blocks to find the one with [`XFS_DIR2_LEAF1_MAGIC`],
/// then binary-searches its leaf entries by hash, reads only the matched
/// data entry, and verifies the name to guard against hash collisions.
///
/// Returns `Ok(Some(ino))` on match, `Ok(None)` if not found, or
/// `Err(Error)` on I/O failure.
pub(crate) fn lookup_leaf_dir_by_hash(
    device: &Arc<dyn BlockDevice>,
    sb: &super::types::Superblock,
    extents: &[Extent],
    target_hash: u32,
    target_name: &[u8],
) -> Result<Option<u64>, Error> {
    let bs = sb.block_size as u64;

    for ext in extents {
        for i in 0..ext.block_count {
            let block_addr = (ext.start_block + i) * bs;
            let mut buf = vec![0u8; bs as usize];
            read_device_bytes(device, block_addr, &mut buf)?;

            if buf.len() < 16 {
                continue;
            }
            let magic = u16::from_be_bytes([buf[8], buf[9]]);
            if magic != XFS_DIR2_LEAF1_MAGIC {
                continue;
            }

            let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
            if count == 0 {
                return Ok(None);
            }

            let leaf_data = &buf[16..];
            let leaf_entries = parse_dir_leaf_entries(leaf_data, count);

            // Leaf entries are sorted by hash — binary search, then scan for
            // the matching name across same-hash entries (hash collision guard).
            if let Ok(idx) = leaf_entries.binary_search_by_key(&target_hash, |(hash, _addr)| *hash)
            {
                // Walk left to the first entry with this hash.
                let mut first = idx;
                while first > 0 && leaf_entries[first - 1].0 == target_hash {
                    first -= 1;
                }
                // Walk right, checking each same-hash candidate's name.
                let mut pos = first;
                while pos < leaf_entries.len() && leaf_entries[pos].0 == target_hash {
                    let address = leaf_entries[pos].1 as u64;
                    // LEAF1 address is a byte offset within the directory's data
                    // area — resolve to physical block + offset.
                    if let Some((phys, block_off)) = dir_byte_to_phys(address, extents, bs) {
                        let mut data_buf = vec![0u8; bs as usize];
                        read_device_bytes(device, phys, &mut data_buf)?;
                        if let Some(entry) = super::types::parse_data_entry_at(&data_buf, block_off)
                        {
                            if entry.name == target_name {
                                return Ok(Some(entry.inode));
                            }
                        }
                    }
                    pos += 1;
                }
            }
            // LEAF1 block found and searched — done regardless of match.
            return Ok(None);
        }
    }
    Ok(None)
}

/// Look up an inode by name in a **node-format** directory B+tree.
///
/// Walks the B+tree from root (logical block 0) downwards: binary-searches
/// node entries at each internal level to find the correct child, then
/// binary-searches LEAFN leaf entries against [`XFS_DIR2_LEAFN_MAGIC`]
/// blocks.  Leaf-entry addresses encode the data logical block (upper 16
/// bits) and byte offset (lower 16 bits), which are resolved via the extent
/// list.  Name comparison guards against hash collisions.
///
/// Returns `Ok(Some(ino))` on match, `Ok(None)` if not found.
pub(crate) fn lookup_node_dir_by_hash(
    device: &Arc<dyn BlockDevice>,
    sb: &super::types::Superblock,
    extents: &[Extent],
    target_hash: u32,
    target_name: &[u8],
) -> Result<Option<u64>, Error> {
    let bs = sb.block_size as u64;
    let mut lbn: u32 = 0; // root is always at logical block 0

    loop {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs as usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            return Ok(None);
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                // Internal node — binary-search for the correct child.
                // node entries are sorted by hashval; entry i's `before`
                // covers hashes ≤ hashval_i (and > hashval_{i-1}).
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    if node_entries.is_empty() {
                        return Ok(None);
                    }
                    let child = node_entries
                        .iter()
                        .find(|(hashval, _before)| target_hash <= *hashval)
                        .map(|(_, before)| *before)
                        .unwrap_or_else(|| {
                            // target_hash > all entries → rightmost child.
                            node_entries.last().unwrap().1
                        });
                    lbn = child;
                } else {
                    return Ok(None);
                }
            }
            XFS_DIR2_LEAFN_MAGIC => {
                let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
                if count == 0 {
                    return Ok(None);
                }
                let leaf_data = &buf[16..];
                let leaf_entries = parse_dir_leaf_entries(leaf_data, count);

                if let Ok(idx) =
                    leaf_entries.binary_search_by_key(&target_hash, |(hash, _addr)| *hash)
                {
                    let mut first = idx;
                    while first > 0 && leaf_entries[first - 1].0 == target_hash {
                        first -= 1;
                    }
                    let mut pos = first;
                    while pos < leaf_entries.len() && leaf_entries[pos].0 == target_hash {
                        let address = leaf_entries[pos].1;
                        let data_lbn = address >> 16;
                        let byte_off = (address & 0xFFFF) as usize;

                        let data_phys = logical_block_to_phys(data_lbn, extents, bs)
                            .ok_or(Error::InvalidArgument)?;
                        let mut data_buf = vec![0u8; bs as usize];
                        read_device_bytes(device, data_phys, &mut data_buf)?;

                        if let Some(entry) = super::types::parse_data_entry_at(&data_buf, byte_off)
                        {
                            if entry.name == target_name {
                                return Ok(Some(entry.inode));
                            }
                        }
                        pos += 1;
                    }
                }
                return Ok(None);
            }
            XFS_DIR2_LEAF1_MAGIC => {
                // LEAF1 inside a node tree is unusual; fall back to the
                // leaf-dir path for this single block.
                return lookup_leaf_dir_by_hash(device, sb, extents, target_hash, target_name);
            }
            _ => {
                // Unknown block type — cannot continue hash-indexed traversal.
                return Ok(None);
            }
        }
    }
}

// ── Extended attribute parsing ──────────────────────────────────────────────

/// Parse shortform (inline) attribute entries from the attribute fork.
///
/// Layout at `fork_off` within the inode buffer:
///   u16 count (number of entries)
///   count × variable-length entries:
///     u8  namelen
///     u8  valuelen
///     u8  flags
///     u8[namelen] name
///     u8[valuelen] value
#[allow(clippy::type_complexity)]
pub(crate) fn parse_attr_sf_entries(
    buf: &[u8],
    fork_off: usize,
    inode_size: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    if fork_off + 2 > inode_size || fork_off + 2 > buf.len() {
        return result;
    }
    let count = u16::from_be_bytes([buf[fork_off], buf[fork_off + 1]]) as usize;
    let mut pos = fork_off + 4; // skip count + 2 unused padding bytes
    for _ in 0..count {
        if pos + 3 > buf.len() || pos + 3 > inode_size {
            break;
        }
        let namelen = buf[pos] as usize;
        let valuelen = buf[pos + 1] as usize;
        let _flags = buf[pos + 2];
        pos += 3;
        if pos + namelen + valuelen > buf.len() || pos + namelen + valuelen > inode_size {
            break;
        }
        let name = buf[pos..pos + namelen].to_vec();
        pos += namelen;
        let value = buf[pos..pos + valuelen].to_vec();
        pos += valuelen;
        result.push((name, value));
    }
    result
}

/// Parse name/value pairs from a single attribute leaf block.
///
/// The attribute leaf block has a `xfs_da_blkinfo_t` header (12 bytes) followed
/// by attribute-specific header fields.  Entry data is stored in a name/value
/// region indexed by the leaf entries.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_attr_leaf_entries(
    data: &[u8],
    sb_block_size: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    // Need at least: blkinfo (12) + count (2) + usedbytes (2) + firstused (2) = 18
    if data.len() < 18 {
        return result;
    }
    // Verify magic at offset 8 (u16).
    let magic = u16::from_be_bytes([data[8], data[9]]);
    if magic != super::types::XFS_ATTR_LEAF_MAGIC {
        return result;
    }
    let count = u16::from_be_bytes([data[12], data[13]]) as usize;
    if count == 0 {
        return result;
    }
    // After blkinfo (12 bytes) comes the attr leaf header:
    //   u16 count (at 12), u16 usedbytes (at 14), u16 firstused (at 16), u8 holes (at 18), u8 pad (at 19)
    // Then at offset 20: the leaf entries array (count × 8 bytes: hash u32 + offset u16 + flags u8 + pad u8)
    //   Actually each entry is: u32 hash, u16 nameidx, u8 flags, u8 pad = 8 bytes
    // After entries: the name/value region grows from `firstused` toward the
    // end of the block (or from the end of the entries array).
    let entries_start = 20usize; // after blkinfo(12) + header(8: count, usedbytes, firstused, holes+pad)
    if entries_start + count * 8 > sb_block_size || entries_start + count * 8 > data.len() {
        return result;
    }
    for i in 0..count {
        let off = entries_start + i * 8;
        if off + 6 > data.len() {
            break;
        }
        let _hash = be32(data, off);
        let nameidx = u16::from_be_bytes([data[off + 4], data[off + 5]]) as usize;
        // Scan forward from nameidx to read the entry: u8 namelen, u8 valuelen, u8 flags,
        // then name[namelen], then value[valuelen].
        if nameidx + 3 > data.len() || nameidx + 3 > sb_block_size {
            continue;
        }
        let namelen = data[nameidx] as usize;
        let valuelen = data[nameidx + 1] as usize;
        let _flags = data[nameidx + 2];
        let name_start = nameidx + 3;
        if name_start + namelen + valuelen > data.len()
            || name_start + namelen + valuelen > sb_block_size
        {
            continue;
        }
        let name = data[name_start..name_start + namelen].to_vec();
        let value = data[name_start + namelen..name_start + namelen + valuelen].to_vec();
        result.push((name, value));
    }
    result
}

/// Walk an attribute B+tree and collect all name/value pairs.
///
/// Reuses `parse_node_block()` and `logical_block_to_phys()` for node traversal.
/// Leaf blocks use `XFS_ATTR_LEAF_MAGIC` (0xfbee) and require a different parser
/// than directory leaf blocks.
#[allow(clippy::type_complexity)]
pub(crate) fn walk_attr_tree(
    device: &Arc<dyn BlockDevice>,
    sb: &super::types::Superblock,
    extents: &[Extent],
    root_lbn: u32,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let bs = sb.block_size as u64;
    let bs_usize = sb.block_size as usize;
    let mut result = Vec::new();
    let mut stack: Vec<u32> = vec![root_lbn];

    while let Some(lbn) = stack.pop() {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs_usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            continue;
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                // Internal node: extract children.
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    for child in node_entries.iter().map(|&(_, before)| before).rev() {
                        stack.push(child);
                    }
                }
            }
            super::types::XFS_ATTR_LEAF_MAGIC => {
                result.extend(parse_attr_leaf_entries(&buf, bs_usize));
            }
            _ => {
                // Unknown block type — skip.
            }
        }
    }

    Ok(result)
}

pub(crate) fn read_device_bytes(
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xfs_dir_hash_basic() {
        assert_eq!(xfs_dir_hash(b""), 0);
        assert_ne!(xfs_dir_hash(b"test"), 0);
        assert_ne!(xfs_dir_hash(b"longer_filename"), 0);
        // Same input → same hash.
        assert_eq!(xfs_dir_hash(b"same"), xfs_dir_hash(b"same"));
        // Different inputs → different hashes (with high probability).
        assert_ne!(xfs_dir_hash(b"abc"), xfs_dir_hash(b"abd"));
    }

    #[test]
    fn parse_dir_leaf_entries_single() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&0x1234u32.to_be_bytes());
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        let entries = parse_dir_leaf_entries(&buf, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (0x1234, 42));
    }

    #[test]
    fn parse_dir_leaf_entries_multiple() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&10u32.to_be_bytes());
        buf[8..12].copy_from_slice(&2u32.to_be_bytes());
        buf[12..16].copy_from_slice(&20u32.to_be_bytes());
        let entries = parse_dir_leaf_entries(&buf, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (1, 10));
        assert_eq!(entries[1], (2, 20));
    }
}
