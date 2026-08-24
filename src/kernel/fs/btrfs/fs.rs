//! src/kernel/fs/btrfs/fs.rs
//!
//! Btrfs low-level operations: superblock, trees, extents.
//! Btrfs low-level operations: superblock, B-tree traversal, inode/dir/file reading.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::Error;

use crate::kernel::compression::zstd_decompress;
use crate::kernel::crypto::crc32c;

use super::types::{
    parse_dir_entry, ChunkItemData, DirEntry, ExtentData, InodeItem, Item, Key, NodeHeader,
    RootItem, Superblock, ITEM_HEADER_SIZE, KEY_CHUNK_ITEM, KEY_DIR_ITEM, KEY_EXTENT_DATA,
    KEY_INODE_ITEM, KEY_ROOT_ITEM, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE,
};

// ── Superblock ──────────────────────────────────────────────────────────

pub fn read_superblock(device: &Arc<dyn BlockDevice>) -> Result<Superblock, Error> {
    let mut buf = [0u8; SUPERBLOCK_SIZE];
    read_device_bytes(device, SUPERBLOCK_OFFSET, &mut buf)?;
    Superblock::parse(&buf).ok_or(Error::InvalidArgument)
}

// ── B-tree traversal ────────────────────────────────────────────────────

pub fn read_node(
    device: &Arc<dyn BlockDevice>,
    bytenr: u64,
    node_size: u32,
) -> Result<(NodeHeader, Vec<Item>, Vec<u8>), Error> {
    let mut buf = vec![0u8; node_size as usize];
    read_device_bytes(device, bytenr, &mut buf)?;

    // Verify CRC32C checksum (covers the entire node, csum field zeroed).
    // Stored csum is a u32 LE at bytes 0-3; bytes 4-31 are reserved/padding.
    if buf.len() >= 32 {
        let stored = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stored != 0 {
            // Save the full csum header, zero it for computation, then restore.
            let mut saved_csum = [0u8; 32];
            saved_csum.copy_from_slice(&buf[..32]);
            buf[..32].fill(0);
            let computed = crc32c(&buf);
            buf[..32].copy_from_slice(&saved_csum);
            if computed != stored {
                return Err(Error::InvalidArgument);
            }
        }
    }

    let header = NodeHeader::parse(&buf).ok_or(Error::InvalidArgument)?;

    let nritems = header.nritems as usize;
    let item_offset = 101;

    let mut items = Vec::with_capacity(nritems);
    for i in 0..nritems {
        let off = item_offset + i * ITEM_HEADER_SIZE;
        let item = Item::parse(&buf[off..]).ok_or(Error::InvalidArgument)?;
        items.push(item);
    }

    Ok((header, items, buf))
}

pub fn leaf_search(
    device: &Arc<dyn BlockDevice>,
    root_bytenr: u64,
    node_size: u32,
    target: &Key,
) -> Result<Option<Vec<u8>>, Error> {
    let mut bytenr = root_bytenr;

    loop {
        let (header, items, buf) = read_node(device, bytenr, node_size)?;

        let idx = match items.binary_search_by(|item| item.key.cmp(target)) {
            Ok(i) => i,
            Err(_) => return Ok(None),
        };

        let item = &items[idx];
        let data_start = item.data_offset as usize;
        let data_end = data_start + item.data_size as usize;
        if data_end > buf.len() {
            return Err(Error::InvalidArgument);
        }

        if header.level == 0 {
            return Ok(Some(buf[data_start..data_end].to_vec()));
        }

        if data_start + 8 > buf.len() {
            return Err(Error::InvalidArgument);
        }
        bytenr = u64::from_le_bytes([
            buf[data_start],
            buf[data_start + 1],
            buf[data_start + 2],
            buf[data_start + 3],
            buf[data_start + 4],
            buf[data_start + 5],
            buf[data_start + 6],
            buf[data_start + 7],
        ]);
    }
}

// ── Root tree traversal ─────────────────────────────────────────────────

pub fn find_tree_root(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    tree_objectid: u64,
) -> Result<Option<u64>, Error> {
    let key = Key {
        objectid: tree_objectid,
        ty: KEY_ROOT_ITEM,
        offset: 0,
    };
    let data = leaf_search(device, sb.root_tree_root, sb.node_size, &key)?;
    match data {
        Some(ref buf) => {
            // Use the proper RootItem parser when data is large enough.
            if let Some(ri) = RootItem::parse(buf) {
                return Ok(Some(ri.root_bytenr));
            }
            // Fallback for legacy test images: first 8 bytes = tree root bytenr.
            if buf.len() >= 8 {
                Ok(Some(u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ])))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

// ── Subvolume discovery ───────────────────────────────────────────────────

/// Scan the root tree and return all subvolume (ROOT_ITEM) entries.
///
/// Returns `Vec<(tree_objectid, RootItem)>` where `tree_objectid` is the
/// key's objectid (the subvolume's tree ID) and `RootItem` contains the
/// root directory inode and tree root byte address.
///
/// Both user-created subvolumes and internal trees (FS_TREE, EXTENT_TREE, …)
/// are returned; callers typically filter by checking whether the root_dirid
/// appears as a DIR_ITEM in the default subvolume.
pub fn discover_subvolumes(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
) -> Result<Vec<(u64, RootItem)>, Error> {
    let mut subvols = Vec::new();
    let mut bytenr = sb.root_tree_root;

    loop {
        let (header, items, buf) = read_node(device, bytenr, sb.node_size)?;

        // Collect ROOT_ITEMs from this node.
        for item in &items {
            if item.key.ty == KEY_ROOT_ITEM && item.key.offset == 0 {
                let ds = item.data_offset as usize;
                let de = ds + item.data_size as usize;
                if de <= buf.len() {
                    if let Some(root_item) = RootItem::parse(&buf[ds..de]) {
                        subvols.push((item.key.objectid, root_item));
                    }
                }
            }
        }

        if header.level == 0 {
            break;
        }

        // Descend to the first child (root tree is small; breadth-first not needed).
        let first_key = Key {
            objectid: 0,
            ty: 0,
            offset: 0,
        };
        let idx = items
            .binary_search_by(|item| item.key.cmp(&first_key))
            .unwrap_or_else(|i| i.saturating_sub(1));
        if idx >= items.len() {
            break;
        }
        let ds = items[idx].data_offset as usize;
        if ds + 8 > buf.len() {
            break;
        }
        bytenr = u64::from_le_bytes([
            buf[ds],
            buf[ds + 1],
            buf[ds + 2],
            buf[ds + 3],
            buf[ds + 4],
            buf[ds + 5],
            buf[ds + 6],
            buf[ds + 7],
        ]);
    }

    Ok(subvols)
}

// ── Inode lookup ────────────────────────────────────────────────────────

pub fn lookup_inode(
    device: &Arc<dyn BlockDevice>,
    fs_tree_root: u64,
    node_size: u32,
    ino: u64,
) -> Result<Option<InodeItem>, Error> {
    let key = Key {
        objectid: ino,
        ty: KEY_INODE_ITEM,
        offset: 0,
    };
    let data = leaf_search(device, fs_tree_root, node_size, &key)?;
    match data {
        Some(ref buf) => Ok(InodeItem::parse(buf)),
        None => Ok(None),
    }
}

// ── Directory lookup ────────────────────────────────────────────────────

pub fn read_dir_entries(
    device: &Arc<dyn BlockDevice>,
    fs_tree_root: u64,
    node_size: u32,
    dir_ino: u64,
) -> Result<Vec<DirEntry>, Error> {
    let mut entries = Vec::new();
    let _current_ino = dir_ino;
    let mut bytenr = fs_tree_root;

    loop {
        let (header, items, buf) = read_node(device, bytenr, node_size)?;

        let leaf_contains_key = items
            .iter()
            .any(|item| item.key.objectid == dir_ino && item.key.ty == KEY_DIR_ITEM);

        if leaf_contains_key {
            for item in &items {
                if item.key.objectid == dir_ino && item.key.ty == KEY_DIR_ITEM {
                    let ds = item.data_offset as usize;
                    let de = ds + item.data_size as usize;
                    if de <= buf.len() {
                        if let Some(entry) = parse_dir_entry(&buf[ds..de]) {
                            entries.push(entry);
                        }
                    }
                }
            }
            break;
        }

        if header.level == 0 {
            break;
        }

        let target_key = Key {
            objectid: dir_ino,
            ty: KEY_DIR_ITEM,
            offset: 0,
        };
        let idx = items
            .binary_search_by(|item| item.key.cmp(&target_key))
            .unwrap_or_else(|i| i.saturating_sub(1));
        if idx >= items.len() {
            break;
        }
        let data_start = items[idx].data_offset as usize;
        if data_start + 8 > buf.len() {
            break;
        }
        bytenr = u64::from_le_bytes([
            buf[data_start],
            buf[data_start + 1],
            buf[data_start + 2],
            buf[data_start + 3],
            buf[data_start + 4],
            buf[data_start + 5],
            buf[data_start + 6],
            buf[data_start + 7],
        ]);
    }

    Ok(entries)
}

// ── File extent lookup ──────────────────────────────────────────────────

pub fn read_extents(
    device: &Arc<dyn BlockDevice>,
    fs_tree_root: u64,
    node_size: u32,
    file_ino: u64,
) -> Result<Vec<ExtentData>, Error> {
    let mut extents = Vec::new();
    let mut bytenr = fs_tree_root;

    let search_key = Key {
        objectid: file_ino,
        ty: KEY_EXTENT_DATA,
        offset: 0,
    };

    loop {
        let (header, items, buf) = read_node(device, bytenr, node_size)?;

        if header.level == 0 {
            for item in &items {
                if item.key.objectid == file_ino && item.key.ty == KEY_EXTENT_DATA {
                    let ds = item.data_offset as usize;
                    let de = ds + item.data_size as usize;
                    if de <= buf.len() {
                        if let Some(ext) = ExtentData::parse(&buf[ds..de]) {
                            extents.push(ext);
                        }
                    }
                }
            }
            break;
        }

        let idx = items
            .binary_search_by(|item| item.key.cmp(&search_key))
            .unwrap_or_else(|i| i.saturating_sub(1));
        if idx >= items.len() {
            break;
        }
        let data_start = items[idx].data_offset as usize;
        if data_start + 8 > buf.len() {
            break;
        }
        bytenr = u64::from_le_bytes([
            buf[data_start],
            buf[data_start + 1],
            buf[data_start + 2],
            buf[data_start + 3],
            buf[data_start + 4],
            buf[data_start + 5],
            buf[data_start + 6],
            buf[data_start + 7],
        ]);
    }

    Ok(extents)
}

pub fn read_file(
    devices: &[Arc<dyn BlockDevice>],
    chunk_map: &ChunkMap,
    extents: &[ExtentData],
    file_size: u64,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize, Error> {
    if offset >= file_size || buffer.is_empty() {
        return Ok(0);
    }

    let mut total = 0usize;
    let end_off = (offset + buffer.len() as u64).min(file_size);

    // Scratch buffer for compressed data (reused across extents).
    let mut scratch: Vec<u8> = Vec::new();

    for ext in extents {
        // Skip non-regular extents (inline=0, prealloc=2).
        if ext.extent_type != 1 {
            continue;
        }
        let ext_start = ext.offset;
        let ext_end = ext_start + ext.num_bytes;

        if offset >= ext_end || end_off <= ext_start {
            continue;
        }

        let seg_start = offset.max(ext_start);
        let seg_end = end_off.min(ext_end);
        let seg_len = (seg_end - seg_start) as usize;

        let dest_off = (seg_start - offset) as usize;

        // Translate the extent's logical disk address through the chunk map.
        let ext_logical = ext.disk_bytenr + (seg_start - ext_start);
        let (dev_index, physical) = chunk_map
            .translate(ext_logical)
            .ok_or(Error::InvalidArgument)?;

        if dev_index >= devices.len() {
            return Err(Error::InvalidArgument);
        }
        let target_device = &devices[dev_index];

        if ext.compression == 0 {
            // Uncompressed — read directly from the mapped device.
            read_device_bytes(
                target_device,
                physical,
                &mut buffer[dest_off..dest_off + seg_len],
            )?;
        } else if ext.compression == 3 {
            // ZSTD compressed: read entire compressed extent, decompress into scratch.
            let disk_size = ext.disk_num_bytes as usize;
            scratch.resize(disk_size, 0u8);
            // The compressed blob starts at the logical address `ext.disk_bytenr`.
            let (comp_dev_index, comp_physical) = chunk_map
                .translate(ext.disk_bytenr)
                .ok_or(Error::InvalidArgument)?;
            if comp_dev_index >= devices.len() {
                return Err(Error::InvalidArgument);
            }
            read_device_bytes(&devices[comp_dev_index], comp_physical, &mut scratch)?;

            let uncompressed = ext.ram_bytes as usize;
            let mut decompressed = vec![0u8; uncompressed];
            let written =
                zstd_decompress(&scratch, &mut decompressed).map_err(|_| Error::InvalidArgument)?;

            // Copy the requested segment from the decompressed data.
            let seg_in_ext = (seg_start - ext_start) as usize;
            if seg_in_ext + seg_len <= written {
                buffer[dest_off..dest_off + seg_len]
                    .copy_from_slice(&decompressed[seg_in_ext..seg_in_ext + seg_len]);
            } else {
                return Err(Error::InvalidArgument);
            }
        } else {
            // Unsupported compression algorithm (zlib=1, lzo=2, etc.).
            return Err(Error::Unsupported);
        }

        total += seg_len;
    }

    Ok(total)
}

// ── Chunk tree / logical→physical address translation ───────────────────

/// Maps a logical byte address range to a physical (device_index, offset) pair.
#[derive(Debug, Clone)]
struct ChunkMapEntry {
    logical_start: u64,
    logical_end: u64, // exclusive
    dev_index: usize,
    physical_base: u64,
}

/// Logical-to-physical address translation map built from the chunk tree.
///
/// Used to route file-data reads to the correct device in multi-device setups.
/// For a single-device filesystem this is an identity map.
#[derive(Debug, Clone)]
pub struct ChunkMap {
    entries: Vec<ChunkMapEntry>,
}

impl ChunkMap {
    /// Identity mapping — all logical addresses map directly to device 0.
    pub fn identity() -> Self {
        Self {
            entries: vec![ChunkMapEntry {
                logical_start: 0,
                logical_end: u64::MAX,
                dev_index: 0,
                physical_base: 0,
            }],
        }
    }

    /// Build a [`ChunkMap`] by parsing the chunk tree.
    ///
    /// The chunk tree root is read from device 0 using direct (untranslated)
    /// addressing — this is the Btrfs bootstrap convention: system chunks that
    /// contain the chunk tree itself are placed at physical addresses that
    /// match their logical addresses on device 0.
    pub fn from_chunk_tree(
        device: &Arc<dyn BlockDevice>,
        chunk_tree_root: u64,
        node_size: u32,
        num_devices: usize,
    ) -> Result<Self, Error> {
        let mut entries: Vec<ChunkMapEntry> = Vec::new();

        // Collect all CHUNK_ITEM leaves by traversing the chunk tree.
        // For simplicity (and because chunk trees are typically small),
        // we only handle a single-level (level=0) chunk tree here.
        let (header, items, buf) = read_node(device, chunk_tree_root, node_size)?;

        if header.level > 0 {
            // Multi-level chunk tree is rare; bail out cleanly.
            return Err(Error::Unsupported);
        }

        for item in &items {
            if item.key.ty == KEY_CHUNK_ITEM {
                let ds = item.data_offset as usize;
                let de = ds + item.data_size as usize;
                if de <= buf.len() {
                    if let Some(chunk) = ChunkItemData::parse(&buf[ds..de]) {
                        let logical_start = item.key.offset;
                        let logical_end = logical_start.saturating_add(chunk.size);

                        // Find which device index each stripe's devid maps to.
                        for stripe in &chunk.stripes {
                            let dev_index = stripe.devid as usize;
                            if dev_index < num_devices {
                                entries.push(ChunkMapEntry {
                                    logical_start,
                                    logical_end,
                                    dev_index,
                                    physical_base: stripe.offset,
                                });
                            }
                        }
                    }
                }
            }
        }

        if entries.is_empty() {
            // No chunk entries found — fall back to identity mapping
            // (single-device or test images without a real chunk tree).
            return Ok(Self::identity());
        }

        // Sort by logical_start for binary search.
        entries.sort_by_key(|e| e.logical_start);
        Ok(Self { entries })
    }

    /// Translate a logical byte address to `(device_index, physical_offset)`.
    ///
    /// `logical` is the starting byte offset within the filesystem's logical
    /// address space (i.e. an extent's `disk_bytenr`).  Returns `None` if the
    /// address is not covered by any known chunk.
    pub fn translate(&self, logical: u64) -> Option<(usize, u64)> {
        // Binary search for the entry containing `logical`.
        let idx = match self
            .entries
            .binary_search_by_key(&logical, |e| e.logical_start)
        {
            Ok(i) => i,
            Err(0) => return None,         // logical < first entry's start
            Err(i) => i.saturating_sub(1), // check the entry before the insertion point
        };

        let entry = &self.entries[idx];
        if logical >= entry.logical_start && logical < entry.logical_end {
            let offset_in_chunk = logical - entry.logical_start;
            Some((entry.dev_index, entry.physical_base + offset_in_chunk))
        } else {
            None
        }
    }
}

// ── Byte I/O ────────────────────────────────────────────────────────────

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
