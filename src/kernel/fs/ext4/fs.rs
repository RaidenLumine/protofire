//! src/kernel/fs/ext4/fs.rs
//! Ext4Fs internal state and core implementation (block I/O, inode ops,
//! extent tree management, directory scanning, block/inode allocation,
//! file data read/write, journal integration).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::super::block::{BlockDevice, BLOCK_SIZE};
use super::super::block_cache::BlockCache;
use super::super::filesystem::profiler::FsProfiler;
use super::super::unicode;
use super::super::vfs::checksum::ChecksumPolicy;
use super::super::vfs::{Metadata, NodeKind, SecurityDescriptor};

use super::constants::*;
use super::journal::*;
use super::types::*;
use super::Ext4Fs;

pub(crate) fn read_inode_raw(
    cache: &BlockCache,
    sb: &Ext4Superblock,
    bgs: &[Ext4BgDescriptor],
    ino: u32,
) -> Result<Ext4Inode> {
    let block_size = sb.block_size();
    let inode_size = if sb.rev_level >= 1 {
        sb.inode_size as usize
    } else {
        EXT4_GOOD_OLD_INODE_SIZE
    };
    let bg_idx = sb.group_of_ino(ino);
    let inode_idx = sb.inode_index_in_group(ino);
    let bg = &bgs[bg_idx as usize];
    let inode_table_block = bg.bg_inode_table as u64;
    let inodes_per_block = block_size / inode_size;
    let block_offset = inode_idx as usize / inodes_per_block;
    let offset_in_block = (inode_idx as usize % inodes_per_block) * inode_size;

    let lba = inode_table_block * (block_size as u64 / BLOCK_SIZE as u64);
    let sector_count = block_size / BLOCK_SIZE;
    let mut buf = vec![0u8; block_size];
    for i in 0..sector_count {
        cache.read_cached(
            lba + block_offset as u64 * sector_count as u64 + i as u64,
            &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
        )?;
    }
    let raw = &buf[offset_in_block..offset_in_block + inode_size];
    Ok(read_ext4_inode(raw, inode_size as u16))
}

// ─── Ext4Fs implementation ────────────────────────────────────────────────

impl Ext4Fs {
    pub(crate) fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let read_only = device.is_read_only();
        let cache = BlockCache::new(device.clone());
        let sb = Self::read_superblock(&cache)?;
        let block_size = sb.block_size();
        let bg_descriptors = Self::read_bg_descriptors(&sb, &cache)?;

        // Replay journal if present and dirty.
        let mut journal_writer = None;
        if sb.feature_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL != 0 {
            if let Err(e) = replay_ext4_journal(&cache, &sb, &bg_descriptors) {
                // Journal replay failed — continue with noload semantics.
                crate::println!("ext4: journal replay failed ({:?}), mounting noload", e);
            }
            // Initialise the journal writer if the filesystem is writable.
            if !read_only {
                match read_inode_raw(&cache, &sb, &bg_descriptors, EXT4_JOURNAL_INO) {
                    Ok(journal_inode) => {
                        journal_writer =
                            JournalWriter::open(&cache, &journal_inode, &sb).map(Mutex::new);
                        if journal_writer.is_some() {
                            crate::println!("ext4: journal write enabled");
                        }
                    }
                    Err(_) => {
                        crate::println!("ext4: cannot read journal inode, journal write disabled");
                    }
                }
            }
        }

        Ok(Self {
            device,
            cache,
            sb,
            bg_descriptors: Mutex::new(bg_descriptors),
            read_only,
            block_buf: Mutex::new(vec![0_u8; block_size]),
            journal_writer,
            profiler: FsProfiler::default(),
            checksum_policy: ChecksumPolicy::Strict,
        })
    }

    pub(crate) fn block_size(&self) -> usize {
        self.sb.block_size()
    }

    fn sectors_per_block(&self) -> u64 {
        (self.block_size() / BLOCK_SIZE) as u64
    }

    fn block_to_lba(&self, ext2_block: u64) -> u64 {
        ext2_block * self.sectors_per_block()
    }

    fn read_ext2_block(&self, ext2_block: u64, buffer: &mut [u8]) -> Result<()> {
        let block_size = self.block_size();
        let lba = self.block_to_lba(ext2_block);
        let sector_count = self.sectors_per_block() as usize;

        assert!(buffer.len() >= block_size);
        for i in 0..sector_count {
            let sector_buf = &mut buffer[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            self.cache.read_cached(lba + i as u64, sector_buf)?;
        }
        Ok(())
    }

    pub(crate) fn read_superblock(cache: &BlockCache) -> Result<Ext4Superblock> {
        let start_lba = SUPERBLOCK_BYTE_OFFSET / BLOCK_SIZE as u64;
        let lba_count = SUPERBLOCK_SIZE / BLOCK_SIZE;
        let mut raw = [0_u8; SUPERBLOCK_SIZE];

        for i in 0..lba_count {
            let mut sector = [0_u8; BLOCK_SIZE];
            cache.read_cached(start_lba + i as u64, &mut sector)?;
            let offset = i * BLOCK_SIZE;
            let end = (offset + BLOCK_SIZE).min(SUPERBLOCK_SIZE);
            raw[offset..end].copy_from_slice(&sector[..end - offset]);
        }

        let magic = u16::from_le_bytes([raw[0x38], raw[0x39]]);
        if magic != EXT4_MAGIC {
            return Err(Error::NotFound);
        }

        let rev_level = u32::from_le_bytes([raw[0x4C], raw[0x4D], raw[0x4E], raw[0x4F]]);
        let log_block_size = u32::from_le_bytes([raw[0x18], raw[0x19], raw[0x1A], raw[0x1B]]);

        let sb = Ext4Superblock {
            inodes_count: u32::from_le_bytes([raw[0x00], raw[0x01], raw[0x02], raw[0x03]]),
            blocks_count: u32::from_le_bytes([raw[0x04], raw[0x05], raw[0x06], raw[0x07]]),
            free_blocks_count: u32::from_le_bytes([raw[0x0C], raw[0x0D], raw[0x0E], raw[0x0F]]),
            free_inodes_count: u32::from_le_bytes([raw[0x10], raw[0x11], raw[0x12], raw[0x13]]),
            log_block_size,
            blocks_per_group: u32::from_le_bytes([raw[0x20], raw[0x21], raw[0x22], raw[0x23]]),
            inodes_per_group: u32::from_le_bytes([raw[0x28], raw[0x29], raw[0x2A], raw[0x2B]]),
            magic,
            rev_level,
            inode_size: u16::from_le_bytes([raw[0x58], raw[0x59]]),
            feature_compat: u32::from_le_bytes([raw[0x60], raw[0x61], raw[0x62], raw[0x63]]),
            feature_incompat: u32::from_le_bytes([raw[0x64], raw[0x65], raw[0x66], raw[0x67]]),
        };

        // Accept ext4 volumes with features this driver handles.
        // Reject any volume with genuinely unknown INCOMPAT feature flags.
        if sb.feature_incompat & !EXT4_FEATURE_INCOMPAT_SUPPORTED != 0 {
            return Err(Error::Unsupported);
        }

        let block_size = sb.block_size();
        if !(1024..=4096).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(Error::DeviceError);
        }

        let inode_size = if sb.rev_level >= 1 {
            sb.inode_size as usize
        } else {
            EXT4_GOOD_OLD_INODE_SIZE
        };
        if inode_size < EXT4_GOOD_OLD_INODE_SIZE || inode_size > block_size {
            return Err(Error::InvalidArgument);
        }

        Ok(sb)
    }

    pub(crate) fn read_bg_descriptors(
        sb: &Ext4Superblock,
        cache: &BlockCache,
    ) -> Result<Vec<Ext4BgDescriptor>> {
        let block_size = sb.block_size();
        let num_groups = sb.block_group_count() as usize;
        let first_bg_block: u64 = if block_size > 1024 { 1 } else { 2 };
        let bg_size_per_entry: usize = 32;
        let entries_per_block = block_size / bg_size_per_entry;
        let bg_table_blocks = num_groups.div_ceil(entries_per_block);
        let mut entries = Vec::with_capacity(num_groups);

        for block_idx in 0..bg_table_blocks {
            let ext2_block = first_bg_block + block_idx as u64;
            let lba = ext2_block * (block_size / BLOCK_SIZE) as u64;
            let sectors = block_size / BLOCK_SIZE;
            let mut block_buf = vec![0_u8; block_size];

            for i in 0..sectors {
                let mut sector = [0_u8; BLOCK_SIZE];
                cache.read_cached(lba + i as u64, &mut sector)?;
                let offset = i * BLOCK_SIZE;
                let len = BLOCK_SIZE.min(block_size - offset);
                block_buf[offset..offset + len].copy_from_slice(&sector[..len]);
            }

            let entries_this_block = entries_per_block.min(num_groups - entries.len());
            for i in 0..entries_this_block {
                let offset = i * bg_size_per_entry;
                let e = &block_buf[offset..offset + bg_size_per_entry];
                entries.push(Ext4BgDescriptor {
                    bg_block_bitmap: u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
                    bg_inode_bitmap: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
                    bg_inode_table: u32::from_le_bytes([e[8], e[9], e[10], e[11]]),
                    bg_free_blocks_count: u16::from_le_bytes([e[12], e[13]]),
                    bg_free_inodes_count: u16::from_le_bytes([e[14], e[15]]),
                    bg_used_dirs_count: u16::from_le_bytes([e[16], e[17]]),
                });
            }
        }

        Ok(entries)
    }

    pub(crate) fn read_inode(&self, ino: u32) -> Result<Ext4Inode> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Error::InvalidArgument);
        }

        let group = self.sb.group_of_ino(ino);
        let index = self.sb.inode_index_in_group(ino);
        let bg = &self.bg_descriptors.lock()[group as usize];

        let inode_size = if self.sb.rev_level >= 1 {
            self.sb.inode_size as usize
        } else {
            EXT4_GOOD_OLD_INODE_SIZE
        };

        let inode_table_block = bg.bg_inode_table as u64;
        let block_size = self.block_size();
        let inodes_per_block = block_size / inode_size;
        let block_offset = (index as usize) / inodes_per_block;
        let inode_offset_in_block = (index as usize) % inodes_per_block;

        let mut block_buf = vec![0_u8; block_size];
        self.read_ext2_block(inode_table_block + block_offset as u64, &mut block_buf)?;

        let raw = &block_buf
            [inode_offset_in_block * inode_size..(inode_offset_in_block + 1) * inode_size];

        let mode = u16::from_le_bytes([raw[0], raw[1]]);
        let uid = u16::from_le_bytes([raw[2], raw[3]]);
        let size_low = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let gid = u16::from_le_bytes([raw[24], raw[25]]);
        let links_count = u16::from_le_bytes([raw[26], raw[27]]);
        let flags = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);

        let mut block = [0_u32; EXT4_TIND_BLOCK + 1];
        for (i, item) in block.iter_mut().enumerate() {
            let off = 40 + i * 4;
            *item = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        }

        let osd2_start = 40 + (EXT4_TIND_BLOCK + 1) * 4;
        let uid_high = u16::from_le_bytes([raw[osd2_start + 4], raw[osd2_start + 5]]);
        let gid_high = u16::from_le_bytes([raw[osd2_start + 6], raw[osd2_start + 7]]);

        // Parse 256-byte inode extension fields (zero for 128-byte inodes).
        let (size_high, block_high) = if inode_size >= 256 {
            // i_size_hi is at raw offset 0x6C, but our slice starts at inode start.
            let size_high = u32::from_le_bytes([raw[0x6C], raw[0x6D], raw[0x6E], raw[0x6F]]);
            let mut block_high = [0_u16; EXT4_TIND_BLOCK + 1];
            // i_block_hi starts at raw offset 0x6A (15 × u16 = 30 bytes).
            for (i, item) in block_high.iter_mut().enumerate().take(EXT4_TIND_BLOCK + 1) {
                let off = 0x6A + i * 2;
                *item = u16::from_le_bytes([raw[off], raw[off + 1]]);
            }
            (size_high, block_high)
        } else {
            (0, [0_u16; EXT4_TIND_BLOCK + 1])
        };

        Ok(Ext4Inode {
            mode,
            uid,
            size_low,
            atime: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
            ctime: u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]),
            mtime: u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]),
            gid,
            links_count,
            block,
            uid_high,
            gid_high,
            flags,
            size_high,
            block_high,
        })
    }

    pub(crate) fn read_inode_data(
        &self,
        inode: &Ext4Inode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let file_size = inode.file_size();
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let max_bytes = ((file_size - offset) as usize).min(buffer.len());
        let start_block = (offset / block_size) as usize;
        let block_off = (offset % block_size) as usize;
        let mut bytes_read = 0;
        let mut remaining = max_bytes;
        let total_blocks = start_block + (remaining + block_off).div_ceil(block_size as usize);

        for rel_block in 0..total_blocks {
            if bytes_read >= max_bytes {
                break;
            }
            let abs_block = start_block + rel_block;
            let Some(phys_block) = self.map_inode_block(inode, abs_block)? else {
                break;
            };

            let mut block_buf = vec![0_u8; block_size as usize];
            self.read_ext2_block(phys_block, &mut block_buf)?;

            let copy_start = if rel_block == 0 { block_off } else { 0 };
            let copy_end = (copy_start + remaining).min(block_size as usize);
            let copy_len = copy_end - copy_start;

            buffer[bytes_read..bytes_read + copy_len]
                .copy_from_slice(&block_buf[copy_start..copy_start + copy_len]);
            bytes_read += copy_len;
            remaining -= copy_len;
        }

        Ok(bytes_read)
    }

    /// Walk an extent tree to map a logical block to a physical block.
    ///
    /// The extent tree root lives in `i_block[0..60]` as an [`Ext4ExtentHeader`]
    /// followed by either [`Ext4ExtentIdx`] (internal nodes) or [`Ext4Extent`]
    /// (leaf nodes).  Internal nodes are walked by comparing `block_idx` against
    /// `ei_block`; leaf nodes are searched for an extent covering `block_idx`.
    fn map_inode_block_extents(&self, inode: &Ext4Inode, block_idx: usize) -> Result<Option<u64>> {
        let block_size = self.block_size();
        let root_bytes = inode_block_bytes(inode);
        let header = parse_extent_header(&root_bytes);

        if header.eh_magic != EXT4_EXT_MAGIC {
            return Err(Error::DeviceError);
        }

        let mut node_buf = vec![0_u8; block_size];
        let mut node_bytes = root_bytes.to_vec();
        let mut depth = header.eh_depth;

        loop {
            let hdr = parse_extent_header(&node_bytes);
            if hdr.eh_magic != EXT4_EXT_MAGIC {
                return Err(Error::DeviceError);
            }

            if depth == 0 {
                // Leaf node — search for the extent covering block_idx.
                let block_u32 = block_idx as u32;
                for i in 0..hdr.eh_entries as usize {
                    let off = 12 + i * 12;
                    let ext = parse_extent(&node_bytes[off..off + 12]);
                    let start = ext.ee_block;
                    let count = ext.len() as u32;
                    if block_u32 >= start && block_u32 < start + count {
                        let offset = (block_u32 - start) as u64;
                        return Ok(Some(ext.start_block() + offset));
                    }
                }
                return Ok(None); // block not found in extent tree
            }

            // Internal node — find the child covering block_idx.
            let block_u32 = block_idx as u32;
            let mut child_block: Option<u64> = None;
            for i in 0..hdr.eh_entries as usize {
                let off = 12 + i * 12;
                let idx = parse_extent_idx(&node_bytes[off..off + 12]);
                // Indices are sorted by ei_block ascending.  Track the last
                // index whose ei_block ≤ block_u32 — that is the child
                // whose subtree covers this logical block.
                if block_u32 >= idx.ei_block {
                    child_block = Some(idx.leaf_block());
                } else {
                    break;
                }
            }

            let phys = child_block.ok_or(Error::DeviceError)?;
            self.read_ext2_block(phys, &mut node_buf)?;
            node_bytes = node_buf.clone();
            depth -= 1;
        }
    }

    fn map_inode_block(&self, inode: &Ext4Inode, block_idx: usize) -> Result<Option<u64>> {
        // Dispatch to extent tree for inodes with EXT4_EXTENTS_FL set.
        if inode.has_extents() {
            return self.map_inode_block_extents(inode, block_idx);
        }

        let block_size = self.block_size();

        if block_idx < EXT4_NDIR_BLOCKS {
            let phys = inode.block_48(block_idx);
            return Ok(if phys == 0 { None } else { Some(phys) });
        }

        let ptrs_per_blk = ptrs_per_block(block_size);

        // Singly-indirect
        if block_idx < EXT4_NDIR_BLOCKS + ptrs_per_blk {
            let indirect_blk = inode.block_48(EXT4_IND_BLOCK);
            if indirect_blk == 0 {
                return Ok(None);
            }
            let idx = block_idx - EXT4_NDIR_BLOCKS;
            let ptr = self.read_block_ptr(indirect_blk, idx)?;
            return Ok(if ptr == 0 { None } else { Some(ptr) });
        }

        // Doubly-indirect
        let dind_start = EXT4_NDIR_BLOCKS + ptrs_per_blk;
        let dind_count = ptrs_per_blk * ptrs_per_blk;
        if block_idx < dind_start + dind_count {
            let dind_blk = inode.block_48(EXT4_DIND_BLOCK);
            if dind_blk == 0 {
                return Ok(None);
            }
            let offset = block_idx - dind_start;
            let outer_idx = offset / ptrs_per_blk;
            let inner_idx = offset % ptrs_per_blk;
            let indirect_blk = self.read_block_ptr(dind_blk, outer_idx)?;
            if indirect_blk == 0 {
                return Ok(None);
            }
            let ptr = self.read_block_ptr(indirect_blk, inner_idx)?;
            return Ok(if ptr == 0 { None } else { Some(ptr) });
        }

        // Triply-indirect
        let ti_start = dind_start + dind_count;
        let ti_count = ptrs_per_blk * ptrs_per_blk * ptrs_per_blk;
        if block_idx < ti_start + ti_count {
            let tind_blk = inode.block_48(EXT4_TIND_BLOCK);
            if tind_blk == 0 {
                return Ok(None);
            }
            let offset = block_idx - ti_start;
            let l1_idx = offset / (ptrs_per_blk * ptrs_per_blk);
            let rest = offset % (ptrs_per_blk * ptrs_per_blk);
            let l2_idx = rest / ptrs_per_blk;
            let l3_idx = rest % ptrs_per_blk;
            let dind_blk = self.read_block_ptr(tind_blk, l1_idx)?;
            if dind_blk == 0 {
                return Ok(None);
            }
            let ind_blk = self.read_block_ptr(dind_blk, l2_idx)?;
            if ind_blk == 0 {
                return Ok(None);
            }
            let ptr = self.read_block_ptr(ind_blk, l3_idx)?;
            return Ok(if ptr == 0 { None } else { Some(ptr) });
        }

        Ok(None)
    }

    fn read_block_ptr(&self, blk: u64, idx: usize) -> Result<u64> {
        let block_size = self.block_size();
        let ptrs = ptrs_per_block(block_size);
        if idx >= ptrs {
            return Err(Error::InvalidArgument);
        }
        let mut buf = self.block_buf.lock();
        buf.resize(block_size, 0);
        self.read_ext2_block(blk, &mut buf)?;
        let off = idx * 4;
        Ok(u64::from(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ])))
    }

    /// Read every pointer stored in an indirect block, returning them in order.
    /// This batches what would otherwise be N individual `read_block_ptr` calls
    /// into a single block-cache read.
    fn read_block_ptrs(&self, blk: u64) -> Result<Vec<u64>> {
        let block_size = self.block_size();
        let ptrs = ptrs_per_block(block_size);
        let mut buf = self.block_buf.lock();
        buf.resize(block_size, 0);
        self.read_ext2_block(blk, &mut buf)?;
        let mut out = Vec::with_capacity(ptrs);
        for i in 0..ptrs {
            let off = i * 4;
            let ptr = u64::from(u32::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]));
            out.push(ptr);
        }
        Ok(out)
    }

    // ─── extent tree write-helpers ───────────────────────────────────────

    /// Initialise the `i_block` area with an empty extent tree header,
    /// returning (block, block_high, flags) suitable for a new extent inode.
    fn new_extent_inode_blocks() -> ([u32; EXT4_TIND_BLOCK + 1], [u16; EXT4_TIND_BLOCK + 1], u32) {
        let mut block = [0_u32; EXT4_TIND_BLOCK + 1];
        let block_high = [0_u16; EXT4_TIND_BLOCK + 1];
        // Write an empty extent header: magic=0xF30A, entries=0, max=4, depth=0
        let mut raw = [0_u8; 12];
        write_extent_header(
            &mut raw,
            &Ext4ExtentHeader {
                eh_magic: EXT4_EXT_MAGIC,
                eh_entries: 0,
                eh_max: 4,
                eh_depth: 0,
                eh_generation: 0,
            },
        );
        for i in 0..3 {
            block[i] =
                u32::from_le_bytes([raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]);
        }
        (block, block_high, EXT4_EXTENTS_FL)
    }

    /// Read the extent tree leaf node from `inode`, returning the raw leaf bytes
    /// and the header.  If the tree is empty (entries==0), returns `Ok(None)`.
    fn read_extent_leaf_node(
        &self,
        inode: &Ext4Inode,
    ) -> Result<Option<(Ext4ExtentHeader, Vec<u8>)>> {
        let root_bytes = inode_block_bytes(inode);
        let header = parse_extent_header(&root_bytes);
        if header.eh_magic != EXT4_EXT_MAGIC {
            return Err(Error::DeviceError);
        }
        if header.eh_depth == 0 {
            return Ok(Some((header, root_bytes.to_vec())));
        }
        // Walk internal nodes to reach the rightmost leaf.
        let block_size = self.block_size();
        let mut node_buf = vec![0_u8; block_size];
        let mut node_bytes = root_bytes.to_vec();
        let mut depth = header.eh_depth;
        loop {
            let hdr = parse_extent_header(&node_bytes);
            if hdr.eh_magic != EXT4_EXT_MAGIC {
                return Err(Error::DeviceError);
            }
            if depth == 0 {
                return Ok(Some((hdr, node_bytes)));
            }
            // Take the last index entry (rightmost child).
            let last_idx = hdr.eh_entries as usize;
            if last_idx == 0 {
                return Ok(None);
            }
            let off = 12 + (last_idx - 1) * 12;
            let idx = parse_extent_idx(&node_bytes[off..off + 12]);
            self.read_ext2_block(idx.leaf_block(), &mut node_buf)?;
            node_bytes = node_buf.clone();
            depth -= 1;
        }
    }

    /// Allocate a new data block for an extent-based inode.
    /// Simple strategy:
    /// 1. Walk to the leaf node
    /// 2. If the last extent's end is adjacent to a free block, grow it
    /// 3. Otherwise, allocate a new block and append a new extent entry
    /// 4. If the leaf is full, fall back to indirect blocks
    fn allocate_extent_block(&self, inode: &mut Ext4Inode, logical_block: usize) -> Result<u64> {
        let block_size = self.block_size();
        // Read current leaf node.
        let Some((leaf_hdr, leaf_bytes)) = self.read_extent_leaf_node(inode)? else {
            // Empty tree — allocate first block and create the leaf.
            let new_block = self.allocate_block()?;
            // Build leaf node: header (12) + one extent (12) = 24 bytes
            let capacity = (block_size - 12) / 12;
            let max_entries = (capacity as u16).min(4);
            let mut raw = vec![0_u8; block_size];
            write_extent_header(
                &mut raw[..12],
                &Ext4ExtentHeader {
                    eh_magic: EXT4_EXT_MAGIC,
                    eh_entries: 1,
                    eh_max: max_entries,
                    eh_depth: 0,
                    eh_generation: 0,
                },
            );
            write_extent(
                &mut raw[12..24],
                &Ext4Extent {
                    ee_block: logical_block as u32,
                    ee_len: 1,
                    ee_start_hi: ((new_block >> 32) & 0xFFFF) as u16,
                    ee_start_lo: new_block as u32,
                },
            );
            // Allocate metadata block for the leaf node.
            let leaf_block = self.allocate_block()?;
            self.write_ext2_block(leaf_block, &raw)?;
            // Store the leaf block as the extent tree root (depth-0 node).
            let root_raw = raw;
            write_inode_block_bytes(inode, &root_raw[..60].try_into().unwrap_or([0; 60]));
            // Set EXT4_EXTENTS_FL.
            inode.flags = EXT4_EXTENTS_FL;
            return Ok(new_block);
        };

        // Parse existing extents from the leaf.
        let extents: Vec<Ext4Extent> = (0..leaf_hdr.eh_entries as usize)
            .map(|i| parse_extent(&leaf_bytes[12 + i * 12..12 + (i + 1) * 12]))
            .collect();

        // Try to grow the last extent if adjacent.
        if let Some(last) = extents.last() {
            let last_logical_end = last.ee_block as u64 + last.len() as u64;
            if last_logical_end == logical_block as u64 {
                let last_phys_end = last.start_block() + last.len() as u64;
                // Try to allocate the next physical block.
                let next_phys = last_phys_end;
                // Simple check: if the next physical block is free, use it.
                // For now just do a direct allocation and if it happens to
                // match, great; otherwise create a new extent.
                // Actually, we just allocate a new block and see if it's
                // adjacent.  This is simplified — a real ext4 driver would
                // check the block bitmap first.
                let new_block = self.allocate_block()?;
                if new_block == next_phys {
                    // Grow the last extent!
                    let mut raw_leaf = leaf_bytes.clone();
                    let off = 12 + (extents.len() - 1) * 12;
                    let ee_len = last.len() + 1;
                    raw_leaf[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
                    // Write back the leaf node (it's the tree root if depth=0,
                    // or a separate block).
                    write_inode_block_bytes(inode, &raw_leaf[..60].try_into().unwrap_or([0; 60]));
                    return Ok(new_block);
                }
                // Not adjacent — fall through to new extent insertion.
                // (new_block was already allocated; we'll use it below)
                self.free_block(new_block)?;
            }
        }

        // Append a new extent entry.
        if leaf_hdr.eh_entries < leaf_hdr.eh_max {
            let new_block = self.allocate_block()?;
            let new_ext = Ext4Extent {
                ee_block: logical_block as u32,
                ee_len: 1,
                ee_start_hi: ((new_block >> 32) & 0xFFFF) as u16,
                ee_start_lo: new_block as u32,
            };
            let mut raw_leaf = leaf_bytes.clone();
            let off = 12 + leaf_hdr.eh_entries as usize * 12;
            write_extent(&mut raw_leaf[off..off + 12], &new_ext);
            // Bump entry count.
            let entries = leaf_hdr.eh_entries + 1;
            raw_leaf[2..4].copy_from_slice(&entries.to_le_bytes());
            write_inode_block_bytes(inode, &raw_leaf[..60].try_into().unwrap_or([0; 60]));
            return Ok(new_block);
        }

        // Leaf is full — fall back to indirect blocks.
        // Clear EXT4_EXTENTS_FL, zero i_block, and retry with indirect path.
        inode.flags = 0;
        inode.block = [0_u32; EXT4_TIND_BLOCK + 1];
        inode.block_high = [0_u16; EXT4_TIND_BLOCK + 1];
        self.allocate_inode_block_ext4_indirect(inode, logical_block)
    }

    /// Free all data blocks (and metadata blocks) owned by an extent-based inode.
    fn free_extent_blocks(&self, inode: &Ext4Inode) -> Result<()> {
        let block_size = self.block_size();
        let root_bytes = inode_block_bytes(inode);
        let header = parse_extent_header(&root_bytes);
        if header.eh_magic != EXT4_EXT_MAGIC {
            return Ok(()); // not an extent tree; nothing to do
        }

        // Walk the tree and collect all physical blocks (data + metadata).
        let mut metadata_blocks: Vec<u64> = Vec::new();
        let mut data_blocks: Vec<u64> = Vec::new();

        if header.eh_depth == 0 {
            // Root is leaf — free data blocks, no metadata blocks.
            for i in 0..header.eh_entries as usize {
                let ext = parse_extent(&root_bytes[12 + i * 12..12 + (i + 1) * 12]);
                let start = ext.start_block();
                for j in 0..ext.len() as u64 {
                    data_blocks.push(start + j);
                }
            }
        } else {
            // Need to walk the tree to find all leaf nodes.
            let mut node_buf = vec![0_u8; block_size];
            let mut stack: Vec<(Ext4ExtentHeader, Vec<u8>, u16)> =
                vec![(header, root_bytes.to_vec(), 0)];
            while let Some((hdr, node_bytes, _depth)) = stack.pop() {
                if hdr.eh_depth == 0 {
                    // Leaf node — collect data blocks.
                    for i in 0..hdr.eh_entries as usize {
                        let ext = parse_extent(&node_bytes[12 + i * 12..12 + (i + 1) * 12]);
                        let start = ext.start_block();
                        for j in 0..ext.len() as u64 {
                            data_blocks.push(start + j);
                        }
                    }
                } else {
                    // Internal node — push children and track metadata blocks.
                    for i in 0..hdr.eh_entries as usize {
                        let idx = parse_extent_idx(&node_bytes[12 + i * 12..12 + (i + 1) * 12]);
                        let child_block = idx.leaf_block();
                        metadata_blocks.push(child_block);
                        self.read_ext2_block(child_block, &mut node_buf)?;
                        let child_hdr = parse_extent_header(&node_buf);
                        stack.push((child_hdr, node_buf.clone(), hdr.eh_depth - 1));
                    }
                }
            }
        }

        // Free all data blocks.
        for blk in &data_blocks {
            self.free_block(*blk)?;
        }
        // Free all metadata blocks (internal nodes; leaf nodes are the root
        // and live in the inode, so they are not freed).
        for blk in &metadata_blocks {
            self.free_block(*blk)?;
        }

        Ok(())
    }

    pub(crate) fn read_dir_entries(&self, dir_inode: &Ext4Inode) -> Result<Vec<Ext4DirEntry>> {
        let file_size = dir_inode.file_size();
        let block_size = self.block_size() as u64;
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut offset: u64 = 0;

        while offset < file_size {
            let block_idx = (offset / block_size) as usize;
            let block_off = (offset % block_size) as usize;

            let Some(phys_block) = self.map_inode_block(dir_inode, block_idx)? else {
                break;
            };

            let mut block_buf = vec![0_u8; block_size as usize];
            self.read_ext2_block(phys_block, &mut block_buf)?;

            let mut pos = block_off;
            while pos + 8 <= block_size as usize {
                let rec_len = u16::from_le_bytes([block_buf[pos + 4], block_buf[pos + 5]]) as usize;
                if rec_len == 0 || rec_len < 8 {
                    break;
                }
                let name_len = block_buf[pos + 6] as usize;
                let inode = u32::from_le_bytes([
                    block_buf[pos],
                    block_buf[pos + 1],
                    block_buf[pos + 2],
                    block_buf[pos + 3],
                ]);
                let file_type = block_buf[pos + 7];

                if inode != 0 && pos + 8 + name_len <= block_size as usize {
                    let name_bytes = &block_buf[pos + 8..pos + 8 + name_len];
                    // Use from_utf8_lossy to ensure non-UTF-8 directory entries
                    // are at least visible rather than silently dropped.  This
                    // matches the SimpleFs behaviour; U+FFFD replacement
                    // characters make it obvious to users that a filename
                    // contains non-UTF-8 bytes.
                    //
                    // Store the filename as-is — the kernel treats names as
                    // opaque UTF-8 byte sequences (Linux / HarmonyOS semantics).
                    let name = String::from_utf8_lossy(name_bytes).into_owned();
                    entries.push(Ext4DirEntry {
                        inode,
                        name,
                        file_type,
                    });
                }

                pos += rec_len;
                if pos >= block_size as usize {
                    break;
                }
            }

            offset = ((offset / block_size) + 1) * block_size;
        }

        Ok(entries)
    }

    pub(crate) fn walk_path(&self, path: &str) -> Result<(u32, Ext4Inode)> {
        self.walk_path_limited(path, 0)
    }

    /// Resolve `path` to an inode, following symlinks up to `depth` levels.
    /// Internal helper — callers use [`walk_path`] which starts at depth 0.
    fn walk_path_limited(&self, path: &str, depth: usize) -> Result<(u32, Ext4Inode)> {
        const MAX_SYMLINK_DEPTH: usize = 8;
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Error::InvalidArgument); // symlink loop or too deep
        }

        if path == "/" {
            return Ok((EXT4_ROOT_INO, self.read_inode(EXT4_ROOT_INO)?));
        }

        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        let mut current_ino = EXT4_ROOT_INO;
        let mut walked = String::new(); // track the path prefix resolved so far

        for (i, component) in components.iter().enumerate() {
            let dir_inode = self.read_inode(current_ino)?;
            if dir_inode.kind() != NodeKind::Directory {
                return Err(Error::NotFound);
            }
            let entries = self.read_dir_entries(&dir_inode)?;
            let found = if dir_inode.has_casefold() {
                entries
                    .iter()
                    .find(|e| unicode::eq_unicode_insensitive(e.name.as_str(), component))
            } else {
                entries.iter().find(|e| e.name.as_str() == *component)
            };
            let entry_ino = match found {
                Some(entry) => entry.inode,
                None => return Err(Error::NotFound),
            };

            let entry_inode = self.read_inode(entry_ino)?;
            walked.push('/');
            walked.push_str(component);

            // If this component is a symlink, follow it.
            if entry_inode.kind() == NodeKind::Symlink {
                let target = self.read_symlink_target(&entry_inode)?;
                let target_str =
                    core::str::from_utf8(&target).map_err(|_| Error::InvalidArgument)?;

                // Build the unresolved suffix (remaining components after this one).
                let suffix: String = if i + 1 < components.len() {
                    let rest: Vec<&str> = components[i + 1..].to_vec();
                    format!("/{}", rest.join("/"))
                } else {
                    String::new()
                };

                // Resolve target relative to the current walked prefix.
                let resolved = if target_str.starts_with('/') {
                    format!("{}{}", target_str, suffix)
                } else {
                    format!(
                        "{}/{}",
                        walked.rsplit_once('/').map(|(p, _)| p).unwrap_or(""),
                        target_str
                    ) + &suffix
                };

                return self.walk_path_limited(&resolved, depth + 1);
            }

            current_ino = entry_ino;
        }

        Ok((current_ino, self.read_inode(current_ino)?))
    }

    /// Read the target path from a fast symlink inode (≤60 bytes stored in
    /// the block pointer array).
    pub(crate) fn read_symlink_target(&self, inode: &Ext4Inode) -> Result<Vec<u8>> {
        let len = (inode.size_low as usize).min(60);
        let mut target = [0_u8; 60];
        for i in 0..15 {
            let off = i * 4;
            let bytes = inode.block[i].to_le_bytes();
            target[off..off + 4].copy_from_slice(&bytes);
        }
        Ok(target[..len].to_vec())
    }

    /// Read the device identifier (major, minor) from a device inode.
    /// The device number is stored in `inode.block[0]` using the encoding
    /// `(major << 8) | minor`.
    pub(crate) fn read_device_id(&self, inode: &Ext4Inode) -> Result<(u32, u32)> {
        let dev = inode.block[0];
        let major = dev >> 8;
        let minor = dev & 0xFF;
        Ok((major, minor))
    }

    pub(crate) fn stat_inode(&self, _ino: u32, inode: &Ext4Inode) -> Metadata {
        Metadata::new(inode.kind(), inode.file_size() as usize).with_security(
            SecurityDescriptor::new(
                inode.owner_uid(),
                inode.owner_gid(),
                inode.permission_mode(),
            ),
        )
    }

    // ─── write helpers ──────────────────────────────────────────────────

    /// Check that the volume is writable.
    pub(crate) fn check_writable(&self) -> Result<()> {
        if self.read_only {
            Err(Error::PermissionDenied)
        } else {
            Ok(())
        }
    }

    /// Write data to an ext2 block through the cache (write-back).
    pub(crate) fn write_ext2_block(&self, ext2_block: u64, data: &[u8]) -> Result<()> {
        self.check_writable()?;
        // Write-ahead log: journal the block before writing to its final
        // location.  Data-only blocks (file contents) also pass through here,
        // but journaling them is harmless — only metadata blocks matter for
        // crash consistency, and the journal treats all blocks uniformly.
        if let Some(ref jw) = self.journal_writer {
            let mut jw = jw.lock();
            let _ = jw.write_block(&self.cache, ext2_block, data);
        }
        let lba = self.block_to_lba(ext2_block);
        let sector_count = self.sectors_per_block() as usize;
        assert!(data.len() >= self.block_size());
        for i in 0..sector_count {
            let chunk = &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            self.cache.write_back(lba + i as u64, chunk)?;
        }
        Ok(())
    }

    pub(crate) fn flush_all(&self) -> Result<()> {
        if let Some(ref jw) = self.journal_writer {
            let mut jw = jw.lock();
            jw.begin_tx(&self.cache)?;
            drop(jw);
            self.write_bg_descriptors()?;
            self.write_superblock()?;
            let mut jw = self.journal_writer.as_ref().unwrap().lock();
            jw.commit_tx(&self.cache)?;
        } else {
            self.write_bg_descriptors()?;
            self.write_superblock()?;
            self.cache.flush()?;
            self.device.flush()?;
        }
        Ok(())
    }

    /// Allocate a free block by scanning the block bitmap.
    /// Returns the allocated block number (0-based, includes boot block).
    pub(crate) fn allocate_block(&self) -> Result<u64> {
        self.check_writable()?;
        let block_size = self.block_size();
        let blocks_per_group = self.sb.blocks_per_group as u64;
        let num_groups = self.sb.block_group_count() as usize;

        for group in 0..num_groups {
            // Scope the lock to extract per-group metadata, then release
            // before doing I/O.
            let (bitmap_block, group_start, group_end) = {
                let bg = self.bg_descriptors.lock();
                let bitmap_block = bg[group].bg_block_bitmap as u64;
                let start = group as u64 * blocks_per_group;
                let end = (start + blocks_per_group).min(self.sb.blocks_count as u64);
                (bitmap_block, start, end)
            };

            let mut bitmap = vec![0_u8; block_size];
            self.read_ext2_block(bitmap_block, &mut bitmap)?;

            let max_bit = (group_end - group_start) as usize;

            for byte_idx in 0..block_size {
                let byte = bitmap[byte_idx];
                if byte != 0xFF {
                    for bit in 0..8 {
                        if byte & (1 << bit) == 0 {
                            let local_block = byte_idx * 8 + bit;
                            if local_block >= max_bit {
                                break;
                            }
                            let block = group_start + local_block as u64;

                            // Mark allocated
                            bitmap[byte_idx] |= 1 << bit;
                            self.write_ext2_block(bitmap_block, &bitmap)?;

                            // Update free block counts
                            {
                                let mut bg = self.bg_descriptors.lock();
                                bg[group].bg_free_blocks_count =
                                    bg[group].bg_free_blocks_count.saturating_sub(1);
                            }

                            return Ok(block);
                        }
                    }
                }
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Allocate a free inode, initialise it with default values, and return
    /// its number.
    pub(crate) fn allocate_inode(&self, mode: u16, uid: u32, gid: u32) -> Result<u32> {
        self.check_writable()?;
        let block_size = self.block_size();
        let inodes_per_group = self.sb.inodes_per_group;
        let num_groups = self.sb.block_group_count() as usize;

        for group in 0..num_groups {
            let (bitmap_block, group_base_ino) = {
                let bg = self.bg_descriptors.lock();
                let bitmap_block = bg[group].bg_inode_bitmap as u64;
                let base_ino = group as u32 * inodes_per_group;
                (bitmap_block, base_ino)
            };

            let mut bitmap = vec![0_u8; block_size];
            self.read_ext2_block(bitmap_block, &mut bitmap)?;

            let max_inodes_in_group = (inodes_per_group as usize)
                .min(self.sb.inodes_count as usize - group_base_ino as usize);

            for byte_idx in 0..block_size {
                let byte = bitmap[byte_idx];
                if byte != 0xFF {
                    for bit in 0..8 {
                        if byte & (1 << bit) == 0 {
                            let local_bit = byte_idx * 8 + bit;
                            if local_bit >= max_inodes_in_group {
                                continue;
                            }
                            // Bit N of group G's bitmap maps to inode
                            // G * inodes_per_group + N + 1 (inode 0 does
                            // not exist).
                            let ino = group_base_ino + local_bit as u32 + 1;

                            // Mark allocated
                            bitmap[byte_idx] |= 1 << bit;
                            self.write_ext2_block(bitmap_block, &bitmap)?;

                            // Update free inode counts
                            {
                                let mut bg = self.bg_descriptors.lock();
                                bg[group].bg_free_inodes_count =
                                    bg[group].bg_free_inodes_count.saturating_sub(1);
                            }

                            // Initialise the inode.
                            self.write_fresh_inode(ino, mode, uid, gid)?;

                            // Track directory count for the block group.
                            if mode & EXT4_S_IFMT == EXT4_S_IFDIR {
                                let mut bg = self.bg_descriptors.lock();
                                bg[group].bg_used_dirs_count =
                                    bg[group].bg_used_dirs_count.saturating_add(1);
                            }

                            return Ok(ino);
                        }
                    }
                }
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Write a newly-allocated (all-zeroes except mode/size/links) inode.
    fn write_fresh_inode(&self, ino: u32, mode: u16, uid: u32, gid: u32) -> Result<()> {
        // Build a minimal in-memory inode and serialise it.
        // On ext4 volumes with EXTENTS feature, new regular files start with
        // an empty extent tree header.  Directories never use extents —
        // they always use the classic indirect/direct block format.
        let is_regular_file = mode & EXT4_S_IFMT == EXT4_S_IFREG;
        let (block, block_high, flags) = if self.sb.has_extents() && is_regular_file {
            Self::new_extent_inode_blocks()
        } else {
            (
                [0_u32; EXT4_TIND_BLOCK + 1],
                [0_u16; EXT4_TIND_BLOCK + 1],
                0,
            )
        };
        let inode = Ext4Inode {
            mode,
            uid: (uid & 0xFFFF) as u16,
            size_low: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            gid: (gid & 0xFFFF) as u16,
            links_count: 1,
            block,
            uid_high: ((uid >> 16) & 0xFFFF) as u16,
            gid_high: ((gid >> 16) & 0xFFFF) as u16,
            flags,
            size_high: 0,
            block_high,
        };

        self.write_inode_raw(ino, &inode)
    }

    /// Write an inode back to the inode table.
    pub(crate) fn write_inode_raw(&self, ino: u32, inode: &Ext4Inode) -> Result<()> {
        self.write_inode_raw_impl(ino, |raw| {
            raw[0x00..0x02].copy_from_slice(&inode.mode.to_le_bytes());
            raw[0x02..0x04].copy_from_slice(&inode.uid.to_le_bytes());
            raw[0x04..0x08].copy_from_slice(&inode.size_low.to_le_bytes());
            raw[0x18..0x1A].copy_from_slice(&inode.gid.to_le_bytes());
            raw[0x1A..0x1C].copy_from_slice(&inode.links_count.to_le_bytes());
            raw[0x20..0x24].copy_from_slice(&inode.flags.to_le_bytes());
            for i in 0..=EXT4_TIND_BLOCK {
                let off = 40 + i * 4;
                raw[off..off + 4].copy_from_slice(&inode.block[i].to_le_bytes());
            }
            let osd2_start = 40 + (EXT4_TIND_BLOCK + 1) * 4;
            raw[osd2_start + 4..osd2_start + 6].copy_from_slice(&inode.uid_high.to_le_bytes());
            raw[osd2_start + 6..osd2_start + 8].copy_from_slice(&inode.gid_high.to_le_bytes());
            // Write 256-byte inode extension fields when present.
            let inode_size = self.sb.inode_size as usize;
            if inode_size >= 256 {
                raw[0x6C..0x70].copy_from_slice(&inode.size_high.to_le_bytes());
                for i in 0..=EXT4_TIND_BLOCK {
                    let off = 0x6A + i * 2;
                    raw[off..off + 2].copy_from_slice(&inode.block_high[i].to_le_bytes());
                }
            }
        })
    }

    /// Write a raw inode using a closure that fills the raw bytes.
    /// Shared by `write_inode_raw` and `write_inode_zero`.
    fn write_inode_raw_impl(&self, ino: u32, fill: impl FnOnce(&mut [u8])) -> Result<()> {
        let inode_size = if self.sb.rev_level >= 1 {
            self.sb.inode_size as usize
        } else {
            EXT4_GOOD_OLD_INODE_SIZE
        };
        let group = self.sb.group_of_ino(ino);
        let index = self.sb.inode_index_in_group(ino);
        let bg = &self.bg_descriptors.lock()[group as usize];
        let inode_table_block = bg.bg_inode_table as u64;
        let block_size = self.block_size();
        let inodes_per_block = block_size / inode_size;
        let block_offset = (index as usize) / inodes_per_block;
        let inode_offset_in_block = (index as usize) % inodes_per_block;
        let ext2_block = inode_table_block + block_offset as u64;

        let mut buf = vec![0_u8; block_size];
        self.read_ext2_block(ext2_block, &mut buf)?;

        let raw =
            &mut buf[inode_offset_in_block * inode_size..(inode_offset_in_block + 1) * inode_size];
        raw.fill(0);
        fill(raw);

        self.write_ext2_block(ext2_block, &buf)
    }

    /// Zero out an inode in the inode table (used when freeing an inode).
    fn write_inode_zero(&self, ino: u32) -> Result<()> {
        self.write_inode_raw_impl(ino, |_raw| {})
    }

    /// Write a single block pointer inside an indirect block.
    fn write_block_ptr(&self, blk: u64, idx: usize, value: u64) -> Result<()> {
        let block_size = self.block_size();
        let ptrs = ptrs_per_block(block_size);
        if idx >= ptrs {
            return Err(Error::InvalidArgument);
        }
        let mut buf = self.block_buf.lock();
        buf.resize(block_size, 0);
        self.read_ext2_block(blk, &mut buf)?;
        let off = idx * 4;
        buf[off..off + 4].copy_from_slice(&(value as u32).to_le_bytes());
        self.write_ext2_block(blk, &buf)
    }

    /// Free a single block: clear the bitmap bit and update the free count.
    fn free_block(&self, block_num: u64) -> Result<()> {
        self.check_writable()?;
        let block_size = self.block_size();
        let blocks_per_group = self.sb.blocks_per_group as u64;

        let group = (block_num / blocks_per_group) as usize;
        let local_block = (block_num % blocks_per_group) as usize;

        let bitmap_block = {
            let bg = self.bg_descriptors.lock();
            if group >= bg.len() {
                return Err(Error::InvalidArgument);
            }
            bg[group].bg_block_bitmap as u64
        };

        let mut bitmap = vec![0_u8; block_size];
        self.read_ext2_block(bitmap_block, &mut bitmap)?;

        let byte_idx = local_block / 8;
        let bit = local_block % 8;
        if byte_idx >= block_size || local_block >= self.sb.blocks_per_group as usize {
            return Err(Error::InvalidArgument);
        }
        if bitmap[byte_idx] & (1 << bit) == 0 {
            return Err(Error::InvalidArgument); // already free
        }
        bitmap[byte_idx] &= !(1 << bit);
        self.write_ext2_block(bitmap_block, &bitmap)?;

        {
            let mut bg = self.bg_descriptors.lock();
            bg[group].bg_free_blocks_count = bg[group].bg_free_blocks_count.saturating_add(1);
        }
        Ok(())
    }

    /// Free an inode: clear the bitmap bit, zero the inode table entry, and
    /// update the free count.
    pub(crate) fn free_inode(&self, ino: u32) -> Result<()> {
        self.check_writable()?;
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Error::InvalidArgument);
        }
        let block_size = self.block_size();
        let inodes_per_group = self.sb.inodes_per_group;

        let idx = (ino - 1) as usize;
        let group = (idx as u32 / inodes_per_group) as usize;
        let local_idx = idx as u32 % inodes_per_group;

        let bitmap_block = {
            let bg = self.bg_descriptors.lock();
            if group >= bg.len() {
                return Err(Error::InvalidArgument);
            }
            bg[group].bg_inode_bitmap as u64
        };

        let mut bitmap = vec![0_u8; block_size];
        self.read_ext2_block(bitmap_block, &mut bitmap)?;

        let byte_idx = local_idx as usize / 8;
        let bit = local_idx as usize % 8;
        if byte_idx >= block_size {
            return Err(Error::InvalidArgument);
        }
        if bitmap[byte_idx] & (1 << bit) == 0 {
            return Err(Error::InvalidArgument); // already free
        }
        // If this is a directory, decrement the block-group's directory count.
        // The inode is still on-disk, so read it to inspect the mode.
        if let Ok(inode) = self.read_inode(ino) {
            if inode.mode & EXT4_S_IFMT == EXT4_S_IFDIR {
                let mut bg = self.bg_descriptors.lock();
                bg[group].bg_used_dirs_count = bg[group].bg_used_dirs_count.saturating_sub(1);
            }
        }

        bitmap[byte_idx] &= !(1 << bit);
        self.write_ext2_block(bitmap_block, &bitmap)?;

        // Zero the inode table entry.
        self.write_inode_zero(ino)?;

        // Update free inode count.
        {
            let mut bg = self.bg_descriptors.lock();
            bg[group].bg_free_inodes_count = bg[group].bg_free_inodes_count.saturating_add(1);
        }
        Ok(())
    }

    /// Walk every block owned by an inode (direct, singly-, doubly-, and
    /// triply-indirect) and free each one, including the indirect blocks
    /// themselves.
    pub(crate) fn free_inode_blocks(&self, ino: u32) -> Result<()> {
        let inode = self.read_inode(ino)?;

        // Device nodes and fast symlinks store non-block data (device IDs,
        // target paths) in the block-pointer array — nothing to free.
        let inner_kind = inode.mode & EXT4_S_IFMT;
        if inner_kind == EXT4_S_IFCHR || inner_kind == EXT4_S_IFBLK || inner_kind == EXT4_S_IFLNK {
            return Ok(());
        }

        // Dispatch to extent-based freeing.
        if inode.has_extents() {
            return self.free_extent_blocks(&inode);
        }

        // Direct blocks.
        for i in 0..EXT4_NDIR_BLOCKS {
            let blk = inode.block_48(i);
            if blk != 0 {
                self.free_block(blk)?;
            }
        }

        // Singly-indirect — batch-read all pointers at once.
        let indirect_blk = inode.block_48(EXT4_IND_BLOCK);
        if indirect_blk != 0 {
            let ptrs = self.read_block_ptrs(indirect_blk)?;
            for &p in &ptrs {
                if p != 0 {
                    self.free_block(p)?;
                }
            }
            self.free_block(indirect_blk)?;
        }

        // Doubly-indirect — batch-read each level.
        let dind_blk = inode.block_48(EXT4_DIND_BLOCK);
        if dind_blk != 0 {
            let outer_ptrs = self.read_block_ptrs(dind_blk)?;
            for &inner_blk in &outer_ptrs {
                if inner_blk != 0 {
                    let inner_ptrs = self.read_block_ptrs(inner_blk)?;
                    for &p in &inner_ptrs {
                        if p != 0 {
                            self.free_block(p)?;
                        }
                    }
                    self.free_block(inner_blk)?;
                }
            }
            self.free_block(dind_blk)?;
        }

        // Triply-indirect — batch-read each level.
        let tind_blk = inode.block_48(EXT4_TIND_BLOCK);
        if tind_blk != 0 {
            let l1_ptrs = self.read_block_ptrs(tind_blk)?;
            for &l2_blk in &l1_ptrs {
                if l2_blk != 0 {
                    let l2_ptrs = self.read_block_ptrs(l2_blk)?;
                    for &l3_blk in &l2_ptrs {
                        if l3_blk != 0 {
                            let l3_ptrs = self.read_block_ptrs(l3_blk)?;
                            for &p in &l3_ptrs {
                                if p != 0 {
                                    self.free_block(p)?;
                                }
                            }
                            self.free_block(l3_blk)?;
                        }
                    }
                    self.free_block(l2_blk)?;
                }
            }
            self.free_block(tind_blk)?;
        }

        Ok(())
    }

    /// Remove a directory entry by name from a directory inode.
    /// Returns Ok(()) if the entry was found and removed, Err(NotFound)
    /// otherwise.
    pub(crate) fn remove_dir_entry(&self, dir_ino: u32, name: &str) -> Result<()> {
        let dir_inode = self.read_inode(dir_ino)?;
        if dir_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let block_size = self.block_size();
        let dir_size = dir_inode.file_size();
        if dir_size == 0 {
            return Err(Error::NotFound);
        }

        let name_bytes = name.as_bytes();
        let total_blocks = dir_size.div_ceil(block_size as u64) as usize;

        for block_idx in 0..total_blocks {
            let Some(phys_block) = self.map_inode_block(&dir_inode, block_idx)? else {
                continue;
            };

            let mut buf = vec![0_u8; block_size];
            self.read_ext2_block(phys_block, &mut buf)?;

            let mut pos: usize = 0;
            let mut prev_pos: Option<(usize, usize)> = None; // (pos, rec_len)

            while pos + 8 <= block_size {
                let rec_len = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]) as usize;
                if rec_len == 0 || rec_len < 8 {
                    break;
                }
                let name_len = buf[pos + 6] as usize;
                let inode_num =
                    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);

                if inode_num != 0
                    && name_len == name_bytes.len()
                    && pos + 8 + name_len <= block_size
                    && &buf[pos + 8..pos + 8 + name_len] == name_bytes
                {
                    // Found the entry to remove.
                    if let Some((prev_p, prev_rl)) = prev_pos {
                        // Merge into previous entry: extend its rec_len.
                        let new_prev_len = prev_rl + rec_len;
                        buf[prev_p + 4..prev_p + 6]
                            .copy_from_slice(&(new_prev_len as u16).to_le_bytes());
                    } else {
                        // First entry in block: zero the inode to mark unused.
                        buf[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
                    }

                    self.write_ext2_block(phys_block, &buf)?;
                    return Ok(());
                }

                prev_pos = Some((pos, rec_len));
                pos += rec_len;
            }
        }

        Err(Error::NotFound)
    }

    /// Ensure that block `block_idx` in the given inode is allocated (possibly
    /// allocating intermediate indirect blocks) and return its physical block
    /// number.
    fn allocate_inode_block(&self, inode: &mut Ext4Inode, block_idx: usize) -> Result<u64> {
        if inode.has_extents() {
            return self.allocate_extent_block(inode, block_idx);
        }
        self.allocate_inode_block_ext4_indirect(inode, block_idx)
    }

    /// Original indirect-block allocation logic (ext2 fallback path).
    fn allocate_inode_block_ext4_indirect(
        &self,
        inode: &mut Ext4Inode,
        block_idx: usize,
    ) -> Result<u64> {
        let block_size = self.block_size();
        let ptrs = ptrs_per_block(block_size);

        // Direct blocks.
        if block_idx < EXT4_NDIR_BLOCKS {
            if inode.block[block_idx] == 0 {
                let new_block = self.allocate_block()? as u32;
                inode.block[block_idx] = new_block;
            }
            return Ok(inode.block[block_idx] as u64);
        }

        // Singly-indirect.
        let si_start = EXT4_NDIR_BLOCKS;
        if block_idx < si_start + ptrs {
            if inode.block[EXT4_IND_BLOCK] == 0 {
                let new_indirect = self.allocate_block()? as u32;
                inode.block[EXT4_IND_BLOCK] = new_indirect;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_indirect as u64, &buf)?;
                }
            }
            let indirect_blk = inode.block[EXT4_IND_BLOCK] as u64;
            let idx = block_idx - si_start;
            let existing = self.read_block_ptr(indirect_blk, idx)?;
            if existing == 0 {
                let new_data = self.allocate_block()? as u32;
                self.write_block_ptr(indirect_blk, idx, new_data as u64)?;
                return Ok(new_data as u64);
            }
            return Ok(existing);
        }

        // Doubly-indirect.
        let di_start = si_start + ptrs;
        let di_count = ptrs * ptrs;
        if block_idx < di_start + di_count {
            if inode.block[EXT4_DIND_BLOCK] == 0 {
                let new_dind = self.allocate_block()? as u32;
                inode.block[EXT4_DIND_BLOCK] = new_dind;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_dind as u64, &buf)?;
                }
            }
            let dind_blk = inode.block[EXT4_DIND_BLOCK] as u64;
            let offset = block_idx - di_start;
            let outer_idx = offset / ptrs;
            let inner_idx = offset % ptrs;

            let existing_outer = self.read_block_ptr(dind_blk, outer_idx)?;
            let inner_blk = if existing_outer == 0 {
                let new_inner = self.allocate_block()? as u32;
                self.write_block_ptr(dind_blk, outer_idx, new_inner as u64)?;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_inner as u64, &buf)?;
                }
                new_inner as u64
            } else {
                existing_outer
            };

            let existing_inner = self.read_block_ptr(inner_blk, inner_idx)?;
            if existing_inner == 0 {
                let new_data = self.allocate_block()? as u32;
                self.write_block_ptr(inner_blk, inner_idx, new_data as u64)?;
                return Ok(new_data as u64);
            }
            return Ok(existing_inner);
        }

        // Triply-indirect.
        let ti_start = di_start + di_count;
        let ti_count = ptrs * ptrs * ptrs;
        if block_idx < ti_start + ti_count {
            if inode.block[EXT4_TIND_BLOCK] == 0 {
                let new_tind = self.allocate_block()? as u32;
                inode.block[EXT4_TIND_BLOCK] = new_tind;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_tind as u64, &buf)?;
                }
            }
            let tind_blk = inode.block[EXT4_TIND_BLOCK] as u64;
            let offset = block_idx - ti_start;
            let l1_idx = offset / (ptrs * ptrs);
            let rest = offset % (ptrs * ptrs);
            let l2_idx = rest / ptrs;
            let l3_idx = rest % ptrs;

            // Level 1: ensure doubly-indirect block exists.
            let existing_l1 = self.read_block_ptr(tind_blk, l1_idx)?;
            let dind_blk = if existing_l1 == 0 {
                let new_dind = self.allocate_block()? as u32;
                self.write_block_ptr(tind_blk, l1_idx, new_dind as u64)?;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_dind as u64, &buf)?;
                }
                new_dind as u64
            } else {
                existing_l1
            };

            // Level 2: ensure singly-indirect block exists.
            let existing_l2 = self.read_block_ptr(dind_blk, l2_idx)?;
            let ind_blk = if existing_l2 == 0 {
                let new_ind = self.allocate_block()? as u32;
                self.write_block_ptr(dind_blk, l2_idx, new_ind as u64)?;
                {
                    let mut buf = self.block_buf.lock();
                    buf.resize(block_size, 0);
                    buf.fill(0);
                    self.write_ext2_block(new_ind as u64, &buf)?;
                }
                new_ind as u64
            } else {
                existing_l2
            };

            // Level 3: ensure data block exists.
            let existing_data = self.read_block_ptr(ind_blk, l3_idx)?;
            if existing_data == 0 {
                let new_data = self.allocate_block()? as u32;
                self.write_block_ptr(ind_blk, l3_idx, new_data as u64)?;
                return Ok(new_data as u64);
            }
            return Ok(existing_data);
        }

        Err(Error::InvalidArgument)
    }

    /// Add a directory entry to a directory inode.
    pub(crate) fn add_dir_entry(
        &self,
        dir_ino: u32,
        child_ino: u32,
        name: &str,
        file_type: u8,
    ) -> Result<()> {
        let dir_inode = self.read_inode(dir_ino)?;
        if dir_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let name_bytes = name.as_bytes();
        let entry_len = 8 + name_bytes.len();
        let rec_len = ((entry_len + 3) & !3).max(12); // round up to 4-byte boundary
        let block_size = self.block_size();

        let dir_size = dir_inode.file_size();
        let last_block_idx = if dir_size == 0 {
            0
        } else {
            ((dir_size - 1) / block_size as u64) as usize
        };

        // Try to find space in the last block, or allocate a new block.
        if dir_size > 0 {
            let Some(phys_block) = self.map_inode_block(&dir_inode, last_block_idx)? else {
                return Err(Error::DeviceError);
            };
            let mut buf = vec![0_u8; block_size];
            self.read_ext2_block(phys_block, &mut buf)?;

            let _offset_in_block = (dir_size % block_size as u64) as usize;
            // Walk entries to find the last one's rec_len (which extends to EOF).
            let mut pos: usize = 0;
            let mut last_pos: usize = 0;
            let mut last_rec_len: usize = 0;
            while pos < block_size {
                let rl = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]) as usize;
                if rl == 0 || rl < 8 {
                    break;
                }
                last_pos = pos;
                last_rec_len = rl;
                pos += rl;
                if pos >= block_size {
                    break;
                }
            }

            // The last entry's real length is `name_len`; we can shrink its
            // rec_len and place a new entry after it.
            let last_real_len = 8 + buf[last_pos + 6] as usize;
            let last_real_padded = ((last_real_len + 3) & !3).max(12);

            if last_rec_len - last_real_padded >= rec_len {
                // Shrink the last entry and insert after it.
                buf[last_pos + 4..last_pos + 6]
                    .copy_from_slice(&(last_real_padded as u16).to_le_bytes());
                let new_pos = last_pos + last_real_padded;
                buf[new_pos..new_pos + 4].copy_from_slice(&child_ino.to_le_bytes());
                buf[new_pos + 4..new_pos + 6]
                    .copy_from_slice(&((last_rec_len - last_real_padded) as u16).to_le_bytes());
                buf[new_pos + 6] = name_bytes.len() as u8;
                buf[new_pos + 7] = file_type;
                buf[new_pos + 8..new_pos + 8 + name_bytes.len()].copy_from_slice(name_bytes);

                self.write_ext2_block(phys_block, &buf)?;
            } else {
                // Need a new block.
                let new_block = self.allocate_block()? as u32;
                let mut new_buf = vec![0_u8; block_size];
                new_buf[0x00..0x04].copy_from_slice(&child_ino.to_le_bytes());
                let rest = block_size as u16;
                new_buf[0x04..0x06].copy_from_slice(&rest.to_le_bytes());
                new_buf[0x06] = name_bytes.len() as u8;
                new_buf[0x07] = file_type;
                new_buf[0x08..0x08 + name_bytes.len()].copy_from_slice(name_bytes);
                self.write_ext2_block(new_block as u64, &new_buf)?;

                // Update inode with new block.
                let new_block_idx = last_block_idx + 1;
                let mut updated_inode = self.read_inode(dir_ino)?;
                updated_inode.size_low = ((new_block_idx + 1) * block_size) as u32;
                if new_block_idx < EXT4_NDIR_BLOCKS {
                    updated_inode.block[new_block_idx] = new_block;
                }
                self.write_inode_raw(dir_ino, &updated_inode)?;
            }
        } else {
            // Empty directory — allocate first block.
            let new_block = self.allocate_block()? as u32;
            let mut new_buf = vec![0_u8; block_size];
            new_buf[0x00..0x04].copy_from_slice(&child_ino.to_le_bytes());
            let rest = block_size as u16;
            new_buf[0x04..0x06].copy_from_slice(&rest.to_le_bytes());
            new_buf[0x06] = name_bytes.len() as u8;
            new_buf[0x07] = file_type;
            new_buf[0x08..0x08 + name_bytes.len()].copy_from_slice(name_bytes);
            self.write_ext2_block(new_block as u64, &new_buf)?;

            let mut updated_inode = self.read_inode(dir_ino)?;
            updated_inode.size_low = block_size as u32;
            updated_inode.block[0] = new_block;
            self.write_inode_raw(dir_ino, &updated_inode)?;
        }

        Ok(())
    }

    /// Write data to a file inode, allocating new blocks as needed.
    pub(crate) fn write_file_data(&self, ino: u32, file_offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable()?;
        if data.is_empty() {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let mut inode = self.read_inode(ino)?;
        if inode.kind() != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let start_block_idx = (file_offset / block_size) as usize;
        let block_off = (file_offset % block_size) as usize;
        let mut bytes_written: usize = 0;
        let total_writable = data.len();
        let total_blocks_needed =
            start_block_idx + (total_writable + block_off).div_ceil(block_size as usize);

        for rel_block in 0..total_blocks_needed.saturating_sub(start_block_idx) {
            let abs_block_idx = start_block_idx + rel_block;
            if bytes_written >= total_writable {
                break;
            }

            // Get or allocate a physical block (handles direct and
            // singly/doubly-indirect allocation chain).
            let phys_block = self.allocate_inode_block(&mut inode, abs_block_idx)?;

            // Read-modify-write the block.
            let mut buf = vec![0_u8; block_size as usize];
            self.read_ext2_block(phys_block, &mut buf)?;

            let copy_start = if rel_block == 0 { block_off } else { 0 };
            let copy_len = (total_writable - bytes_written).min(block_size as usize - copy_start);
            buf[copy_start..copy_start + copy_len]
                .copy_from_slice(&data[bytes_written..bytes_written + copy_len]);

            self.write_ext2_block(phys_block, &buf)?;
            bytes_written += copy_len;
        }

        // Update file size if we wrote past the end.
        let new_end = file_offset + bytes_written as u64;
        let current_size = inode.file_size();
        if new_end > current_size {
            inode.size_low = new_end as u32;
        }
        self.write_inode_raw(ino, &inode)?;

        Ok(bytes_written)
    }

    /// Write updated superblock fields back to disk.
    pub(crate) fn write_superblock(&self) -> Result<()> {
        let start_lba = SUPERBLOCK_BYTE_OFFSET / BLOCK_SIZE as u64;
        let mut raw = [0_u8; SUPERBLOCK_SIZE];

        // Read current superblock first (preserve fields we don't touch).
        for i in 0..(SUPERBLOCK_SIZE / BLOCK_SIZE) {
            let mut sector = [0_u8; BLOCK_SIZE];
            self.cache.read_cached(start_lba + i as u64, &mut sector)?;
            let offset = i * BLOCK_SIZE;
            let end = (offset + BLOCK_SIZE).min(SUPERBLOCK_SIZE);
            raw[offset..end].copy_from_slice(&sector[..end - offset]);
        }

        // Update mutable fields.
        let free_blocks = self.sb.blocks_count - self.count_used_blocks();
        raw[0x0C..0x10].copy_from_slice(&free_blocks.to_le_bytes());
        let free_inodes = self.sb.inodes_count - self.count_used_inodes();
        raw[0x10..0x14].copy_from_slice(&free_inodes.to_le_bytes());

        for i in 0..(SUPERBLOCK_SIZE / BLOCK_SIZE) {
            let offset = i * BLOCK_SIZE;
            self.cache
                .write_through(start_lba + i as u64, &raw[offset..offset + BLOCK_SIZE])?;
        }
        Ok(())
    }

    /// Write updated block-group descriptors back to disk.
    pub(crate) fn write_bg_descriptors(&self) -> Result<()> {
        let block_size = self.block_size();
        let first_bg_block: u64 = if block_size > 1024 { 1 } else { 2 };
        let bg_size_per_entry: usize = 32;
        let entries_per_block = block_size / bg_size_per_entry;
        let num_groups = self.sb.block_group_count() as usize;
        let bg_table_blocks = num_groups.div_ceil(entries_per_block);

        let bg = self.bg_descriptors.lock();

        for block_idx in 0..bg_table_blocks {
            let ext2_block = first_bg_block + block_idx as u64;
            let mut buf = vec![0_u8; block_size];
            // Read existing block first to preserve unmodified entries.
            self.read_ext2_block(ext2_block, &mut buf)?;

            let entries_this_block =
                entries_per_block.min(num_groups - block_idx * entries_per_block);
            for i in 0..entries_this_block {
                let group_idx = block_idx * entries_per_block + i;
                let offset = i * bg_size_per_entry;
                let e = &mut buf[offset..offset + bg_size_per_entry];
                e[0x0C..0x0E].copy_from_slice(&bg[group_idx].bg_free_blocks_count.to_le_bytes());
                e[0x0E..0x10].copy_from_slice(&bg[group_idx].bg_free_inodes_count.to_le_bytes());
            }

            self.write_ext2_block(ext2_block, &buf)?;
        }
        Ok(())
    }

    /// Count used blocks from the block bitmap (for superblock update).
    fn count_used_blocks(&self) -> u32 {
        let block_size = self.block_size();
        let bitmap_block = self.bg_descriptors.lock()[0].bg_block_bitmap as u64;
        let mut bitmap = vec![0_u8; block_size];
        if self.read_ext2_block(bitmap_block, &mut bitmap).is_err() {
            return 0;
        }
        let total = (self.sb.blocks_count as usize).min(block_size * 8);
        let mut used = 0u32;
        for idx in 0..total {
            if bitmap[idx / 8] & (1 << (idx % 8)) != 0 {
                used += 1;
            }
        }
        used
    }

    /// Count used inodes from the inode bitmap.
    fn count_used_inodes(&self) -> u32 {
        let block_size = self.block_size();
        let bitmap_block = self.bg_descriptors.lock()[0].bg_inode_bitmap as u64;
        let mut bitmap = vec![0_u8; block_size];
        if self.read_ext2_block(bitmap_block, &mut bitmap).is_err() {
            return 0;
        }
        let total = (self.sb.inodes_count as usize).min(block_size * 8);
        let mut used = 0u32;
        for idx in 0..total {
            if bitmap[idx / 8] & (1 << (idx % 8)) != 0 {
                used += 1;
            }
        }
        used
    }
}
