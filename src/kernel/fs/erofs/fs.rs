//! src/kernel/fs/erofs/fs.rs
//!
//! EROFS low-level operations: superblock, inode, data maps.
//! Core EROFS filesystem logic: superblock reading, inode I/O,
//! directory entry listing, path resolution, and file data reading.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block_cache::BlockCache;
use crate::kernel::fs::vfs::NodeKind;
use crate::{Error, Result};

use super::types::*;

// Device block size (the granularity at which BlockCache operates).
use crate::kernel::fs::block::BLOCK_SIZE as DEV_BLOCK_SIZE;

/// Internal EROFS filesystem state, shared between [`EroFsVolume`] and
/// every [`EroVNode`] it hands out.
pub(crate) struct EroFs {
    pub cache: BlockCache,
    pub sb: ErofsSuperblock,
    /// Reusable filesystem-block-sized buffer — avoids repeated
    /// allocations in read-inode and read-directory hot paths.
    block_buf: crate::kernel::sync::Mutex<Vec<u8>>,
}

impl EroFs {
    // ── Open / Initialise ───────────────────────────────────────────

    /// Open an EROFS volume from a block device.
    ///
    /// Reads the superblock from offset 1024, validates it, and
    /// returns the initialised filesystem handle.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let cache = BlockCache::new(device.clone());
        let sb = Self::read_superblock(&cache)?;

        // Basic validation beyond superblock parsing.
        if !sb.validate_block_size() {
            return Err(Error::Unsupported);
        }
        if !sb.validate_root_nid() {
            return Err(Error::InvalidArgument);
        }

        let block_size = sb.block_size();
        let block_buf = crate::kernel::sync::Mutex::new(alloc::vec![0u8; block_size]);

        Ok(Self {
            cache,
            sb,
            block_buf,
        })
    }

    /// Read and parse the superblock from the device.
    ///
    /// EROFS superblock is at byte offset 1024.  Since device I/O
    /// operates in 512-byte sectors, we read the necessary sectors
    /// and assemble the superblock bytes.
    fn read_superblock(cache: &BlockCache) -> Result<ErofsSuperblock> {
        // EROFS superblock is at byte offset 1024 (sector 2 on a
        // 512-byte-sector device).  The structure is 128 bytes, which
        // fits within a single sector.
        let start_lba = EROFS_SUPERBLOCK_OFFSET / DEV_BLOCK_SIZE as u64;
        let offset_in_sector = (EROFS_SUPERBLOCK_OFFSET % DEV_BLOCK_SIZE as u64) as usize;
        let needed_bytes = offset_in_sector + EROFS_SUPERBLOCK_SIZE;
        // Ceiling division to determine how many sectors we need.
        let lba_count = needed_bytes.div_ceil(DEV_BLOCK_SIZE);

        let mut raw = vec![0u8; lba_count * DEV_BLOCK_SIZE];
        for i in 0..lba_count {
            let mut sector = [0_u8; DEV_BLOCK_SIZE];
            cache.read_cached(start_lba + i as u64, &mut sector)?;
            let offset = i * DEV_BLOCK_SIZE;
            raw[offset..offset + DEV_BLOCK_SIZE].copy_from_slice(&sector);
        }

        ErofsSuperblock::parse(&raw[offset_in_sector..]).ok_or(Error::Unsupported)
    }

    // ── Block I/O helpers ──────────────────────────────────────────

    pub fn block_size(&self) -> usize {
        self.sb.block_size()
    }

    /// Number of 512-byte device sectors per filesystem block.
    fn sectors_per_block(&self) -> usize {
        self.block_size() / DEV_BLOCK_SIZE
    }

    /// Translate an EROFS block address to a device LBA.
    fn block_to_lba(&self, blkaddr: u32) -> u64 {
        blkaddr as u64 * self.sectors_per_block() as u64
    }

    /// Read a full EROFS filesystem block into `buffer`.
    /// `buffer` must be at least `block_size()` bytes.
    fn read_fs_block(&self, blkaddr: u32, buffer: &mut [u8]) -> Result<()> {
        let lba = self.block_to_lba(blkaddr);
        let sector_count = self.sectors_per_block();
        assert!(buffer.len() >= self.block_size());
        for i in 0..sector_count {
            let sector_buf = &mut buffer[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE];
            self.cache.read_cached(lba + i as u64, sector_buf)?;
        }
        Ok(())
    }

    /// Read raw bytes from an EROFS block at a given byte offset.
    fn read_fs_block_offset(
        &self,
        blkaddr: u32,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let block_size = self.block_size();
        if offset >= block_size {
            return Ok(0);
        }

        let mut block_buf = self.block_buf.lock();
        block_buf.resize(block_size, 0u8);
        self.read_fs_block(blkaddr, &mut block_buf)?;

        let available = (block_size - offset).min(buffer.len());
        buffer[..available].copy_from_slice(&block_buf[offset..offset + available]);
        Ok(available)
    }

    // ── Inode operations ────────────────────────────────────────────

    /// Read a compact inode by NID (inode number).
    pub fn read_inode(&self, nid: u32) -> Result<ErofsInodeCompact> {
        if nid as u64 >= self.sb.inos {
            return Err(Error::InvalidArgument);
        }

        let (blkaddr, offset) = self.sb.nid_to_location(nid);
        let inode_size = self.sb.inode_size();

        let mut raw = vec![0u8; inode_size];
        self.read_fs_block_offset(blkaddr, offset, &mut raw)?;

        Ok(ErofsInodeCompact::parse(&raw))
    }

    /// Read directory entries for the given directory NID.
    pub fn read_dir_entries(&self, dir_nid: u32) -> Result<Vec<ErofsDirEntry>> {
        let inode = self.read_inode(dir_nid)?;
        if erofs_mode_to_kind(inode.mode()) != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        let block_size = self.block_size();
        let mut entries = Vec::new();
        let mut block_buf = self.block_buf.lock();
        block_buf.resize(block_size, 0u8);

        // Read each direct block of the directory.
        for slot in 0..inode.direct_block_count() {
            if let Some(blkaddr) = inode.direct_block(slot) {
                self.read_fs_block(blkaddr, &mut block_buf)?;
                let block_entries = parse_erofs_dir_entries(&block_buf, block_size);
                entries.extend(block_entries);
            }
        }

        // Drop the lock before returning.
        drop(block_buf);
        Ok(entries)
    }

    /// Look up a named child within a directory.  Returns the child's
    /// NID and file-type.
    pub fn lookup_in_dir(&self, dir_nid: u32, name: &str) -> Result<(u32, u8)> {
        let entries = self.read_dir_entries(dir_nid)?;
        for entry in &entries {
            if entry.name == name {
                return Ok((entry.nid as u32, entry.file_type));
            }
        }
        Err(Error::NotFound)
    }

    // ── Path resolution ─────────────────────────────────────────────

    /// Walk a forward-slash-separated absolute path returning the NID
    /// and inode of the final component.
    ///
    /// The path must start with `/`.  Returns `(nid, inode)`.
    pub fn walk_path(&self, path: &str) -> Result<(u32, ErofsInodeCompact)> {
        let trimmed = path.trim_start_matches('/');
        let mut current_nid = self.sb.root_nid as u32;

        if trimmed.is_empty() {
            let inode = self.read_inode(current_nid)?;
            return Ok((current_nid, inode));
        }

        for component in trimmed.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }

            let (child_nid, _ft) = self.lookup_in_dir(current_nid, component)?;
            current_nid = child_nid;
        }

        let inode = self.read_inode(current_nid)?;
        Ok((current_nid, inode))
    }

    // ── File data reading ───────────────────────────────────────────

    /// Read file data starting at `offset` into `buffer`.
    ///
    /// Returns the number of bytes actually read (may be less than
    /// `buffer.len()` at end-of-file).
    pub fn read_file_data(&self, file_nid: u32, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(file_nid)?;
        if erofs_mode_to_kind(inode.mode()) != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let file_size = inode.i_size as u64;
        if offset >= file_size {
            return Ok(0);
        }

        let max_read = (file_size - offset).min(buffer.len() as u64) as usize;
        let block_size = self.block_size() as u64;
        let mut total_read = 0usize;

        while total_read < max_read {
            let current_offset = offset + total_read as u64;
            let block_index = (current_offset / block_size) as usize;
            let block_offset = (current_offset % block_size) as usize;

            let blkaddr = match inode.direct_block(block_index) {
                Some(blk) => blk,
                None => break,
            };

            let mut chunk = vec![0u8; block_size as usize];
            let chunk_available = self.read_fs_block_offset(blkaddr, block_offset, &mut chunk)?;
            let copy_len = chunk_available.min(max_read - total_read);
            buffer[total_read..total_read + copy_len].copy_from_slice(&chunk[..copy_len]);
            total_read += copy_len;

            if chunk_available == 0 {
                break;
            }
        }

        Ok(total_read)
    }

    /// Read symlink target from an inode (fast symlink — inline in i_u).
    pub fn read_symlink_target(&self, sym_nid: u32) -> Result<Vec<u8>> {
        let inode = self.read_inode(sym_nid)?;
        if erofs_mode_to_kind(inode.mode()) != NodeKind::Symlink {
            return Err(Error::InvalidArgument);
        }

        // For fast symlinks, the target is stored inline in i_u.
        let mut inline_data = Vec::with_capacity(16);
        for slot in 0..4 {
            inline_data.extend_from_slice(&inode.i_u[slot].to_le_bytes());
        }
        let len = (inode.i_size as usize).min(16);
        Ok(inline_data[..len].to_vec())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::fs::block::MemoryBlockDevice;
    use alloc::vec;

    /// Build a minimal valid EROFS image in memory.
    ///
    /// The image uses 4096-byte logical blocks but is stored as a flat
    /// byte buffer accessed via [`MemoryBlockDevice`] (512-byte sectors).
    ///
    /// Layout:
    ///   Byte 0-511:       sector 0   (first 512 bytes of superblock area)
    ///   Byte 512-1023:    sector 1
    ///   Byte 1024-1535:   sector 2   (superblock starts here)
    ///   Byte 1536-2047:   sector 3
    ///   Byte 2048-2559:   sector 4
    ///   ...
    ///   Block 64 (byte 262144): metadata — compact inodes
    ///     NID 1 (offset 0):    root dir
    ///     NID 2 (offset 32):   regular file
    ///   Block 65 (byte 266240): root dir data
    ///   Block 66 (byte 270336): file data
    fn build_test_image() -> Vec<u8> {
        let block_size = 4096usize;
        let total_blocks = 128;
        let mut image = vec![0u8; total_blocks * block_size];

        // ── Superblock at byte offset 1024 ─────────────────────────
        let sb_off = 1024;
        image[sb_off..sb_off + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        image[sb_off + 0x0C] = 12; // blkszbits = 12 → 4096
        image[sb_off + 0x0E..sb_off + 0x10].copy_from_slice(&1u16.to_le_bytes()); // root_nid = 1
        image[sb_off + 0x10..sb_off + 0x18].copy_from_slice(&10u64.to_le_bytes()); // inos = 10
        image[sb_off + 0x24..sb_off + 0x28].copy_from_slice(&(total_blocks as u32).to_le_bytes()); // blocks
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&64u32.to_le_bytes()); // meta_blkaddr
        image[sb_off + 0x50..sb_off + 0x54]
            .copy_from_slice(&EROFS_FEATURE_INCOMPAT_NID_TABLE.to_le_bytes());
        let volname = b"test";
        image[sb_off + 0x40..sb_off + 0x40 + volname.len()].copy_from_slice(volname);

        // ── NID 1: root directory inode (at block 64, offset 32) ──
        // NID 0 is unused (reserved); the first real inode is NID 1.
        let meta_base = 64 * block_size;
        let root_inode_off = meta_base + 32; // NID 1 → offset 32
                                             // i_format: directory + 0755, plain
        image[root_inode_off..root_inode_off + 2]
            .copy_from_slice(&(EROFS_S_IFDIR | 0o755).to_le_bytes());
        image[root_inode_off + 4..root_inode_off + 8].copy_from_slice(&2u32.to_le_bytes()); // nlink
        image[root_inode_off + 8..root_inode_off + 12]
            .copy_from_slice(&(block_size as u32).to_le_bytes()); // size
        image[root_inode_off + 16..root_inode_off + 20].copy_from_slice(&65u32.to_le_bytes()); // i_u[0] → block 65

        // ── NID 2: regular file inode (at block 64, offset 64) ────
        let file_inode_off = meta_base + 64; // NID 2 → offset 64
        let file_content = b"Hello, EROFS!\n";
        image[file_inode_off..file_inode_off + 2]
            .copy_from_slice(&(EROFS_S_IFREG | 0o644).to_le_bytes());
        image[file_inode_off + 4..file_inode_off + 8].copy_from_slice(&1u32.to_le_bytes()); // nlink
        image[file_inode_off + 8..file_inode_off + 12]
            .copy_from_slice(&(file_content.len() as u32).to_le_bytes()); // size
        image[file_inode_off + 16..file_inode_off + 20].copy_from_slice(&66u32.to_le_bytes()); // i_u[0] → block 66

        // ── Block 65: root directory data ──────────────────────────
        // EROFS directory entries: 12-byte headers at the start of the
        // block, names packed at the tail growing backwards.  Names MUST
        // NOT overlap — each name starts immediately before the previous
        // name (or at the end of the block for the first name).
        let dir_data_off = 65 * block_size;

        // Names, packed from the end of the block backwards:
        //  "."        -> 1 byte  at offset 4095
        //  ".."       -> 2 bytes at offset 4093
        //  "hello.txt" -> 9 bytes at offset 4084
        let name_dot = b".";
        let name_dotdot = b"..";
        let name_hello = b"hello.txt";

        let off_dot = block_size - name_dot.len(); // 4095
        let off_dotdot = off_dot - name_dotdot.len(); // 4093
        let off_hello = off_dotdot - name_hello.len(); // 4084

        // Write names at the tail.
        image[dir_data_off + off_dot..dir_data_off + off_dot + name_dot.len()]
            .copy_from_slice(name_dot);
        image[dir_data_off + off_dotdot..dir_data_off + off_dotdot + name_dotdot.len()]
            .copy_from_slice(name_dotdot);
        image[dir_data_off + off_hello..dir_data_off + off_hello + name_hello.len()]
            .copy_from_slice(name_hello);

        // Entry 0: "." → NID 1 (12-byte header at offset 0)
        {
            image[dir_data_off..dir_data_off + 8].copy_from_slice(&1u64.to_le_bytes());
            image[dir_data_off + 8..dir_data_off + 10]
                .copy_from_slice(&(off_dot as u16).to_le_bytes());
            image[dir_data_off + 10..dir_data_off + 12]
                .copy_from_slice(&(EROFS_FT_DIR as u16).to_le_bytes());
        }
        // Entry 1: ".." → NID 1 (12-byte header at offset 12)
        {
            let off = dir_data_off + 12;
            image[off..off + 8].copy_from_slice(&1u64.to_le_bytes());
            image[off + 8..off + 10].copy_from_slice(&(off_dotdot as u16).to_le_bytes());
            image[off + 10..off + 12].copy_from_slice(&(EROFS_FT_DIR as u16).to_le_bytes());
        }
        // Entry 2: "hello.txt" → NID 2 (12-byte header at offset 24)
        {
            let off = dir_data_off + 24;
            image[off..off + 8].copy_from_slice(&2u64.to_le_bytes());
            image[off + 8..off + 10].copy_from_slice(&(off_hello as u16).to_le_bytes());
            image[off + 10..off + 12].copy_from_slice(&(EROFS_FT_REG_FILE as u16).to_le_bytes());
        }

        // ── Block 66: file data ────────────────────────────────────
        let file_data_off = 66 * block_size;
        image[file_data_off..file_data_off + file_content.len()].copy_from_slice(file_content);

        image
    }

    #[test]
    fn open_erofs_volume_and_read_root_dir() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-1", image, true);
        let erofs = EroFs::open(device).expect("open");

        assert_eq!(erofs.block_size(), 4096);
        assert_eq!(erofs.sb.root_nid, 1);

        let entries = erofs.read_dir_entries(1).expect("read root dir");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
        assert!(names.contains(&"hello.txt"));

        let (nid, ft) = erofs.lookup_in_dir(1, "hello.txt").expect("lookup");
        assert_eq!(nid, 2);
        assert_eq!(ft, EROFS_FT_REG_FILE);
    }

    #[test]
    fn walk_path_and_read_file() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-2", image, true);
        let erofs = EroFs::open(device).expect("open");

        let (nid, inode) = erofs.walk_path("/hello.txt").expect("walk");
        assert_eq!(nid, 2);
        assert_eq!(inode.i_size, 14);

        let mut buf = [0u8; 64];
        let n = erofs.read_file_data(nid, 0, &mut buf).expect("read");
        assert_eq!(n, 14);
        assert_eq!(&buf[..14], b"Hello, EROFS!\n");

        let mut buf2 = [0u8; 5];
        let n2 = erofs.read_file_data(nid, 7, &mut buf2).expect("read2");
        assert_eq!(n2, 5);
        assert_eq!(&buf2[..5], b"EROFS");
    }

    #[test]
    fn walk_root_path_returns_root_inode() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-3", image, true);
        let erofs = EroFs::open(device).expect("open");

        let (nid, inode) = erofs.walk_path("/").expect("walk root");
        assert_eq!(nid, 1);
        assert!(matches!(
            erofs_mode_to_kind(inode.mode()),
            NodeKind::Directory
        ));
    }

    #[test]
    fn walk_nonexistent_path_returns_not_found() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-4", image, true);
        let erofs = EroFs::open(device).expect("open");

        assert!(erofs.walk_path("/nonexistent").is_err());
    }

    #[test]
    fn read_file_past_eof_returns_zero() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-5", image, true);
        let erofs = EroFs::open(device).expect("open");

        let mut buf = [0u8; 32];
        let n = erofs.read_file_data(2, 100, &mut buf).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn walk_dotdot_resolves_to_parent() {
        let image = build_test_image();
        let device = MemoryBlockDevice::new("erofs-dotdot", image, true);
        let erofs = EroFs::open(device).expect("open");

        // "/./.." should resolve back to root (nid 1): root → "." (skip) → ".." (root dir entry).
        let (nid, _inode) = erofs.walk_path("/./..").expect("walk dotdot");
        assert_eq!(nid, 1);
    }
}
