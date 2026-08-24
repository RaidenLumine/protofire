//! src/kernel/fs/f2fs/fs.rs
//!
//! F2FS core: mount, block I/O, path walking, directory scanning, and file
//! data reading.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BLOCK_SIZE as DEV_BLOCK_SIZE;
use crate::kernel::fs::block_cache::BlockCache;
use crate::kernel::fs::vfs::{Metadata, NodeKind, SecurityDescriptor};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::super::block::BlockDevice;
use super::constants::*;
use super::types::*;
use super::F2fsFs;

// ══════════════════════════════════════════════════════════════════════
//  Mount
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Open an F2FS volume from the given block device.
    ///
    /// Reads the superblock from block 0, validates the magic, reads and
    /// selects the newer checkpoint copy, initialises in-memory NAT and
    /// SIT caches, and picks the first free segment for append writes.
    pub(crate) fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let read_only = device.is_read_only();
        let cache = BlockCache::new(device.clone());

        // 1. Read and validate superblock.
        let sb = Self::read_superblock(&cache)?;

        // 2. Read both checkpoint copies and pick the newer one.
        let checkpoint = Self::read_checkpoint(&cache, &sb)?;

        // 3. Initialise NAT cache from NAT area + CP journal.
        let nat_cache = Self::init_nat_cache(&cache, &sb, &checkpoint)?;

        // 4. Initialise SIT cache from SIT area + CP journal.
        let sit_cache = Self::init_sit_cache(&cache, &sb)?;

        // 5. Determine first free segment and starting offset.
        let (cur_seg, cur_seg_off) = Self::find_first_free_segment(&sit_cache, &sb);

        let block_size = sb.block_size();
        let block_buf = Mutex::new(vec![0u8; block_size]);

        let next_nid = Mutex::new(checkpoint.next_free_nid.max(F2FS_NID_ROOT + 1));

        Ok(Self {
            device,
            cache,
            sb,
            checkpoint: Mutex::new(checkpoint),
            nat_cache: Mutex::new(nat_cache),
            sit_cache: Mutex::new(sit_cache),
            cur_seg: Mutex::new(cur_seg),
            cur_seg_off: Mutex::new(cur_seg_off),
            block_buf,
            read_only,
            dirty_nat: Mutex::new(alloc::collections::BTreeMap::new()),
            dirty_sit: Mutex::new(Vec::new()),
            next_nid,
        })
    }

    /// Read and validate the F2FS superblock from block 0.
    fn read_superblock(cache: &BlockCache) -> Result<F2fsSuperblock> {
        // F2FS superblock is at block 0, taking up the first 4096 bytes.
        let block_size = F2FS_DEFAULT_BLOCK_SIZE;
        let sector_count = block_size / DEV_BLOCK_SIZE;
        let mut buf = vec![0u8; block_size];
        for i in 0..sector_count {
            cache.read_cached(
                i as u64,
                &mut buf[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE],
            )?;
        }

        let sb = parse_f2fs_superblock(&buf);

        if sb.magic != F2FS_MAGIC {
            return Err(Error::InvalidArgument);
        }

        Ok(sb)
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Geometry helpers
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Block size in bytes (default 4096).
    pub(crate) fn block_size(&self) -> usize {
        self.sb.block_size()
    }

    /// Number of 512-byte device sectors per filesystem block.
    pub(crate) fn sectors_per_block(&self) -> u64 {
        self.block_size() as u64 / DEV_BLOCK_SIZE as u64
    }

    /// Convert an F2FS block address to a device LBA.
    pub(crate) fn block_to_lba(&self, blkaddr: u32) -> u64 {
        blkaddr as u64 * self.sectors_per_block()
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Block I/O
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Read a full F2FS block into `buffer`.  `buffer.len()` must be at
    /// least `block_size()`.
    pub(crate) fn read_fs_block(&self, blkaddr: u32, buffer: &mut [u8]) -> Result<()> {
        let lba = self.block_to_lba(blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            let sector_buf = &mut buffer[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE];
            self.cache.read_cached(lba + i as u64, sector_buf)?;
        }
        Ok(())
    }

    /// Write a full F2FS block through the write-back cache.
    pub(crate) fn write_fs_block(&self, blkaddr: u32, data: &[u8]) -> Result<()> {
        let lba = self.block_to_lba(blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            let chunk = &data[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE];
            self.cache.write_back(lba + i as u64, chunk)?;
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Inode I/O
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Read the inode for the given NID from disk.
    pub(crate) fn read_inode(&self, nid: u32) -> Result<F2fsInode> {
        let nat = self.nat_cache.lock();
        let entry = nat.entries.get(nid as usize).ok_or(Error::NotFound)?;
        if entry.block_addr == F2FS_NULL_ADDR {
            return Err(Error::NotFound);
        }
        let phys_block = entry.block_addr;
        drop(nat);

        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        self.read_fs_block(phys_block, &mut buf)?;
        Ok(parse_f2fs_inode(&buf))
    }

    /// Write an inode back to disk (append a new block to the active
    /// segment and update the NAT entry).
    pub(crate) fn write_inode(&self, nid: u32, inode: &F2fsInode) -> Result<()> {
        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_inode(inode, &mut buf);

        let phys = self.segment_alloc_block(&buf)?;
        self.nat_update(nid, phys)?;

        Ok(())
    }

    /// Build [`Metadata`] from an inode.
    pub(crate) fn stat_inode(&self, _nid: u32, inode: &F2fsInode) -> Metadata {
        let kind = inode.kind();
        let size = inode.file_size() as usize;
        let perm = inode.permission_mode();
        Metadata::new(kind, size).with_security(SecurityDescriptor::new(
            inode.i_uid,
            inode.i_gid,
            perm,
        ))
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Directory operations
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Read all directory entries from a directory inode.
    ///
    /// Reads each data block pointed to by `i_addr[..]` and parses the
    /// variable-length F2FS directory entries.
    pub(crate) fn read_dir_entries(&self, dir_inode: &F2fsInode) -> Result<Vec<F2fsDirEntry>> {
        let block_size = self.block_size();
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let mut entries = Vec::new();
        let mut buf = vec![0u8; block_size];

        for blk_idx in 0..num_blocks {
            if blk_idx >= F2FS_ADDRS_PER_INODE {
                break;
            }
            let phys = dir_inode.i_addr[blk_idx];
            if phys == F2FS_NULL_ADDR || phys == F2FS_NEW_ADDR {
                continue;
            }
            self.read_fs_block(phys, &mut buf)?;
            let block_entries = parse_f2fs_dir_entries(&buf);
            entries.extend(block_entries);
        }

        Ok(entries)
    }

    /// Look up a name in a directory, returning the child's NID and file
    /// type.
    pub(crate) fn lookup_in_dir(&self, dir_nid: u32, name: &str) -> Result<(u32, u8)> {
        let dir_inode = self.read_inode(dir_nid)?;
        let entries = self.read_dir_entries(&dir_inode)?;
        for entry in &entries {
            if entry.name == name {
                return Ok((entry.ino, entry.file_type));
            }
        }
        Err(Error::NotFound)
    }

    /// Add a new directory entry to a directory inode.
    ///
    /// Appends the entry to the last data block, or allocates a new block
    /// if there is not enough space.
    pub(crate) fn add_dir_entry(
        &self,
        dir_nid: u32,
        child_nid: u32,
        name: &str,
        file_type: u8,
    ) -> Result<()> {
        let block_size = self.block_size();
        let mut dir_inode = self.read_inode(dir_nid)?;
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let new_entry_size = dir_entry_size(name.len());
        let hash_code = 0u32; // v1: hash not used for lookups

        let mut buf = vec![0u8; block_size];

        // Try to fit in the last existing block.
        if num_blocks > 0 && num_blocks <= F2FS_ADDRS_PER_INODE {
            let last_blk_idx = num_blocks - 1;
            let old_phys = dir_inode.i_addr[last_blk_idx];
            if old_phys != F2FS_NULL_ADDR && old_phys != F2FS_NEW_ADDR {
                self.read_fs_block(old_phys, &mut buf)?;

                // Find the end of used space in this block.
                let used = Self::dir_block_used_bytes(&buf, block_size);
                if used + new_entry_size <= block_size {
                    // There is room — append the new entry.
                    write_f2fs_dir_entry(child_nid, name, file_type, hash_code, &mut buf[used..]);
                    let new_phys = self.segment_alloc_block(&buf)?;
                    dir_inode.i_addr[last_blk_idx] = new_phys;
                    dir_inode.i_size += new_entry_size as u64;
                    self.write_inode(dir_nid, &dir_inode)?;
                    return Ok(());
                }
            }
        }

        // No room in existing blocks — allocate a new data block.
        if num_blocks >= F2FS_ADDRS_PER_INODE {
            return Err(Error::DeviceError);
        }

        let mut new_block = vec![0u8; block_size];
        let written = write_f2fs_dir_entry(child_nid, name, file_type, hash_code, &mut new_block);
        let new_phys = self.segment_alloc_block(&new_block)?;

        dir_inode.i_addr[num_blocks] = new_phys;
        dir_inode.i_size += written as u64;
        self.write_inode(dir_nid, &dir_inode)?;

        Ok(())
    }

    /// Remove a directory entry by name from a directory inode.
    ///
    /// Marks the entry's `ino` field as 0 (deleted).  The space is not
    /// reclaimed in v1 (no GC).
    pub(crate) fn remove_dir_entry(&self, dir_nid: u32, name: &str) -> Result<()> {
        let block_size = self.block_size();
        let dir_inode = self.read_inode(dir_nid)?;
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let mut buf = vec![0u8; block_size];

        for blk_idx in 0..num_blocks.min(F2FS_ADDRS_PER_INODE) {
            let old_phys = dir_inode.i_addr[blk_idx];
            if old_phys == F2FS_NULL_ADDR || old_phys == F2FS_NEW_ADDR {
                continue;
            }
            self.read_fs_block(old_phys, &mut buf)?;

            // Scan entries in this block.
            let mut offset = 0usize;
            let mut found = false;
            while offset + 13 <= block_size {
                let rec_len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
                if rec_len < 13 || rec_len == 0 {
                    break;
                }
                let name_len = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
                let ino = u32::from_le_bytes([
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                ]);

                if ino != 0 && name_len == name.len() {
                    let entry_name = &buf[offset + 13..offset + 13 + name_len];
                    if entry_name == name.as_bytes() {
                        // Mark as deleted by zeroing the ino field.
                        buf[offset + 9] = 0;
                        buf[offset + 10] = 0;
                        buf[offset + 11] = 0;
                        buf[offset + 12] = 0;
                        found = true;
                        break;
                    }
                }
                offset += rec_len;
            }

            if found {
                let new_phys = self.segment_alloc_block(&buf)?;
                let mut updated_inode = self.read_inode(dir_nid)?;
                updated_inode.i_addr[blk_idx] = new_phys;
                self.write_inode(dir_nid, &updated_inode)?;
                return Ok(());
            }
        }

        Err(Error::NotFound)
    }

    /// Scan a raw directory block and return the byte offset just past the
    /// last valid entry.
    fn dir_block_used_bytes(data: &[u8], block_size: usize) -> usize {
        let mut offset = 0usize;
        while offset + 13 <= block_size {
            let rec_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            if rec_len < 13 || rec_len == 0 {
                break;
            }
            offset += rec_len;
        }
        offset
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Path resolution
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Resolve an absolute path to `(NID, F2fsInode)`.
    pub(crate) fn walk_path(&self, path: &str) -> Result<(u32, F2fsInode)> {
        self.walk_path_limited(path, 0)
    }

    /// Recursive path walker with symlink-depth guard.
    pub(crate) fn walk_path_limited(&self, path: &str, depth: usize) -> Result<(u32, F2fsInode)> {
        const MAX_SYMLINK_DEPTH: usize = 8;
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Error::InvalidArgument);
        }

        // Root directory.
        if path == "/" || path.is_empty() {
            let root_inode = self.read_inode(F2FS_NID_ROOT)?;
            return Ok((F2FS_NID_ROOT, root_inode));
        }

        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        let mut current_nid = F2FS_NID_ROOT;
        let mut walked = String::new();

        for (i, component) in components.iter().enumerate() {
            let dir_inode = self.read_inode(current_nid)?;
            if dir_inode.kind() != NodeKind::Directory {
                return Err(Error::NotFound);
            }

            let (child_nid, _file_type) = self.lookup_in_dir(current_nid, component)?;
            let child_inode = self.read_inode(child_nid)?;

            walked.push('/');
            walked.push_str(component);

            // Symlink resolution.
            if child_inode.kind() == NodeKind::Symlink {
                let target = self.read_symlink_target(&child_inode)?;
                let target_str =
                    core::str::from_utf8(&target).map_err(|_| Error::InvalidArgument)?;

                // Build the remaining path suffix.
                let suffix: String = if i + 1 < components.len() {
                    let mut s = String::from("/");
                    for c in &components[i + 1..] {
                        s.push_str(c);
                        s.push('/');
                    }
                    // Trim trailing '/'
                    if s.len() > 1 {
                        s.pop();
                    }
                    s
                } else {
                    String::new()
                };

                let resolved = if target_str.starts_with('/') {
                    format!("{}{}", target_str, suffix)
                } else {
                    let parent = walked.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    format!("{}/{}{}", parent, target_str, suffix)
                };

                return self.walk_path_limited(&resolved, depth + 1);
            }

            current_nid = child_nid;
        }

        let inode = self.read_inode(current_nid)?;
        Ok((current_nid, inode))
    }
}

// ══════════════════════════════════════════════════════════════════════
//  File data reading
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Read file data from the given inode starting at `offset`.
    ///
    /// Returns the number of bytes actually read (may be less than
    /// `buffer.len()` at EOF).
    pub(crate) fn read_file_data(
        &self,
        inode: &F2fsInode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let file_size = inode.file_size();
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let bytes_to_read = buffer.len().min((file_size - offset) as usize);
        let start_block = (offset / block_size) as usize;
        let block_offset = (offset % block_size) as usize;

        let mut buf = vec![0u8; self.block_size()];
        let mut bytes_read = 0usize;
        let mut remaining = bytes_to_read;
        let mut buf_offset = 0usize;

        for blk_idx in start_block.. {
            if blk_idx >= F2FS_ADDRS_PER_INODE || remaining == 0 {
                break;
            }

            let phys = inode.i_addr[blk_idx];
            if phys == F2FS_NULL_ADDR || phys == F2FS_NEW_ADDR {
                // Hole — fill with zeroes.
                let n = remaining.min(block_size as usize);
                for b in buffer[buf_offset..buf_offset + n].iter_mut() {
                    *b = 0;
                }
                bytes_read += n;
                buf_offset += n;
                remaining -= n;
                continue;
            }

            self.read_fs_block(phys, &mut buf)?;

            let start = if blk_idx == start_block {
                block_offset
            } else {
                0
            };
            let n = remaining.min(self.block_size() - start);

            buffer[buf_offset..buf_offset + n].copy_from_slice(&buf[start..start + n]);

            bytes_read += n;
            buf_offset += n;
            remaining -= n;
        }

        Ok(bytes_read)
    }

    /// Read a fast symlink target from the inode's `i_addr` area.
    ///
    /// For fast symlinks, the target path is stored inline in the first
    /// `i_size` bytes of `i_addr`.
    pub(crate) fn read_symlink_target(&self, inode: &F2fsInode) -> Result<Vec<u8>> {
        if inode.kind() != NodeKind::Symlink {
            return Err(Error::InvalidArgument);
        }

        let len = inode.file_size() as usize;
        if len == 0 {
            return Ok(Vec::new());
        }

        // Fast symlink: target is in the first bytes of i_addr.
        let addr_bytes = len.min(F2FS_ADDRS_PER_INODE * 4);
        let mut target = Vec::with_capacity(addr_bytes);

        // Read target bytes from i_addr[..] interpreted as raw bytes.
        let raw_addr: &[u8] = unsafe {
            core::slice::from_raw_parts(
                inode.i_addr.as_ptr() as *const u8,
                F2FS_ADDRS_PER_INODE * 4,
            )
        };

        target.extend_from_slice(&raw_addr[..len]);
        Ok(target)
    }
}

// ══════════════════════════════════════════════════════════════════════
//  Write guard and flush
// ══════════════════════════════════════════════════════════════════════

impl F2fsFs {
    /// Check that the filesystem is writable.
    pub(crate) fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Flush all dirty state to disk: write checkpoint, write superblock,
    /// flush block cache, flush device.
    pub(crate) fn flush_all(&self) -> Result<()> {
        self.write_checkpoint()?;
        self.write_superblock()?;
        self.cache.flush()?;
        self.device.flush()?;
        Ok(())
    }
}
