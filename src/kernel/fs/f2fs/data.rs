//! src/kernel/fs/f2fs/data.rs
//!
//! F2FS data block I/O: block mapping, file read, and file write.

use crate::Result;

use super::constants::*;
use super::F2fsFs;

impl F2fsFs {
    /// Write data to a file at `offset`.
    ///
    /// For each affected logical block:
    ///   - If the block already exists: read old content, modify, write to a
    ///     *new* physical block (log-structured, never overwrites in place).
    ///   - If the block is a hole or newly allocated: build the block content
    ///     and allocate a new physical block.
    ///
    /// This is append-only — old blocks are invalidated in the SIT but
    /// not erased (no GC in v1).
    pub(crate) fn write_file_data(&self, nid: u32, offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable()?;

        if data.is_empty() {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let mut inode = self.read_inode(nid)?;

        let start_block = (offset / block_size) as usize;
        let end_pos = offset + data.len() as u64;
        let end_block = end_pos.div_ceil(block_size) as usize;

        let mut data_pos = 0usize;

        for blk_idx in start_block..end_block {
            if blk_idx >= F2FS_ADDRS_PER_INODE {
                break;
            }

            // Determine the byte range of `data` that falls into this
            // logical block.
            let block_start = blk_idx as u64 * block_size;
            let block_end = block_start + block_size;
            let seg_start = offset.max(block_start);
            let seg_end = end_pos.min(block_end);
            let seg_len = (seg_end - seg_start) as usize;

            let old_phys = inode.i_addr[blk_idx];

            // Use the shared block-sized scratch buffer.
            let mut buf = self.block_buf.lock();
            buf.resize(self.block_size(), 0);

            if old_phys != F2FS_NULL_ADDR && old_phys != F2FS_NEW_ADDR {
                // Read-modify-write: copy old content, overlay new data.
                self.read_fs_block(old_phys, &mut buf[..])?;
                let write_start = (seg_start - block_start) as usize;
                buf[write_start..write_start + seg_len]
                    .copy_from_slice(&data[data_pos..data_pos + seg_len]);
            } else {
                // New block or hole: start with zeroes, place data at
                // the correct offset.
                buf.fill(0);
                let write_start = (seg_start - block_start) as usize;
                let copy_len = seg_len.min(block_size as usize - write_start);
                buf[write_start..write_start + copy_len]
                    .copy_from_slice(&data[data_pos..data_pos + copy_len]);
            }

            // Allocate a new physical block (append-only).
            let new_phys = self.segment_alloc_block(&buf[..])?;
            inode.i_addr[blk_idx] = new_phys;

            data_pos += seg_len;
        }

        // Update file size if we wrote past the current EOF.
        if end_pos > inode.i_size {
            inode.i_size = end_pos;
        }

        // Update i_blocks (count in 512-byte sectors).
        inode.i_blocks = inode.i_size.div_ceil(512);

        self.write_inode(nid, &inode)?;

        Ok(data.len())
    }
}
