//! src/kernel/fs/f2fs/segment.rs
//!
//! F2FS segment management: append-only block allocation, free segment
//! selection, and block freeing.

use crate::Error;
use crate::Result;

use super::constants::*;
use super::F2fsFs;

impl F2fsFs {
    /// Allocate a new block in the current active segment and write `data`
    /// to it.
    ///
    /// Returns the physical block address of the newly written block.
    /// If the current segment is full, a new free segment is selected.
    pub(crate) fn segment_alloc_block(&self, data: &[u8]) -> Result<u32> {
        self.check_writable()?;

        let blocks_per_seg = self.sb.blocks_per_seg();
        let mut cur_seg = self.cur_seg.lock();
        let mut cur_off = self.cur_seg_off.lock();

        // Check if current segment is full — switch to a free segment.
        if *cur_off as u32 >= blocks_per_seg {
            let mut sit = self.sit_cache.lock();
            // Remove the first free segment from the list.
            if let Some(new_seg) = sit.free_segments.first().copied() {
                sit.free_segments.remove(0);
                drop(sit);
                *cur_seg = new_seg;
                *cur_off = 0;
            } else {
                return Err(Error::DeviceError);
            }
        }

        let phys = self.sb.segment0_blkaddr + *cur_seg * blocks_per_seg + *cur_off as u32;

        // Write the data.
        self.write_fs_block(phys, data)?;

        // Update SIT: mark this block as valid.
        {
            let mut sit = self.sit_cache.lock();
            if (*cur_seg as usize) < sit.entries.len() {
                sit.entries[*cur_seg as usize].mark_valid(*cur_off);
            }
            // Mark this segment as dirty.
            let mut dirty = self.dirty_sit.lock();
            if !dirty.contains(&*cur_seg) {
                dirty.push(*cur_seg);
            }
        }

        *cur_off += 1;

        Ok(phys)
    }

    /// Free all data blocks belonging to an inode.
    ///
    /// Walks `i_addr[..]` and invalidates every non-hole block in the
    /// SIT bitmap.  Doesn't actually erase any data — just marks the
    /// segments' valid-bitmap bits as 0.
    pub(crate) fn free_inode_blocks(&self, nid: u32) -> Result<()> {
        let inode = self.read_inode(nid)?;
        let blocks_per_seg = self.sb.blocks_per_seg();
        let segment0 = self.sb.segment0_blkaddr;

        for addr in &inode.i_addr {
            if *addr == F2FS_NULL_ADDR || *addr == F2FS_NEW_ADDR {
                continue;
            }

            let phys = *addr;
            if phys < segment0 {
                continue; // not in main area
            }

            let rel = phys - segment0;
            let segno = rel / blocks_per_seg;
            let offset = (rel % blocks_per_seg) as u16;

            let mut sit = self.sit_cache.lock();
            if (segno as usize) < sit.entries.len() {
                let was_valid = sit.entries[segno as usize].is_valid(offset);
                sit.entries[segno as usize].mark_invalid(offset);

                // If the segment just became fully free, add it to the
                // free list.
                if was_valid
                    && sit.entries[segno as usize].vblocks == 0
                    && !sit.free_segments.contains(&segno)
                {
                    sit.free_segments.push(segno);
                }
            }

            let mut dirty = self.dirty_sit.lock();
            if !dirty.contains(&segno) {
                dirty.push(segno);
            }
        }

        Ok(())
    }
}
