//! src/kernel/fs/ext4/write.rs
//!
//! Ext4 inode and superblock write helpers.

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
