//! src/kernel/fs/ext4/block_alloc.rs
//!
//! Ext4 block allocation helpers.

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

    pub(crate) fn free_block(&self, block_num: u64) -> Result<()> {
        self.check_writable()?;
        let block_size = self.block_size();
        let blocks_per_group = self.sb.blocks_per_group as u64;