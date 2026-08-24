//! src/kernel/fs/f2fs/checkpoint.rs
//!
//! F2FS checkpoint read and write, including NAT/SIT journal handling.

use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block_cache::BlockCache;
use crate::{Error, Result};

use super::constants::*;
use super::types::*;
use super::F2fsFs;

impl F2fsFs {
    /// Read both checkpoint copies and return the newer one.
    ///
    /// Copy 0 is at `cp_blkaddr`, copy 1 is at `cp_blkaddr + cp_payload + 1`.
    /// The copy with the larger `check_ver` wins.
    pub(crate) fn read_checkpoint(
        cache: &BlockCache,
        sb: &F2fsSuperblock,
    ) -> Result<F2fsCheckpoint> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;
        let cp0_blkaddr = sb.cp_blkaddr;
        let cp1_blkaddr = sb.cp_blkaddr + sb.cp_payload + 1;

        // Read copy 0.
        let mut buf0 = vec![0u8; block_size];
        let lba0 = cp0_blkaddr as u64 * sector_count as u64;
        for i in 0..sector_count {
            cache
                .read_cached(lba0 + i as u64, &mut buf0[i * 512..(i + 1) * 512])
                .or(Err(Error::InvalidArgument))?;
        }
        let ver0 = u64::from_le_bytes([
            buf0[F2FS_CP_CHECK_VER_OFF],
            buf0[F2FS_CP_CHECK_VER_OFF + 1],
            buf0[F2FS_CP_CHECK_VER_OFF + 2],
            buf0[F2FS_CP_CHECK_VER_OFF + 3],
            buf0[F2FS_CP_CHECK_VER_OFF + 4],
            buf0[F2FS_CP_CHECK_VER_OFF + 5],
            buf0[F2FS_CP_CHECK_VER_OFF + 6],
            buf0[F2FS_CP_CHECK_VER_OFF + 7],
        ]);

        // Read copy 1.
        let mut buf1 = vec![0u8; block_size];
        let lba1 = cp1_blkaddr as u64 * sector_count as u64;
        for i in 0..sector_count {
            cache
                .read_cached(lba1 + i as u64, &mut buf1[i * 512..(i + 1) * 512])
                .or(Err(Error::InvalidArgument))?;
        }
        let ver1 = u64::from_le_bytes([
            buf1[F2FS_CP_CHECK_VER_OFF],
            buf1[F2FS_CP_CHECK_VER_OFF + 1],
            buf1[F2FS_CP_CHECK_VER_OFF + 2],
            buf1[F2FS_CP_CHECK_VER_OFF + 3],
            buf1[F2FS_CP_CHECK_VER_OFF + 4],
            buf1[F2FS_CP_CHECK_VER_OFF + 5],
            buf1[F2FS_CP_CHECK_VER_OFF + 6],
            buf1[F2FS_CP_CHECK_VER_OFF + 7],
        ]);

        // Pick the newer copy.
        if ver0 >= ver1 {
            Ok(parse_f2fs_checkpoint(&buf0, 0))
        } else {
            Ok(parse_f2fs_checkpoint(&buf1, 1))
        }
    }

    /// Write a new checkpoint to the *other* copy, bumping `check_ver`.
    ///
    /// This ensures that if the write is interrupted, the old (valid) copy
    /// remains intact.  Uses write-through for the CP block to avoid
    /// caching-related corruption.
    pub(crate) fn write_checkpoint(&self) -> Result<()> {
        let mut cp = self.checkpoint.lock().clone();

        // Flush dirty NAT entries to the NAT area before checkpointing.
        self.flush_dirty_nat()?;

        // Bump version.
        cp.check_ver += 1;
        cp.nat_ver += 1;
        cp.sit_ver += 1;

        // Collect current NAT journal from dirty entries (for the CP
        // journal area — we also persist to NAT area above).
        cp.nat_journal.clear();
        {
            let dirty = self.dirty_nat.lock();
            cp.nat_journal_entries = dirty.len() as u32;
        }

        // Update valid counts.
        {
            let nat = self.nat_cache.lock();
            let sit = self.sit_cache.lock();
            cp.valid_node_count = nat
                .entries
                .iter()
                .filter(|e| e.block_addr != F2FS_NULL_ADDR)
                .count() as u32;
            cp.valid_block_count = sit.entries.iter().map(|e| e.vblocks as u32).sum();
            cp.valid_inode_count = nat
                .entries
                .iter()
                .filter(|e| e.block_addr != F2FS_NULL_ADDR)
                .count() as u32;
        }
        cp.next_free_nid = *self.next_nid.lock();

        // Toggle which copy we write to.
        let new_copy = if cp.cp_copy == 0 { 1u8 } else { 0u8 };
        cp.cp_copy = new_copy;

        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_checkpoint(&cp, &mut buf);

        let cp_blkaddr = if new_copy == 0 {
            self.sb.cp_blkaddr
        } else {
            self.sb.cp_blkaddr + self.sb.cp_payload + 1
        };

        // Write through (not write-back) for checkpoint safety.
        let lba = self.block_to_lba(cp_blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            self.cache
                .write_through(lba + i as u64, &buf[i * 512..(i + 1) * 512])?;
        }

        // Update in-memory checkpoint.
        *self.checkpoint.lock() = cp;

        Ok(())
    }

    /// Flush dirty NAT entries to the NAT area blocks.
    fn flush_dirty_nat(&self) -> Result<()> {
        let dirty: Vec<(u32, F2fsNatEntry)> = {
            let mut guard = self.dirty_nat.lock();
            let entries: Vec<_> = guard.iter().map(|(k, v)| (*k, *v)).collect();
            guard.clear();
            entries
        };

        if dirty.is_empty() {
            return Ok(());
        }

        // Each NAT block holds NAT_ENTRIES_PER_BLOCK entries.
        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];

        // Group dirty entries by NAT block.
        for (nid, entry) in &dirty {
            let nat_block_idx = *nid / F2FS_NAT_ENTRIES_PER_BLOCK as u32;
            let nat_block = self.sb.nat_blkaddr + nat_block_idx;

            // Read the existing NAT block.
            self.read_fs_block(nat_block, &mut buf)?;

            // Update the entry within the block.
            let entry_off = (*nid as usize % F2FS_NAT_ENTRIES_PER_BLOCK) * F2FS_NAT_ENTRY_SIZE;
            write_nat_entry(entry, &mut buf[entry_off..entry_off + F2FS_NAT_ENTRY_SIZE]);

            // Write the block back through write-back cache.
            self.write_fs_block(nat_block, &buf)?;
        }

        Ok(())
    }

    /// Initialise the in-memory NAT cache from the NAT area and CP journal.
    pub(crate) fn init_nat_cache(
        cache: &BlockCache,
        sb: &F2fsSuperblock,
        cp: &F2fsCheckpoint,
    ) -> Result<F2fsNatCache> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;
        let nat_blocks = (sb.nat_entry_cnt as usize).div_ceil(F2FS_NAT_ENTRIES_PER_BLOCK);

        let total_entries = sb.nat_entry_cnt as usize;
        let mut entries = Vec::with_capacity(total_entries);

        // Read NAT entries from the NAT area.
        for blk in 0..nat_blocks {
            let mut buf = vec![0u8; block_size];
            let phys = sb.nat_blkaddr as u64 + blk as u64;
            let lba = phys * sector_count as u64;
            for i in 0..sector_count {
                cache.read_cached(lba + i as u64, &mut buf[i * 512..(i + 1) * 512])?;
            }
            let entries_in_block = F2FS_NAT_ENTRIES_PER_BLOCK;
            for j in 0..entries_in_block {
                let off = j * F2FS_NAT_ENTRY_SIZE;
                if off + F2FS_NAT_ENTRY_SIZE <= buf.len() {
                    entries.push(parse_nat_entry(&buf[off..off + F2FS_NAT_ENTRY_SIZE]));
                }
            }
        }

        // Truncate to declared entry count.
        entries.truncate(total_entries);

        let mut nat_cache = F2fsNatCache { entries };

        // Apply NAT journal entries from the checkpoint (they override the
        // base NAT area).
        for entry in &cp.nat_journal {
            let nid = entry.nid as usize;
            if nid < nat_cache.entries.len() {
                nat_cache.entries[nid] = entry.ne;
            }
        }

        Ok(nat_cache)
    }

    /// Initialise the in-memory SIT cache from the SIT area.
    pub(crate) fn init_sit_cache(cache: &BlockCache, sb: &F2fsSuperblock) -> Result<F2fsSitCache> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;

        // Each SIT entry is 66 bytes.  How many fit in one 4K block?
        let entries_per_block = block_size / 66;
        let sit_blocks = (sb.sit_entry_cnt as usize).div_ceil(entries_per_block);

        let total_entries = sb.sit_entry_cnt as usize;
        let mut entries = Vec::with_capacity(total_entries);

        for blk in 0..sit_blocks {
            let mut buf = vec![0u8; block_size];
            let phys = sb.sit_blkaddr + blk as u32;
            let lba = phys as u64 * sector_count as u64;
            for i in 0..sector_count {
                cache.read_cached(lba + i as u64, &mut buf[i * 512..(i + 1) * 512])?;
            }
            let n_in_block = (total_entries - entries.len()).min(entries_per_block);
            for j in 0..n_in_block {
                let off = j * 66;
                if off + 66 <= buf.len() {
                    entries.push(parse_sit_entry(&buf[off..off + 66]));
                }
            }
        }

        entries.truncate(total_entries);

        // Build free segments list.
        let mut free_segments = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            if entry.vblocks == 0 {
                free_segments.push(i as u32);
            }
        }

        Ok(F2fsSitCache {
            entries,
            free_segments,
        })
    }

    /// Find the first free segment to use for append writes.
    pub(crate) fn find_first_free_segment(
        sit_cache: &F2fsSitCache,
        _sb: &F2fsSuperblock,
    ) -> (u32, u16) {
        if let Some(&segno) = sit_cache.free_segments.first() {
            (segno, 0)
        } else {
            // No fully free segments — fall back to segment 0 offset 0
            // (will quickly fail on write, which is the correct behaviour).
            (0, 0)
        }
    }

    /// Write the superblock back to block 0.
    pub(crate) fn write_superblock(&self) -> Result<()> {
        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_superblock(&self.sb, &mut buf);
        self.write_fs_block(0, &buf)
    }
}
