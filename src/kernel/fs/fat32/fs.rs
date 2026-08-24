//! src/kernel/fs/fat32/fs.rs
//!
//! Internal FAT filesystem read/write operations — volume open, FAT table
//! access, cluster chain walking, directory reading, path resolution, and
//! cluster allocation.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::fs::filesystem::profiler::FsProfiler;
use crate::kernel::fs::unicode;
use crate::kernel::fs::vfs::NodeKind;
use crate::{Error, Result};

use super::types::{
    build_lfn_name, parse_lfn_fragment, parse_short_dir_entry, read_u16, read_u32, FatDirEntry,
    FatGeometry, FatType, DIR_ENTRY_SIZE, FIRST_DATA_CLUSTER,
};
use super::FatFs;

impl FatFs {
    pub(crate) fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let cache = crate::kernel::fs::block_cache::BlockCache::new(device.clone());
        let mut block_buf = [0u8; BLOCK_SIZE];

        // Read boot sector (LBA 0).
        cache.read_cached(0, &mut block_buf).map_err(|_| {
            crate::println!("FAT: failed to read boot sector");
            Error::DeviceError
        })?;
        let geom = FatGeometry::from_boot_sector(&block_buf)?;

        Ok(Self {
            cache,
            geom,
            code_page: crate::kernel::fs::unicode::OemCodePage::Cp437,
            block_buf,
            profiler: FsProfiler::default(),
        })
    }

    /// Read a single-sector block through the cache.
    pub(crate) fn read_block(&mut self, lba: u64) -> Result<&[u8; BLOCK_SIZE]> {
        self.cache
            .read_cached(lba, &mut self.block_buf)
            .map_err(|_| Error::DeviceError)?;
        Ok(&self.block_buf)
    }

    /// Write prepared data from `self.block_buf` back through the cache.
    pub(crate) fn write_block(&mut self, lba: u64) -> Result<()> {
        self.cache.write_back(lba, &self.block_buf)
    }

    /// Write a FAT entry value for the given cluster into **both** FAT tables.
    /// For FAT12, handles the 12-bit packing with a read-modify-write of the
    /// affected 16-bit word.
    pub(crate) fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
        match self.geom.fat_type {
            FatType::Fat12 => {
                // FAT12: two 12-bit entries share 3 bytes.
                let fat_offset = cluster as u64 + (cluster as u64 >> 1);
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                // Read the existing 16-bit word that contains our 12-bit entry.
                self.read_block(fat_lba)?;
                let mut word = read_u16(&self.block_buf, offset_in_block);
                if cluster & 1 == 0 {
                    // Even cluster: keep high 4 bits, replace low 12 bits.
                    word = (word & 0xF000) | (value as u16 & 0x0FFF);
                } else {
                    // Odd cluster: keep low 4 bits, replace high 12 bits.
                    word = (word & 0x000F) | ((value as u16) << 4);
                }
                self.block_buf[offset_in_block] = word as u8;
                self.block_buf[offset_in_block + 1] = (word >> 8) as u8;
                self.write_block(fat_lba)?;

                // FAT12 typically has one FAT; second copy at same offset.
                // For FAT12, num_fats is usually 1 or 2 in practice — write
                // the second FAT if present.
                if self.geom.num_fats > 1 {
                    let fat2_lba = fat_lba + self.geom.sectors_per_fat as u64;
                    self.read_block(fat2_lba)?;
                    self.block_buf[offset_in_block] = word as u8;
                    self.block_buf[offset_in_block + 1] = (word >> 8) as u8;
                    self.write_block(fat2_lba)?;
                }
            }
            FatType::Fat16 => {
                let fat_offset = cluster as u64 * 2;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                for &lba in &[fat_lba, fat_lba + self.geom.sectors_per_fat as u64] {
                    self.read_block(lba)?;
                    self.block_buf[offset_in_block] = value as u8;
                    self.block_buf[offset_in_block + 1] = (value >> 8) as u8;
                    self.write_block(lba)?;
                }
            }
            FatType::Fat32 => {
                let fat_offset = cluster as u64 * 4;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                for &lba in &[fat_lba, fat_lba + self.geom.sectors_per_fat as u64] {
                    self.read_block(lba)?;
                    self.block_buf[offset_in_block] = value as u8;
                    self.block_buf[offset_in_block + 1] = (value >> 8) as u8;
                    self.block_buf[offset_in_block + 2] = (value >> 16) as u8;
                    self.block_buf[offset_in_block + 3] = (value >> 24) as u8;
                    self.write_block(lba)?;
                }
            }
        }
        Ok(())
    }

    /// Find a free cluster in the FAT table.  Returns the cluster number or
    /// `Err(Error::NoSpace)` if none are available.
    pub(crate) fn find_free_cluster(&mut self) -> Result<u32> {
        let eoc_min = self.geom.fat_type.eoc_min();
        for cluster in FIRST_DATA_CLUSTER..FIRST_DATA_CLUSTER + self.geom.data_cluster_count {
            let entry = self.read_fat_entry(cluster)?;
            if entry == 0x0000_0000 {
                return Ok(cluster);
            }
            // Guard against bad clusters that would loop forever.
            if entry >= eoc_min {
                continue;
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate a new cluster and append it to the end of an existing chain.
    /// If `last_cluster` is 0, allocate the first cluster and mark it EOC.
    /// Returns the newly-allocated cluster number.
    pub(crate) fn append_cluster(&mut self, last_cluster: u32) -> Result<u32> {
        let new_cluster = self.find_free_cluster()?;
        let eoc_min = self.geom.fat_type.eoc_min();

        // Mark the new cluster as EOC.
        self.write_fat_entry(new_cluster, eoc_min)?;

        // If there's a last cluster, update it to point to the new one.
        if last_cluster != 0 {
            self.write_fat_entry(last_cluster, new_cluster)?;
        }

        Ok(new_cluster)
    }

    /// Free all clusters in a chain starting at `start_cluster`.
    pub(crate) fn free_cluster_chain(&mut self, start_cluster: u32) -> Result<()> {
        let eoc_min = self.geom.fat_type.eoc_min();
        let mut cluster = start_cluster;
        for _ in 0..65536 {
            if cluster < FIRST_DATA_CLUSTER || cluster >= eoc_min {
                break;
            }
            let next = self.read_fat_entry(cluster)?;
            self.write_fat_entry(cluster, 0x0000_0000)?;
            if next >= eoc_min {
                break;
            }
            cluster = next;
        }
        Ok(())
    }

    /// Write raw bytes to a cluster chain, overwriting from `start_cluster`
    /// with offsets within the first cluster.
    pub(crate) fn write_cluster_chain_data(
        &mut self,
        start_cluster: u32,
        data: &[u8],
    ) -> Result<()> {
        let cluster_size = self.geom.cluster_size_bytes as usize;
        let sectors = self.geom.sectors_per_cluster as u64;
        let chain = self.walk_cluster_chain(start_cluster)?;
        let total_capacity = chain.len() * cluster_size;

        if data.len() > total_capacity {
            return Err(Error::InvalidArgument);
        }

        for (ci, &cluster) in chain.iter().enumerate() {
            let lba = self.geom.cluster_to_lba(cluster);
            let chunk_start = ci * cluster_size;
            let chunk_end = (chunk_start + cluster_size).min(data.len());
            if chunk_start >= data.len() {
                break;
            }
            let chunk = &data[chunk_start..chunk_end];

            for s in 0..sectors {
                let block_start = s as usize * BLOCK_SIZE;
                let block_end = block_start + BLOCK_SIZE;
                let buf_slice = &mut self.block_buf;

                if block_start < chunk.len() {
                    let copy_end = block_end.min(chunk.len());
                    buf_slice[..copy_end - block_start]
                        .copy_from_slice(&chunk[block_start..copy_end]);
                    // Zero-fill remainder of this block within the chunk.
                    for b in buf_slice.iter_mut().skip(copy_end - block_start) {
                        *b = 0;
                    }
                } else {
                    buf_slice.fill(0);
                }

                self.cache
                    .write_back(lba + s, buf_slice)
                    .map_err(|_| Error::DeviceError)?;
            }
        }
        Ok(())
    }

    /// Write file data at `start_cluster`, allocating new clusters as
    /// needed.  Updates the FAT chain.  Returns the (possibly new) start
    /// cluster.
    pub(crate) fn write_file_data_extend(
        &mut self,
        start_cluster: u32,
        data: &[u8],
    ) -> Result<u32> {
        let cluster_size = self.geom.cluster_size_bytes as usize;

        // If no start cluster, allocate the first.
        let first = if start_cluster == 0 {
            self.append_cluster(0)?
        } else {
            start_cluster
        };

        // Walk the existing chain and count clusters.
        let mut chain = self.walk_cluster_chain(first)?;
        let _existing_capacity = chain.len() * cluster_size;

        // Extend the chain if needed.
        while chain.len() * cluster_size < data.len() {
            let last_cluster = chain.last().copied().unwrap_or(first);
            let new_cluster = self.append_cluster(last_cluster)?;
            chain.push(new_cluster);
        }

        // Now we have enough clusters to hold the data for the first `chain.len()` clusters.
        // BUT we might be writing fewer clusters than the chain has. In that case,
        // we should NOT truncate the chain; we just overwrite the first N clusters.

        // Write to the chain.
        self.write_cluster_chain_data(first, data)?;

        // If the data fits in fewer clusters than we walked, truncate the chain.
        let needed_clusters = data.len().div_ceil(cluster_size).max(1);
        if needed_clusters < chain.len() {
            // Free the extra clusters.
            let first_extra = chain[needed_clusters - 1];
            let next_after_first_extra = self.read_fat_entry(first_extra)?;
            // Mark the last-needed cluster as EOC.
            let eoc_min = self.geom.fat_type.eoc_min();
            let last_needed_cluster = chain[needed_clusters - 1];
            self.write_fat_entry(last_needed_cluster, eoc_min)?;
            // Free from the first extra cluster onwards.
            if next_after_first_extra < eoc_min {
                self.free_cluster_chain(next_after_first_extra)?;
            }
        }

        Ok(first)
    }

    /// Read the raw FAT12/16 root directory region (for in-place writes).
    pub(crate) fn read_root_dir_raw(&mut self) -> Result<Vec<u8>> {
        let raw_len = self.geom.root_dir_sectors as usize * BLOCK_SIZE;
        let mut raw = vec![0u8; raw_len];
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            self.cache
                .read_cached(lba, &mut self.block_buf)
                .map_err(|_| Error::DeviceError)?;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            raw[start..end].copy_from_slice(&self.block_buf);
        }
        Ok(raw)
    }

    /// Write raw bytes back to the FAT12/16 root directory region.
    pub(crate) fn write_root_dir_raw(&mut self, data: &[u8]) -> Result<()> {
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            if start >= data.len() {
                self.block_buf.fill(0);
            } else {
                let copy_end = end.min(data.len());
                let n = copy_end - start;
                self.block_buf[..n].copy_from_slice(&data[start..copy_end]);
                for b in &mut self.block_buf[n..] {
                    *b = 0;
                }
            }
            self.write_block(lba)?;
        }
        Ok(())
    }

    /// Read raw directory bytes for a cluster-based directory (FAT32 root or
    /// any subdirectory).
    pub(crate) fn read_dir_cluster_raw(&mut self, start_cluster: u32) -> Result<Vec<u8>> {
        self.read_cluster_chain_data(start_cluster)
    }

    /// Write raw bytes into a directory's cluster chain, extending as needed.
    pub(crate) fn write_dir_raw(&mut self, start_cluster: u32, data: &[u8]) -> Result<u32> {
        self.write_file_data_extend(start_cluster, data)
    }

    /// Get raw directory content (byte-level) for read-modify-write.
    pub(crate) fn get_dir_raw(
        &mut self,
        dir_cluster: u32,
        is_root: bool,
    ) -> Result<(Vec<u8>, u32)> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            let raw = self.read_root_dir_raw()?;
            Ok((raw, dir_cluster))
        } else {
            let raw = self.read_dir_cluster_raw(dir_cluster)?;
            Ok((raw, dir_cluster))
        }
    }

    /// Write raw directory content back.
    pub(crate) fn put_dir_raw(
        &mut self,
        dir_cluster: u32,
        is_root: bool,
        raw: &[u8],
    ) -> Result<u32> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            self.write_root_dir_raw(raw)?;
            Ok(dir_cluster)
        } else {
            self.write_dir_raw(dir_cluster, raw)
        }
    }

    /// Find a free slot in a directory's raw bytes.  Returns the byte offset
    /// of the free slot.  A free slot is either a deleted entry (0xE5) or the
    /// first position after the logical end (0x00 terminator).
    pub(crate) fn find_free_dir_offset(&self, raw: &[u8]) -> Option<usize> {
        let num_entries = raw.len() / DIR_ENTRY_SIZE;
        let mut found_free = None;
        for i in 0..num_entries {
            let offset = i * DIR_ENTRY_SIZE;
            let first_byte = raw[offset];
            if first_byte == 0xE5 && found_free.is_none() {
                // First deleted entry — candidate for reuse.
                found_free = Some(offset);
            }
            if first_byte == 0x00 {
                // End of directory — use this position (or earlier free slot).
                return Some(found_free.unwrap_or(offset));
            }
        }
        found_free
    }

    /// Read the FAT entry for a given cluster.
    pub(crate) fn read_fat_entry(&mut self, cluster: u32) -> Result<u32> {
        match self.geom.fat_type {
            FatType::Fat12 => {
                // FAT12 packs two 12-bit entries into three bytes.
                // Byte offset = cluster + cluster/2 (i.e. cluster * 1.5).
                let fat_offset = cluster as u64 + (cluster as u64 >> 1); // cluster * 1.5
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                let word = read_u16(&self.block_buf, offset_in_block);
                if cluster & 1 == 0 {
                    // Even cluster: low 12 bits.
                    Ok((word & 0x0FFF) as u32)
                } else {
                    // Odd cluster: high 12 bits.
                    Ok((word >> 4) as u32)
                }
            }
            FatType::Fat16 => {
                let fat_offset = cluster as u64 * 2;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                Ok(read_u16(&self.block_buf, offset_in_block) as u32)
            }
            FatType::Fat32 => {
                let fat_offset = cluster as u64 * 4;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                let entry = read_u32(&self.block_buf, offset_in_block);
                Ok(entry & self.geom.fat_type.eoc_mask())
            }
        }
    }

    /// Walk a cluster chain starting at `start_cluster` and collect all
    /// cluster numbers. Returns the chain in order.
    pub(crate) fn walk_cluster_chain(&mut self, start_cluster: u32) -> Result<Vec<u32>> {
        let eoc_min = self.geom.fat_type.eoc_min();
        let mut chain = Vec::new();
        let mut cluster = start_cluster;
        // Safety limit: prevent infinite loops on corrupt FAT
        let max_clusters = (self.geom.data_cluster_count as usize).min(65536);
        for _ in 0..max_clusters {
            if cluster < FIRST_DATA_CLUSTER {
                break;
            }
            if cluster >= eoc_min {
                break;
            }
            chain.push(cluster);
            cluster = self.read_fat_entry(cluster)?;
        }
        Ok(chain)
    }

    /// Read all raw bytes from a cluster chain into a Vec<u8>.
    pub(crate) fn read_cluster_chain_data(&mut self, start_cluster: u32) -> Result<Vec<u8>> {
        let chain = self.walk_cluster_chain(start_cluster)?;
        let cluster_size = self.geom.cluster_size_bytes as usize;
        let mut data = vec![0u8; chain.len() * cluster_size];

        for (i, &cluster) in chain.iter().enumerate() {
            let lba = self.geom.cluster_to_lba(cluster);
            let sectors = self.geom.sectors_per_cluster as u64;
            let dest = &mut data[i * cluster_size..(i + 1) * cluster_size];
            for s in 0..sectors {
                let block_start = s as usize * BLOCK_SIZE;
                let block_end = block_start + BLOCK_SIZE;
                self.cache
                    .read_cached(lba + s, &mut self.block_buf)
                    .map_err(|_| Error::DeviceError)?;
                dest[block_start..block_end].copy_from_slice(&self.block_buf);
            }
        }
        Ok(data)
    }

    /// Read file data starting at `start_cluster`, up to `size` bytes
    /// (capped by chain length).
    pub(crate) fn read_file_data(&mut self, start_cluster: u32, size: u32) -> Result<Vec<u8>> {
        let mut all_data = self.read_cluster_chain_data(start_cluster)?;
        let len = (size as usize).min(all_data.len());
        all_data.truncate(len);
        Ok(all_data)
    }

    /// Read the FAT12/16 root directory (fixed region, not a cluster chain).
    pub(crate) fn read_root_directory(&mut self) -> Result<Vec<FatDirEntry>> {
        let raw_len = self.geom.root_dir_sectors as usize * BLOCK_SIZE;
        let mut raw = vec![0u8; raw_len];
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            self.cache
                .read_cached(lba, &mut self.block_buf)
                .map_err(|_| Error::DeviceError)?;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            raw[start..end].copy_from_slice(&self.block_buf);
        }
        Ok(parse_directory_entries(&raw, self.code_page))
    }

    /// Read all directory entries from a directory cluster chain (FAT32 root
    /// or any FAT subdirectory).
    pub(crate) fn read_directory_cluster(
        &mut self,
        start_cluster: u32,
    ) -> Result<Vec<FatDirEntry>> {
        let raw = self.read_cluster_chain_data(start_cluster)?;
        Ok(parse_directory_entries(&raw, self.code_page))
    }

    /// Read a directory: cluster-based for FAT32 and any subdirectory;
    /// fixed-region for FAT12/16 root.
    pub(crate) fn read_directory(
        &mut self,
        start_cluster: u32,
        is_root: bool,
    ) -> Result<Vec<FatDirEntry>> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            self.read_root_directory()
        } else {
            self.read_directory_cluster(start_cluster)
        }
    }

    /// Walk a path from the root directory, returning the matching directory
    /// entry or NotFound.
    pub(crate) fn walk_path(&mut self, path: &str) -> Result<FatDirEntry> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let is_root = path.is_empty();

        if is_root {
            let root_cluster = self.geom.root_cluster;
            return Ok(FatDirEntry {
                name: String::from("/"),
                kind: NodeKind::Directory,
                first_cluster: root_cluster,
                file_size: 0,
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }

        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let root_cluster = self.geom.root_cluster;
        let mut current_cluster = root_cluster;
        let mut is_current_root = true;

        for (i, &component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let entries = self.read_directory(current_cluster, is_current_root)?;

            let found = entries
                .iter()
                .find(|e| unicode::eq_unicode_insensitive(e.name.as_str(), component));

            match found {
                Some(entry) => {
                    if is_last {
                        return Ok(entry.clone());
                    }
                    if entry.kind == NodeKind::Directory {
                        current_cluster = entry.first_cluster;
                        is_current_root = false;
                    } else {
                        return Err(Error::InvalidArgument);
                    }
                }
                None => return Err(Error::NotFound),
            }
        }

        Err(Error::NotFound)
    }
}

/// Parse raw directory entry bytes into [`FatDirEntry`] values, merging LFN
/// fragments with their short entries.  Shared between cluster-based and
/// fixed-region directory reads.
pub(crate) fn parse_directory_entries(
    raw: &[u8],
    code_page: crate::kernel::fs::unicode::OemCodePage,
) -> Vec<FatDirEntry> {
    let mut entries = Vec::new();
    let mut lfn_buffer: Vec<(u8, [u16; 13])> = Vec::new();

    let num_entries = raw.len() / DIR_ENTRY_SIZE;
    for i in 0..num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        let entry_data = &raw[offset..offset + DIR_ENTRY_SIZE];

        if entry_data[0] == 0x00 {
            // End of directory
            break;
        }

        // Try to parse as LFN fragment first
        if let Some(lfn) = parse_lfn_fragment(entry_data) {
            if lfn.0 & 0x40 != 0 {
                // This is the last LFN entry; clear previous
                lfn_buffer.clear();
            }
            lfn_buffer.push(lfn);
            continue;
        }

        // Parse short entry
        if let Some(entry) = parse_short_dir_entry(entry_data, code_page) {
            // Build LFN name from fragments if available
            let final_name = if !lfn_buffer.is_empty() {
                let name = build_lfn_name(&lfn_buffer);
                lfn_buffer.clear();
                if name.is_empty() {
                    entry.name
                } else {
                    name
                }
            } else {
                entry.name
            };

            entries.push(FatDirEntry {
                name: final_name,
                ..entry
            });
        }
    }

    entries
}
