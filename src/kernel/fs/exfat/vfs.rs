//! src/kernel/fs/exfat/vfs.rs
//!
//! VFS integration — [`ExfatVolume`] open/close, [`VfsFileSystem`] trait
//! implementation, [`ExfatVNode`] type, and [`VNode`] trait implementation.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block::BLOCK_SIZE;
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::kernel::fs::unicode;
use crate::kernel::fs::vfs::DirectoryEntry;
use crate::kernel::fs::vfs::FileSystem as VfsTrait;
use crate::kernel::fs::vfs::Metadata;
use crate::kernel::fs::vfs::NodeKind;
use crate::kernel::fs::vfs::SecurityDescriptor;
use crate::kernel::fs::vfs::SecurityDescriptorMutationSupport;
use crate::kernel::fs::vfs::VNode;
use crate::kernel::fs::vfs::VolumeCheckReport;
use crate::Error;
use crate::Result;

use super::fs::find_entry_set_position;
use super::fs::split_path;
use super::types::*;
use super::ExfatFs;
use super::ExfatVolume;

// ─── Public volume entry point ─────────────────────────────────────────────

impl ExfatVolume {
    /// Open an exFAT volume from the given block device.
    ///
    /// Reads and validates the boot region.  Returns an error if the
    /// filesystem type is not recognised or the boot checksum is invalid.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let fs = ExfatFs::open(device.clone())?;
        let name = format!(
            "exfat:{}",
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        Ok(Self {
            name,
            fs: Arc::new(crate::kernel::sync::Mutex::new(fs)),
        })
    }

    fn with_fs<T>(&self, f: impl FnOnce(&mut ExfatFs) -> Result<T>) -> Result<T> {
        f(&mut self.fs.lock())
    }
}

// ─── VFS trait implementation ──────────────────────────────────────────────

impl VfsTrait for ExfatVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.lock().profiler.inc_lookups();
        let entry = self.with_fs(|fs| fs.walk_path(path))?;

        // Determine parent directory cluster and entry set offset.
        let (parent_dir_cluster, entry_set_offset) = if path == "/" || path.is_empty() {
            (0, 0)
        } else {
            let (parent_path, name) = split_path(path);
            self.with_fs(|fs| {
                let parent_entry = fs.walk_path(&parent_path)?;
                let raw = fs.read_cluster_chain_data(parent_entry.first_cluster)?;
                let offset = find_entry_set_position(&raw, &name).unwrap_or(0);
                Ok((parent_entry.first_cluster, offset))
            })
            .unwrap_or((0, 0))
        };

        Ok(Arc::new(ExfatVNode {
            name: entry.name.clone(),
            kind: entry.kind,
            first_cluster: entry.first_cluster,
            parent_dir_cluster,
            entry_set_offset,
            fs: self.fs.clone(),
            valid_data_length: crate::kernel::sync::Mutex::new(entry.valid_data_length),
            data_length: crate::kernel::sync::Mutex::new(entry.data_length),
            no_fat_chain: crate::kernel::sync::Mutex::new(entry.no_fat_chain),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let entry = self.with_fs(|fs| fs.walk_path(path))?;
        let kind = entry.kind;
        let size = if kind == NodeKind::Directory {
            0
        } else {
            entry.valid_data_length as usize
        };
        Ok(Metadata {
            kind,
            size,
            security: SecurityDescriptor::root_for_kind(kind),
            created: entry.created,
            modified: entry.modified,
            accessed: entry.accessed,
        })
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.fs.lock().profiler.inc_lookups();
        let dir_entry = self.with_fs(|fs| fs.walk_path(path))?;
        if dir_entry.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let entries = self.with_fs(|fs| fs.read_directory_entries(dir_entry.first_cluster))?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        Ok(DirectoryEntry::new(
            entry.kind,
            if entry.kind == NodeKind::Directory {
                0
            } else {
                entry.valid_data_length as usize
            },
            entry.name.clone(),
        ))
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check the file doesn't already exist.
        let parent_clone = parent_dir_cluster;
        if self.with_fs(|fs| fs.walk_path(path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        self.with_fs(|fs| {
            // Allocate a cluster for the new file.
            let new_cluster = fs.find_free_cluster()?;
            fs.set_bitmap_bit(new_cluster, true)?;
            fs.write_fat_entry(new_cluster, FAT32_EOC)?;

            // Build the entry set.
            let entry_set =
                ExfatFs::build_entry_set(&name, NodeKind::File, new_cluster, 0, 0, true);
            let entry_bytes = entry_set.len() * DIR_ENTRY_SIZE;

            // Find a free slot in the parent directory.
            let slot_offset = fs.find_free_dir_slot(parent_clone, entry_bytes)?;

            // Write the entry set into the parent directory.
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = slot_offset as u64 / cluster_size;
            let intra_off = (slot_offset as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(parent_clone)?;
            let target_cluster = chain
                .get(cluster_off as usize)
                .copied()
                .ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            // Write each entry to the right LBA.
            for (i, entry) in entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / BLOCK_SIZE;
                let sec_off = byte_pos % BLOCK_SIZE;
                fs.read_block(lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                fs.write_block_cached(lba + sector as u64, &fs.block_buf.clone())?;
            }

            fs.flush()?;
            Ok(())
        })?;

        self.lookup(path)
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        if self.with_fs(|fs| fs.walk_path(path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        self.with_fs(|fs| {
            // Allocate a cluster for the new directory.
            let dir_cluster = fs.find_free_cluster()?;
            fs.set_bitmap_bit(dir_cluster, true)?;
            fs.write_fat_entry(dir_cluster, FAT32_EOC)?;

            // Write "." and ".." entries into the new directory.
            let dot_entry =
                ExfatFs::build_entry_set(".", NodeKind::Directory, dir_cluster, 0, 0, false);
            let dotdot_entry = ExfatFs::build_entry_set(
                "..",
                NodeKind::Directory,
                parent_dir_cluster,
                0,
                0,
                false,
            );

            let lba = fs.boot.cluster_to_lba(dir_cluster);

            // Flatten entry arrays into a contiguous byte slice.
            let flatten_entries = |entries: &[[u8; DIR_ENTRY_SIZE]]| -> &[u8] {
                let ptr = entries.as_ptr() as *const u8;
                let len = entries.len() * DIR_ENTRY_SIZE;
                unsafe { core::slice::from_raw_parts(ptr, len) }
            };

            let dot_bytes = flatten_entries(&dot_entry);
            let dotdot_bytes = flatten_entries(&dotdot_entry);

            // Read-modify-write the first sector.
            fs.read_block(lba)?;
            fs.block_buf[..dot_bytes.len()].copy_from_slice(dot_bytes);
            let dd_start = dot_bytes.len();
            fs.block_buf[dd_start..dd_start + dotdot_bytes.len()].copy_from_slice(dotdot_bytes);
            // EOD after dotdot.
            let eod_pos = dd_start + dotdot_bytes.len();
            if eod_pos < BLOCK_SIZE {
                fs.block_buf[eod_pos] = EXFAT_ENTRY_EOD;
            }
            fs.write_block_cached(lba, &fs.block_buf.clone())?;

            // Build the entry set for the new directory in the parent.
            let entry_set =
                ExfatFs::build_entry_set(&name, NodeKind::Directory, dir_cluster, 0, 0, false);
            let entry_bytes = entry_set.len() * DIR_ENTRY_SIZE;

            let slot_offset = fs.find_free_dir_slot(parent_dir_cluster, entry_bytes)?;
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = slot_offset as u64 / cluster_size;
            let intra_off = (slot_offset as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(parent_dir_cluster)?;
            let target_cluster = chain
                .get(cluster_off as usize)
                .copied()
                .ok_or(Error::OutOfMemory)?;
            let parent_lba = fs.boot.cluster_to_lba(target_cluster);

            for (i, entry) in entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / BLOCK_SIZE;
                let sec_off = byte_pos % BLOCK_SIZE;
                fs.read_block(parent_lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                fs.write_block_cached(parent_lba + sector as u64, &fs.block_buf.clone())?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (old_parent_cluster, old_name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(old_path);
            let parent_entry = fs.walk_path(&parent_path)?;
            Ok((parent_entry.first_cluster, name))
        })?;

        let (_new_parent_cluster, new_name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(new_path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.first_cluster != old_parent_cluster {
                // Cross-directory rename not yet supported.
                return Err(Error::Unsupported);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        // Check new path doesn't already exist.
        if self.with_fs(|fs| fs.walk_path(new_path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let target_entry = self.with_fs(|fs| fs.walk_path(old_path))?;

        self.with_fs(|fs| {
            // Build new entry set with the new name.
            let new_entry_set = ExfatFs::build_entry_set(
                &new_name,
                target_entry.kind,
                target_entry.first_cluster,
                target_entry.valid_data_length,
                target_entry.data_length,
                target_entry.no_fat_chain,
            );
            let new_byte_count = new_entry_set.len() * DIR_ENTRY_SIZE;

            // Mark old entries as not-in-use.
            let old_raw = fs.read_cluster_chain_data(old_parent_cluster)?;
            let old_name_utf16 = unicode::utf8_to_utf16le(&old_name);
            let old_fn_count = old_name_utf16.len().div_ceil(FN_CHARS_PER_ENTRY);
            let old_total = 2 + old_fn_count; // file + stream + filename entries

            // Find the old entry set position.
            if let Some(old_pos) = find_entry_set_position(&old_raw, &old_name) {
                let cluster_size = fs.boot.cluster_size_bytes as usize;
                let cluster_off = old_pos / cluster_size;
                let intra_off = old_pos % cluster_size;

                let chain = fs.walk_cluster_chain(old_parent_cluster)?;
                if let Some(&target_cluster) = chain.get(cluster_off) {
                    let lba = fs.boot.cluster_to_lba(target_cluster);
                    // Mark old entries as not-in-use by clearing bit 7.
                    for i in 0..old_total {
                        let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                        let sector = byte_pos / BLOCK_SIZE;
                        let sec_off = byte_pos % BLOCK_SIZE;
                        fs.read_block(lba + sector as u64)?;
                        fs.block_buf[sec_off] &= !ENTRY_INUSE_MASK;
                        fs.write_block_cached(lba + sector as u64, &fs.block_buf.clone())?;
                    }
                }

                // Try to write the new entry set at the same position if it fits.
                if new_byte_count <= old_total * DIR_ENTRY_SIZE {
                    let chain2 = fs.walk_cluster_chain(old_parent_cluster)?;
                    if let Some(&target_cluster2) = chain2.get(cluster_off) {
                        let lba2 = fs.boot.cluster_to_lba(target_cluster2);
                        for (i, entry) in new_entry_set.iter().enumerate() {
                            let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                            let sector = byte_pos / BLOCK_SIZE;
                            let sec_off = byte_pos % BLOCK_SIZE;
                            fs.read_block(lba2 + sector as u64)?;
                            fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                            fs.write_block_cached(lba2 + sector as u64, &fs.block_buf.clone())?;
                        }
                        fs.flush()?;
                        return Ok(());
                    }
                }
            }

            // Fallback: allocate a new slot and write the new entry set.
            let new_slot = fs.find_free_dir_slot(old_parent_cluster, new_byte_count)?;
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = new_slot as u64 / cluster_size;
            let intra_off = (new_slot as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(old_parent_cluster)?;
            let target_cluster = chain
                .get(cluster_off as usize)
                .copied()
                .ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            for (i, entry) in new_entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / BLOCK_SIZE;
                let sec_off = byte_pos % BLOCK_SIZE;
                fs.read_block(lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                fs.write_block_cached(lba + sector as u64, &fs.block_buf.clone())?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        let target = self.with_fs(|fs| fs.walk_path(path))?;

        // If it's a directory, check it's empty (only "." and ".." entries).
        if target.kind == NodeKind::Directory {
            let entries = self.with_fs(|fs| fs.read_directory_entries(target.first_cluster))?;
            let non_dot_count = entries
                .iter()
                .filter(|e| e.name != "." && e.name != "..")
                .count();
            if non_dot_count > 0 {
                return Err(Error::PermissionDenied);
            }
        }

        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            Ok((parent_entry.first_cluster, name))
        })?;

        self.with_fs(|fs| {
            // Read the raw parent directory.
            let raw = fs.read_cluster_chain_data(parent_dir_cluster)?;

            // Find the entry set position for the target name.
            let pos = find_entry_set_position(&raw, &name).ok_or(Error::NotFound)?;
            let cluster_size = fs.boot.cluster_size_bytes as usize;
            let cluster_off = pos / cluster_size;
            let intra_off = pos % cluster_size;

            let chain = fs.walk_cluster_chain(parent_dir_cluster)?;
            let target_cluster = chain.get(cluster_off).copied().ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            // Mark the file entry as not-in-use (clear bit 7).
            let byte_pos = intra_off;
            let sector = byte_pos / BLOCK_SIZE;
            let sec_off = byte_pos % BLOCK_SIZE;
            fs.read_block(lba + sector as u64)?;
            fs.block_buf[sec_off] &= !ENTRY_INUSE_MASK;
            fs.write_block_cached(lba + sector as u64, &fs.block_buf.clone())?;

            // Free the cluster chain.
            if target.first_cluster >= FIRST_DATA_CLUSTER {
                fs.free_cluster_chain(target.first_cluster)?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.fs.lock().profiler.snapshot()
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        let fs = self.fs.lock();
        // Basic boot region sanity checks.
        if fs.boot.cluster_size_bytes == 0 {
            issues += 1;
        }
        if fs.boot.cluster_count < 2 {
            issues += 1;
        }
        if fs.boot.root_dir_cluster < FIRST_DATA_CLUSTER {
            issues += 1;
        }
        drop(fs);

        // Verify the root directory is reachable.
        if self.lookup("/").is_err() {
            issues += 1;
        }

        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }
}

// ─── exFAT VNode ───────────────────────────────────────────────────────────

struct ExfatVNode {
    /// File/directory name (immutable after creation).
    name: String,
    /// Node kind (immutable after creation).
    kind: NodeKind,
    /// First cluster of the data stream.
    first_cluster: u32,
    /// Cluster number of the parent directory.
    parent_dir_cluster: u32,
    /// Byte offset of this file's entry set within the parent directory.
    entry_set_offset: usize,
    /// Shared filesystem state.
    fs: Arc<crate::kernel::sync::Mutex<ExfatFs>>,
    /// Valid data length in bytes (mutable, updated on write).
    valid_data_length: crate::kernel::sync::Mutex<u64>,
    /// Allocated data length in bytes (mutable, updated on write).
    data_length: crate::kernel::sync::Mutex<u64>,
    /// Whether the file is stored contiguously (mutable, may be cleared on
    /// write).
    no_fat_chain: crate::kernel::sync::Mutex<bool>,
}

impl VNode for ExfatVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        *self.valid_data_length.lock() as usize
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.fs.lock().profiler.inc_reads();
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }
        let valid_len = *self.valid_data_length.lock();
        let no_fat = *self.no_fat_chain.lock();
        let data = self
            .fs
            .lock()
            .read_file_data(self.first_cluster, valid_len, no_fat)?;
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }
        let mut fs = self.fs.lock();

        let old_valid = *self.valid_data_length.lock();
        let old_data_len = *self.data_length.lock();
        let old_nofat = *self.no_fat_chain.lock();

        // Write the data.
        let bytes_written = fs.write_cluster_data(self.first_cluster, offset, buffer)?;

        let new_valid = (offset + bytes_written as u64).max(old_valid);
        let new_data_len = new_valid.max(old_data_len);
        let keep_nofat = old_nofat && offset == 0;

        // Update the stream extension in the parent directory.
        fs.update_stream_entry(
            self.parent_dir_cluster,
            self.entry_set_offset,
            new_valid,
            new_data_len,
            keep_nofat,
        )?;

        fs.flush()?;

        // Update cached entry.
        *self.valid_data_length.lock() = new_valid;
        *self.data_length.lock() = new_data_len;
        *self.no_fat_chain.lock() = keep_nofat;

        Ok(bytes_written)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let mut fs = self.fs.lock();
        let old_valid = *self.valid_data_length.lock();
        let old_data = *self.data_length.lock();
        let old_nofat = *self.no_fat_chain.lock();

        if length == old_valid {
            return Ok(());
        }

        if length < old_data {
            // Truncate: free clusters beyond the new length.
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let old_clusters = if old_data == 0 {
                0
            } else {
                old_data.div_ceil(cluster_size) as usize
            };
            let new_clusters = if length == 0 {
                0
            } else {
                length.div_ceil(cluster_size) as usize
            };

            if new_clusters < old_clusters && self.first_cluster >= FIRST_DATA_CLUSTER {
                let chain = fs.walk_cluster_chain(self.first_cluster)?;
                if new_clusters > 0 && new_clusters <= chain.len() {
                    let last_keep = chain[new_clusters - 1];
                    fs.write_fat_entry(last_keep, FAT32_EOC)?;
                    for &c in &chain[new_clusters..] {
                        fs.write_fat_entry(c, 0)?;
                        fs.set_bitmap_bit(c, false)?;
                    }
                } else if new_clusters == 0 {
                    fs.free_cluster_chain(self.first_cluster)?;
                }
            }

            let new_data = (new_clusters as u64) * cluster_size;
            fs.update_stream_entry(
                self.parent_dir_cluster,
                self.entry_set_offset,
                length.min(old_valid),
                new_data,
                old_nofat,
            )?;
            fs.flush()?;
            *self.valid_data_length.lock() = length;
            *self.data_length.lock() = new_data;
        } else {
            // Extend: write zeros beyond current EOF.
            drop(fs);
            let zeros = vec![0u8; (length - old_valid) as usize];
            self.write(old_valid, &zeros)?;
            return Ok(());
        }

        Ok(())
    }
}
