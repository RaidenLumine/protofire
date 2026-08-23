//! src/kernel/fs/fat32/vfs.rs
//! VFS integration — [`FatVolume`] open/close, [`VfsFileSystem`] trait
//! implementation, [`FatVNode`] type, and [`VNode`] trait implementation.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;

use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::fs::filesystem::profiler::FsProfilerSnapshot;
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsTrait, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport,
};
use crate::{Error, Result};

use super::types::{
    build_dir_entry_set, insert_dir_entry_set, write_short_entry, FatDirEntry, FatType,
    ATTR_DIRECTORY, ATTR_LFN_MASK, DIR_ENTRY_SIZE, FIRST_DATA_CLUSTER,
};
use super::{FatFs, FatVolume};

// ─── Public volume entry point ─────────────────────────────────────────────

impl FatVolume {
    /// Open a FAT volume from the given block device.
    ///
    /// Reads and validates the BPB. Returns an error if the filesystem type
    /// is not recognised or if the geometry is unsupported.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let fs = FatFs::open(device.clone())?;
        let fat_type = fs.geom.fat_type;
        let name = format!(
            "{}:{}",
            fat_type.label(),
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        Ok(Self {
            name,
            fs: Arc::new(crate::kernel::sync::Mutex::new(fs)),
        })
    }

    fn with_fs<T>(&self, f: impl FnOnce(&mut FatFs) -> Result<T>) -> Result<T> {
        f(&mut self.fs.lock())
    }
}

// ─── VFS trait implementation ──────────────────────────────────────────────

impl VfsTrait for FatVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.lock().profiler.inc_lookups();
        let (entry, parent_dir_cluster, entry_offset, lfn_count, is_parent_root, has_entry_info) =
            self.with_fs(|fs| {
                let entry = fs.walk_path(path)?;

                let (parent_path, _) = split_parent(path);
                let is_root = parent_path == "/";

                // Walk parent to get its cluster.
                let parent = fs.walk_path(parent_path)?;
                let parent_cluster = parent.first_cluster;

                // Find the entry's position in the parent directory (works
                // for both root and non-root directories).
                let (raw, _) = fs.get_dir_raw(parent_cluster, is_root)?;
                let found = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
                let (off, lfn) = found.unwrap_or((0, 0));
                let has_info = found.is_some();
                Ok((entry, parent_cluster, off, lfn, is_root, has_info))
            })?;
        Ok(Arc::new(FatVNode {
            name: entry.name,
            kind: entry.kind,
            first_cluster: AtomicU32::new(entry.first_cluster),
            file_size: AtomicU32::new(entry.file_size),
            fs: self.fs.clone(),
            parent_dir_cluster,
            entry_offset,
            lfn_count,
            is_parent_root,
            has_entry_info,
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let entry = self.with_fs(|fs| fs.walk_path(path))?;
        let kind = entry.kind;
        let size = entry.file_size as usize;
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
        let is_root = path.is_empty() || path == "/";
        let entries = self.with_fs(|fs| fs.read_directory(dir_entry.first_cluster, is_root))?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        Ok(DirectoryEntry::new(
            entry.kind,
            entry.file_size as usize,
            entry.name.clone(),
        ))
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            // Split path into parent directory + file name.
            let (parent_path, file_name) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            // Allocate first cluster for the new (empty) file.
            let first_cluster = fs.append_cluster(0)?;

            // Read parent directory raw bytes.
            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            // Build the new directory entry set.
            let mut entry_buf = [0u8; 256];
            let num = build_dir_entry_set(
                &mut entry_buf,
                file_name,
                0x20,
                first_cluster,
                0,
                fs.code_page,
            );

            // Find a free slot.
            let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
            insert_dir_entry_set(&mut raw, free_offset, num, &entry_buf);

            // Write back the parent directory.
            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;

            // The short entry is the last entry in the set (after any LFN entries).
            let lfn_count = num.saturating_sub(1);

            let entry = FatDirEntry {
                name: String::from(file_name),
                kind: NodeKind::File,
                first_cluster,
                file_size: 0,
                created: 0,
                modified: 0,
                accessed: 0,
            };
            Ok(Arc::new(FatVNode {
                name: entry.name,
                kind: entry.kind,
                first_cluster: AtomicU32::new(entry.first_cluster),
                file_size: AtomicU32::new(entry.file_size),
                fs: self.fs.clone(),
                parent_dir_cluster: parent_cluster,
                entry_offset: free_offset,
                lfn_count,
                is_parent_root,
                has_entry_info: true,
            }) as Arc<dyn VNode>)
        })
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let (parent_path, dir_name) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            // Allocate cluster for the new directory.
            let dir_cluster = fs.append_cluster(0)?;

            // Write "." and ".." entries into the new directory.
            let cluster_size = fs.geom.cluster_size_bytes as usize;
            let sectors = fs.geom.sectors_per_cluster as u64;
            let lba = fs.geom.cluster_to_lba(dir_cluster);
            // Build raw directory content: "." entry + ".." entry.
            let dot_name = [
                b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
            ];
            let dotdot_name = [
                b'.', b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
            ];
            let parent_cluster_for_dotdot = if is_parent_root && fs.geom.fat_type != FatType::Fat32
            {
                0 // FAT12/16 root has no cluster
            } else {
                parent_cluster
            };

            let mut dir_content = vec![0u8; cluster_size];
            write_short_entry(
                &mut dir_content,
                0,
                &dot_name,
                ATTR_DIRECTORY,
                dir_cluster,
                0,
            );
            write_short_entry(
                &mut dir_content,
                32,
                &dotdot_name,
                ATTR_DIRECTORY,
                parent_cluster_for_dotdot,
                0,
            );

            // Write the new directory content.
            for s in 0..sectors {
                let block_start = s as usize * BLOCK_SIZE;
                let block_end = block_start + BLOCK_SIZE;
                let chunk = &dir_content[block_start..block_end];
                fs.block_buf.copy_from_slice(chunk);
                fs.write_block(lba + s)?;
            }

            // Write the directory entry in the parent.
            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;
            let mut entry_buf = [0u8; 256];
            let num = build_dir_entry_set(
                &mut entry_buf,
                dir_name,
                ATTR_DIRECTORY,
                dir_cluster,
                0,
                fs.code_page,
            );
            let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
            insert_dir_entry_set(&mut raw, free_offset, num, &entry_buf);
            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;

            Ok(())
        })
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            // Walk to the target entry.
            let entry = fs.walk_path(old_path)?;

            // Get parent directory info.
            let (parent_path, _) = split_parent(old_path);
            let parent_entry = fs.walk_path(parent_path)?;
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            // Get the new file name.
            let (_, new_name) = split_parent(new_path);

            // Read the parent directory raw bytes.
            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            // Scan the raw bytes for the entry set that matches `entry` by name.
            let found_pos = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
            match found_pos {
                Some((entry_start, lfn_entries)) => {
                    // Mark the old entries as deleted (0xE5).
                    let total_old_entries = lfn_entries + 1;
                    for i in 0..total_old_entries {
                        let off = entry_start + i * DIR_ENTRY_SIZE;
                        raw[off] = 0xE5;
                    }

                    // Build new entry set.
                    let mut entry_buf = [0u8; 256];
                    let attrs = if entry.kind == NodeKind::Directory {
                        ATTR_DIRECTORY
                    } else {
                        0x20
                    };
                    let num_new = build_dir_entry_set(
                        &mut entry_buf,
                        new_name,
                        attrs,
                        entry.first_cluster,
                        entry.file_size,
                        fs.code_page,
                    );

                    // Find a free slot for the new entries.
                    let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
                    insert_dir_entry_set(&mut raw, free_offset, num_new, &entry_buf);
                }
                None => return Err(Error::NotFound),
            }

            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;
            Ok(())
        })
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let entry = fs.walk_path(path)?;
            if entry.kind == NodeKind::Directory {
                // Check directory is empty (only "." and "..").
                let is_root = path.is_empty() || path == "/";
                let sub_entries = fs.read_directory(entry.first_cluster, is_root)?;
                if sub_entries.len() > 1 {
                    // More than just "." — directory is not empty.
                    // Actually, "." is not returned by read_directory;
                    // we need to check for any entries.
                    if !sub_entries.is_empty() {
                        return Err(Error::Busy);
                    }
                }
            }

            // Free the cluster chain.
            if entry.first_cluster >= FIRST_DATA_CLUSTER {
                fs.free_cluster_chain(entry.first_cluster)?;
            }

            // Remove the directory entry from parent.
            let (parent_path, _) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            let found_pos = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
            match found_pos {
                Some((entry_start, lfn_entries)) => {
                    let total = lfn_entries + 1;
                    for i in 0..total {
                        let off = entry_start + i * DIR_ENTRY_SIZE;
                        raw[off] = 0xE5;
                    }
                }
                None => return Err(Error::NotFound),
            }

            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;
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
        // Basic BPB geometry sanity checks.
        if fs.geom.bytes_per_sector != 512 {
            issues += 1;
        }
        if fs.geom.sectors_per_cluster == 0 || !fs.geom.sectors_per_cluster.is_power_of_two() {
            issues += 1;
        }
        if fs.geom.cluster_size_bytes == 0 {
            issues += 1;
        }
        if fs.geom.data_cluster_count < 2 {
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

// ─── FAT VNode ─────────────────────────────────────────────────────────────

struct FatVNode {
    name: String,
    kind: NodeKind,
    first_cluster: AtomicU32,
    file_size: AtomicU32,
    fs: Arc<crate::kernel::sync::Mutex<FatFs>>,
    /// Parent directory cluster (for updating on-disk directory entry).
    parent_dir_cluster: u32,
    /// Byte offset of the first LFN entry (or the short entry if no LFN) in
    /// the parent directory's raw bytes.
    entry_offset: usize,
    /// Number of LFN entries preceding the short entry.
    lfn_count: usize,
    /// Whether the parent directory is the root directory.
    is_parent_root: bool,
    /// Whether `entry_offset` and `lfn_count` are valid (i.e. we successfully
    /// located the on-disk directory entry).  When false, write/set_len skip
    /// updating the on-disk directory entry.
    has_entry_info: bool,
}

impl VNode for FatVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.file_size.load(core::sync::atomic::Ordering::Relaxed) as usize
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.fs.lock().profiler.inc_reads();
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }
        let data = self.fs.lock().read_file_data(
            self.first_cluster
                .load(core::sync::atomic::Ordering::Relaxed),
            self.file_size.load(core::sync::atomic::Ordering::Relaxed),
        )?;
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }

        let mut fs = self.fs.lock();
        let start_cluster = self
            .first_cluster
            .load(core::sync::atomic::Ordering::Relaxed);
        let current_size = self.file_size.load(core::sync::atomic::Ordering::Relaxed) as usize;

        // Read existing data to preserve bytes before `offset`.
        let new_end = offset as usize + buffer.len();
        let final_size = new_end.max(current_size);

        let mut data = if current_size > 0 && start_cluster >= FIRST_DATA_CLUSTER {
            fs.read_file_data(start_cluster, current_size as u32)?
        } else {
            Vec::new()
        };

        // Extend data buffer if needed.
        if final_size > data.len() {
            data.resize(final_size, 0);
        }

        // Write the new data.
        let copy_len = buffer.len().min(data.len() - offset as usize);
        data[offset as usize..offset as usize + copy_len].copy_from_slice(&buffer[..copy_len]);

        // Write data to cluster chain.  write_file_data_extend may allocate a
        // new first cluster if `start_cluster` was 0 (empty file).
        let new_start = fs.write_file_data_extend(start_cluster, &data)?;

        // Keep the in-memory first_cluster in sync with what's on disk.
        if new_start != start_cluster {
            self.first_cluster
                .store(new_start, core::sync::atomic::Ordering::Relaxed);
        }

        // Update the on-disk directory entry if we have a valid entry position
        // and the file metadata actually changed.
        if self.has_entry_info
            && (new_start != start_cluster || final_size as u32 != current_size as u32)
        {
            // Update directory entry: file_size + possibly-new first_cluster.
            let (mut raw, _) = fs.get_dir_raw(self.parent_dir_cluster, self.is_parent_root)?;
            let short_off = self.entry_offset + self.lfn_count * DIR_ENTRY_SIZE;
            if short_off + 32 <= raw.len() {
                raw[short_off + 28] = final_size as u8;
                raw[short_off + 29] = (final_size >> 8) as u8;
                raw[short_off + 30] = (final_size >> 16) as u8;
                raw[short_off + 31] = (final_size >> 24) as u8;
                raw[short_off + 26] = new_start as u8;
                raw[short_off + 27] = (new_start >> 8) as u8;
                raw[short_off + 20] = (new_start >> 16) as u8;
                raw[short_off + 21] = (new_start >> 24) as u8;
                let _ = fs.put_dir_raw(self.parent_dir_cluster, self.is_parent_root, &raw);
            }
        }
        drop(fs);

        // Update in-memory file size.
        self.file_size
            .store(final_size as u32, core::sync::atomic::Ordering::Relaxed);

        Ok(copy_len)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let length = length as u32;
        let mut fs = self.fs.lock();
        let current_size = self.file_size.load(core::sync::atomic::Ordering::Relaxed);

        if length == current_size {
            return Ok(());
        }

        // Helper: update the on-disk directory entry with new file_size and
        // first_cluster.  We hold `fs` locked, so the read-modify-write of
        // the parent directory is atomic with respect to other operations on
        // this volume.
        let update_dir_entry = |fs: &mut FatFs, file_size: u32, first_cluster: u32| -> Result<()> {
            let (mut raw, _) = fs.get_dir_raw(self.parent_dir_cluster, self.is_parent_root)?;
            let short_off = self.entry_offset + self.lfn_count * DIR_ENTRY_SIZE;
            if short_off + 32 > raw.len() {
                return Err(Error::InvalidArgument);
            }
            // file_size at offset 28..32 (little-endian u32).
            raw[short_off + 28] = file_size as u8;
            raw[short_off + 29] = (file_size >> 8) as u8;
            raw[short_off + 30] = (file_size >> 16) as u8;
            raw[short_off + 31] = (file_size >> 24) as u8;
            // first_cluster at offset 20..22 (high) and 26..28 (low).
            raw[short_off + 26] = first_cluster as u8;
            raw[short_off + 27] = (first_cluster >> 8) as u8;
            raw[short_off + 20] = (first_cluster >> 16) as u8;
            raw[short_off + 21] = (first_cluster >> 24) as u8;
            fs.put_dir_raw(self.parent_dir_cluster, self.is_parent_root, &raw)?;
            Ok(())
        };

        if length < current_size {
            let start_cluster = self
                .first_cluster
                .load(core::sync::atomic::Ordering::Relaxed);

            if length == 0 {
                // Truncate to zero: free the entire cluster chain and clear
                // the start cluster in the directory entry.
                if start_cluster >= FIRST_DATA_CLUSTER {
                    fs.free_cluster_chain(start_cluster)?;
                }
                self.first_cluster
                    .store(0, core::sync::atomic::Ordering::Relaxed);
                self.file_size
                    .store(0, core::sync::atomic::Ordering::Relaxed);
                if self.has_entry_info {
                    update_dir_entry(&mut fs, 0, 0)?;
                }
            } else {
                // Partial truncate: read existing data, shrink, and write
                // back.  write_file_data_extend handles freeing the tail
                // clusters of the FAT chain.
                let mut data = if start_cluster >= FIRST_DATA_CLUSTER {
                    fs.read_file_data(start_cluster, current_size)?
                } else {
                    Vec::new()
                };
                data.truncate(length as usize);
                let new_start = fs.write_file_data_extend(start_cluster, &data)?;
                if new_start != start_cluster {
                    self.first_cluster
                        .store(new_start, core::sync::atomic::Ordering::Relaxed);
                }
                self.file_size
                    .store(length, core::sync::atomic::Ordering::Relaxed);
                if self.has_entry_info {
                    update_dir_entry(&mut fs, length, new_start)?;
                }
            }
        } else {
            // Extend: write zeros beyond current EOF.  write() already
            // updates the on-disk directory entry (file_size + first_cluster).
            drop(fs);
            let zeros = vec![0u8; (length - current_size) as usize];
            self.write(current_size as u64, &zeros)?;
        }

        Ok(())
    }
}

// ─── Helpers for the write path ────────────────────────────────────────────

/// Split a path into `(parent_path, file_name)`.
pub(crate) fn split_parent(path: &str) -> (&str, &str) {
    let path = path.strip_prefix('/').unwrap_or(path);
    match path.rsplit_once('/') {
        Some((parent, name)) => {
            if parent.is_empty() {
                ("/", name)
            } else {
                // parent doesn't have leading /, so re-add it.
                (
                    path.strip_suffix(name)
                        .unwrap_or(path)
                        .trim_end_matches('/'),
                    name,
                )
            }
        }
        None => ("/", path),
    }
}

/// Find the byte offset and LFN entry count for a directory entry by
/// its first cluster number (more reliable than name comparison after
/// writes where LFN data may differ from the in-memory name).
///
/// When `target_cluster` is below [`FIRST_DATA_CLUSTER`] (i.e. zero for
/// empty files), cluster matching is ambiguous — in that case
/// `expected_name` is used to disambiguate by comparing with the short
/// (8.3) name stored in the directory entry.
fn find_entry_by_cluster(
    raw: &[u8],
    target_cluster: u32,
    expected_name: &str,
) -> Option<(usize, usize)> {
    let num_entries = raw.len() / DIR_ENTRY_SIZE;
    let mut i = 0;
    let mut lfn_count = 0usize;
    let name_must_match = target_cluster < FIRST_DATA_CLUSTER;

    while i < num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        let first_byte = raw[offset];

        if first_byte == 0x00 {
            break;
        }
        if first_byte == 0xE5 {
            lfn_count = 0;
            i += 1;
            continue;
        }

        let entry_data = &raw[offset..offset + DIR_ENTRY_SIZE];

        // Count LFN entries before a short entry.
        if entry_data[11] == ATTR_LFN_MASK {
            lfn_count += 1;
            i += 1;
            continue;
        }

        // Short entry — check cluster.
        let cluster_lo = u16::from_le_bytes([entry_data[26], entry_data[27]]) as u32;
        let cluster_hi = u16::from_le_bytes([entry_data[20], entry_data[21]]) as u32;
        let entry_cluster = cluster_lo | (cluster_hi << 16);

        if entry_cluster == target_cluster {
            // For empty files (cluster 0), disambiguate by short name.
            if name_must_match && !short_name_matches(entry_data, expected_name) {
                lfn_count = 0;
                i += 1;
                continue;
            }
            let entry_start = offset - lfn_count * DIR_ENTRY_SIZE;
            return Some((entry_start, lfn_count));
        }

        lfn_count = 0;
        i += 1;
    }
    None
}

/// Compare the 11-byte short name in a FAT directory entry (bytes 0–10)
/// against a user-visible file name.
///
/// The comparison is case-insensitive and treats the short name as
/// space-padded 8.3 format (e.g. `b"HELLO   TXT"` matches `"hello.txt"`).
fn short_name_matches(entry_data: &[u8], expected: &str) -> bool {
    let expected = expected.to_uppercase();
    let expected_bytes = expected.as_bytes();

    // Build the 8.3 name: up to 8 chars for the name part, a dot, up to 3
    // chars for the extension.
    let dot = expected_bytes.iter().position(|&b| b == b'.');
    let (name_part, ext_part) = match dot {
        Some(pos) => (
            &expected_bytes[..pos.min(8)],
            &expected_bytes[pos + 1..][..3.min(expected_bytes.len().saturating_sub(pos + 1))],
        ),
        None => (&expected_bytes[..8.min(expected_bytes.len())], &[] as &[u8]),
    };

    // Compare name part (bytes 0–7), space-padded.
    for i in 0..8 {
        let exp = if i < name_part.len() {
            name_part[i]
        } else {
            b' '
        };
        let got = entry_data[i].to_ascii_uppercase();
        if got != exp && !(got == b' ' && i >= expected_bytes.len().min(8)) {
            // Allow the entry to have trailing spaces without requiring
            // the expected name to be exactly 8+3.
            if got != b' ' {
                return false;
            }
        }
    }

    // Compare extension part (bytes 8–10), space-padded.
    for i in 0..3 {
        let exp = if i < ext_part.len() {
            ext_part[i]
        } else {
            b' '
        };
        let got = entry_data[8 + i].to_ascii_uppercase();
        if got != exp && got != b' ' {
            return false;
        }
    }

    true
}
