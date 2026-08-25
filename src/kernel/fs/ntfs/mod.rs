//! src/kernel/fs/ntfs/mod.rs
//!
//! NTFS filesystem driver — MFT, attributes, directory operations, and file
//! I/O.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::fs::vfs::{
    filesystem::FileSystem,
    types::{DirectoryEntry, NodeKind},
    vnode::VNode,
};
use crate::kernel::sync::{Mutex, SpinLock};
use crate::{Error, Result};

use crate::kernel::fs::ntfs::fs::parse_attributes;
use crate::kernel::fs::ntfs::types::*;

mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;

// ── NTFS filesystem handle ──────────────────────────────────────────────

pub struct NtfsFs {
    device: Arc<dyn BlockDevice>,
    info: Mutex<fs::NtfsInfo>,
    mft_cache: Mutex<BTreeMap<u64, Vec<u8>>>,
}

impl NtfsFs {
    pub fn new(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let bs = fs::read_boot_sector(&device)?;
        let info = fs::NtfsInfo::new(bs);
        Ok(Self {
            device,
            info: Mutex::new(info),
            mft_cache: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn info(&self) -> &Mutex<fs::NtfsInfo> {
        &self.info
    }

    pub fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.device
    }

    pub fn read_mft_record(&self, record_number: u64) -> Result<Vec<u8>> {
        let mut cache = self.mft_cache.lock();
        if let Some(cached_record) = cache.get(&record_number) {
            return Ok(cached_record.clone());
        }

        let info = self.info.lock();
        let record_size = info.mft_record_size as usize;
        let mut record = alloc::vec![0u8; record_size];

        // Calculate the LBA for the MFT record
        let record_lba = (info.bs.mft_lcn * info.cluster_size as u64
            + record_number * info.mft_record_size as u64)
            / BLOCK_SIZE as u64;

        // Read the record in blocks
        let blocks_to_read = record_size.div_ceil(BLOCK_SIZE);
        for i in 0..blocks_to_read {
            let block_offset = record_lba + i as u64;
            let block_data_start = i * BLOCK_SIZE;
            let block_data_end = ((i + 1) * BLOCK_SIZE).min(record_size);
            let block_len = block_data_end - block_data_start;

            let mut block = [0u8; BLOCK_SIZE];
            self.device.read_blocks(block_offset, &mut block)?;

            record[block_data_start..block_data_end].copy_from_slice(&block[..block_len]);
        }

        // Apply USA fixup if present
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.usa_count > 0 {
            apply_usa_fixup(&mut record, &header);
        }

        cache.insert(record_number, record.clone());
        Ok(record)
    }

    /// Whether the volume is writable. NTFS is currently read-only, so this
    /// is informational for the VFS layer.
    #[allow(dead_code)]
    fn read_only(&self) -> bool {
        false // Enable write support
    }

    /// Resolve the root directory vnode (MFT record 5).
    fn root_vnode(&self) -> Result<Arc<dyn VNode>> {
        let root_record_number = self.find_root_directory_record()?;
        let root_record = self.read_mft_record(root_record_number)?;
        Ok(Arc::new(NtfsVnode {
            fs: Arc::new(self.clone()),
            mft_record: SpinLock::new(root_record),
            mft_record_number: SpinLock::new(root_record_number),
            first_cluster: SpinLock::new(0),
            file_size: SpinLock::new(0),
            kind: SpinLock::new(NodeKind::Directory),
        }))
    }
}

impl FileSystem for NtfsFs {
    fn name(&self) -> &str {
        "ntfs"
    }

    fn lookup(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        // For now, just return the root vnode
        // In a full implementation, you'd parse the path and traverse the directory
        // structure
        self.root_vnode()
    }

    fn read_dir(&self, _path: &str, _index: usize) -> Result<DirectoryEntry> {
        let vnode = self.lookup(_path)?;
        if vnode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        // For now, just return a dummy entry
        // In a full implementation, you'd read the directory entries
        Ok(DirectoryEntry::new(NodeKind::File, 0, "dummy".to_string()))
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        // NTFS rename is complex - for now, just return not implemented
        Err(Error::NotImplemented)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        // NTFS file creation is complex - for now, just return not implemented
        Err(Error::NotImplemented)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        // NTFS directory creation is complex - for now, just return not implemented
        Err(Error::NotImplemented)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        // NTFS path removal is complex - for now, just return not implemented
        Err(Error::NotImplemented)
    }
}

// ── NTFS vnode ─────────────────────────────────────────────────────────

pub struct NtfsVnode {
    pub fs: Arc<NtfsFs>,
    pub mft_record: SpinLock<Vec<u8>>,
    pub mft_record_number: SpinLock<u64>,
    pub first_cluster: SpinLock<u64>,
    pub file_size: SpinLock<u64>,
    pub kind: SpinLock<NodeKind>,
}

impl VNode for NtfsVnode {
    fn name(&self) -> &str {
        "ntfs_file"
    }

    fn kind(&self) -> NodeKind {
        *self.kind.lock()
    }

    fn size(&self) -> usize {
        *self.file_size.lock() as usize
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let info = self.fs.info.lock();
        let record = self.mft_record.lock();

        // Parse the MFT record to find attributes
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);

        // Find the data attribute
        let data_attr = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        let file_size = data_attr.data_size as u64;
        let data_runs = &data_attr.data_runs;

        // Calculate how much data to read
        let end_offset = (offset + buffer.len() as u64).min(file_size);
        let read_size = (end_offset - offset) as usize;

        if read_size == 0 {
            return Ok(0);
        }

        // Use read_from_runs to handle data runs properly
        fs::read_from_runs(&self.fs.device, &info, data_runs, file_size, offset, buffer)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        let info = self.fs.info.lock();
        let mut record = self.mft_record.lock();

        // Parse the MFT record to find attributes
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut attributes = parse_attributes(&record[header.size() as usize..]);

        // Find or create the data attribute
        let data_attr = if let Some(pos) = attributes
            .iter()
            .position(|attr| attr.attr_type == ATTR_TYPE_DATA)
        {
            attributes.get_mut(pos).unwrap()
        } else {
            // Create a new data attribute
            let data_attr = ParsedAttr {
                attr_type: ATTR_TYPE_DATA,
                content: Vec::new(),
                data_runs_offset: None,
                data_runs: Vec::new(),
                data_size: 0,
            };
            attributes.push(data_attr);
            attributes.last_mut().unwrap()
        };

        let file_size = data_attr.data_size as u64;
        let new_size = (offset + buffer.len() as u64).max(file_size);

        // For simplicity, we'll just write to existing runs
        // In a full implementation, you'd need to handle extending the file
        if offset + buffer.len() as u64 > file_size {
            // File extension would require cluster allocation
            return Err(Error::NotImplemented);
        }

        let data_runs = &mut data_attr.data_runs;

        // Write data using data runs
        let mut remaining = buffer.len();
        let mut buf_offset = 0;
        let mut current_offset = offset;

        for data_run in data_runs.iter_mut() {
            // `lcn` is signed to allow sparse runs (-1); a write targets only
            // real runs, so treat it as an unsigned cluster address.
            let run_lcn = data_run.lcn as u64;
            let run_offset = run_lcn * info.cluster_size as u64;
            let run_size = data_run.cluster_count * info.cluster_size as u64;

            if current_offset >= run_offset + run_size {
                continue;
            }

            let run_start = current_offset.saturating_sub(run_offset);
            let run_end = (current_offset + remaining as u64)
                .saturating_sub(run_offset)
                .min(run_size);
            let run_write_size = (run_end - run_start) as usize;

            if run_write_size > 0 {
                fs::write_clusters(
                    &self.fs.device,
                    &info,
                    run_lcn + run_start / info.cluster_size as u64,
                    run_write_size as u64 / info.cluster_size as u64,
                    &buffer[buf_offset..buf_offset + run_write_size],
                )?;

                buf_offset += run_write_size;
                remaining -= run_write_size;
                current_offset += run_write_size as u64;

                if remaining == 0 {
                    break;
                }
            }
        }

        // Update file size if needed
        if new_size > file_size {
            data_attr.data_size = new_size as u32;
            *self.file_size.lock() = new_size;
        }

        // Update the MFT record
        update_mft_record(&mut record, &attributes);

        Ok(buffer.len())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        let mut record = self.mft_record.lock();

        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut attributes = parse_attributes(&record[header.size() as usize..]);

        if let Some(pos) = attributes
            .iter()
            .position(|attr| attr.attr_type == ATTR_TYPE_DATA)
        {
            let data_attr = attributes.get_mut(pos).unwrap();
            data_attr.data_size = len as u32;
            *self.file_size.lock() = len;
            update_mft_record(&mut record, &attributes);
        } else {
            return Err(Error::NotFound);
        }

        Ok(())
    }
}

impl NtfsVnode {
    /// Enumerate the directory entries stored in this vnode's index-root
    /// attribute. This is a convenience helper on `NtfsVnode` rather than a
    /// `VNode` trait method (the trait has no `readdir`).
    #[allow(dead_code)]
    fn readdir(&self) -> Result<Vec<(String, Arc<dyn VNode>)>> {
        let record = self.mft_record.lock();

        // Parse the MFT record to find attributes
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);

        // Find the index root attribute for directory entries
        let index_root_attr = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;

        // Parse the index root to get directory entries
        let entries = fs::parse_index_entries(&index_root_attr.content)?;

        let mut result = Vec::new();

        for (name, mft_ref) in entries {
            // Create vnode for each entry
            let entry_record = self.fs.read_mft_record(mft_ref)?;
            let entry_header =
                MftRecordHeader::parse(&entry_record).ok_or(Error::InvalidArgument)?;

            let entry_kind = if entry_header.is_dir() {
                NodeKind::Directory
            } else {
                NodeKind::File
            };

            result.push((
                name,
                Arc::new(NtfsVnode {
                    fs: self.fs.clone(),
                    mft_record: SpinLock::new(entry_record),
                    mft_record_number: SpinLock::new(mft_ref),
                    first_cluster: SpinLock::new(0),
                    file_size: SpinLock::new(0),
                    kind: SpinLock::new(entry_kind),
                }) as Arc<dyn VNode>,
            ));
        }

        Ok(result)
    }
}

// Helper functions

fn apply_usa_fixup(record: &mut [u8], header: &MftRecordHeader) {
    let usa_offset = header.usa_offset as usize;
    let usa_count = header.usa_count as usize;

    if usa_offset + usa_count * 2 > record.len() {
        return;
    }

    // Read fixup sequence value (first u16 of the USA array; validation of the
    // sector-end markers is not performed).
    let _fixup_seq = u16::from_le_bytes([record[usa_offset], record[usa_offset + 1]]);

    // Apply fixup for each sector
    for i in 1..usa_count {
        let sector_end = i * BLOCK_SIZE;
        if sector_end >= 2 && sector_end <= record.len() && usa_offset + i * 2 + 1 < record.len() {
            let orig_lo = record[usa_offset + i * 2];
            let orig_hi = record[usa_offset + i * 2 + 1];
            record[sector_end - 2] = orig_lo;
            record[sector_end - 1] = orig_hi;
        }
    }
}

fn update_mft_record(record: &mut [u8], attributes: &[ParsedAttr]) {
    // Update the record with modified attributes
    let mut offset = 48; // Start after header

    for attr in attributes {
        let attr_header = AttrHeader {
            attr_type: attr.attr_type,
            attr_len: 24 + attr.content.len() as u32,
            non_resident: attr.data_runs_offset.is_some(),
            name_len: 0,
            name_offset: 0,
            flags: 0,
            instance: 0,
            content_size: attr.data_size,
            data_runs_offset: attr.data_runs_offset.map(|o| o as u16).unwrap_or(0),
            data_runs_length: 0,
        };

        // Copy attribute header
        let header_bytes = [
            attr_header.attr_type.to_le_bytes()[0],
            attr_header.attr_type.to_le_bytes()[1],
            attr_header.attr_type.to_le_bytes()[2],
            attr_header.attr_type.to_le_bytes()[3],
            attr_header.attr_len.to_le_bytes()[0],
            attr_header.attr_len.to_le_bytes()[1],
            attr_header.attr_len.to_le_bytes()[2],
            attr_header.attr_len.to_le_bytes()[3],
            attr_header.non_resident as u8,
            attr_header.name_len,
            attr_header.name_offset.to_le_bytes()[0],
            attr_header.name_offset.to_le_bytes()[1],
            attr_header.flags.to_le_bytes()[0],
            attr_header.flags.to_le_bytes()[1],
            attr_header.instance.to_le_bytes()[0],
            attr_header.instance.to_le_bytes()[1],
            attr_header.content_size.to_le_bytes()[0],
            attr_header.content_size.to_le_bytes()[1],
            attr_header.content_size.to_le_bytes()[2],
            attr_header.content_size.to_le_bytes()[3],
            attr_header.data_runs_offset.to_le_bytes()[0],
            attr_header.data_runs_offset.to_le_bytes()[1],
            attr_header.data_runs_length.to_le_bytes()[0],
            attr_header.data_runs_length.to_le_bytes()[1],
        ];

        if offset + header_bytes.len() <= record.len() {
            record[offset..offset + header_bytes.len()].copy_from_slice(&header_bytes);
            offset += header_bytes.len();

            // Copy attribute content
            if offset + attr.content.len() <= record.len() {
                record[offset..offset + attr.content.len()].copy_from_slice(&attr.content);
                offset += attr.content.len();
            }
        }
    }
}

impl Clone for NtfsFs {
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            info: Mutex::new((*self.info.lock()).clone()),
            mft_cache: Mutex::new(self.mft_cache.lock().clone()),
        }
    }
}

impl NtfsFs {
    fn find_root_directory_record(&self) -> Result<u64> {
        // Root directory is typically in MFT record 5, but we need to verify
        // For now, we'll use the standard location
        Ok(5)
    }
}
