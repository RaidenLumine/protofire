//! src/fs/ntfs/mod.rs
//!
//! NTFS filesystem driver — MFT, attributes, directory operations, and file
//! I/O.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::block::BlockDevice;
use crate::fs::vfs::filesystem::FileSystem;
use crate::fs::vfs::types::DirectoryEntry;
use crate::fs::vfs::types::NodeKind;
use crate::fs::vfs::vnode::VNode;
use crate::kernel::sync::Mutex;
use crate::kernel::sync::SpinLock;
use crate::Error;
use crate::Result;

use crate::fs::ntfs::fs::parse_attributes;
use crate::fs::ntfs::fs::parse_index_node;
use crate::fs::ntfs::types::*;

mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;

// ── NTFS filesystem handle ──────────────────────────────────────────────

/// The root directory's record, which the standard fixes at the fifth.
const ROOT_RECORD: u64 = 5;

/// How deep an index tree this driver will follow before it gives up.
///
/// A directory's index is a B-tree, and a volume can make one deeper than a
/// reader should walk looking for a name: the bound is what keeps a damaged
/// pointer from being a loop.
const MAX_INDEX_DEPTH: u32 = 8;

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

        let mut info = self.info.lock();
        let record_size = info.mft_record_size as usize;
        let mut record = alloc::vec![0u8; record_size];
        let runs = info.resolve_mft_runs(&self.device)?;
        let data_size = info.mft_data_size;
        let offset = record_number
            .checked_mul(info.mft_record_size as u64)
            .ok_or(Error::InvalidArgument)?;
        if offset + record_size as u64 > data_size {
            return Err(Error::NotFound);
        }
        fs::read_from_runs(&self.device, &info, &runs, data_size, offset, &mut record)?;

        // Apply USA fixup if present
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.usa_count > 0 {
            fs::apply_usa_fixup(
                &mut record,
                header.usa_offset as usize,
                header.usa_count as usize,
                info.bs.bytes_per_sector as usize,
            );
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

    /// The entries a directory holds, whatever shape its index is in.
    ///
    /// A directory's index is a tree.  Its root lives in the record's
    /// `$INDEX_ROOT`, and a directory that has children keeps the entries
    /// themselves in an `$INDEX_ALLOCATION` whose blocks the root's last entry
    /// points at by virtual cluster number — which is the shape a real volume
    /// uses even for a single file, so this walks the tree rather than reading
    /// one node.
    fn directory_entries(&self, record_number: u64) -> Result<Vec<(String, u64)>> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);

        let index_root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        let mut node = parse_index_node(&index_root.content, 16);

        let mut depth = 0;
        while node.has_children && depth < MAX_INDEX_DEPTH {
            let pointer = match node.entries.iter().find(|entry| entry.points_at_a_node) {
                Some(pointer) => pointer,
                None => break,
            };
            let block = self.read_index_block(&attributes, pointer.reference)?;
            node = parse_index_node(&block, 24);
            depth += 1;
        }

        // A directory's index holds an entry for itself, and one file can have
        // more than one name: a short one and a long one.  The listing is the
        // long one, and it is not the self entry.
        let mut best: Vec<(String, u64)> = Vec::new();
        for entry in &node.entries {
            let Some(name) = &entry.name else { continue };
            if name.name == "." {
                continue;
            }
            match best
                .iter()
                .position(|(_, record)| *record == entry.reference)
            {
                Some(index) => {
                    if name.preferred_namespace() {
                        best[index] = (name.name.clone(), entry.reference);
                    }
                }
                None => best.push((name.name.clone(), entry.reference)),
            }
        }
        Ok(best)
    }

    /// Read the index allocation block a virtual cluster number names.
    fn read_index_block(&self, attributes: &[ParsedAttr], vcn: u64) -> Result<Vec<u8>> {
        let info = self.info.lock();
        let allocation = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ALLOC && !attr.data_runs.is_empty())
            .ok_or(Error::NotFound)?;
        let mut block = alloc::vec![0u8; info.index_block_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &allocation.data_runs,
            allocation.data_size as u64,
            vcn * info.cluster_size as u64,
            &mut block,
        )?;

        // The block carries its own update sequence array, and the volume's
        // sector size says where its sectors end.
        let usa_offset = u16::from_le_bytes([block[4], block[5]]) as usize;
        let usa_count = u16::from_le_bytes([block[6], block[7]]) as usize;
        fs::apply_usa_fixup(
            &mut block,
            usa_offset,
            usa_count,
            info.bs.bytes_per_sector as usize,
        );
        Ok(block)
    }

    /// The record a path names, from the root down, and the name it has.
    ///
    /// A name is matched against what the volume stores, byte for byte.  NTFS
    /// compares through a folding table the volume carries (`$UpCase`), which
    /// this driver does not read yet ([RFC 0012]).
    fn resolve(&self, path: &str) -> Result<(u64, String)> {
        let mut record_number = ROOT_RECORD;
        let mut name = String::from("/");
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            let entries = self.directory_entries(record_number)?;
            let (found_name, found_record) = entries
                .into_iter()
                .find(|(entry_name, _)| entry_name == segment)
                .ok_or(Error::NotFound)?;
            record_number = found_record;
            name = found_name;
        }
        Ok((record_number, name))
    }

    /// The bytes a record's `$DATA` says it holds.
    fn data_size(&self, record: &[u8]) -> u64 {
        let Some(header) = MftRecordHeader::parse(record) else {
            return 0;
        };
        parse_attributes(&record[header.size() as usize..])
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .map(|attr| attr.data_size as u64)
            .unwrap_or(0)
    }

    /// The vnode for a record, named the way its parent's index names it.
    fn vnode(&self, record_number: u64, name: String) -> Result<Arc<dyn VNode>> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA);
        let first_cluster = data
            .map(|attr| {
                attr.data_runs
                    .first()
                    .map(|run| run.lcn.max(0) as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        Ok(Arc::new(NtfsVnode {
            fs: Arc::new(self.clone()),
            mft_record: SpinLock::new(record),
            mft_record_number: SpinLock::new(record_number),
            first_cluster: SpinLock::new(first_cluster),
            file_size: SpinLock::new(if header.is_dir() {
                0
            } else {
                data.map(|attr| attr.data_size as u64).unwrap_or(0)
            }),
            kind: SpinLock::new(if header.is_dir() {
                NodeKind::Directory
            } else {
                NodeKind::File
            }),
            name,
        }))
    }
}

impl FileSystem for NtfsFs {
    fn name(&self) -> &str {
        "ntfs"
    }

    fn lookup(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        let (record_number, name) = self.resolve(_path)?;
        self.vnode(record_number, name)
    }

    fn read_dir(&self, _path: &str, _index: usize) -> Result<DirectoryEntry> {
        let (record_number, _name) = self.resolve(_path)?;
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if !header.is_dir() {
            return Err(Error::InvalidArgument);
        }

        let (name, child) = self
            .directory_entries(record_number)?
            .into_iter()
            .nth(_index)
            .ok_or(Error::NotFound)?;
        let child_record = self.read_mft_record(child)?;
        let child_header = MftRecordHeader::parse(&child_record).ok_or(Error::InvalidArgument)?;
        let kind = if child_header.is_dir() {
            NodeKind::Directory
        } else {
            NodeKind::File
        };
        let size = if kind == NodeKind::Directory {
            0
        } else {
            self.data_size(&child_record) as usize
        };
        Ok(DirectoryEntry::new(kind, size, name))
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
    /// The name its parent's index gives it.
    pub name: String,
    pub fs: Arc<NtfsFs>,
    pub mft_record: SpinLock<Vec<u8>>,
    pub mft_record_number: SpinLock<u64>,
    pub first_cluster: SpinLock<u64>,
    pub file_size: SpinLock<u64>,
    pub kind: SpinLock<NodeKind>,
}

impl VNode for NtfsVnode {
    fn name(&self) -> &str {
        &self.name
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

        // A *resident* attribute has no runs: its bytes are in the record the
        // node already holds, which is where a small file lives.
        if data_attr.data_runs_offset.is_none() {
            let content = &data_attr.content;
            let start = (offset as usize).min(content.len());
            let end = (start + buffer.len()).min(content.len());
            buffer[..end - start].copy_from_slice(&content[start..end]);
            return Ok(end - start);
        }

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

// Helper functions

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
