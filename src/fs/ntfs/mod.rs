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

/// The volume's own record, which the standard fixes at the third.
const VOLUME_RECORD: u64 = 3;

/// Where a volume's flags are inside its `$VOLUME_INFORMATION` value: eight
/// reserved bytes, then a major and a minor version.
const VOLUME_FLAGS_OFFSET: usize = 10;

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

    /// Where a record's own bytes are on the volume.
    ///
    /// The MFT is a file: a record's position is its number's offset inside
    /// that file, mapped through the file's own runs.
    fn record_offset(&self, info: &fs::NtfsInfo, record_number: u64) -> Result<u64> {
        let runs = info.mft_runs.as_ref().ok_or(Error::InvalidArgument)?;
        let offset = record_number
            .checked_mul(u64::from(info.mft_record_size))
            .ok_or(Error::InvalidArgument)?;
        fs::byte_offset_in_runs(runs, info.cluster_size, offset).ok_or(Error::InvalidArgument)
    }

    /// Where the volume's `$VOLUME_INFORMATION` flags are, if it has them.
    ///
    /// The flags are the last two bytes of a twelve-byte value in the third
    /// record, and bit zero is the one that says the volume is dirty — which
    /// is what a reader that finds it left set is supposed to check rather
    /// than trust.
    fn volume_flags_offset(&self) -> Result<u64> {
        let record = self.read_mft_record(VOLUME_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let information = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_VOLUME_INFORMATION)
            .ok_or(Error::NotFound)?;
        // The lock is taken here and not around the read above: reading a
        // record takes it too, and a lock held across that is a lock held
        // against itself.
        let info = self.info.lock();
        let record_at = self.record_offset(&info, VOLUME_RECORD)?;
        Ok(record_at
            + header.size() as u64
            + information.offset as u64
            + information.value_offset as u64
            + VOLUME_FLAGS_OFFSET as u64)
    }

    /// Say whether the volume is in the middle of being changed.
    pub fn set_dirty(&self, dirty: bool) -> Result<()> {
        let info = self.info.lock();
        if info.bs.bytes_per_sector == 0 {
            return Err(Error::InvalidArgument);
        }
        drop(info);

        let at = self.volume_flags_offset()?;
        let mut field = [0u8; 2];
        fs::read_device_bytes(&self.device, at, &mut field)?;
        let flags = u16::from_le_bytes(field);
        let wanted = if dirty {
            flags | 0x0001
        } else {
            flags & !0x0001
        };
        if wanted == flags {
            return Ok(());
        }
        fs::write_device_bytes(&self.device, at, &wanted.to_le_bytes())
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

    /// Settle the volume.
    ///
    /// A volume this driver has changed is left **dirty** until it is told it
    /// is done: that flag is what tells a checker to look rather than trust,
    /// and clearing it is the one honest thing this driver can say about the
    /// changes it made, since it writes no `$LogFile`
    /// ([RFC 0012](../../docs/rfcs/0012-the-harness-an-ntfs-write-is-proven-on.
    /// md)).
    fn sync(&self) -> Result<()> {
        self.set_dirty(false)
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
        if self.kind() == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let end = offset.saturating_add(buffer.len() as u64);
        if end > self.size() as u64 {
            // A write past the end grows the file first, and a growth this
            // driver cannot make is a *short* write rather than an error: the
            // contract's own answer for bytes it could not take.
            if self.set_len(end).is_err() {
                let room = self.size().saturating_sub(offset as usize);
                if room == 0 {
                    return Ok(0);
                }
                return self.write(offset, &buffer[..room]);
            }
        }

        // The flag goes up before the change, and before the locks below are
        // taken: setting it reads a record, and reading a record takes the lock
        // this write is about to hold.
        self.fs.set_dirty(true)?;

        let info = self.fs.info.lock();
        let record = self.mft_record.lock();
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        if data.data_runs_offset.is_none() {
            // A resident file's bytes are in the record itself, so the field
            // write is the data write — and the volume is where the record is.
            let length = self.size().min(data.content.len());
            let start = (offset as usize).min(length);
            let take = (length - start).min(buffer.len());
            if take == 0 {
                return Ok(0);
            }
            let record_at = self
                .fs
                .record_offset(&info, *self.mft_record_number.lock())?;
            let field = record_at
                + (header.size() as u64 + data.offset as u64 + data.value_offset as u64)
                + start as u64;
            fs::write_device_bytes(&self.fs.device, field, &buffer[..take])?;
            return Ok(take);
        }

        let written = fs::write_to_runs(&self.fs.device, &info, &data.data_runs, offset, buffer)?;
        Ok(written)
    }

    fn set_len(&self, len: u64) -> Result<()> {
        if self.kind() != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let length = u32::try_from(len).map_err(|_| Error::InvalidArgument)?;
        let current = *self.file_size.lock() as u32;
        if length == current {
            return Ok(());
        }

        // Raised before the locks below, for the same reason the write raises
        // it there: setting the flag reads a record.
        self.fs.set_dirty(true)?;

        let info = self.fs.info.lock();
        let mut record = self.mft_record.lock();
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        // What the file already *has* is what this stage can use.  A resident
        // value can only shrink — growing it would need the record's own room
        // and its bookkeeping — and a file with runs can be as long as those
        // runs add up to.  Growing past either is allocation, which is the next
        // stage.
        let allocated = if data.data_runs_offset.is_none() {
            if length > current {
                return Err(Error::NoSpace);
            }
            current
        } else {
            let clusters: u64 = data.data_runs.iter().map(|run| run.cluster_count).sum();
            (clusters * info.cluster_size as u64) as u32
        };
        if length > allocated {
            return Err(Error::NoSpace);
        }

        let record_at = self
            .fs
            .record_offset(&info, *self.mft_record_number.lock())?;
        let attr_at = record_at + header.size() as u64 + data.offset as u64;
        if data.data_runs_offset.is_none() {
            // The value's length, in the header the attribute carries.
            fs::write_device_bytes(&self.fs.device, attr_at + 16, &length.to_le_bytes())?;
        } else {
            // The data size and the initialized size, adjacent in a
            // non-resident header: a shorter file has no initialized bytes
            // beyond its length.
            let mut field = [0u8; 16];
            field[..8].copy_from_slice(&u64::from(length).to_le_bytes());
            field[8..].copy_from_slice(&u64::from(length).to_le_bytes());
            fs::write_device_bytes(&self.fs.device, attr_at + 48, &field)?;
        }

        // The record this node holds says the same thing now.
        {
            let at = header.size() as usize + data.offset + 16;
            if data.data_runs_offset.is_none() {
                record[at..at + 4].copy_from_slice(&length.to_le_bytes());
            } else {
                let at = header.size() as usize + data.offset + 48;
                record[at..at + 8].copy_from_slice(&u64::from(length).to_le_bytes());
                record[at + 8..at + 16].copy_from_slice(&u64::from(length).to_le_bytes());
            }
        }
        *self.file_size.lock() = u64::from(length);
        Ok(())
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
