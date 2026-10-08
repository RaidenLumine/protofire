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

/// The volume's cluster bitmap, which the standard fixes at the sixth.
const BITMAP_RECORD: u64 = 6;

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

    /// How many clusters the volume holds.
    fn volume_clusters(&self, info: &fs::NtfsInfo) -> u64 {
        info.bs.total_sectors / u64::from(info.bs.sectors_per_cluster.max(1))
    }

    /// The volume's cluster bitmap, as many bytes of it as the volume needs.
    ///
    /// The bitmap is a *file* — the sixth record's `$DATA` — with its own
    /// runs, so reading it is the same walk as reading any other file's data.
    fn read_bitmap(&self) -> Result<Vec<u8>> {
        let record = self.read_mft_record(BITMAP_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        // The lock goes on after the record has been read: reading a record
        // takes the same one, and a lock held across that is a lock held
        // against itself.
        let info = self.info.lock();
        let wanted = self.volume_clusters(&info).div_ceil(8) as usize;
        let size = wanted.min(data.data_size as usize);
        let mut bitmap = alloc::vec![0u8; size];
        if data.data_runs_offset.is_none() {
            bitmap.copy_from_slice(&data.content[..size.min(data.content.len())]);
            return Ok(bitmap);
        }
        fs::read_from_runs(
            &self.device,
            &info,
            &data.data_runs,
            u64::from(data.data_size),
            0,
            &mut bitmap,
        )?;
        Ok(bitmap)
    }

    /// Write the bitmap back where it came from.
    fn write_bitmap(&self, bitmap: &[u8]) -> Result<()> {
        let record = self.read_mft_record(BITMAP_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        let info = self.info.lock();
        if data.data_runs_offset.is_none() {
            let record_at = self.record_offset(&info, BITMAP_RECORD)?;
            let at =
                record_at + header.size() as u64 + data.offset as u64 + data.value_offset as u64;
            return fs::write_device_bytes(&self.device, at, bitmap);
        }
        fs::write_to_runs(&self.device, &info, &data.data_runs, 0, bitmap)?;
        Ok(())
    }

    /// Take `count` clusters from the volume's free space.
    ///
    /// The bitmap is the free list: the first run of `count` clear bits is
    /// what a growth gets, and the bits it took are set before the cluster is
    /// handed out — so a crash after the answer leaves a cluster claimed and
    /// unused, which is the harmless direction to be wrong in.
    fn claim_clusters(&self, count: u64) -> Result<u64> {
        let volume_clusters = {
            let info = self.info.lock();
            self.volume_clusters(&info)
        };
        let mut bitmap = self.read_bitmap()?;

        let mut found = None;
        let mut run_start = 0u64;
        let mut run = 0u64;
        for cluster in 0..volume_clusters {
            let used = bitmap[cluster as usize / 8] & (1 << (cluster % 8)) != 0;
            if used {
                run = 0;
                continue;
            }
            if run == 0 {
                run_start = cluster;
            }
            run += 1;
            if run == count {
                found = Some(run_start);
                break;
            }
        }
        let first = found.ok_or(Error::NoSpace)?;

        for cluster in first..first + count {
            bitmap[cluster as usize / 8] |= 1 << (cluster % 8);
        }
        self.set_dirty(true)?;
        self.write_bitmap(&bitmap)?;
        Ok(first)
    }

    /// Where the volume's `$VOLUME_INFORMATION` flags are, if it has them.
    ///
    /// The flags are the last two bytes of a twelve-byte value in the third
    /// record, and bit zero is the one that says the volume is dirty — which is
    /// what a reader that finds it left set is supposed to check rather than
    /// trust.
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

        // A growth's clusters are taken **before** the locks below: claiming
        // reads and writes the bitmap, which are record reads, and a lock held
        // across that is a lock held against itself.
        let needs = {
            let info = self.fs.info.lock();
            let record = self.mft_record.lock();
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let attributes = parse_attributes(&record[header.size() as usize..]);
            let data = attributes
                .iter()
                .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
                .ok_or(Error::NotFound)?;
            let held: u64 = if data.data_runs_offset.is_none() {
                0
            } else {
                data.data_runs
                    .iter()
                    .map(|run| run.cluster_count)
                    .sum::<u64>()
                    * u64::from(info.cluster_size)
            };
            (data.data_runs_offset.is_some() && u64::from(length) > held)
                .then(|| (u64::from(length) - held).div_ceil(u64::from(info.cluster_size)))
        };
        let claim = match needs {
            Some(needed) => Some((needed, self.fs.claim_clusters(needed)?)),
            None => None,
        };

        let info = self.fs.info.lock();
        let mut record = self.mft_record.lock();
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        // A resident value can only shrink: growing it would need the record's
        // own room and its bookkeeping.  A file with runs can be as long as
        // those runs add up to, and past that it *claims clusters*.
        let mut runs = data.data_runs.clone();
        let allocated = if data.data_runs_offset.is_none() {
            if length > current {
                return Err(Error::NoSpace);
            }
            current
        } else {
            let clusters: u64 = data.data_runs.iter().map(|run| run.cluster_count).sum();
            let mut allocated = clusters * u64::from(info.cluster_size);
            if let Some((needed, first)) = claim {
                // The run list sits at an offset from the *attribute's* start,
                // which is what the room it has is measured from.
                let attr_len = data.attr_len;
                let runs_relative =
                    data.data_runs_offset.ok_or(Error::InvalidArgument)? - data.offset;
                let encoded_length = fs::encode_runs(
                    &[
                        runs.clone(),
                        alloc::vec![DataRun {
                            lcn: first as i64,
                            cluster_count: needed,
                        }],
                    ]
                    .concat(),
                )
                .len();
                // The run list has to fit where the old one did: an attribute
                // that has outgrown its room **moves**, and with it everything
                // after it in the record.
                if runs_relative + encoded_length > attr_len {
                    runs.push(DataRun {
                        lcn: first as i64,
                        cluster_count: needed,
                    });
                    allocated += needed * u64::from(info.cluster_size);
                    let encoded = fs::encode_runs(&runs);
                    let zeros = alloc::vec![0u8; (allocated - u64::from(current)) as usize];
                    self.relocate_run_list(
                        &info,
                        &mut record,
                        &header,
                        &data.clone(),
                        &runs,
                        runs_relative,
                        &encoded,
                        length,
                        allocated as u32,
                        &zeros,
                    )?;
                    *self.file_size.lock() = u64::from(length);
                    return Ok(());
                }
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: needed,
                });
                allocated += needed * u64::from(info.cluster_size);
            }
            allocated as u32
        };
        let grew = runs.len() > data.data_runs.len();

        let record_at = self
            .fs
            .record_offset(&info, *self.mft_record_number.lock())?;
        let attr_at = record_at + header.size() as u64 + data.offset as u64;
        if data.data_runs_offset.is_none() {
            // The value's length, in the header the attribute carries.
            fs::write_device_bytes(&self.fs.device, attr_at + 16, &length.to_le_bytes())?;
        } else {
            if grew {
                // The run list, and the three sizes that say how much of the
                // file's space is spoken for.  A run that was appended is what
                // the mapping pairs have to spell; the bytes it claims are
                // written as zeros, which is what a file that has just grown
                // holds and what its initialized size then says it holds.
                let encoded = fs::encode_runs(&runs);
                let runs_relative =
                    data.data_runs_offset.ok_or(Error::InvalidArgument)? - data.offset;
                let room = data.attr_len - runs_relative;
                let mut field = alloc::vec![0u8; room];
                field[..encoded.len()].copy_from_slice(&encoded);
                fs::write_device_bytes(&self.fs.device, attr_at + runs_relative as u64, &field)?;

                // And the node's own copy of the record says the same: a stale
                // run list here would answer with the length the file had.
                let at = header.size() as usize + data.offset + runs_relative;
                record[at..at + encoded.len()].copy_from_slice(&encoded);
                record[at + encoded.len()..at + room].fill(0);

                // The clusters the file just took have never held its bytes,
                // so they read as zeros until something writes them.
                let zeros = alloc::vec![0u8; (u64::from(allocated) - u64::from(current)) as usize];
                fs::write_to_runs(&self.fs.device, &info, &runs, u64::from(current), &zeros)?;

                let mut sizes = [0u8; 16];
                sizes[..8].copy_from_slice(&u64::from(length).to_le_bytes());
                sizes[8..].copy_from_slice(&u64::from(length).to_le_bytes());
                fs::write_device_bytes(&self.fs.device, attr_at + 48, &sizes)?;

                let mut allocated_field = [0u8; 8];
                allocated_field.copy_from_slice(&u64::from(allocated).to_le_bytes());
                fs::write_device_bytes(&self.fs.device, attr_at + 40, &allocated_field)?;
                let last_vcn = u64::from(allocated) / u64::from(info.cluster_size) - 1;
                fs::write_device_bytes(&self.fs.device, attr_at + 24, &last_vcn.to_le_bytes())?;
            }
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

impl NtfsVnode {
    /// Move a record's `$DATA` to the end of its used area, with a longer run
    /// list, and write the record whole.
    ///
    /// A run list that no longer fits the room its attribute has means the
    /// attribute **moves**: it goes last, and every attribute that followed it
    /// shifts up by the difference.  That changes the record from end to end,
    /// so it is written in one piece, with the update sequence array packed —
    /// the shift crosses sector ends, and a partial write could not leave
    /// those as they were.
    ///
    /// The record has to have the room.  A record with none left at all is the
    /// MFT growing, which is the stage after this one.
    #[allow(clippy::too_many_arguments)]
    fn relocate_run_list(
        &self,
        info: &fs::NtfsInfo,
        record: &mut Vec<u8>,
        header: &MftRecordHeader,
        data: &ParsedAttr,
        runs: &[DataRun],
        runs_relative: usize,
        encoded: &[u8],
        length: u32,
        allocated: u32,
        zeros: &[u8],
    ) -> Result<()> {
        let base = header.size() as usize;
        let attributes = parse_attributes(&record[base..]);

        // Every attribute as it is, except this one — which goes last, grown.
        let mut rebuilt = record[..base].to_vec();
        for attr in &attributes {
            if attr.attr_type == ATTR_TYPE_DATA && attr.offset == data.offset {
                continue;
            }
            let at = base + attr.offset;
            rebuilt.extend_from_slice(&record[at..at + attr.attr_len]);
        }

        let mut grown = record[base + data.offset..base + data.offset + runs_relative].to_vec();
        grown.resize((runs_relative + encoded.len()).div_ceil(8) * 8, 0);
        grown[runs_relative..runs_relative + encoded.len()].copy_from_slice(encoded);
        let grown_len = grown.len() as u32;
        grown[4..8].copy_from_slice(&grown_len.to_le_bytes());
        grown[40..48].copy_from_slice(&u64::from(allocated).to_le_bytes());
        grown[48..56].copy_from_slice(&u64::from(length).to_le_bytes());
        grown[56..64].copy_from_slice(&u64::from(length).to_le_bytes());
        let last_vcn = u64::from(allocated) / u64::from(info.cluster_size) - 1;
        grown[24..32].copy_from_slice(&last_vcn.to_le_bytes());
        rebuilt.extend_from_slice(&grown);
        rebuilt.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            info.bs.bytes_per_sector as usize,
        );

        // The clusters the file just took have never held its bytes.
        fs::write_to_runs(
            &self.fs.device,
            info,
            runs,
            u64::from(length) - zeros.len() as u64,
            zeros,
        )?;

        let number = *self.mft_record_number.lock();
        let at = self.fs.record_offset(info, number)?;
        fs::write_device_bytes(&self.fs.device, at, &rebuilt)?;

        // The volume, the cache and this node all say the same thing now.
        self.fs.mft_cache.lock().insert(number, rebuilt.clone());
        *record = rebuilt;
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
