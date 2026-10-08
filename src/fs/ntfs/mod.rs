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

/// The `$MFT`'s own record, whose `$DATA` is the records themselves.
const MFT_RECORD: u64 = 0;

/// The volume's `$UpCase` table, which the standard fixes at the tenth.
const UPCASE_RECORD: u64 = 10;

/// Where a volume's flags are inside its `$VOLUME_INFORMATION` value: eight
/// reserved bytes, then a major and a minor version.
const VOLUME_FLAGS_OFFSET: usize = 10;

/// The first record a new file's own can come from.
///
/// The volume keeps its first sixteen records for itself; the free space a
/// file's record comes from is what follows them.  Which of those is free is
/// the record header's own business: a record that is formatted but not in use
/// is one nothing names.
const FIRST_FREE_RECORD: u64 = 16;

/// How deep an index tree this driver will follow before it gives up.
///
/// A directory's index is a B-tree, and a volume can make one deeper than a
/// reader should walk looking for a name: the bound is what keeps a damaged
/// pointer from being a loop.
const MAX_INDEX_DEPTH: u32 = 8;

/// A path's last segment, and the directory it is in.
///
/// A path here begins at the root and is separated by one byte, so the last
/// separator is what tells a name from the path above it.
fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(at) => {
            let parent = if at == 0 { "/" } else { &path[..at] };
            (parent, &path[at + 1..])
        }
        None => ("/", path),
    }
}

/// Compare two names the way the volume's index does.
///
/// NTFS orders an index through the `$UpCase` table the volume carries: names
/// are compared uppercased, character by character, and a name that is a
/// prefix of another sorts first.  A volume whose table cannot be read is
/// compared as its names are stored, which is this driver's own order and not
/// the format's.
fn compare_names(left: &str, right: &str, upcase: &[u16]) -> core::cmp::Ordering {
    let folded = |code: u16| upcase.get(code as usize).copied().unwrap_or(code);
    let mut left = left.encode_utf16();
    let mut right = right.encode_utf16();
    loop {
        match (left.next(), right.next()) {
            (Some(a), Some(b)) => {
                let (a, b) = (folded(a), folded(b));
                if a != b {
                    return a.cmp(&b);
                }
            }
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (None, None) => return core::cmp::Ordering::Equal,
        }
    }
}

/// Where a directory keeps its index entries, so a change can be written back
/// to the place it belongs.
enum IndexHome {
    /// In the record's own `$INDEX_ROOT` value: the record is the buffer, and
    /// writing it back means writing the record whole, its update sequence
    /// array packed again.
    Record,
    /// In an `$INDEX_ALLOCATION` block at a virtual cluster number: the block
    /// is the buffer, and it carries an update sequence array of its own.
    Block {
        vcn: u64,
        runs: Vec<DataRun>,
        usa_offset: usize,
        usa_count: usize,
    },
}

/// Whether a bitmap says a particular number is in use.
fn bit_is_set(bits: &[u8], number: u64) -> bool {
    let index = (number / 8) as usize;
    index < bits.len() && bits[index] & (1 << (number % 8)) != 0
}

/// The bytes of a new file's record.
///
/// It carries what a real one carries at the moment it is made: its own name,
/// the timestamps a volume with no clock leaves zero, and an empty `$DATA` —
/// which is *resident*, because that is where an empty file's bytes live.  A
/// file that grows out of its record converts that attribute, which is a step
/// this driver does not take yet.
fn new_record(
    record_size: usize,
    sector_size: usize,
    number: u64,
    sequence: u16,
    parent: u64,
    name: &str,
    directory: bool,
) -> Vec<u8> {
    // A record's own standard information is where the file-attribute bits
    // live: archive for a file, the "is a directory" bit for a directory.
    let mut standard = alloc::vec![0u8; 48];
    let file_attributes: u32 = if directory { 0x1000_0000 } else { 0x20 };
    standard[32..36].copy_from_slice(&file_attributes.to_le_bytes());
    let filename = fs::file_name_value(parent, name, directory, 0);
    let data = fs::resident_attribute(ATTR_TYPE_DATA, "", 4, &[]);
    fs::build_record(
        record_size,
        sector_size,
        number,
        sequence,
        if directory { 0x03 } else { 0x01 },
        1,
        &[
            fs::resident_attribute(ATTR_TYPE_STANDARD_INFO, "", 0, &standard),
            fs::resident_attribute(ATTR_TYPE_FILENAME, "", 1, &filename),
            data,
        ],
    )
}

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
    /// A name is matched the way the volume's index orders names: through the
    /// folding table it carries (`$UpCase`), so a name is found by the case a
    /// real NTFS would find it by — and by the bytes it is stored as, for a
    /// volume whose table cannot be read ([RFC 0012]).
    fn resolve(&self, path: &str) -> Result<(u64, String)> {
        let upcase = self.upcase_table();
        let mut record_number = ROOT_RECORD;
        let mut name = String::from("/");
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            let entries = self.directory_entries(record_number)?;
            let (found_name, found_record) = entries
                .into_iter()
                .find(|(entry_name, _)| compare_names(entry_name, segment, &upcase).is_eq())
                .ok_or(Error::NotFound)?;
            record_number = found_record;
            name = found_name;
        }
        Ok((record_number, name))
    }

    /// The volume's `$UpCase` table, when it has one this driver can read.
    ///
    /// The table is a file like any other — the tenth record's `$DATA`, 128
    /// KiB of code units — and it is what a name is folded through.  A volume
    /// whose table is missing or unreadable answers with none, and names are
    /// then compared as they are stored.
    fn upcase_table(&self) -> Vec<u16> {
        self.read_upcase_table().unwrap_or_default()
    }

    fn read_upcase_table(&self) -> Option<Vec<u16>> {
        let record = self.read_mft_record(UPCASE_RECORD).ok()?;
        let header = MftRecordHeader::parse(&record)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)?;

        let units = |bytes: &[u8]| -> Vec<u16> {
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        };
        if data.data_runs_offset.is_none() {
            return Some(units(&data.content));
        }

        let info = self.info.lock();
        let mut bytes = alloc::vec![0u8; 0x1_0000 * 2];
        let size = (data.data_size as usize).min(bytes.len());
        fs::read_from_runs(
            &self.device,
            &info,
            &data.data_runs,
            u64::from(data.data_size),
            0,
            &mut bytes[..size],
        )
        .ok()?;
        Some(units(&bytes[..size]))
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

    /// Give a file's clusters back to the volume's free space.
    ///
    /// The bitmap is the free list in the other direction: the bits a file's
    /// runs name go clear, which is what the next claim then hands out again.
    /// A sparse run names no cluster and has nothing to give back.
    fn free_clusters(&self, runs: &[DataRun]) -> Result<()> {
        let mut bitmap = self.read_bitmap()?;
        for run in runs {
            if run.lcn < 0 {
                continue;
            }
            let first = run.lcn as u64;
            for cluster in first..first + run.cluster_count {
                let byte = cluster as usize / 8;
                if byte >= bitmap.len() {
                    break;
                }
                bitmap[byte] &= !(1 << (cluster % 8));
            }
        }
        self.set_dirty(true)?;
        self.write_bitmap(&bitmap)
    }

    /// The node a directory's entries are in, as the buffer it lives in.
    ///
    /// A directory's entries are in its index root, or in the
    /// `$INDEX_ALLOCATION` block its root points at — and a block that has
    /// children points at another.  The entries are in the node that has *no*
    /// children, which is where this descends to; the buffer comes back with
    /// the node's place and its room, so a change to the entries can be
    /// written back where they belong.
    fn index_leaf(&self, parent_record: u64) -> Result<(Vec<u8>, usize, usize, IndexHome)> {
        let record = self.read_mft_record(parent_record)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;

        // An index *root*'s node begins after the root header — the indexed
        // attribute's type, the collation rule and the buffer size — and the
        // room it has is the rest of the value the record gives it.
        let mut node = header.size() as usize + root.offset + root.value_offset + 16;
        let mut room = root.content.len().saturating_sub(16);
        let mut buffer = record;
        let mut home = IndexHome::Record;

        let mut depth = 0;
        while parse_index_node(&buffer, node).has_children {
            if depth >= MAX_INDEX_DEPTH {
                return Err(Error::InvalidArgument);
            }
            depth += 1;
            let pointer = parse_index_node(&buffer, node)
                .entries
                .iter()
                .find(|entry| entry.points_at_a_node)
                .map(|entry| entry.reference)
                .ok_or(Error::InvalidArgument)?;
            let allocation = attributes
                .iter()
                .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ALLOC && !attr.data_runs.is_empty())
                .ok_or(Error::NotFound)?;

            // A block's node begins after `INDX`, its update sequence array
            // and its virtual cluster number, and it has the rest of the block.
            let block = self.read_index_block(&attributes, pointer)?;
            let usa_offset = u16::from_le_bytes([block[4], block[5]]) as usize;
            let usa_count = u16::from_le_bytes([block[6], block[7]]) as usize;
            home = IndexHome::Block {
                vcn: pointer,
                runs: allocation.data_runs.clone(),
                usa_offset,
                usa_count,
            };
            room = block.len().saturating_sub(24);
            node = 24;
            buffer = block;
        }
        Ok((buffer, node, room, home))
    }

    /// Write an index node's buffer back to the volume.
    fn write_index_leaf(
        &self,
        parent_record: u64,
        buffer: &mut [u8],
        home: &IndexHome,
    ) -> Result<()> {
        match home {
            IndexHome::Record => {
                // The record is the buffer: it goes back whole, with its
                // update sequence array packed again for the sector ends the
                // entries do not reach.
                let header = MftRecordHeader::parse(buffer).ok_or(Error::InvalidArgument)?;
                let (at, sector) = {
                    let info = self.info.lock();
                    (
                        self.record_offset(&info, parent_record)?,
                        info.bs.bytes_per_sector as usize,
                    )
                };
                fs::pack_usa(
                    buffer,
                    header.usa_offset as usize,
                    header.usa_count as usize,
                    sector,
                );
                fs::write_device_bytes(&self.device, at, buffer)?;
                self.mft_cache.lock().insert(parent_record, buffer.to_vec());
            }
            IndexHome::Block {
                vcn,
                runs,
                usa_offset,
                usa_count,
            } => {
                let (cluster_size, sector) = {
                    let info = self.info.lock();
                    (
                        u64::from(info.cluster_size),
                        info.bs.bytes_per_sector as usize,
                    )
                };
                fs::pack_usa(buffer, *usa_offset, *usa_count, sector);
                let info = self.info.lock();
                fs::write_to_runs(&self.device, &info, runs, vcn * cluster_size, buffer)?;
            }
        }
        Ok(())
    }

    /// Put a name into a directory's index, where the index's order puts it.
    ///
    /// The entries a node holds are rewritten as a run, with the new one in
    /// the place its folded name sorts to and the node's terminator last: an
    /// index is ordered, and an entry that breaks the order is not one a real
    /// NTFS would have written.  A node that has no room for the entry refuses
    /// (`NoSpace`) rather than writing past what it owns — the format's answer
    /// to a full node is to split it, which this driver does not do yet.
    fn index_insert(
        &self,
        parent_record: u64,
        name: &str,
        reference: u64,
        directory: bool,
        size: u64,
    ) -> Result<()> {
        let parent = self.read_mft_record(parent_record)?;
        let parent_sequence = u16::from_le_bytes([parent[16], parent[17]]);
        let upcase = self.upcase_table();
        let entry = fs::index_entry(
            name,
            reference,
            parent_record | (u64::from(parent_sequence) << 48),
            directory,
            size,
        );

        let (mut buffer, node, room, home) = self.index_leaf(parent_record)?;
        let parsed = parse_index_node(&buffer, node);
        let Some((terminator, rest)) = parsed.entries.split_last() else {
            return Err(Error::InvalidArgument);
        };
        // The terminator is the entry no name follows, and it stays last.
        if terminator.name.is_some() {
            return Err(Error::InvalidArgument);
        }

        let mut raws: Vec<Vec<u8>> = rest
            .iter()
            .map(|entry| buffer[entry.offset..entry.offset + entry.length].to_vec())
            .collect();
        let place =
            rest.iter()
                .position(|existing| {
                    existing.name.as_ref().is_some_and(|existing| {
                        compare_names(name, &existing.name, &upcase).is_lt()
                    })
                })
                .unwrap_or(rest.len());
        raws.insert(place, entry);
        raws.push(buffer[terminator.offset..terminator.offset + terminator.length].to_vec());

        fs::write_index_entries(&mut buffer, node, room, &raws)?;
        self.write_index_leaf(parent_record, &mut buffer, &home)
    }

    /// Take a name out of a directory's index.
    ///
    /// The entry that goes is the one that names this record *and* this name:
    /// a file can have more than one name, and a number alone would take the
    /// wrong one.
    fn index_remove(&self, parent_record: u64, name: &str, reference: u64) -> Result<()> {
        let upcase = self.upcase_table();
        let (mut buffer, node, room, home) = self.index_leaf(parent_record)?;
        let parsed = parse_index_node(&buffer, node);
        let last = parsed.entries.len().saturating_sub(1);

        let mut raws: Vec<Vec<u8>> = Vec::new();
        let mut removed = false;
        for (index, entry) in parsed.entries.iter().enumerate() {
            let bytes = buffer[entry.offset..entry.offset + entry.length].to_vec();
            if index == last {
                // The terminator stays, wherever the removal left it.
                raws.push(bytes);
                continue;
            }
            let matches = entry.reference == reference
                && entry
                    .name
                    .as_ref()
                    .is_some_and(|existing| compare_names(name, &existing.name, &upcase).is_eq());
            if matches && !removed {
                removed = true;
                continue;
            }
            raws.push(bytes);
        }
        if !removed {
            return Err(Error::NotFound);
        }

        fs::write_index_entries(&mut buffer, node, room, &raws)?;
        self.write_index_leaf(parent_record, &mut buffer, &home)
    }

    /// Put a new file's record into the MFT's first free slot, and answer its
    /// number and its sequence.
    ///
    /// A record that is formatted but not in use is free: its own header says
    /// so, and a record a volume has never written is all zeros and free too.
    /// Where `$MFT` carries its own `$BITMAP`, the bit is the volume's word on
    /// it and is read first; the header is then a second one.
    fn claim_mft_record(&self, parent: u64, name: &str, directory: bool) -> Result<(u64, u16)> {
        let (record_size, sector_size, records, runs, cluster_size) = {
            let mut info = self.info.lock();
            let runs = info.resolve_mft_runs(&self.device)?;
            let record_size = u64::from(info.mft_record_size);
            (
                record_size,
                info.bs.bytes_per_sector as usize,
                info.mft_data_size / record_size,
                runs,
                info.cluster_size,
            )
        };
        let parent_sequence = {
            let parent = self.read_mft_record(parent)?;
            u16::from_le_bytes([parent[16], parent[17]])
        };
        let bitmap = self.mft_bitmap()?;

        for number in FIRST_FREE_RECORD..records {
            if bitmap.as_ref().is_some_and(|bits| bit_is_set(bits, number)) {
                continue;
            }
            let offset = number * record_size;
            let Some(at) = fs::byte_offset_in_runs(&runs, cluster_size, offset) else {
                continue;
            };
            let mut raw = alloc::vec![0u8; record_size as usize];
            fs::read_device_bytes(&self.device, at, &mut raw)?;

            // A record that was used before keeps its number unusable through
            // its sequence, which only ever goes up; a record a volume has
            // never written is all zeros, and its sequence starts at one.
            let sequence = match MftRecordHeader::parse(&raw) {
                Some(header) if header.flags & MFT_RECORD_IN_USE == 0 => {
                    u16::from_le_bytes([raw[16], raw[17]]).wrapping_add(1)
                }
                Some(_) => continue,
                None if raw.iter().all(|byte| *byte == 0) => 1,
                None => continue,
            };

            // The volume's word on it goes first: a record the volume says is
            // in use and nothing names is a leak, and the other order would
            // leave a record in use that the volume would hand out again.
            self.set_mft_bitmap(number, true)?;
            let record = new_record(
                record_size as usize,
                sector_size,
                number,
                sequence,
                parent | (u64::from(parent_sequence) << 48),
                name,
                directory,
            );
            fs::write_device_bytes(&self.device, at, &record)?;
            // Whatever the mount had of this number is not what is there now.
            self.mft_cache.lock().remove(&number);
            return Ok((number, sequence));
        }
        Err(Error::NoSpace)
    }

    /// `$MFT`'s own `$BITMAP`, as many bytes of it as the volume's records
    /// need.
    ///
    /// The MFT is a file whose content is its records, and its `$BITMAP` is
    /// the volume's own list of which of them are in use — the thing a real
    /// NTFS allocates from.  A volume that does not carry one answers with
    /// none, and the record headers are then the only word on what is free.
    fn mft_bitmap(&self) -> Result<Option<Vec<u8>>> {
        let record = self.read_mft_record(MFT_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let Some(bitmap) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(None);
        };
        let wanted = {
            let mut info = self.info.lock();
            info.resolve_mft_runs(&self.device)?;
            (info.mft_data_size / u64::from(info.mft_record_size)).div_ceil(8) as usize
        };

        if bitmap.data_runs_offset.is_none() {
            return Ok(Some(
                bitmap.content[..wanted.min(bitmap.content.len())].to_vec(),
            ));
        }
        let info = self.info.lock();
        let mut bits = alloc::vec![0u8; wanted];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            0,
            &mut bits,
        )?;
        Ok(Some(bits))
    }

    /// Move a record's bit in `$MFT`'s own bitmap, where the volume keeps one.
    ///
    /// A claim raises the bit and a release lowers it, and the bit is what a
    /// volume that mounts this one afterwards will believe: a record this
    /// driver took and did not name there is one that would be handed out
    /// twice.
    fn set_mft_bitmap(&self, number: u64, in_use: bool) -> Result<()> {
        let record = self.read_mft_record(MFT_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = parse_attributes(&record[header.size() as usize..]);
        let Some(bitmap) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(());
        };
        let index = (number / 8) as usize;
        let mask = 1u8 << (number % 8);

        if bitmap.data_runs_offset.is_none() {
            if index >= bitmap.content.len() {
                return Err(Error::InvalidArgument);
            }
            // The bitmap is a value in the record, so the record is what is
            // written: the field change and the record it lives in go together.
            let at = header.size() as usize + bitmap.offset + bitmap.value_offset + index;
            let mut raw = record.clone();
            if in_use {
                raw[at] |= mask;
            } else {
                raw[at] &= !mask;
            }
            let (device_at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, MFT_RECORD)?,
                    info.bs.bytes_per_sector as usize,
                )
            };
            fs::pack_usa(
                &mut raw,
                header.usa_offset as usize,
                header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, device_at, &raw)?;
            self.mft_cache.lock().insert(MFT_RECORD, raw);
            return Ok(());
        }

        if index as u64 >= u64::from(bitmap.data_size) {
            return Err(Error::InvalidArgument);
        }
        let info = self.info.lock();
        let mut byte = [0u8; 1];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            index as u64,
            &mut byte,
        )?;
        if in_use {
            byte[0] |= mask;
        } else {
            byte[0] &= !mask;
        }
        fs::write_to_runs(&self.device, &info, &bitmap.data_runs, index as u64, &byte)?;
        Ok(())
    }

    /// Take a record back: it stops being in use, and its number stops being
    /// usable — the sequence number goes up, which is what makes a reference
    /// that still named it stop matching.
    fn release_mft_record(&self, number: u64) -> Result<()> {
        let record = self.read_mft_record(number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut raw = record.clone();

        let sequence = u16::from_le_bytes([raw[16], raw[17]]).wrapping_add(1);
        raw[16..18].copy_from_slice(&sequence.to_le_bytes());
        raw[18..20].copy_from_slice(&0u16.to_le_bytes()); // link count
        let flags = u16::from_le_bytes([raw[22], raw[23]]) & !MFT_RECORD_IN_USE;
        raw[22..24].copy_from_slice(&flags.to_le_bytes());

        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, number)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut raw,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, at, &raw)?;
        self.mft_cache.lock().insert(number, raw);

        // The volume's word last, so a crash between the two leaves a record
        // the volume still calls used and nothing names: a leak, rather than a
        // number the volume would hand out while this driver's record is here.
        self.set_mft_bitmap(number, false)
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

    /// Make a file: a record from the MFT's free space, and its name in the
    /// parent's index.
    ///
    /// The record goes down first and the name second, so a crash between them
    /// leaves a record in use that nothing names — a leak, which is the
    /// direction that does not break a walk — rather than a name pointing at a
    /// record that is not a file.
    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_path, name) = split_parent(path);
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // The flag goes up before the change, and before the locks the work
        // below takes: setting it reads a record, and a lock held across that
        // is a lock held against itself.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        let (number, sequence) = self.claim_mft_record(parent_record, name, false)?;
        let reference = number | (u64::from(sequence) << 48);
        if let Err(error) = self.index_insert(parent_record, name, reference, false, 0) {
            // A record nothing names is a leak rather than a break, but it is
            // still a record given up for nothing, so it is handed back.
            let _ = self.release_mft_record(number);
            return Err(error);
        }
        self.vnode(number, String::from(name))
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        // NTFS directory creation is complex - for now, just return not implemented
        Err(Error::NotImplemented)
    }

    /// Take a file out: its name from the parent's index, its clusters back
    /// to the volume, and its record back to the MFT's free space.
    ///
    /// The name goes first, which is the reverse of a creation and for the
    /// same reason: a name that a walk finds and a record that is already free
    /// is the worse half of the two, and what is left after a crash is a
    /// cluster claimed by a record nothing names.
    fn remove_path(&self, path: &str) -> Result<()> {
        let (parent_path, _) = split_parent(path);
        let (record_number, name) = self.resolve(path)?;
        if record_number == ROOT_RECORD {
            return Err(Error::InvalidArgument);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.is_dir() {
            // A directory's removal is its own stage: what it holds has to go
            // first, and so does the index bitmap that says its block is in
            // use.
            return Err(Error::NotImplemented);
        }

        // Raised before the work below, for the same reason a creation raises
        // it there: setting the flag reads a record.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        self.index_remove(parent_record, &name, record_number)?;

        // The clusters go back before the record stops naming them, so a crash
        // between the two leaves them claimed and unused rather than free and
        // spoken for.
        let attributes = parse_attributes(&record[header.size() as usize..]);
        if let Some(data) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
        {
            if data.data_runs_offset.is_some() {
                self.free_clusters(&data.data_runs)?;
            }
        }

        self.release_mft_record(record_number)
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
