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

/// How far up a parent chain this driver will walk.
///
/// A name's `$FILE_NAME` is the only link from a record to the record it is in,
/// so a walk upward is a walk of those — and the bound is what keeps a loop
/// written by something else from being this driver's loop.
const MAX_ANCESTORS: u32 = 64;

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
#[derive(Clone)]
enum IndexHome {
    /// In the `$INDEX_ROOT`'s value: the record that *holds* that attribute is
    /// the buffer — the parent record itself, or an extension record an
    /// `$ATTRIBUTE_LIST` moved the root into — and writing it back means
    /// writing that record whole, its update sequence array packed again.
    Record { holder: u64 },
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

/// Whether two list entries are parts of the same attribute.
fn names_the_same(left: &fs::AttributeListEntry, right: &fs::AttributeListEntry) -> bool {
    left.attr_type == right.attr_type
        && left.instance == right.instance
        && left.name.as_deref() == right.name.as_deref()
}

/// Whether a list entry names an attribute, wherever it lives.
fn names_the_same_attribute(entry: &fs::AttributeListEntry, attribute: &ParsedAttr) -> bool {
    entry.attr_type == attribute.attr_type
        && entry.instance == attribute.instance
        && entry.name.as_deref() == attribute.name.as_deref()
}

/// The attribute a record holds *in its own* bytes.
///
/// A writer patches a field where it lies, so an attribute that lives in
/// another record — an `$ATTRIBUTE_LIST` moved it — or in several — a run list
/// *split* by virtual cluster number — is `NotImplemented`: there is no one
/// place the field is, and half a patch is worse than none.
fn own_attribute(
    record_number: u64,
    attributes: &[ParsedAttr],
    attr_type: u32,
) -> Result<&ParsedAttr> {
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.attr_type == attr_type)
        .ok_or(Error::NotFound)?;
    if attribute.holder != record_number {
        return Err(Error::NotImplemented);
    }
    Ok(attribute)
}

/// How many bytes of a record are in use, from its own header.
fn bytes_in_use(record: &[u8]) -> usize {
    u32::from_le_bytes([record[24], record[25], record[26], record[27]]) as usize
}

/// Refuse a stream this driver cannot read, rather than returning bytes that
/// are not the file's.
///
/// A `$DATA` whose flags say it is **compressed** has runs that name clusters
/// holding an LZNT1 bitstream, and one whose flags say it is **encrypted**
/// holds ciphertext; either read as a plain runlist answers a caller with
/// something file-shaped and false, and a read that succeeds and is wrong is
/// the one failure a filesystem cannot report.  `NotImplemented` can be
/// reported, and [RFC
/// 0013](../../docs/rfcs/0013-refuse-the-ntfs-streams-this-driver-cannot-read.
/// md) decides it is the answer: the file stays listed — its name and sizes are
/// in its parent's index — and the operation that asks for its bytes is what
/// fails.
fn refuse_a_stream_this_driver_cannot_read(attribute: &ParsedAttr) -> Result<()> {
    if attribute.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED) != 0 {
        return Err(Error::NotImplemented);
    }
    Ok(())
}

/// The value of a record's `$ATTRIBUTE_LIST`, with an entry added for the
/// attribute that is about to join an extension record of its own — and one
/// for the index bitmap beside it — each where its own type sorts.
///
/// `home` is the record the two new entries name, which is only known for
/// certain once the record has been claimed; the measurement that decides
/// whether it can be claimed builds the value around a placeholder, because
/// the entries' lengths do not depend on the record they name.
fn allocation_list_value(listed: &[fs::AttributeListEntry], instance: u16, home: u64) -> Vec<u8> {
    let allocation = fs::list_entry(ATTR_TYPE_INDEX_ALLOC, "$I30", instance, 0, home);
    let bitmap = fs::list_entry(ATTR_TYPE_BITMAP, "$I30", instance.wrapping_add(1), 0, home);
    let mut value = Vec::new();
    let (mut named_allocation, mut named_bitmap) = (false, false);
    for entry in listed {
        if !named_allocation && entry.attr_type > ATTR_TYPE_INDEX_ALLOC {
            value.extend_from_slice(&allocation);
            named_allocation = true;
        }
        if !named_bitmap && entry.attr_type > ATTR_TYPE_BITMAP {
            value.extend_from_slice(&bitmap);
            named_bitmap = true;
        }
        value.extend_from_slice(&fs::list_entry(
            entry.attr_type,
            entry.name.as_deref().unwrap_or(""),
            entry.instance,
            entry.lowest_vcn,
            entry.holder | (u64::from(entry.sequence) << 48),
        ));
    }
    if !named_allocation {
        value.extend_from_slice(&allocation);
    }
    if !named_bitmap {
        value.extend_from_slice(&bitmap);
    }
    value
}

/// The attributes a new record holds.
/// Where a change to a directory's index is about to happen.
#[derive(Clone)]
struct IndexLeaf {
    /// The buffer the leaf's node is in: a block, or the record that holds the
    /// index root.
    buffer: Vec<u8>,
    /// Where the leaf's node begins in it.
    node: usize,
    /// Where that buffer lives, so the change can be written back.
    home: IndexHome,
    /// The nodes the walk went through, from the index **root** down: the last
    /// is the one the leaf hangs from, and a node above a *block* is the shape
    /// a tree deeper than one level of blocks has.
    ancestors: Vec<IndexParent>,
    /// The name the walk is about, where a node holds it as a **key** rather
    /// than the leaf holding it as an entry: any node on the way down can, and
    /// the node that does is the one a change takes it out of.
    key: Option<IndexKey>,
}

/// The node above a leaf block, and the entry the walk descended through.
#[derive(Clone)]
struct IndexParent {
    buffer: Vec<u8>,
    node: usize,
    /// Where that entry begins in the buffer: the promoted key goes before it.
    before: usize,
    /// Where the parent's buffer lives, so its growth is written back the same
    /// way any index node's is.
    home: IndexHome,
}

/// The name a change is about, where a node holds it as a key.
#[derive(Clone)]
struct IndexKey {
    /// The node's bytes, and where its node begins in them.
    buffer: Vec<u8>,
    node: usize,
    /// Where those bytes live, so the change can be written back.
    home: IndexHome,
    /// Where the entry that carries the name begins in the buffer, and how long
    /// it is — the entry a change replaces or drops.
    offset: usize,
    length: usize,
}

/// What a new record is for, which is what decides what it holds.
enum NewRecord<'a> {
    /// A file or a directory of its own: where it came from, its own name, and
    /// either an empty `$DATA` or an empty index.
    Named {
        parent: u64,
        name: &'a str,
        directory: bool,
    },
    /// An *extension* record: attributes another record's `$ATTRIBUTE_LIST`
    /// names, and a reference back to the record they belong to.
    Extension { base: u64, attributes: Vec<Vec<u8>> },
}

/// The attributes a new record holds.
///
/// What a real one carries at the moment it is made: where it came from, its
/// own name, the timestamps a volume with no clock leaves zero, and then
/// either an empty `$DATA` — which is *resident*, because that is where an
/// empty file's bytes live — or, for a directory, the empty index it grows
/// into.  A file that grows out of its record has to convert that attribute,
/// which is a step this driver does not take yet.
fn record_attributes(
    parent: u64,
    name: &str,
    directory: bool,
    index_block_size: u32,
    cluster_size: u32,
) -> Vec<Vec<u8>> {
    // A record's own standard information is where the file-attribute bits
    // live, and archive is what a real volume writes there — for a directory
    // too, whose "is a directory" bit lives in its name and its record header.
    let mut standard = alloc::vec![0u8; 48];
    standard[32..36].copy_from_slice(&0x20u32.to_le_bytes());
    let filename = fs::file_name_value(parent, name, directory, 0);
    let mut attributes = alloc::vec![
        fs::resident_attribute(ATTR_TYPE_STANDARD_INFO, "", 0, &standard),
        fs::resident_attribute(ATTR_TYPE_FILENAME, "", 1, &filename),
    ];
    if directory {
        attributes.push(fs::resident_attribute(
            ATTR_TYPE_INDEX_ROOT,
            "$I30",
            2,
            &fs::empty_index_root(index_block_size, cluster_size),
        ));
    } else {
        attributes.push(fs::resident_attribute(ATTR_TYPE_DATA, "", 2, &[]));
    }
    attributes
}

pub struct NtfsFs {
    device: Arc<dyn BlockDevice>,
    /// The mount's own state, **shared by every clone of it**.
    ///
    /// A vnode is handed a clone of the filesystem, so a cache and a record
    /// size that each clone kept to itself would be two views of one volume:
    /// a write through a vnode would leave the mount that made it answering
    /// with the record it had.  The locks are the shared things, and a clone
    /// is another handle to them.
    info: Arc<Mutex<fs::NtfsInfo>>,
    mft_cache: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
}

impl NtfsFs {
    pub fn new(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let bs = fs::read_boot_sector(&device)?;
        let info = fs::NtfsInfo::new(bs);
        Ok(Self {
            device,
            info: Arc::new(Mutex::new(info)),
            mft_cache: Arc::new(Mutex::new(BTreeMap::new())),
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

    /// The attributes a record holds, wherever they live.
    ///
    /// A record whose own bytes are not enough carries an **`$ATTRIBUTE_LIST`**
    /// naming each of its attributes and the record that holds it — which is
    /// the record itself, or an *extension* record of its, one with a base
    /// reference to the record it belongs to and no name of its own in any
    /// directory.  A non-resident attribute whose mapping pairs did not fit one
    /// record is **split** by virtual cluster number, so the parts of one
    /// attribute are put back together in the order their entries give them:
    /// what a reader wants is the one attribute the parts are.
    ///
    /// The list does not name itself — the volume this was measured against
    /// leaves its own entry out — so the attributes a record holds *in its own
    /// bytes* are kept as well, where the list does not name them.
    fn attributes_of(&self, record_number: u64) -> Result<Vec<ParsedAttr>> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut inline = parse_attributes(&record[header.size() as usize..]);
        for attribute in &mut inline {
            attribute.holder = record_number;
        }
        let Some(list) = inline
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
        else {
            return Ok(inline);
        };
        let entries = self.list_entries(list)?;

        // One group per attribute the list names, in the order it names them.
        let mut groups: Vec<Vec<fs::AttributeListEntry>> = Vec::new();
        for entry in entries {
            match groups
                .iter_mut()
                .find(|group| names_the_same(&group[0], &entry))
            {
                Some(group) => group.push(entry),
                None => groups.push(alloc::vec![entry]),
            }
        }

        let mut attributes: Vec<ParsedAttr> = Vec::new();
        for group in &mut groups {
            group.sort_by_key(|entry| entry.lowest_vcn);
            if group[0].lowest_vcn != 0 {
                // A part that starts past the first is a list with no
                // beginning, and the attribute it belongs to is not here.
                return Err(Error::InvalidArgument);
            }
            let mut merged = self.attribute_in(&group[0])?;
            // One entry is one record's worth of attribute; more than one is an
            // attribute split across records, which is no one record's bytes.
            let whole = group.len() == 1;
            for part in &group[1..] {
                let part = self.attribute_in(part)?;
                merged.data_runs.extend(part.data_runs);
                if merged.data_runs_offset.is_none() {
                    merged.data_runs_offset = part.data_runs_offset;
                }
            }
            if !whole {
                merged.holder = u64::MAX;
            }
            attributes.push(merged);
        }
        // And an attribute the record holds itself that the list did not name.
        for attribute in inline {
            if !groups
                .iter()
                .any(|group| names_the_same_attribute(&group[0], &attribute))
            {
                attributes.push(attribute);
            }
        }
        Ok(attributes)
    }

    /// The entries of an `$ATTRIBUTE_LIST`, wherever its own bytes are.
    ///
    /// A list is usually resident in the record that carries it, and can be a
    /// file of its own — the volume this was measured against writes one that
    /// is — in which case its entries are read through its own runs.
    fn list_entries(&self, list: &ParsedAttr) -> Result<Vec<fs::AttributeListEntry>> {
        if list.data_runs_offset.is_none() {
            return Ok(fs::parse_attribute_list(&list.content));
        }
        let info = self.info.lock();
        let mut value = alloc::vec![0u8; list.data_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &list.data_runs,
            u64::from(list.data_size),
            0,
            &mut value,
        )?;
        Ok(fs::parse_attribute_list(&value))
    }

    /// The attribute one list entry names, from the record it says holds it.
    ///
    /// The entry is matched by the attribute's type, its name and its instance
    /// number: a record can hold two attributes of the same type, and a name
    /// alone would not tell them apart.
    fn attribute_in(&self, entry: &fs::AttributeListEntry) -> Result<ParsedAttr> {
        let record = self.read_mft_record(entry.holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        // The sequence number is what says this is the record the list was
        // written about, and not one that has since been handed out again.
        if u16::from_le_bytes([record[16], record[17]]) != entry.sequence {
            return Err(Error::InvalidArgument);
        }
        let mut attributes = parse_attributes(&record[header.size() as usize..]);
        for attribute in &mut attributes {
            attribute.holder = entry.holder;
        }
        attributes
            .into_iter()
            .find(|attribute| {
                attribute.attr_type == entry.attr_type
                    && attribute.instance == entry.instance
                    && attribute.name.as_deref() == entry.name.as_deref()
            })
            .ok_or(Error::InvalidArgument)
    }

    /// The record an extension record belongs to, from its own header.
    ///
    /// The base reference is the field that says so: a record whose header
    /// names a base record is an extension of it, and a record whose header
    /// names none is not — the volume this was measured against marks such a
    /// record as in use and nothing else, with a link count of zero.
    fn base_record(&self, record_number: u64) -> Option<u64> {
        let record = self.read_mft_record(record_number).ok()?;
        MftRecordHeader::parse(&record)?;
        let base = u64::from_le_bytes([
            record[32], record[33], record[34], record[35], record[36], record[37], record[38],
            record[39],
        ]) & 0x0000_FFFF_FFFF_FFFF;
        (base != 0 && base != record_number).then_some(base)
    }

    /// The extension records a record's `$ATTRIBUTE_LIST` puts its attributes
    /// in.
    /// Make room in a record by moving attributes into a record of their own.
    ///
    /// This is the format's answer to a record with no room, and the answer the
    /// measured volume gave: the attribute that needs the room **moves out**
    /// into an *extension* record, and an `$ATTRIBUTE_LIST` names every
    /// attribute of the file and which record holds it.  When the attribute
    /// does not free enough room by itself, the largest others go with it,
    /// until the list fits where they were.
    ///
    /// `growing` is the attribute that asked for the room — an index root whose
    /// value has to be longer, or a `$DATA` whose run list does not fit.  It
    /// goes first, and the caller follows it to the record it lands in.
    ///
    /// A record that is *itself* an extension refuses (`NotImplemented`): the
    /// file's list is in the base record, and extending it from an extension is
    /// a step of its own.
    fn make_room(&self, record_number: u64, growing: u32) -> Result<()> {
        if self.base_record(record_number).is_some() {
            return Err(Error::NotImplemented);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let attributes = parse_attributes(&record[base..]);
        let list = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST);
        let base_reference = {
            let sequence = u16::from_le_bytes([record[16], record[17]]);
            record_number | (u64::from(sequence) << 48)
        };

        // The entries the list has, or would have: one per attribute of the
        // file, in the order the record holds them — and the entries that name
        // an attribute in a record of its own keep the record they name.
        let mut entries: Vec<(u32, Option<String>, u16, u64, u64)> = match list {
            Some(list) => self
                .list_entries(list)?
                .into_iter()
                .map(|entry| {
                    (
                        entry.attr_type,
                        entry.name,
                        entry.instance,
                        entry.lowest_vcn,
                        entry.holder | (u64::from(entry.sequence) << 48),
                    )
                })
                .collect(),
            None => attributes
                .iter()
                .map(|attribute| {
                    (
                        attribute.attr_type,
                        attribute.name.clone(),
                        attribute.instance,
                        0,
                        base_reference,
                    )
                })
                .collect(),
        };
        // A list that is not there yet is an attribute like any other, and its
        // room has to be found where the attributes that move were.
        let list_attr_len = match list {
            Some(list) => list.attr_len,
            None => {
                let value: usize = entries
                    .iter()
                    .map(|(attr_type, name, instance, vcn, holder)| {
                        fs::list_entry(
                            *attr_type,
                            name.as_deref().unwrap_or(""),
                            *instance,
                            *vcn,
                            *holder,
                        )
                        .len()
                    })
                    .sum();
                (24 + value).next_multiple_of(8)
            }
        };
        let fits = |moved_len: usize| -> bool {
            let used =
                bytes_in_use(&record) - moved_len + if list.is_some() { 0 } else { list_attr_len };
            used + 8 <= record.len()
        };

        // The attribute that asked for the room goes first, and the largest
        // others follow until what is left of the record fits the list.
        let mut moved: Vec<&ParsedAttr> = Vec::new();
        let mut moved_len = 0usize;
        let grower = attributes
            .iter()
            .find(|attribute| attribute.attr_type == growing);
        if let Some(grower) = grower {
            moved.push(grower);
            moved_len += grower.attr_len;
        }
        let mut others: Vec<&ParsedAttr> = attributes
            .iter()
            .filter(|attribute| {
                attribute.attr_type != ATTR_TYPE_ATTRIBUTE_LIST
                    && grower.is_none_or(|grower| grower.offset != attribute.offset)
            })
            .collect();
        others.sort_by_key(|attribute| core::cmp::Reverse(attribute.attr_len));
        for other in others {
            if fits(moved_len) {
                break;
            }
            moved.push(other);
            moved_len += other.attr_len;
        }
        if moved.is_empty() || !fits(moved_len) {
            return Err(Error::NoSpace);
        }

        // One record for all of them, whose own header will name the record they
        // belong to — and whose own room has to hold them.
        if moved_len + 64 > record.len() {
            return Err(Error::NoSpace);
        }
        let mut to_go: Vec<Vec<u8>> = Vec::new();
        for attribute in &moved {
            let at = base + attribute.offset;
            to_go.push(record[at..at + attribute.attr_len].to_vec());
        }
        let (extension, _) = self.claim_record(NewRecord::Extension {
            base: record_number,
            attributes: to_go,
        })?;
        let extension_reference = {
            let extension_record = self.read_mft_record(extension)?;
            let sequence = u16::from_le_bytes([extension_record[16], extension_record[17]]);
            extension | (u64::from(sequence) << 48)
        };
        for (attr_type, name, instance, _, holder) in entries.iter_mut() {
            if moved.iter().any(|attribute| {
                attribute.attr_type == *attr_type
                    && attribute.instance == *instance
                    && attribute.name == *name
            }) {
                *holder = extension_reference;
            }
        }
        let mut list_value: Vec<u8> = Vec::new();
        for (attr_type, name, instance, lowest_vcn, holder) in &entries {
            list_value.extend_from_slice(&fs::list_entry(
                *attr_type,
                name.as_deref().unwrap_or(""),
                *instance,
                *lowest_vcn,
                *holder,
            ));
        }

        // The list itself: the one the record has, with the holders it just
        // learnt — its value written through its own runs when it is a file of
        // its own — or a new one, where its own type sorts.
        let list_attribute = match list {
            Some(list) => {
                let mut bytes =
                    record[base + list.offset..base + list.offset + list.attr_len].to_vec();
                if list.data_runs_offset.is_none() {
                    let start = list.value_offset;
                    bytes[start..start + list_value.len()].copy_from_slice(&list_value);
                } else {
                    let info = self.info.lock();
                    fs::write_to_runs(&self.device, &info, &list.data_runs, 0, &list_value)?;
                }
                bytes
            }
            None => {
                let instance = u16::from_le_bytes([record[40], record[41]]);
                fs::resident_attribute(ATTR_TYPE_ATTRIBUTE_LIST, "", instance, &list_value)
            }
        };

        // The record, rebuilt: the attributes that stayed, and the list where it
        // was — or where its own type sorts among them.
        let mut rebuilt = record[..base].to_vec();
        let mut placed = false;
        for attribute in &attributes {
            if list.is_some_and(|list| list.offset == attribute.offset) {
                rebuilt.extend_from_slice(&list_attribute);
                placed = true;
                continue;
            }
            if moved.iter().any(|moved| moved.offset == attribute.offset) {
                continue;
            }
            if !placed && list.is_none() && attribute.attr_type > ATTR_TYPE_ATTRIBUTE_LIST {
                rebuilt.extend_from_slice(&list_attribute);
                placed = true;
            }
            let at = base + attribute.offset;
            rebuilt.extend_from_slice(&record[at..at + attribute.attr_len]);
        }
        if !placed {
            rebuilt.extend_from_slice(&list_attribute);
        }
        rebuilt.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        if list.is_none() {
            let instance = u16::from_le_bytes([record[40], record[41]]);
            rebuilt[40..42].copy_from_slice(&instance.wrapping_add(1).to_le_bytes());
        }

        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, record_number)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, at, &rebuilt)?;
        self.mft_cache.lock().insert(record_number, rebuilt);
        Ok(())
    }

    /// Write a grown `$DATA` where it lives: the run list, the allocated, data
    /// and initialized sizes, and the last virtual cluster number, in the
    /// record that holds the attribute.
    ///
    /// The record that holds it need not be the one the node was opened on: an
    /// `$ATTRIBUTE_LIST` can have put the attribute in an extension record, and
    /// the fields are written wherever that record's bytes are.  A run list
    /// that no longer fits the room the attribute has *moves within* the record
    /// — and a record with no room for that answers `NoSpace`, which is where
    /// the caller moves the attribute into a record of its own.
    #[allow(clippy::too_many_arguments)]
    fn write_grown_data(
        &self,
        holder: u64,
        data: &ParsedAttr,
        runs: &[DataRun],
        allocated: u32,
        length: u32,
        zeros: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let Some(runs_offset) = data.data_runs_offset else {
            // A resident value carries its length in its own header, and there
            // is no run list and no allocated size to write: a resident file
            // can only shrink here, which the caller has already checked.
            let info = self.info.lock();
            let record_at = self.record_offset(&info, holder)?;
            fs::write_device_bytes(
                &self.device,
                record_at + (base + data.offset + 16) as u64,
                &length.to_le_bytes(),
            )?;
            let mut raw = record.clone();
            raw[base + data.offset + 16..base + data.offset + 20]
                .copy_from_slice(&length.to_le_bytes());
            self.mft_cache.lock().insert(holder, raw);
            return Ok(());
        };
        let runs_relative = runs_offset - data.offset;
        let encoded = fs::encode_runs(runs);
        if runs_relative + encoded.len() > data.attr_len {
            return self.relocate_run_list(holder, data, runs, allocated, length, zeros);
        }

        let info = self.info.lock();
        let record_at = self.record_offset(&info, holder)?;
        let attr_at = record_at + (base + data.offset) as u64;
        let mut raw = record.clone();

        if runs.len() > data.data_runs.len() {
            // The run list, in the room the attribute has for it.
            let room = data.attr_len - runs_relative;
            let mut field = alloc::vec![0u8; room];
            field[..encoded.len()].copy_from_slice(&encoded);
            fs::write_device_bytes(&self.device, attr_at + runs_relative as u64, &field)?;
            let at = base + data.offset + runs_relative;
            raw[at..at + room].copy_from_slice(&field);

            // The clusters the file just took have never held its bytes.
            fs::write_to_runs(
                &self.device,
                &info,
                runs,
                u64::from(length) - zeros.len() as u64,
                zeros,
            )?;

            let mut allocated_field = [0u8; 8];
            allocated_field.copy_from_slice(&u64::from(allocated).to_le_bytes());
            fs::write_device_bytes(&self.device, attr_at + 40, &allocated_field)?;
            raw[base + data.offset + 40..base + data.offset + 48].copy_from_slice(&allocated_field);
            let last_vcn = u64::from(allocated) / u64::from(info.cluster_size) - 1;
            fs::write_device_bytes(&self.device, attr_at + 24, &last_vcn.to_le_bytes())?;
            raw[base + data.offset + 24..base + data.offset + 32]
                .copy_from_slice(&last_vcn.to_le_bytes());
        }

        // The data size and the initialized size, adjacent in a non-resident
        // header: a shorter file has no initialized bytes beyond its length.
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&u64::from(length).to_le_bytes());
        sizes[8..].copy_from_slice(&u64::from(length).to_le_bytes());
        fs::write_device_bytes(&self.device, attr_at + 48, &sizes)?;
        raw[base + data.offset + 48..base + data.offset + 64].copy_from_slice(&sizes);

        self.mft_cache.lock().insert(holder, raw);
        Ok(())
    }

    /// Move an attribute to the end of its record's used area, with a longer
    /// run list, and write the record whole.
    ///
    /// A run list that no longer fits the room its attribute has means the
    /// attribute **moves**: it goes last, and every attribute that followed it
    /// shifts up by the difference.  The record then changes from end to end,
    /// so it is written in one piece, with the update sequence array packed
    /// again — the shift crosses sector ends, and a field write could not leave
    /// those as they were.
    #[allow(clippy::too_many_arguments)]
    fn relocate_run_list(
        &self,
        holder: u64,
        data: &ParsedAttr,
        runs: &[DataRun],
        allocated: u32,
        length: u32,
        zeros: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let info = self.info.lock();
        let base = header.size() as usize;
        let runs_relative = data.data_runs_offset.ok_or(Error::InvalidArgument)? - data.offset;
        let encoded = fs::encode_runs(runs);

        // Every attribute as it is, except this one — which goes last, grown.
        let attributes = parse_attributes(&record[base..]);
        let mut rebuilt = record[..base].to_vec();
        for attribute in &attributes {
            if attribute.attr_type == data.attr_type
                && attribute.offset == data.offset
                && attribute.instance == data.instance
            {
                continue;
            }
            let at = base + attribute.offset;
            rebuilt.extend_from_slice(&record[at..at + attribute.attr_len]);
        }

        let mut grown = record[base + data.offset..base + data.offset + runs_relative].to_vec();
        grown.resize((runs_relative + encoded.len()).div_ceil(8) * 8, 0);
        grown[runs_relative..runs_relative + encoded.len()].copy_from_slice(&encoded);
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
            &self.device,
            &info,
            runs,
            u64::from(length) - zeros.len() as u64,
            zeros,
        )?;
        let at = self.record_offset(&info, holder)?;
        fs::write_device_bytes(&self.device, at, &rebuilt)?;
        self.mft_cache.lock().insert(holder, rebuilt);
        Ok(())
    }

    /// The extension records a record's `$ATTRIBUTE_LIST` puts its attributes
    /// in.
    fn extension_records(&self, record_number: u64, record: &[u8]) -> Result<Vec<u64>> {
        let header = MftRecordHeader::parse(record).ok_or(Error::InvalidArgument)?;
        let inline = parse_attributes(&record[header.size() as usize..]);
        let Some(list) = inline
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
        else {
            return Ok(Vec::new());
        };

        let mut holders: Vec<u64> = Vec::new();
        for entry in self.list_entries(list)? {
            if entry.holder == record_number
                || holders.contains(&entry.holder)
                || self.base_record(entry.holder) != Some(record_number)
            {
                continue;
            }
            holders.push(entry.holder);
        }
        Ok(holders)
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
        let attributes = self.attributes_of(record_number)?;
        let root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        let mut found: Vec<(FileName, u64)> = Vec::new();
        self.walk_index(&attributes, &root.content, 16, 0, &mut found)?;

        // One file can have more than one name — a short one and a long one —
        // and the listing keeps the preferred of them.
        let mut best: Vec<(FileName, u64)> = Vec::new();
        for (name, record) in found {
            match best.iter().position(|(_, held)| *held == record) {
                Some(index) => {
                    if name.preferred_namespace() && !best[index].0.preferred_namespace() {
                        best[index] = (name, record);
                    }
                }
                None => best.push((name, record)),
            }
        }
        Ok(best
            .into_iter()
            .map(|(name, record)| (name.name, record))
            .collect())
    }

    /// Every name an index node holds, in the order the tree keeps them.
    ///
    /// A node's entries hold its children between its own keys: an entry that
    /// points at a child carries a key, that child holds the keys *less than*
    /// it, and the key is the child's successor — so a walk takes the child
    /// first and the key after it, which is the order the names sort in.  The
    /// last entry of an internal node has no key and points at the child with
    /// the largest names.  A directory's own "." and ".." are links and not
    /// names in it, whichever of them a volume stores.
    fn walk_index(
        &self,
        attributes: &[ParsedAttr],
        buffer: &[u8],
        node: usize,
        depth: u32,
        found: &mut Vec<(FileName, u64)>,
    ) -> Result<()> {
        if depth > MAX_INDEX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        for entry in parse_index_node(buffer, node).entries {
            if let Some(child) = entry.child {
                let block = self.read_index_block(attributes, child)?;
                self.walk_index(attributes, &block, 24, depth + 1, found)?;
            }
            if let Some(name) = entry.name {
                if name.name != "." && name.name != ".." {
                    found.push((name, entry.reference));
                }
            }
        }
        Ok(())
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

    /// One of a directory's index blocks, and the home a change to its entries
    /// is written back through.
    fn read_index_block_home(
        &self,
        attributes: &[ParsedAttr],
        vcn: u64,
    ) -> Result<(Vec<u8>, IndexHome)> {
        let allocation = attributes
            .iter()
            .find(|attribute| {
                attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
            })
            .ok_or(Error::NotFound)?;
        // A block's node begins after `INDX`, its update sequence array and its
        // virtual cluster number, and it has the rest of the block.
        let block = self.read_index_block(attributes, vcn)?;
        let usa_offset = u16::from_le_bytes([block[4], block[5]]) as usize;
        let usa_count = u16::from_le_bytes([block[6], block[7]]) as usize;
        Ok((
            block,
            IndexHome::Block {
                vcn,
                runs: allocation.data_runs.clone(),
                usa_offset,
                usa_count,
            },
        ))
    }

    /// How many clusters one index block is, which is what a block's virtual
    /// cluster number counts in.
    fn clusters_per_index_block(&self) -> u64 {
        let info = self.info.lock();
        u64::from(info.index_block_size / info.cluster_size.max(1))
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
        let attributes = self.attributes_of(UPCASE_RECORD).ok()?;
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
    ///
    /// The `$DATA` an `$ATTRIBUTE_LIST` moved is a `$DATA` like any other, so
    /// this is the merged view's answer and not the record's own.
    fn data_size(&self, record_number: u64) -> u64 {
        self.attributes_of(record_number)
            .unwrap_or_default()
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
        let attributes = self.attributes_of(BITMAP_RECORD)?;
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
        // A bitmap that has moved to an extension record is written through
        // its runs like any other file; a *resident* one is a field inside the
        // record, and writing that is only this record's to do.
        let attributes = self.attributes_of(BITMAP_RECORD)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        let info = self.info.lock();
        if data.data_runs_offset.is_none() {
            // A resident bitmap is a value inside the record, so the field
            // write and the record it lives in go together — which only a
            // record whose attributes are not listed is a writer's to make.
            let data = own_attribute(BITMAP_RECORD, &attributes, ATTR_TYPE_DATA)?;
            let record = self.read_mft_record(BITMAP_RECORD)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
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
    /// A tree routes by key: an internal node's entry carries a key and the
    /// child it points at, that child holds the keys *less than* the entry's,
    /// and the last entry has no key and points at the child with the largest
    /// ones.  A name that *is* a key lives in the node above the blocks, which
    /// is where a promoted key goes when a block is split, and that is the one
    /// answer this walk does not give.
    /// The record a directory's index *root* lives in, and where its node
    /// begins in those bytes.
    ///
    /// The node's place is worked out from a **fresh** read of the record
    /// every time rather than remembered, because a change to another
    /// attribute of the same record moves it: a run list that outgrows the
    /// room its attribute has moves that attribute to the end, which is what
    /// growing `$INDEX_ALLOCATION` does, and the root's node goes with it.
    /// Writing a node back at the offset a walk once measured would put the
    /// record back the way it was and undo the growth.
    fn index_root_node(&self, holder: u64) -> Result<(Vec<u8>, usize)> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        // An index *root*'s node begins after the root header — the indexed
        // attribute's type, the collation rule and the buffer size — and the
        // value it sits in is the resident attribute the record gives it.
        let root = self
            .attributes_of(holder)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::InvalidArgument)?;
        let node = header.size() as usize + root.offset + root.value_offset + 16;
        Ok((record, node))
    }

    fn index_leaf(&self, parent_record: u64, name: &str) -> Result<IndexLeaf> {
        let upcase = self.upcase_table();
        let attributes = self.attributes_of(parent_record)?;
        let root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        // The node's own offset is an offset in the bytes of the record that
        // holds the attribute, which an `$ATTRIBUTE_LIST` can have made an
        // extension record of the parent's.
        let holder = root.holder;
        if holder == u64::MAX {
            // A root split across records is one no single record's bytes are.
            return Err(Error::NotImplemented);
        }
        let (mut buffer, mut node) = self.index_root_node(holder)?;
        let mut home = IndexHome::Record { holder };
        let mut ancestors: Vec<IndexParent> = Vec::new();

        let mut depth = 0;
        while parse_index_node(&buffer, node).has_children {
            if depth >= MAX_INDEX_DEPTH {
                return Err(Error::InvalidArgument);
            }
            depth += 1;
            let parsed = parse_index_node(&buffer, node);
            // The first child whose key is *greater* than the name holds it:
            // that child keeps the keys less than its key.  A name equal to a
            // key is that key, and lives here in the node.
            let mut chosen = None;
            for entry in &parsed.entries {
                let Some(key) = &entry.name else { continue };
                if compare_names(&key.name, name, &upcase).is_gt() {
                    chosen = Some((entry.child, entry.offset));
                    break;
                }
                if compare_names(&key.name, name, &upcase).is_eq() {
                    // The name is this node's own key: it lives here, above the
                    // blocks, and the walk does not go past it.  Where that is
                    // is what a change needs, so the node comes back with the
                    // entry it carries.
                    let key = IndexKey {
                        buffer: buffer.clone(),
                        node,
                        home: home.clone(),
                        offset: entry.offset,
                        length: entry.length,
                    };
                    return Ok(IndexLeaf {
                        ancestors,
                        buffer,
                        node,
                        home,
                        key: Some(key),
                    });
                }
            }
            // Nothing greater: the last child, the one with no key, holds the
            // largest names.
            let (pointer, before) = match chosen {
                Some(chosen) => chosen,
                None => {
                    let last = parsed
                        .entries
                        .iter()
                        .rfind(|entry| entry.child.is_some())
                        .ok_or(Error::InvalidArgument)?;
                    (last.child, last.offset)
                }
            };
            let pointer = pointer.ok_or(Error::InvalidArgument)?;
            ancestors.push(IndexParent {
                buffer: buffer.clone(),
                node,
                before,
                home: home.clone(),
            });
            let (block, block_home) = self.read_index_block_home(&attributes, pointer)?;
            home = block_home;
            node = 24;
            buffer = block;
        }
        Ok(IndexLeaf {
            buffer,
            node,
            home,
            ancestors,
            key: None,
        })
    }

    /// Write a directory's index entries back where they live.
    ///
    /// A node's entries are replaced as a run, so what a caller hands over is
    /// the run itself — the entries that were there, or the ones that should
    /// be, with the node's own terminator last.
    ///
    /// The two places an index lives differ in what "room" means.  A block has
    /// what is left of the block.  An index *root* has the value the record
    /// gives it, and that value **grows** when it has to: an attribute inside a
    /// record can be as long as the record has room for, so the value's bytes
    /// extend, everything after the attribute shifts up with the end marker,
    /// and the record goes back whole.  The record that holds the attribute is
    /// the buffer, which an `$ATTRIBUTE_LIST` can have made an extension record
    /// of the parent's.  A record with no room refuses (`NoSpace`), and the
    /// caller makes room by moving attributes out of it.
    fn write_index_leaf(
        &self,
        _parent_record: u64,
        buffer: &mut [u8],
        node: usize,
        entries: &[Vec<u8>],
        home: &IndexHome,
    ) -> Result<()> {
        match home {
            IndexHome::Record { holder } => {
                let header = MftRecordHeader::parse(buffer).ok_or(Error::InvalidArgument)?;
                let attributes = self.attributes_of(*holder)?;
                let root = own_attribute(*holder, &attributes, ATTR_TYPE_INDEX_ROOT)?;
                let attr_at = header.size() as usize + root.offset;

                // What the node's entries come to, and whether the record has
                // the room for that much value.
                let entries_offset = u32::from_le_bytes([
                    buffer[node],
                    buffer[node + 1],
                    buffer[node + 2],
                    buffer[node + 3],
                ]) as usize;
                let used = entries_offset
                    + entries
                        .iter()
                        .try_fold(0usize, |total, entry| total.checked_add(entry.len()))
                        .ok_or(Error::InvalidArgument)?;
                let value_len = 16 + used;
                let room = buffer.len() - bytes_in_use(buffer);
                if value_len > root.content.len() + room {
                    return Err(Error::NoSpace);
                }

                // The attribute as it should be: the longer value, its node's
                // sizes following, and the entries inside it.
                let mut attribute = buffer[attr_at..attr_at + root.attr_len].to_vec();
                let attr_len = (root.value_offset + value_len).div_ceil(8) * 8;
                attribute.resize(attr_len, 0);
                attribute[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
                attribute[16..20].copy_from_slice(&(value_len as u32).to_le_bytes());
                fs::write_index_entries(
                    &mut attribute[root.value_offset..root.value_offset + value_len],
                    16,
                    value_len - 16,
                    entries,
                )?;

                // Everything after the attribute — the end marker included —
                // shifts up by what it grew.
                let end = bytes_in_use(buffer);
                let mut rebuilt = buffer[..attr_at].to_vec();
                rebuilt.extend_from_slice(&attribute);
                rebuilt.extend_from_slice(&buffer[attr_at + root.attr_len..end]);
                let rebuilt_used = rebuilt.len();
                rebuilt.resize(buffer.len(), 0);
                rebuilt[24..28].copy_from_slice(&(rebuilt_used as u32).to_le_bytes());

                let (at, sector) = {
                    let info = self.info.lock();
                    (
                        self.record_offset(&info, *holder)?,
                        info.bs.bytes_per_sector as usize,
                    )
                };
                fs::pack_usa(
                    &mut rebuilt,
                    header.usa_offset as usize,
                    header.usa_count as usize,
                    sector,
                );
                fs::write_device_bytes(&self.device, at, &rebuilt)?;
                self.mft_cache.lock().insert(*holder, rebuilt);
            }
            IndexHome::Block {
                vcn,
                runs,
                usa_offset,
                usa_count,
            } => {
                fs::write_index_entries(buffer, node, buffer.len() - 24, entries)?;
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

    /// Move one bit of a directory's `$INDEX_ALLOCATION` bitmap, which is the
    /// list of which of its blocks hold a node in use.
    ///
    /// A block a split makes needs a bit the bitmap may not have a *byte* for:
    /// the bitmap names eight blocks per byte, so the block numbered `bit`
    /// needs `bit / 8 + 1` bytes of it.  A bitmap that is short **grows** to
    /// what the bit needs — the value longer where it lives — and the record
    /// that holds it makes room for the growth when it has none, the way any
    /// record with no room does.  A bitmap that is a *file* of its own would be
    /// grown by a step of its own, and refuses (`NotImplemented`).
    ///
    /// Lowering a bit is the same walk without the growth: a byte the bitmap
    /// does not have names no block, so there is nothing there to lower.
    fn set_index_block_bit(&self, parent_record: u64, bit: u64, in_use: bool) -> Result<()> {
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        for attempt in 0..2 {
            let bitmap = self
                .attributes_of(parent_record)?
                .into_iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_BITMAP)
                .ok_or(Error::NotFound)?;
            let mut bits = self.index_bitmap_bytes(&bitmap)?;
            if byte >= bits.len() && !in_use {
                return Ok(());
            }
            let grew = byte >= bits.len();
            if grew {
                bits.resize(byte + 1, 0);
            }
            if in_use {
                bits[byte] |= mask;
            } else {
                bits[byte] &= !mask;
            }
            if bitmap.data_runs_offset.is_some() {
                // A bitmap that is a **file** of its own: the bit goes where
                // its runs say, and a byte it did not have grows the value and
                // its sizes with it — taking clusters for it when the runs it
                // has are full.
                self.write_index_bitmap(&bitmap, &bits, grew)?;
                return Ok(());
            }
            match self.replace_value(parent_record, ATTR_TYPE_BITMAP, &bits) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) if attempt == 0 => {
                    // The value is longer than the record has room for: the
                    // record makes room, and the bit goes in where the value
                    // landed.
                    self.make_room(bitmap.holder, ATTR_TYPE_BITMAP)?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::NoSpace)
    }

    /// A directory's index bitmap, as the attribute holds it: the value in the
    /// record, or the bytes where the runs of a bitmap that is a file say.
    fn index_bitmap_bytes(&self, bitmap: &ParsedAttr) -> Result<Vec<u8>> {
        if bitmap.data_runs_offset.is_none() {
            return Ok(bitmap.content.clone());
        }
        let info = self.info.lock();
        let mut bits = alloc::vec![0u8; bitmap.data_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            0,
            &mut bits,
        )?;
        Ok(bits)
    }

    /// Write an index bitmap that is a file back where its runs say, growing
    /// the value — and the clusters behind it — when it needs a byte it did
    /// not have.
    ///
    /// A growth takes clusters of its own when the runs the bitmap has cannot
    /// hold the new length: the bitmap is a file like any other, so its run
    /// list is extended the way [`Self::write_grown_data`] extends one, and the
    /// bytes between the old length and the new are written as zeros — a
    /// bitmap's bytes are its bits, so what it never wrote reads as free.
    fn write_index_bitmap(&self, bitmap: &ParsedAttr, bits: &[u8], grew: bool) -> Result<()> {
        let cluster_size = u64::from(self.info.lock().cluster_size);
        if !grew {
            // The same length: the value as it is, back where it lives.
            return self.write_index_bitmap_bytes(bitmap, bits);
        }

        let held: u64 = bitmap
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>();
        let wanted = (bits.len() as u64).div_ceil(cluster_size);
        let mut runs = bitmap.data_runs.clone();
        if wanted > held {
            let claim = wanted - held;
            let first = self.claim_clusters(claim)?;
            let continues = runs
                .last()
                .is_some_and(|last| last.lcn >= 0 && last.lcn as u64 + last.cluster_count == first);
            if continues {
                runs.last_mut()
                    .expect("a last run that was just looked at")
                    .cluster_count += claim;
            } else {
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: claim,
                });
            }
        }
        let allocated = (held.max(wanted) * cluster_size) as u32;
        let zeros = alloc::vec![0u8; bits.len() - bitmap.data_size as usize];
        self.write_grown_data(
            bitmap.holder,
            bitmap,
            &runs,
            allocated,
            bits.len() as u32,
            &zeros,
        )?;
        self.write_index_bitmap_bytes(bitmap, bits)
    }

    /// Put the bitmap's bytes where its runs say.
    fn write_index_bitmap_bytes(&self, bitmap: &ParsedAttr, bits: &[u8]) -> Result<()> {
        let info = self.info.lock();
        fs::write_to_runs(&self.device, &info, &bitmap.data_runs, 0, bits)?;
        Ok(())
    }

    /// The first block the directory's index bitmap says is **free**, among the
    /// blocks its allocation has.
    ///
    /// A block that a deletion gave back is a block the tree takes again before
    /// it grows the allocation: a directory whose index only ever grew would
    /// keep the volume's clusters claimed for blocks that nothing is stored in,
    /// and a block that is already the allocation's costs nothing to use again.
    /// A byte the bitmap does not have names no block, and a block nothing
    /// names is free.
    ///
    /// The bitmap is read where it lives: the value in the record, or the bytes
    /// a bitmap that is a *file* of its own keeps where its runs say.
    fn first_free_index_block(&self, parent_record: u64, blocks: u64) -> Result<Option<u64>> {
        let Some(bitmap) = self
            .attributes_of(parent_record)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(None);
        };
        let bits = self.index_bitmap_bytes(&bitmap)?;
        for block in 0..blocks {
            let byte = (block / 8) as usize;
            if byte >= bits.len() || bits[byte] & (1 << (block % 8)) == 0 {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// Put a name into a directory's index, where the index's order puts it.
    ///
    /// The entries a node holds are rewritten as a run, with the new one in
    /// the place its folded name sorts to and the node's terminator last: an
    /// index is ordered, and an entry that breaks the order is not one a real
    /// NTFS would have written.  A node that has no room for the entry
    /// refuses (`NoSpace`) rather than writing past what it owns.
    ///
    /// What answers that refusal is the shape of the node.  A root whose
    /// record has something to spare moves into a record of its own
    /// ([`Self::make_room`]), and the insertion is worked out again there.  A
    /// root that cannot grow in *any* record — one already in a record of its
    /// own, or one that filled the record it was moved to — hands its entries
    /// to an [`Self::entries_leave_for_a_block`] of their own, and the
    /// insertion lands in the block.  A *block* with no room is a split,
    /// which is not built, and refuses.
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

        // Two attempts: a directory whose record has no room for the longer
        // value makes it the way a file does — the index root moves into a
        // record of its own — and that changes the node's place, so the whole
        // insertion is worked out again.
        for attempt in 0..2 {
            let mut leaf = self.index_leaf(parent_record, name)?;
            if leaf.key.is_some() {
                // The name is one of the nodes' own keys, which is where a
                // promoted key lives: it is there.
                return Err(Error::AlreadyExists);
            }
            let parsed = parse_index_node(&leaf.buffer, leaf.node);
            let Some((terminator, rest)) = parsed.entries.split_last() else {
                return Err(Error::InvalidArgument);
            };
            // The terminator is the entry no name follows, and it stays last.
            if terminator.name.is_some() {
                return Err(Error::InvalidArgument);
            }

            let mut raws: Vec<Vec<u8>> = rest
                .iter()
                .map(|entry| leaf.buffer[entry.offset..entry.offset + entry.length].to_vec())
                .collect();
            let place = rest
                .iter()
                .position(|existing| {
                    existing.name.as_ref().is_some_and(|existing| {
                        compare_names(name, &existing.name, &upcase).is_lt()
                    })
                })
                .unwrap_or(rest.len());
            raws.insert(place, entry.clone());
            raws.push(
                leaf.buffer[terminator.offset..terminator.offset + terminator.length].to_vec(),
            );

            match self.write_index_leaf(
                parent_record,
                &mut leaf.buffer,
                leaf.node,
                &raws,
                &leaf.home,
            ) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) if attempt == 0 => match &leaf.home {
                    IndexHome::Record { holder } => {
                        let holder = *holder;
                        if self.base_record(holder).is_some() {
                            // The root already lives in a record of its own,
                            // and no extension extends another: the entries
                            // leave for a block, which is the format's answer
                            // to a root that cannot grow anywhere.
                            self.entries_leave_for_a_block(parent_record, &raws)?;
                            return Ok(());
                        }
                        self.make_room(holder, ATTR_TYPE_INDEX_ROOT)?;
                    }
                    // A block that has no room is split: its middle key is
                    // promoted into the node above it, and half its entries
                    // move to a block of their own.
                    IndexHome::Block { .. } => {
                        return self.split_index_block(parent_record, name, &raws);
                    }
                },
                Err(Error::NoSpace) if attempt == 1 => match leaf.home {
                    IndexHome::Record { .. } => {
                        // The root moved into a record of its own and filled
                        // that too: the entries leave for a block.
                        self.entries_leave_for_a_block(parent_record, &raws)?;
                        return Ok(());
                    }
                    IndexHome::Block { .. } => {
                        return self.split_index_block(parent_record, name, &raws);
                    }
                },
                Err(error) => return Err(error),
            }
        }
        Err(Error::NoSpace)
    }

    /// Split a full index block in two, promoting the key between the halves.
    ///
    /// A block with no room for a name is what the format splits: half the
    /// entries go to a block of their own, the entry between the halves becomes
    /// a **key of the node above** — the entry the walk came through keeps that
    /// node's keys *greater* than it — and the index bitmap gains a bit for the
    /// new block.
    ///
    /// The writes are ordered by what a crash leaves, and every window is one a
    /// mount reads.  The allocation and the bitmap first: a block nothing
    /// points at is a leak, the harmless direction.  The new block next,
    /// still unreachable, so its entries are in the old block *too* and a
    /// listing shows each name once (one name, one record) while a lookup
    /// finds the copy that is reachable.  The node above after that, whose
    /// new key is what makes the new block reachable.  The old block last,
    /// with the half that stayed in it.
    ///
    /// A node above that cannot hold the key refuses (`NoSpace`); it is the
    /// index root here, and a record with no room makes room first, which is
    /// why the whole split is worked out again when that happens.
    fn split_index_block(&self, parent_record: u64, name: &str, entries: &[Vec<u8>]) -> Result<()> {
        let mut derived: Option<IndexLeaf> = None;
        for attempt in 0..2 {
            let leaf = match &derived {
                Some(leaf) => leaf.clone(),
                None => {
                    let leaf = self.index_leaf(parent_record, name)?;
                    if leaf.key.is_some() {
                        return Err(Error::AlreadyExists);
                    }
                    leaf
                }
            };
            let Some(parent) = leaf.ancestors.last() else {
                return Err(Error::InvalidArgument);
            };
            let IndexHome::Block { .. } = &leaf.home else {
                return Err(Error::InvalidArgument);
            };
            let IndexHome::Record { holder } = parent.home else {
                // A leaf that hangs from a block is a tree deeper than this
                // driver writes; `index_leaf` refuses it, so this is a guard.
                return Err(Error::NotImplemented);
            };
            let (block_size, cluster_size, sector_size) = {
                let info = self.info.lock();
                (
                    info.index_block_size,
                    info.cluster_size,
                    usize::from(info.bs.bytes_per_sector),
                )
            };
            let per_block = u64::from(block_size / cluster_size.max(1));
            if per_block == 0 {
                return Err(Error::NotImplemented);
            }

            // The names, and the terminator that is not one.  The entry between
            // the halves is the key the node above learns, and it leaves both.
            let Some((terminator, names)) = entries.split_last() else {
                return Err(Error::InvalidArgument);
            };
            if names.is_empty() {
                return Err(Error::NoSpace);
            }
            let middle = names.len() / 2;
            let promoted = names[middle].clone();

            // Where the half that leaves goes: a block the bitmap says is free
            // is one a deletion gave back, and the tree takes it before the
            // allocation grows.  With none to take, the block is the
            // allocation's *next*, which is the number its size names — the
            // leaf's own number plus one is that only while the leaf is the last
            // block, and a tree's blocks are reached in key order, which need
            // not be number order.
            let allocation = self
                .attributes_of(parent_record)?
                .into_iter()
                .find(|attribute| {
                    attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
                })
                .ok_or(Error::NotFound)?;
            if u64::from(allocation.data_size) % u64::from(block_size) != 0 {
                return Err(Error::InvalidArgument);
            }
            let blocks = u64::from(allocation.data_size) / u64::from(block_size);
            let taken = self.first_free_index_block(parent_record, blocks)?;
            let new_vcn = taken.map_or(blocks * per_block, |block| block * per_block);
            let bit = new_vcn / per_block;
            let separator = fs::index_separator(&promoted, new_vcn)?;

            // The node above, with the key where its own order puts it: before
            // the entry the walk went through, which keeps the greater names.
            let parsed = parse_index_node(&parent.buffer, parent.node);
            let mut parent_entries: Vec<Vec<u8>> = Vec::new();
            let mut inserted = false;
            for entry in &parsed.entries {
                if !inserted && entry.offset >= parent.before {
                    parent_entries.push(separator.clone());
                    inserted = true;
                }
                parent_entries
                    .push(parent.buffer[entry.offset..entry.offset + entry.length].to_vec());
            }
            if !inserted {
                return Err(Error::InvalidArgument);
            }

            // The room the key needs, measured the way the node above is
            // written: its value may grow into the record, and a record with no
            // room makes room first and the split is worked out again.
            let needed = {
                let entries_offset = u32::from_le_bytes([
                    parent.buffer[parent.node],
                    parent.buffer[parent.node + 1],
                    parent.buffer[parent.node + 2],
                    parent.buffer[parent.node + 3],
                ]) as usize;
                let used = entries_offset
                    + parent_entries
                        .iter()
                        .map(|entry| entry.len())
                        .sum::<usize>();
                let record = self.read_mft_record(holder)?;
                let root = self
                    .attributes_of(holder)?
                    .into_iter()
                    .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
                    .ok_or(Error::InvalidArgument)?;
                16 + used > root.content.len() + (record.len() - bytes_in_use(&record))
            };
            if needed {
                if attempt == 0 {
                    self.make_room(holder, ATTR_TYPE_INDEX_ROOT)?;
                    derived = None;
                    continue;
                }
                return Err(Error::NoSpace);
            }

            // The clusters the block lives in.  A block that was already the
            // allocation's has them; one past the end of it takes a block's
            // worth from the volume and moves the allocation with it.
            let runs = match taken {
                Some(_) => allocation.data_runs.clone(),
                None => {
                    let first = self.claim_clusters(per_block)?;
                    let mut runs = allocation.data_runs.clone();
                    let merged = runs.last().is_some_and(|last| {
                        last.lcn >= 0 && last.lcn as u64 + last.cluster_count == first
                    });
                    if merged {
                        runs.last_mut()
                            .expect("the last run that was just looked at")
                            .cluster_count += per_block;
                    } else {
                        runs.push(DataRun {
                            lcn: first as i64,
                            cluster_count: per_block,
                        });
                    }
                    let grown = allocation.data_size + block_size;
                    self.write_grown_data(
                        allocation.holder,
                        &allocation,
                        &runs,
                        grown,
                        grown,
                        &[],
                    )?;
                    runs
                }
            };

            // The bitmap's bit for the block, which is the block's own number.
            self.set_index_block_bit(parent_record, bit, true)?;

            // The new block, with the half that left and its own terminator.
            let mut left: Vec<Vec<u8>> = names[..middle].to_vec();
            left.push(terminator.clone());
            let block =
                fs::index_allocation_block(block_size as usize, sector_size, new_vcn, &left)?;
            {
                let info = self.info.lock();
                fs::write_to_runs(
                    &self.device,
                    &info,
                    &runs,
                    new_vcn * u64::from(cluster_size),
                    &block,
                )?;
            }

            // The node above, whose key makes the new block reachable.
            //
            // It is written from a fresh read of its record, not the copy the
            // walk started with: growing the allocation above may have moved
            // the attribute the root lives in, and a record written from that
            // copy would undo the growth and the bitmap bit with it.
            let (mut parent_buffer, parent_node) = self.index_root_node(holder)?;
            self.write_index_leaf(
                parent_record,
                &mut parent_buffer,
                parent_node,
                &parent_entries,
                &parent.home,
            )?;

            // And the block that stayed, with the half that stayed in it.
            let mut right: Vec<Vec<u8>> = names[middle + 1..].to_vec();
            right.push(terminator.clone());
            let mut leaf_buffer = leaf.buffer.clone();
            self.write_index_leaf(
                parent_record,
                &mut leaf_buffer,
                leaf.node,
                &right,
                &leaf.home,
            )?;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    /// This is the format's answer to a root that cannot grow in any record —
    /// the one a record full of *entries* needs, where the root's move into a
    /// record of its own has already been spent.  Every entry leaves the
    /// root's value for a **block**; the two attributes that describe the
    /// allocation — the runs and the bitmap of the blocks, both named `$I30`
    /// — go into an extension record of their own, the base's
    /// `$ATTRIBUTE_LIST` names them where they went, and the root's node
    /// keeps only the pointer to the block, whose virtual cluster number is
    /// the pointer's last eight bytes.
    ///
    /// The writes are ordered by what a crash between them leaves, and every
    /// window is one a mount reads.  The record and the block go down first —
    /// a record in use that nothing names and a block nothing points at are
    /// leaks, the harmless direction.  The base's list second: the root still
    /// holds its entries as a value, so a listing reads them where they were.
    /// The root's node last, and that write is the one that turns the index
    /// into a tree.
    ///
    /// A block smaller than a cluster is one no virtual cluster number can
    /// address (`NotImplemented`), a set of entries that does not fit one
    /// block refuses (`NoSpace`), and so does a base whose list cannot take
    /// two more entries — refused before anything is claimed, so nothing is
    /// half-spent.
    fn entries_leave_for_a_block(&self, parent_record: u64, entries: &[Vec<u8>]) -> Result<()> {
        let (index_block_size, cluster_size, sector_size) = {
            let info = self.info.lock();
            (
                info.index_block_size,
                info.cluster_size,
                usize::from(info.bs.bytes_per_sector),
            )
        };
        let clusters = u64::from(index_block_size / cluster_size.max(1));
        if clusters == 0 {
            return Err(Error::NotImplemented);
        }

        let attributes = self.attributes_of(parent_record)?;
        let root = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        // A root still in its own record is one the move answers: the block is
        // for a root whose move has been spent, which is the only way this is
        // reached.
        let holder = root.holder;
        if holder == u64::MAX || holder == parent_record {
            return Err(Error::NotImplemented);
        }
        if attributes.iter().any(|attribute| {
            attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
        }) {
            return Err(Error::InvalidArgument);
        }

        // The base's list is what says where the root went, so it is what will
        // say where the two attributes went — a list that is a file of its own
        // is grown by a step of its own, and is refused here.
        let mut base = self.read_mft_record(parent_record)?;
        let mut base_header = MftRecordHeader::parse(&base).ok_or(Error::InvalidArgument)?;
        let base_at = base_header.size() as usize;
        let mut base_attributes = parse_attributes(&base[base_at..]);
        let mut list = base_attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            .ok_or(Error::InvalidArgument)?
            .clone();
        if list.data_runs_offset.is_some() {
            return Err(Error::NotImplemented);
        }
        let mut listed = self.list_entries(&list)?;
        let instance = u16::from_le_bytes([base[40], base[41]]);

        // The base as the list will leave it: two entries longer than it is
        // now, each where its own type sorts.  The entries' lengths do not
        // depend on the record they name, so the fit is measured against a
        // list built around a placeholder before anything is claimed — and a
        // base that cannot hold the growth makes room first, its largest
        // attribute that is not the list moving into a record of its own,
        // which is what the list's entry for it then names.
        let measured = |listed: &[fs::AttributeListEntry], value_offset: usize| -> usize {
            let value = allocation_list_value(listed, instance, 0);
            (value_offset + value.len()).div_ceil(8) * 8
        };
        let mut room = measured(&listed, list.value_offset);
        let mut new_used = bytes_in_use(&base) + room - list.attr_len;
        if new_used + 8 > base.len() {
            let largest = base_attributes
                .iter()
                .filter(|attribute| attribute.attr_type != ATTR_TYPE_ATTRIBUTE_LIST)
                .max_by_key(|attribute| attribute.attr_len)
                .ok_or(Error::NoSpace)?;
            let growing = largest.attr_type;
            self.make_room(parent_record, growing)?;
            base = self.read_mft_record(parent_record)?;
            base_header = MftRecordHeader::parse(&base).ok_or(Error::InvalidArgument)?;
            base_attributes = parse_attributes(&base[base_at..]);
            list = base_attributes
                .iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
                .ok_or(Error::InvalidArgument)?
                .clone();
            listed = self.list_entries(&list)?;
            room = measured(&listed, list.value_offset);
            new_used = bytes_in_use(&base) + room - list.attr_len;
            if new_used + 8 > base.len() {
                return Err(Error::NoSpace);
            }
        }

        // What the block and its two attributes are, and where: the clusters
        // first, then the block's own bytes, then the record that carries the
        // two attributes — each of the three refused with what it took given
        // straight back.
        let first = match self.claim_clusters(clusters) {
            Ok(first) => first,
            Err(error) => {
                return Err(error);
            }
        };
        let runs = alloc::vec![DataRun {
            lcn: first as i64,
            cluster_count: clusters,
        }];
        let block =
            match fs::index_allocation_block(index_block_size as usize, sector_size, 0, entries) {
                Ok(block) => block,
                Err(error) => {
                    self.free_clusters(&runs)?;
                    return Err(error);
                }
            };
        let allocation = fs::non_resident_attribute(
            ATTR_TYPE_INDEX_ALLOC,
            "$I30",
            instance,
            &runs,
            u64::from(index_block_size),
            u64::from(index_block_size),
            u64::from(index_block_size),
        );
        let mut bits = alloc::vec![0u8; 8];
        bits[0] = 1; // the one block is in use
        let bitmap =
            fs::resident_attribute(ATTR_TYPE_BITMAP, "$I30", instance.wrapping_add(1), &bits);
        let (home_of_the_two, _) = match self.claim_record(NewRecord::Extension {
            base: parent_record,
            attributes: alloc::vec![allocation, bitmap],
        }) {
            Ok(claimed) => claimed,
            Err(error) => {
                self.free_clusters(&runs)?;
                return Err(error);
            }
        };
        {
            let info = self.info.lock();
            fs::write_to_runs(&self.device, &info, &runs, 0, &block)?;
        }

        // The base's list, with the entries that name where the two
        // attributes went.  The root still holds the entries as a value, so a
        // mount here lists them where they were.
        let home_reference = {
            let record = self.read_mft_record(home_of_the_two)?;
            let sequence = u16::from_le_bytes([record[16], record[17]]);
            home_of_the_two | (u64::from(sequence) << 48)
        };
        let list_value = allocation_list_value(&listed, instance, home_reference);
        let at = base_at + list.offset;
        let mut new_list = base[at..at + list.attr_len].to_vec();
        new_list.resize(room, 0);
        new_list[4..8].copy_from_slice(&(room as u32).to_le_bytes());
        new_list[16..20].copy_from_slice(&(list_value.len() as u32).to_le_bytes());
        new_list[list.value_offset..list.value_offset + list_value.len()]
            .copy_from_slice(&list_value);

        let mut rebuilt_base = base[..base_at].to_vec();
        for attribute in &base_attributes {
            let at = base_at + attribute.offset;
            if attribute.offset == list.offset {
                rebuilt_base.extend_from_slice(&new_list);
            } else {
                rebuilt_base.extend_from_slice(&base[at..at + attribute.attr_len]);
            }
        }
        rebuilt_base.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = rebuilt_base.len();
        rebuilt_base.resize(base.len(), 0);
        rebuilt_base[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        rebuilt_base[40..42].copy_from_slice(&instance.wrapping_add(2).to_le_bytes());
        {
            let (at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, parent_record)?,
                    usize::from(info.bs.bytes_per_sector),
                )
            };
            fs::pack_usa(
                &mut rebuilt_base,
                base_header.usa_offset as usize,
                base_header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, at, &rebuilt_base)?;
            self.mft_cache.lock().insert(parent_record, rebuilt_base);
        }

        // The root, reduced to the node that points at the block: its own
        // header is the value's first sixteen bytes and stays, and the node's
        // only entry is the pointer, whose last eight bytes are where the
        // format puts the child's virtual cluster number.  This write is what
        // turns the index into a tree, so it is the last.
        let home = self.read_mft_record(holder)?;
        let home_header = MftRecordHeader::parse(&home).ok_or(Error::InvalidArgument)?;
        let home_at = home_header.size() as usize;
        let home_attributes = parse_attributes(&home[home_at..]);
        let root_here = home_attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::InvalidArgument)?;
        let attr_len = root_here.value_offset + 56;
        let mut new_root = home
            [home_at + root_here.offset..home_at + root_here.offset + root_here.attr_len]
            .to_vec();
        new_root.resize(attr_len, 0);
        new_root[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        new_root[16..20].copy_from_slice(&56u32.to_le_bytes());
        let value_at = root_here.value_offset;
        new_root[value_at + 16..value_at + 20].copy_from_slice(&16u32.to_le_bytes());
        new_root[value_at + 20..value_at + 24].copy_from_slice(&40u32.to_le_bytes());
        new_root[value_at + 24..value_at + 28].copy_from_slice(&40u32.to_le_bytes());
        new_root[value_at + 28..value_at + 32].copy_from_slice(&1u32.to_le_bytes());
        new_root[value_at + 32..value_at + 56].copy_from_slice(&fs::index_child_pointer(0));

        let mut rebuilt_home = home[..home_at].to_vec();
        for attribute in &home_attributes {
            let at = home_at + attribute.offset;
            if attribute.offset == root_here.offset {
                rebuilt_home.extend_from_slice(&new_root);
            } else {
                rebuilt_home.extend_from_slice(&home[at..at + attribute.attr_len]);
            }
        }
        rebuilt_home.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // The value only ever *shrinks* here, so the record it leaves has the
        // room by construction; the sizes follow the layout all the same.
        let used = rebuilt_home.len();
        rebuilt_home.resize(home.len(), 0);
        rebuilt_home[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        {
            let (at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, holder)?,
                    usize::from(info.bs.bytes_per_sector),
                )
            };
            fs::pack_usa(
                &mut rebuilt_home,
                home_header.usa_offset as usize,
                home_header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, at, &rebuilt_home)?;
            self.mft_cache.lock().insert(holder, rebuilt_home);
        }
        Ok(())
    }

    /// Refuse a record a name cannot be put in: one that is not a directory.
    fn check_directory(&self, record_number: u64) -> Result<()> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if !header.is_dir() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Whether `ancestor` is the record `start` is inside.
    ///
    /// The only link from a record to its parent is the parent's reference in
    /// its own `$FILE_NAME`, so this walks those up — which is what makes
    /// moving a directory into itself a refusal rather than a tree no walk can
    /// leave.
    fn is_inside(&self, ancestor: u64, start: u64) -> Result<bool> {
        let mut at = start;
        for _ in 0..MAX_ANCESTORS {
            if at == ancestor {
                return Ok(true);
            }
            if at == ROOT_RECORD {
                return Ok(false);
            }
            let attributes = self.attributes_of(at)?;
            let name = own_attribute(at, &attributes, ATTR_TYPE_FILENAME)?;
            if name.content.len() < 8 {
                return Err(Error::InvalidArgument);
            }
            let parent = u64::from_le_bytes([
                name.content[0],
                name.content[1],
                name.content[2],
                name.content[3],
                name.content[4],
                name.content[5],
                name.content[6],
                name.content[7],
            ]) & 0x0000_FFFF_FFFF_FFFF;
            if parent == at {
                // A record that names itself is a root, and a root has no
                // parent to walk to.
                return Ok(false);
            }
            at = parent;
        }
        Err(Error::InvalidArgument)
    }

    /// Replace a resident attribute's value in the record that holds it, and
    /// write the record whole.
    ///
    /// A value that has grown shifts everything after it up by the difference,
    /// which crosses sector ends — so the record goes back in one piece, with
    /// its update sequence array packed again.  A record with no room for the
    /// shift refuses (`NoSpace`), which is where the caller makes room; a value
    /// that lives in another record is patched there, and one that is split
    /// across records is not this writer's to patch at all.
    fn replace_value(&self, record_number: u64, attr_type: u32, value: &[u8]) -> Result<()> {
        let attributes = self.attributes_of(record_number)?;
        let attribute = attributes
            .iter()
            .find(|attribute| attribute.attr_type == attr_type)
            .ok_or(Error::NotFound)?;
        if attribute.holder == u64::MAX || attribute.data_runs_offset.is_some() {
            return Err(Error::NotImplemented);
        }
        let holder = attribute.holder;
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attr_at = header.size() as usize + attribute.offset;

        // The attribute as it should be: its own header, and the value where
        // that header points.
        let mut bytes = record[attr_at..attr_at + attribute.attr_len].to_vec();
        let attr_len = (attribute.value_offset + value.len()).next_multiple_of(8);
        bytes.resize(attr_len, 0);
        bytes[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        bytes[attribute.value_offset..attribute.value_offset + value.len()].copy_from_slice(value);

        self.replace_attribute(holder, attr_at, attribute.attr_len, &bytes)
    }

    /// Put bytes where one of a record's attributes is, and write the record
    /// whole.
    ///
    /// `at` is where the attribute begins in the record, and `old_len` what it
    /// occupies now.  The bytes may be longer or shorter than those, which
    /// shifts everything after them — so the record goes back in one piece, its
    /// update sequence array packed again; a record with no room for the shift
    /// refuses (`NoSpace`), which is where the caller makes room, and a record
    /// that cannot be addressed at all refuses too.
    fn replace_attribute(
        &self,
        holder: u64,
        at: usize,
        old_len: usize,
        replacement: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if at < header.size() as usize || at + old_len > bytes_in_use(&record) {
            return Err(Error::InvalidArgument);
        }

        let end = bytes_in_use(&record);
        let mut rebuilt = record[..at].to_vec();
        rebuilt.extend_from_slice(replacement);
        rebuilt.extend_from_slice(&record[at + old_len..end]);
        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());

        let (device_at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, holder)?,
                usize::from(info.bs.bytes_per_sector),
            )
        };
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, device_at, &rebuilt)?;
        self.mft_cache.lock().insert(holder, rebuilt);
        Ok(())
    }

    /// Take a name out of a directory's index.
    ///
    /// The entry that goes is the one that names this record *and* this name:
    /// a file can have more than one name, and a number alone would take the
    /// wrong one.
    ///
    /// A name the *node above* the blocks holds is a key a split promoted, and
    /// it comes out the way a key does — see [`Self::remove_index_key`].  A
    /// name a block holds comes out of the block, and the block it left may
    /// then be one the tree does not have to keep — see
    /// [`Self::merge_block_if_it_fits`].
    fn index_remove(&self, parent_record: u64, name: &str, reference: u64) -> Result<()> {
        let leaf = self.index_leaf(parent_record, name)?;
        if let Some(key) = leaf.key.clone() {
            return self.remove_index_key(parent_record, &key);
        }
        let raws = self.entries_without(&leaf.buffer, leaf.node, name, reference)?;
        let mut buffer = leaf.buffer.clone();
        self.write_index_leaf(parent_record, &mut buffer, leaf.node, &raws, &leaf.home)?;

        // The entries are in the index root itself when the directory has no
        // blocks: a record has nothing to be merged with, and a block has the
        // node above it, wherever that node lives.
        let IndexHome::Block { vcn, .. } = leaf.home else {
            return Ok(());
        };
        // The node above, read now: the write above touched the block and not
        // it, and reading it here is what keeps a change from starting at a
        // copy some other write has already gone past.
        let Some(parent_home) = leaf.ancestors.last().map(|parent| parent.home.clone()) else {
            return Ok(());
        };
        let attributes = self.attributes_of(parent_record)?;
        let parent = self.index_node_above(&attributes, &parent_home, vcn)?;
        self.merge_block_if_it_fits(parent_record, parent, vcn)
    }

    /// One node's entries with one name taken out of them, and the node's
    /// terminator still last.
    fn entries_without(
        &self,
        buffer: &[u8],
        node: usize,
        name: &str,
        reference: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let upcase = self.upcase_table();
        let parsed = parse_index_node(buffer, node);
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
        Ok(raws)
    }

    /// Take out a name that lives in the node **above** the blocks, which is a
    /// key a split promoted.
    ///
    /// A key's entry carries the child whose keys are *less* than it, so the
    /// entry cannot simply go: that child would be left unreachable.  What
    /// takes its place is the key's **predecessor**, the largest name the child
    /// holds — which keeps the child where it is, keeps every other name where
    /// it was, and leaves the name that is going nowhere at all.  The
    /// predecessor is then taken out of the block it came from, which is the
    /// removal a block's name takes, and that block may then be one the tree
    /// does not have to keep.
    ///
    /// The node above goes first.  Written with the predecessor's key in it,
    /// the removed name is gone and the predecessor appears **twice** — in the
    /// node and still in the block — which a walk reads as one name, because
    /// both copies name the same record.  Taking it out of the block is the
    /// write that follows, and the other order would leave the name in neither.
    ///
    /// A key whose child holds **nothing** is the case where the entry can go
    /// as it is: the child has no names that would be left behind, and the
    /// block it is in is given back.
    fn remove_index_key(&self, parent_record: u64, key: &IndexKey) -> Result<()> {
        let attributes = self.attributes_of(parent_record)?;
        let parsed = parse_index_node(&key.buffer, key.node);
        let position = parsed
            .entries
            .iter()
            .position(|entry| entry.offset == key.offset && entry.length == key.length)
            .ok_or(Error::NotFound)?;
        let child = parsed.entries[position]
            .child
            .ok_or(Error::InvalidArgument)?;

        let (block, home) = self.read_index_block_home(&attributes, child)?;
        let picked = parse_index_node(&block, 24)
            .entries
            .into_iter()
            .rev()
            .find(|entry| entry.name.is_some());
        let predecessor = picked
            .as_ref()
            .map(|entry| block[entry.offset..entry.offset + entry.length].to_vec());

        let mut parent_entries: Vec<Vec<u8>> = Vec::new();
        for (index, entry) in parsed.entries.iter().enumerate() {
            if index == position {
                if let Some(predecessor) = &predecessor {
                    parent_entries.push(fs::index_separator(predecessor, child)?);
                }
                continue;
            }
            parent_entries.push(key.buffer[entry.offset..entry.offset + entry.length].to_vec());
        }

        // A predecessor whose name is longer than the one that goes makes the
        // node above longer, and a record with no room makes room first — which
        // moves the node, so the write is worked out again from where it is now.
        // A *block* has what is left of itself, and a name that does not fit one
        // is refused rather than moved anywhere.
        let mut written = false;
        for attempt in 0..2 {
            let (mut buffer, node) = match &key.home {
                IndexHome::Record { holder } => self.index_root_node(*holder)?,
                IndexHome::Block { .. } => (key.buffer.clone(), key.node),
            };
            match self.write_index_leaf(
                parent_record,
                &mut buffer,
                node,
                &parent_entries,
                &key.home,
            ) {
                Ok(()) => {
                    written = true;
                    break;
                }
                Err(Error::NoSpace) if attempt == 0 => match &key.home {
                    IndexHome::Record { holder } => {
                        self.make_room(*holder, ATTR_TYPE_INDEX_ROOT)?;
                    }
                    IndexHome::Block { .. } => return Err(Error::NoSpace),
                },
                Err(error) => return Err(error),
            }
        }
        if !written {
            return Err(Error::NoSpace);
        }

        let Some(predecessor) = picked else {
            // The child held nothing, so the block the key pointed at holds
            // nothing either: nothing points at it now, and its bit goes.
            let bit = child / self.clusters_per_index_block().max(1);
            return self.set_index_block_bit(parent_record, bit, false);
        };
        let predecessor_name = predecessor.name.expect("a name that was looked for");
        let raws =
            self.entries_without(&block, 24, &predecessor_name.name, predecessor.reference)?;
        let mut buffer = block;
        self.write_index_leaf(parent_record, &mut buffer, 24, &raws, &home)?;
        // The node the key was in, **read again**: the swing above wrote it,
        // and a merge that started from the copy the walk made would put the
        // key it replaced back — the same staleness a split's node above has
        // when the allocation it names grows.
        let parent = self.index_node_above(&attributes, &key.home, child)?;
        self.merge_block_if_it_fits(parent_record, parent, child)
    }

    /// The node a block hangs from, read **now**, with the entry the block is
    /// the child of: a record's index root from its record, and a block from
    /// the bytes its runs name.
    fn index_node_above(
        &self,
        attributes: &[ParsedAttr],
        home: &IndexHome,
        child: u64,
    ) -> Result<IndexParent> {
        let (buffer, node, home) = match home {
            IndexHome::Record { holder } => {
                let (buffer, node) = self.index_root_node(*holder)?;
                (buffer, node, home.clone())
            }
            IndexHome::Block { vcn, .. } => {
                let (buffer, home) = self.read_index_block_home(attributes, *vcn)?;
                (buffer, 24, home)
            }
        };
        let before = parse_index_node(&buffer, node)
            .entries
            .iter()
            .find(|entry| entry.child == Some(child))
            .map_or(0, |entry| entry.offset);
        Ok(IndexParent {
            buffer,
            node,
            before,
            home,
        })
    }

    /// Merge a block with the one next to it, when what the two hold still fits
    /// one block again.
    ///
    /// A block that has lost names is a block the tree does not have to keep,
    /// and the key that separated the pair is what goes with it: it moves
    /// **down** into the merged node, where it belongs between the two halves —
    /// every name the two hold is on one side of it or the other — and the
    /// entry that carried it is dropped.  What stays is the block whose key
    /// order came first, so the entry *after* the one that goes is the entry
    /// that points at it afterwards, with its own key unchanged.
    ///
    /// A pair that does not fit one block is not merged, and that is an answer
    /// rather than a refusal (`Ok(())`): the block keeps its names and the tree
    /// keeps its shape, which is what a removal that left a block *nearly* full
    /// should do.
    ///
    /// The writes are ordered by what a crash leaves.  The merged block first:
    /// its names are then reachable twice, and a walk counts them once because
    /// both copies name the same record.  The node above next, after which the
    /// block that lost its names is not reachable at all.  Its bit in the index
    /// bitmap last, which is what gives the block back — the clusters stay part
    /// of the allocation, a free block inside it, because taking the tail of an
    /// allocation back is a step of its own.
    fn merge_block_if_it_fits(
        &self,
        parent_record: u64,
        parent: IndexParent,
        vcn: u64,
    ) -> Result<()> {
        // The node the block hangs from, from the walk that found it: the index
        // root for a directory of one level, and a *block* for a tree deeper
        // than that.  Nothing here reads the directory's own record to find it,
        // which is what makes both shapes the same job.
        let attributes = self.attributes_of(parent_record)?;
        let parsed = parse_index_node(&parent.buffer, parent.node);
        let Some(position) = parsed
            .entries
            .iter()
            .position(|entry| entry.child == Some(vcn))
        else {
            // The node above does not point at the block: nothing to merge.
            return Ok(());
        };
        // The pair, and which of the two keeps its block: the entry whose child
        // is the block that came first, and the entry after it.  A block that
        // is the *last* child has no entry after it, and the pair is the one
        // before it.
        let (left_at, right_at) = if position + 1 < parsed.entries.len() {
            (position, position + 1)
        } else if position > 0 {
            (position - 1, position)
        } else {
            // A node with one child and no keys has no pair to merge, and a
            // tree of one block is a tree.
            return Ok(());
        };
        let left = parsed.entries[left_at]
            .child
            .ok_or(Error::InvalidArgument)?;
        let right = parsed.entries[right_at]
            .child
            .ok_or(Error::InvalidArgument)?;
        let at = parsed.entries[left_at].offset;
        let separator = parent.buffer[at..at + parsed.entries[left_at].length].to_vec();
        let separator = fs::index_leaf_entry(&separator)?;

        let (left_block, left_home) = self.read_index_block_home(&attributes, left)?;
        let (right_block, _) = self.read_index_block_home(&attributes, right)?;

        // What the merged block holds, in the order the tree keeps them: the
        // left block's names, the key that separated the pair, the right
        // block's names, and the terminator the left block already ended with.
        let mut merged: Vec<Vec<u8>> = Vec::new();
        let mut terminator = None;
        for entry in parse_index_node(&left_block, 24).entries {
            let bytes = left_block[entry.offset..entry.offset + entry.length].to_vec();
            if entry.name.is_some() {
                merged.push(bytes);
            } else {
                terminator = Some(bytes);
            }
        }
        merged.push(separator);
        for entry in parse_index_node(&right_block, 24).entries {
            if entry.name.is_some() {
                merged.push(right_block[entry.offset..entry.offset + entry.length].to_vec());
            }
        }
        merged.push(terminator.ok_or(Error::InvalidArgument)?);

        let mut buffer = left_block;
        match self.write_index_leaf(parent_record, &mut buffer, 24, &merged, &left_home) {
            Ok(()) => {}
            // The two still do not fit one block: the tree keeps its shape.
            Err(Error::NoSpace) => return Ok(()),
            Err(error) => return Err(error),
        }

        let mut parent_entries: Vec<Vec<u8>> = Vec::new();
        for (index, entry) in parsed.entries.iter().enumerate() {
            if index == left_at {
                continue;
            }
            let mut bytes = parent.buffer[entry.offset..entry.offset + entry.length].to_vec();
            if index == right_at {
                // The entry that pointed at the block that went points at the
                // one that stayed.  A child's number ends the entry, keyed or
                // not, which is where a reader looks for it.
                let at = bytes.len() - 8;
                bytes[at..].copy_from_slice(&left.to_le_bytes());
            }
            parent_entries.push(bytes);
        }
        // Written from a fresh read when it is a record's index root — a
        // growth of this change's may have moved it — and where it is when the
        // node is a block.
        let (mut parent_buffer, parent_node) = match &parent.home {
            IndexHome::Record { holder } => self.index_root_node(*holder)?,
            IndexHome::Block { .. } => (parent.buffer.clone(), parent.node),
        };
        self.write_index_leaf(
            parent_record,
            &mut parent_buffer,
            parent_node,
            &parent_entries,
            &parent.home,
        )?;

        let bit = right / self.clusters_per_index_block().max(1);
        self.set_index_block_bit(parent_record, bit, false)
    }

    /// Put a new file's record into the MFT's first free slot, and answer its
    /// number and its sequence.
    ///
    /// A record that is formatted but not in use is free: its own header says
    /// so, and a record a volume has never written is all zeros and free too.
    /// Where `$MFT` carries its own `$BITMAP`, the bit is the volume's word on
    /// it and is read first; the header is then a second one.
    ///
    /// A volume whose records are all spoken for **grows the MFT** by a
    /// cluster and looks again, once: a growth that cannot be made is the
    /// volume being full.
    fn claim_mft_record(&self, parent: u64, name: &str, directory: bool) -> Result<(u64, u16)> {
        self.claim_record(NewRecord::Named {
            parent,
            name,
            directory,
        })
    }

    /// Put a record into the MFT's first free slot, and answer its number and
    /// its sequence.
    ///
    /// What the record *is* is the caller's: a file's own record carries its
    /// name and the attributes a new file has, and an extension record carries
    /// attributes another record's list names and a reference back to it.
    fn claim_record(&self, what: NewRecord<'_>) -> Result<(u64, u16)> {
        let base_reference = {
            let base = match &what {
                NewRecord::Named { parent, .. } => *parent,
                NewRecord::Extension { base, .. } => *base,
            };
            let base_record = self.read_mft_record(base)?;
            let sequence = u16::from_le_bytes([base_record[16], base_record[17]]);
            base | (u64::from(sequence) << 48)
        };

        // One growth is enough for one record: the MFT grows by at least a
        // cluster's worth of records, and a volume that grew and still has no
        // free record is a volume with no room.
        let mut grown = false;
        loop {
            let (record_size, sector_size, records, runs, cluster_size, index_block_size) = {
                let mut info = self.info.lock();
                let runs = info.resolve_mft_runs(&self.device)?;
                let record_size = u64::from(info.mft_record_size);
                (
                    record_size,
                    info.bs.bytes_per_sector as usize,
                    info.mft_data_size / record_size,
                    runs,
                    info.cluster_size,
                    info.index_block_size,
                )
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

                // A record that was used before keeps its number unusable
                // through its sequence, which only ever goes up; a record a
                // volume has never written is all zeros, and its sequence
                // starts at one.
                let sequence = match MftRecordHeader::parse(&raw) {
                    Some(header) if header.flags & MFT_RECORD_IN_USE == 0 => {
                        u16::from_le_bytes([raw[16], raw[17]]).wrapping_add(1)
                    }
                    Some(_) => continue,
                    None if raw.iter().all(|byte| *byte == 0) => 1,
                    None => continue,
                };

                // The volume's word on it goes first: a record the volume says
                // is in use and nothing names is a leak, and the other order
                // would leave a record in use that the volume would hand out
                // again.
                self.set_mft_bitmap(number, true)?;
                let (flags, link_count, attributes, extension) = match &what {
                    NewRecord::Named {
                        name, directory, ..
                    } => (
                        if *directory { 0x03 } else { 0x01 },
                        1,
                        record_attributes(
                            base_reference,
                            name,
                            *directory,
                            index_block_size,
                            cluster_size,
                        ),
                        false,
                    ),
                    NewRecord::Extension { attributes, .. } => (0x01, 0, attributes.clone(), true),
                };
                let mut record = fs::build_record(
                    record_size as usize,
                    sector_size,
                    number,
                    sequence,
                    flags,
                    link_count,
                    &attributes,
                );
                if extension {
                    // The record names the record it belongs to: the base
                    // reference is the field that says so, and a record that
                    // has one has no name of its own for a directory to list.
                    record[32..40].copy_from_slice(&base_reference.to_le_bytes());
                }
                fs::write_device_bytes(&self.device, at, &record)?;
                // Whatever the mount had of this number is not what is there
                // now.
                self.mft_cache.lock().remove(&number);
                return Ok((number, sequence));
            }

            if grown {
                return Err(Error::NoSpace);
            }
            self.grow_mft()?;
            grown = true;
        }
    }

    /// Grow the MFT by at least one more record.
    ///
    /// The MFT is a file whose content is its records, so growing it is
    /// growing a file: clusters come from the volume's `$Bitmap`, the run list
    /// in `$MFT`'s own record gains a run — or the last one gets longer, when
    /// the clusters continue it — and the sizes that say how much of it is
    /// spoken for follow.  A record a volume has never written is all zeros,
    /// so the new clusters are **written as zeros**: that is what makes the
    /// records they hold free rather than whatever they held before.
    ///
    /// Its own `$BITMAP` grows with it, because a record past the bitmap's
    /// last byte is a record nothing could say was in use.
    ///
    /// The step is a whole cluster's worth of records, so one growth answers
    /// the one record that asked for it.  A volume with no free *cluster*
    /// refuses (`NoSpace`), and so does a `$MFT` whose `$DATA` run list has no
    /// room for another run: that attribute would have to move inside the
    /// record, which is the relocation the attribute list is for.
    fn grow_mft(&self) -> Result<()> {
        let (record_size, sector_size, cluster_size) = {
            let info = self.info.lock();
            (
                u64::from(info.mft_record_size),
                info.bs.bytes_per_sector as usize,
                u64::from(info.cluster_size),
            )
        };
        let record = self.read_mft_record(MFT_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let attributes = self.attributes_of(MFT_RECORD)?;
        // Growing the MFT rewrites the record that holds its runs, so an
        // attribute an `$ATTRIBUTE_LIST` moved is out of this one's reach.
        let data = own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_DATA)?;
        // A resident `$MFT` is a volume whose records are inside its own
        // record, and growing that is a conversion this driver does not make.
        let data_runs_offset = data.data_runs_offset.ok_or(Error::NotImplemented)?;
        let bitmap = match own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_BITMAP) {
            Ok(bitmap) => Some(bitmap.clone()),
            Err(Error::NotFound) => None,
            Err(error) => return Err(error),
        };

        // How much longer the MFT has to be, and where the new records are.
        let step = cluster_size.max(record_size).div_ceil(record_size) * record_size;
        let old_data = u64::from(data.data_size);
        let new_data = old_data + step;
        let records = new_data / record_size;
        let mut runs = data.data_runs.clone();
        let held: u64 = runs.iter().map(|run| run.cluster_count).sum::<u64>() * cluster_size;
        let claim = if held >= new_data {
            0
        } else {
            (new_data - held).div_ceil(cluster_size)
        };

        // The bitmap has to be able to name the new records, and its own bytes
        // to reach them, before anything is taken from the volume.
        let bitmap_growth = match &bitmap {
            Some(bitmap) => {
                let wanted = records.div_ceil(8);
                if wanted <= u64::from(bitmap.data_size) {
                    None
                } else {
                    let runs = bitmap.data_runs_offset.is_some();
                    let capacity = bitmap
                        .data_runs
                        .iter()
                        .map(|run| run.cluster_count)
                        .sum::<u64>()
                        * cluster_size;
                    if !runs || wanted > capacity {
                        return Err(Error::NoSpace);
                    }
                    Some(wanted)
                }
            }
            None => None,
        };

        let claimed = if claim > 0 {
            let first = self.claim_clusters(claim)?;
            let continues = runs
                .last()
                .is_some_and(|last| last.lcn >= 0 && last.lcn as u64 + last.cluster_count == first);
            if continues {
                runs.last_mut()
                    .expect("a last run that was just looked at")
                    .cluster_count += claim;
            } else {
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: claim,
                });
            }
            Some((first, claim))
        } else {
            None
        };

        // A run list that no longer fits where it is would have to move, and
        // that is not this driver's to do inside the MFT's own record: the
        // clusters just taken go back rather than being half-used.
        let encoded = fs::encode_runs(&runs);
        let room = data.attr_len - (data_runs_offset - data.offset);
        if encoded.len() > room {
            if let Some((first, count)) = claimed {
                let _ = self.free_clusters(&[DataRun {
                    lcn: first as i64,
                    cluster_count: count,
                }]);
            }
            return Err(Error::NoSpace);
        }

        // A record a volume has never written is all zeros.
        if let Some((first, count)) = claimed {
            let zeros = alloc::vec![0u8; cluster_size as usize];
            for cluster in first..first + count {
                fs::write_device_bytes(&self.device, cluster * cluster_size, &zeros)?;
            }
        }
        if let Some(wanted) = bitmap_growth {
            let bitmap = bitmap.as_ref().expect("a bitmap that was just looked at");
            let zeros = alloc::vec![0u8; (wanted - u64::from(bitmap.data_size)) as usize];
            let info = self.info.lock();
            fs::write_to_runs(
                &self.device,
                &info,
                &bitmap.data_runs,
                u64::from(bitmap.data_size),
                &zeros,
            )?;
        }

        // The record that holds the run list, written whole with the sizes the
        // runs now add up to.
        let mut raw = record.clone();
        let attr = base + data.offset;
        let runs_at = attr + (data_runs_offset - data.offset);
        raw[runs_at..runs_at + encoded.len()].copy_from_slice(&encoded);
        raw[runs_at + encoded.len()..attr + data.attr_len].fill(0);
        let allocated = held + claim * cluster_size;
        let last_vcn = allocated / cluster_size - 1;
        raw[attr + 24..attr + 32].copy_from_slice(&last_vcn.to_le_bytes());
        raw[attr + 40..attr + 48].copy_from_slice(&allocated.to_le_bytes());
        raw[attr + 48..attr + 56].copy_from_slice(&new_data.to_le_bytes());
        raw[attr + 56..attr + 64].copy_from_slice(&new_data.to_le_bytes());
        if let Some(wanted) = bitmap_growth {
            let bitmap = bitmap.as_ref().expect("a bitmap that was just looked at");
            // The bitmap is a *file* too, so its sizes are a non-resident
            // attribute's: what it uses at +48, what it has at +40.  A
            // resident value's length is the field at +16, and writing there
            // would have rewritten the attribute's first VCN.
            let attr = base + bitmap.offset;
            let allocated = bitmap
                .data_runs
                .iter()
                .map(|run| run.cluster_count)
                .sum::<u64>()
                * cluster_size;
            raw[attr + 40..attr + 48].copy_from_slice(&allocated.to_le_bytes());
            raw[attr + 48..attr + 56].copy_from_slice(&wanted.to_le_bytes());
            raw[attr + 56..attr + 64].copy_from_slice(&wanted.to_le_bytes());
        }
        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, MFT_RECORD)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        let _ = sector_size;
        fs::pack_usa(
            &mut raw,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, at, &raw)?;
        self.mft_cache.lock().insert(MFT_RECORD, raw);

        // The mount's own idea of the MFT is what it just changed.
        let mut info = self.info.lock();
        info.mft_runs = Some(runs);
        info.mft_data_size = new_data;
        Ok(())
    }

    /// `$MFT`'s own `$BITMAP`, as many bytes of it as the volume's records
    /// need.
    ///
    /// The MFT is a file whose content is its records, and its `$BITMAP` is
    /// the volume's own list of which of them are in use — the thing a real
    /// NTFS allocates from.  A volume that does not carry one answers with
    /// none, and the record headers are then the only word on what is free.
    fn mft_bitmap(&self) -> Result<Option<Vec<u8>>> {
        let attributes = self.attributes_of(MFT_RECORD)?;
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
        let attributes = self.attributes_of(MFT_RECORD)?;
        let Some(bitmap) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(());
        };
        let index = (number / 8) as usize;
        let mask = 1u8 << (number % 8);

        if bitmap.data_runs_offset.is_none() {
            // A bitmap the record holds itself: the field change and the
            // record it lives in go together.
            let bitmap = own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_BITMAP)?;
            let record = self.read_mft_record(MFT_RECORD)?;
            if index >= bitmap.content.len() {
                return Err(Error::InvalidArgument);
            }
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
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
        let attributes = self.attributes_of(VOLUME_RECORD)?;
        // The flags are a field in this record: keeping them in step is a
        // rewrite of the record, so an attribute that has moved out of it is
        // not one this driver can keep in step.
        let information = own_attribute(VOLUME_RECORD, &attributes, ATTR_TYPE_VOLUME_INFORMATION)?;
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
        // The size and the first cluster are the *merged* attributes': a
        // `$DATA` an `$ATTRIBUTE_LIST` split or moved answers with the whole
        // file, not with the part this record happens to hold.
        let attributes = self.attributes_of(record_number)?;
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
            self.data_size(child) as usize
        };
        Ok(DirectoryEntry::new(kind, size, name))
    }

    /// Give a file or a directory another name, in the directory it is in or
    /// another one.
    ///
    /// A name lives in two places and both move: the parent's **index** gains
    /// the new name and loses the old, and the record's own **`$FILE_NAME`**
    /// takes the name and the parent it now has.  The new name goes in first
    /// and the old one leaves last, so a crash between the two leaves two names
    /// for one record — which a walk reads — rather than a file nothing names.
    /// The one order that cannot hold to that is a change of *spelling*: two
    /// names that fold together are one key, so the old one has to go before
    /// the new one arrives.
    ///
    /// The record itself does not move and its number does not change, which is
    /// what lets a directory be renamed with nothing inside it touched.
    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        if _old_path == _new_path {
            return Ok(());
        }
        let (old_parent_path, old_name) = split_parent(_old_path);
        let (new_parent_path, new_name) = split_parent(_new_path);
        if old_name.is_empty() || new_name.is_empty() || new_name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }

        let (record_number, _) = self.resolve(_old_path)?;
        if record_number == ROOT_RECORD {
            return Err(Error::InvalidArgument);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let directory = header.is_dir();

        // The name it is going to have, or the same record under a different
        // spelling, or a name already taken.
        let spelling = match self.resolve(_new_path) {
            Ok((existing, _)) if existing == record_number => true,
            Ok(_) => return Err(Error::AlreadyExists),
            Err(Error::NotFound) => false,
            Err(error) => return Err(error),
        };

        let (new_parent, _) = self.resolve(new_parent_path)?;
        self.check_directory(new_parent)?;
        if directory && self.is_inside(record_number, new_parent)? {
            // Moving a directory into itself would make a tree no walk can
            // leave.
            return Err(Error::InvalidArgument);
        }

        // The flag goes up before the change, and before the reads below:
        // setting it reads a record.
        self.set_dirty(true)?;

        let (old_parent, _) = self.resolve(old_parent_path)?;
        let sequence = u16::from_le_bytes([record[16], record[17]]);
        let reference = record_number | (u64::from(sequence) << 48);
        let size = if directory {
            0
        } else {
            self.data_size(record_number)
        };
        let new_parent_sequence = {
            let parent = self.read_mft_record(new_parent)?;
            u16::from_le_bytes([parent[16], parent[17]])
        };
        let name = fs::file_name_value(
            new_parent | (u64::from(new_parent_sequence) << 48),
            new_name,
            directory,
            size,
        );

        if spelling {
            // The spelling's own order, for the reason the doc above gives: two
            // names that fold together are one key, so the old one goes first.
            self.index_remove(old_parent, old_name, record_number)?;
        }
        self.index_insert(new_parent, new_name, reference, directory, size)?;
        // The record's own name follows the name that is now its, and the old
        // index entry — the one copy that now disagrees — goes last.  A name
        // that does not fit the record makes room the way any growth does, the
        // largest attribute that is not the name moving into a record of its
        // own.
        let mut attempt = 0;
        loop {
            match self.replace_value(record_number, ATTR_TYPE_FILENAME, &name) {
                Ok(()) => break,
                Err(Error::NoSpace) if attempt == 0 => {
                    let holder = self
                        .attributes_of(record_number)?
                        .iter()
                        .find(|attribute| attribute.attr_type == ATTR_TYPE_FILENAME)
                        .map(|attribute| attribute.holder)
                        .unwrap_or(record_number);
                    self.make_room(holder, ATTR_TYPE_FILENAME)?;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
        if !spelling {
            self.index_remove(old_parent, old_name, record_number)?;
        }
        Ok(())
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

    /// Make a directory: a record of its own, and its name in the parent's
    /// index.
    ///
    /// The record a directory gets differs from a file's in one attribute: an
    /// empty `$INDEX_ROOT` in the place of `$DATA`, which is what its children
    /// are later added to.  The order is a creation's — the record down
    /// first — and for the same reason.
    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_path, name) = split_parent(path);
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // Raised before the work below: setting the flag reads a record.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        let (number, sequence) = self.claim_mft_record(parent_record, name, true)?;
        let reference = number | (u64::from(sequence) << 48);
        if let Err(error) = self.index_insert(parent_record, name, reference, true, 0) {
            let _ = self.release_mft_record(number);
            return Err(error);
        }
        Ok(())
    }

    /// Take an entry out: its name from the parent's index, its clusters back
    /// to the volume, and its record back to the MFT's free space.
    ///
    /// The name goes first, which is the reverse of a creation and for the
    /// same reason: a name that a walk finds and a record that is already free
    /// is the worse half of the two, and what is left after a crash is a
    /// cluster claimed by a record nothing names.
    ///
    /// A directory that still holds something cannot go: its children's names
    /// are in *its* index, and a walk that reaches it would find entries whose
    /// parent the volume no longer has.  An empty one goes the same way a file
    /// does.
    fn remove_path(&self, path: &str) -> Result<()> {
        let (parent_path, _) = split_parent(path);
        let (record_number, name) = self.resolve(path)?;
        if record_number == ROOT_RECORD {
            return Err(Error::InvalidArgument);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.is_dir() && !self.directory_entries(record_number)?.is_empty() {
            return Err(Error::Busy);
        }

        // Raised before the work below, for the same reason a creation raises
        // it there: setting the flag reads a record.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        self.index_remove(parent_record, &name, record_number)?;

        // The clusters go back before the record stops naming them, so a crash
        // between the two leaves them claimed and unused rather than free and
        // spoken for.  Every non-resident attribute's runs go back, not only
        // `$DATA`'s: a directory keeps its entries — and the bitmap of the
        // blocks they are in — in files of their own.  The merged view is what
        // is walked, so a part an `$ATTRIBUTE_LIST` put in an extension record
        // gives its clusters back too.
        let attributes = self.attributes_of(record_number)?;
        for attribute in attributes
            .iter()
            .filter(|attribute| attribute.data_runs_offset.is_some())
        {
            self.free_clusters(&attribute.data_runs)?;
        }

        // And the extension records themselves: a record that holds a moved
        // attribute is a record the volume has spoken for, and the removal is
        // what gives it back.
        self.release_mft_record(record_number)?;
        for holder in self.extension_records(record_number, &record)? {
            self.release_mft_record(holder)?;
        }
        Ok(())
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
        // The attributes a record holds *wherever they live*: a `$DATA` an
        // `$ATTRIBUTE_LIST` split across records is one attribute again here,
        // which is what makes the file read whole rather than to its first
        // part.
        let attributes = self.fs.attributes_of(*self.mft_record_number.lock())?;
        let info = self.fs.info.lock();

        // Find the data attribute
        let data_attr = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        refuse_a_stream_this_driver_cannot_read(data_attr)?;

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

        // The attributes a record holds *wherever they live*, and before the
        // locks below: reading a record takes the same lock `info` is.
        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        refuse_a_stream_this_driver_cannot_read(data)?;

        if data.data_runs_offset.is_none() {
            // A resident file's bytes are in the record itself, so the field
            // write is the data write — and the volume is where the record is.
            let data = own_attribute(number, &attributes, ATTR_TYPE_DATA)?;
            let info = self.fs.info.lock();
            let mut record = self.fs.read_mft_record(number)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let length = self.size().min(data.content.len());
            let start = (offset as usize).min(length);
            let take = (length - start).min(buffer.len());
            if take == 0 {
                return Ok(0);
            }
            let record_at = self.fs.record_offset(&info, number)?;
            let field = record_at
                + (header.size() as u64 + data.offset as u64 + data.value_offset as u64)
                + start as u64;
            fs::write_device_bytes(&self.fs.device, field, &buffer[..take])?;
            // The bytes are the file's now, in the mount's copy of the record
            // as well: a read asks for the record by number, and a copy left
            // behind would answer with the bytes it had.
            let at = header.size() as usize + data.offset + data.value_offset + start;
            record[at..at + take].copy_from_slice(&buffer[..take]);
            self.fs.mft_cache.lock().insert(number, record);
            return Ok(take);
        }

        let info = self.fs.info.lock();
        let written = fs::write_to_runs(&self.fs.device, &info, &data.data_runs, offset, buffer)?;
        Ok(written)
    }

    /// Change how long a file is, claiming clusters for a growth and moving
    /// the attribute into a record of its own when the one it is in has no room
    /// left.
    fn set_len(&self, len: u64) -> Result<()> {
        if self.kind() != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let length = u32::try_from(len).map_err(|_| Error::InvalidArgument)?;
        let current = *self.file_size.lock() as u32;
        if length == current {
            return Ok(());
        }

        // Raised before the work below, for the same reason the write raises it
        // there: setting the flag reads a record.
        self.fs.set_dirty(true)?;

        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?
            .clone();
        refuse_a_stream_this_driver_cannot_read(&data)?;

        // A growth's clusters are taken **before** the record is touched:
        // claiming reads and writes the volume's bitmap, which are record
        // reads.
        let needs = {
            if data.data_runs_offset.is_none() {
                None
            } else {
                let info = self.fs.info.lock();
                let held: u64 = data
                    .data_runs
                    .iter()
                    .map(|run| run.cluster_count)
                    .sum::<u64>()
                    * u64::from(info.cluster_size);
                (u64::from(length) > held)
                    .then(|| (u64::from(length) - held).div_ceil(u64::from(info.cluster_size)))
            }
        };
        let claim = match needs {
            Some(needed) => Some((needed, self.fs.claim_clusters(needed)?)),
            None => None,
        };

        let growth = self.grow_data(&data, claim, length, current);
        // A record with no room for the longer run list is what the format
        // gives an attribute list for: the attribute goes into a record of its
        // own, which has the room the old one did not, and the run list follows
        // it there.
        let growth = match growth {
            Err(Error::NoSpace) if data.holder == number => {
                self.fs.make_room(number, ATTR_TYPE_DATA)?;
                let attributes = self.fs.attributes_of(number)?;
                let data = attributes
                    .iter()
                    .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
                    .ok_or(Error::NotFound)?
                    .clone();
                self.grow_data(&data, claim, length, current)
            }
            other => other,
        };
        growth?;

        *self.file_size.lock() = u64::from(length);
        Ok(())
    }
}

impl NtfsVnode {
    /// Take a grown `$DATA` to the record that holds it.
    ///
    /// The runs are the file's own runs with the claimed one appended, the
    /// allocated size is what they add up to, and the clusters the growth took
    /// are written as zeros — they have never held the file's bytes.
    fn grow_data(
        &self,
        data: &ParsedAttr,
        claim: Option<(u64, u64)>,
        length: u32,
        current: u32,
    ) -> Result<()> {
        // An attribute split across records has no one record its fields are
        // in, so it is not one of these writes can patch.
        if data.holder == u64::MAX {
            return Err(Error::NotImplemented);
        }
        let holder = data.holder;
        let cluster_size = {
            let info = self.fs.info.lock();
            u64::from(info.cluster_size)
        };

        if data.data_runs_offset.is_none() {
            // A resident value *shrinks* where it lies, and grows into the
            // record's own room — and a growth the record has no room for is
            // what the conversion is for: the value leaves the record for runs
            // of its own, which is where a file that has outgrown its record
            // lives.
            if length <= current {
                return self
                    .fs
                    .write_grown_data(holder, data, &[], current, length, &[]);
            }
            let mut value = data.content.clone();
            value.resize(length as usize, 0);
            match self.fs.replace_value(holder, ATTR_TYPE_DATA, &value) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) => {}
                Err(error) => return Err(error),
            }
            return self.convert_to_runs(holder, data, length, current, cluster_size);
        }

        let mut runs = data.data_runs.clone();
        // A value that has come back **into the record** keeps nothing in
        // clusters: the attribute becomes one whose bytes are in the record
        // again — the run list it no longer needs is room the value takes —
        // and the clusters it held go back to the volume.  This is the order
        // the two writes go in: the other one leaves an attribute naming
        // clusters the volume has handed out again, and this one leaves
        // clusters nothing names if it stops in between, which is a leak and
        // the harmless direction.  A value the record cannot hold stays where
        // it is (`NoSpace`), and a sparse stream keeps its runs.
        if length < current && data.flags & ATTR_FLAG_SPARSE == 0 {
            match self.convert_to_resident(data, length) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) | Err(Error::NotImplemented) => {}
                Err(error) => return Err(error),
            }
        }
        let allocated = {
            let clusters: u64 = data.data_runs.iter().map(|run| run.cluster_count).sum();
            let mut allocated = clusters * cluster_size;
            if let Some((needed, first)) = claim {
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: needed,
                });
                allocated += needed * cluster_size;
            }
            allocated as u32
        };
        let zeros = if allocated > current {
            alloc::vec![0u8; (u64::from(allocated) - u64::from(current)) as usize]
        } else {
            Vec::new()
        };
        self.fs
            .write_grown_data(holder, data, &runs, allocated, length, &zeros)
    }

    /// Take a value that has come back into its record: the bytes the runs
    /// held are written where the record keeps its values, and the clusters
    /// they were in go back to the volume.
    ///
    /// The record goes first and the clusters second, because the two orders
    /// leave different things behind: writing the record drops the run list (so
    /// the clusters are named by nothing), and freeing them first would leave
    /// an attribute naming clusters the volume has handed out again — a
    /// leak in the first case, and a volume that reads another file's bytes
    /// in the second.
    ///
    /// A record with no room for the value refuses (`NoSpace`) and the caller
    /// leaves the value where it is; an attribute an `$ATTRIBUTE_LIST` split
    /// across records is no one record's to rewrite (`NotImplemented`).
    fn convert_to_resident(&self, data: &ParsedAttr, length: u32) -> Result<()> {
        let holder = data.holder;
        if holder == u64::MAX {
            return Err(Error::NotImplemented);
        }

        // What lies past the **initialized** size was never written, and the
        // format says it reads as zeros: a record that holds the value has no
        // way to say that, so those bytes are made explicit here rather than
        // left as whatever the clusters happened to hold.
        let written = length.min(data.initialized_size);
        let mut value = alloc::vec![0u8; length as usize];
        {
            let info = self.fs.info.lock();
            fs::read_from_runs(
                &self.fs.device,
                &info,
                &data.data_runs,
                u64::from(data.data_size),
                0,
                &mut value[..written as usize],
            )?;
        }

        let resident = fs::resident_attribute(
            ATTR_TYPE_DATA,
            data.name.as_deref().unwrap_or(""),
            data.instance,
            &value,
        );
        let record = self.fs.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize + data.offset;
        self.fs
            .replace_attribute(holder, at, data.attr_len, &resident)?;

        // And the clusters, now that nothing names them.
        self.fs.free_clusters(&data.data_runs)?;
        Ok(())
    }

    /// Give a resident `$DATA` runs, which is what a value that has outgrown
    /// its record takes.
    ///
    /// The clusters are claimed for the whole length, the value's own bytes are
    /// written into them, and the attribute — which keeps its instance number —
    /// becomes one whose value is where the runs say.  The record that holds it
    /// has to have the room for the longer header, and one that has not makes
    /// room the way any record does, its largest attribute that is not the data
    /// moving into a record of its own.
    fn convert_to_runs(
        &self,
        holder: u64,
        data: &ParsedAttr,
        length: u32,
        current: u32,
        cluster_size: u64,
    ) -> Result<()> {
        let clusters = u64::from(length).div_ceil(cluster_size);
        let first = self.fs.claim_clusters(clusters)?;
        let runs = alloc::vec![DataRun {
            lcn: first as i64,
            cluster_count: clusters,
        }];
        let allocated = clusters * cluster_size;
        let value = data.content.clone();

        let mut attempt = 0;
        loop {
            let attributes = self.fs.attributes_of(holder)?;
            let attribute = attributes
                .iter()
                .find(|attribute| {
                    attribute.attr_type == ATTR_TYPE_DATA
                        && attribute.instance == data.instance
                        && attribute.data_runs_offset.is_none()
                })
                .ok_or(Error::NotFound)?;
            let record = self.fs.read_mft_record(attribute.holder)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let at = header.size() as usize + attribute.offset;

            let replacement = fs::non_resident_attribute(
                ATTR_TYPE_DATA,
                "",
                attribute.instance,
                &runs,
                allocated,
                u64::from(length),
                u64::from(length),
            );
            match self
                .fs
                .replace_attribute(attribute.holder, at, attribute.attr_len, &replacement)
            {
                Ok(()) => break,
                Err(Error::NoSpace) if attempt == 0 => {
                    self.fs.make_room(attribute.holder, ATTR_TYPE_DATA)?;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }

        // The value the record held is the file's first bytes; the clusters
        // past the length have never held anything, and read as zeros.
        let mut content = alloc::vec![0u8; allocated as usize];
        let held = (current as usize).min(content.len());
        content[..held].copy_from_slice(&value[..held.min(value.len())]);
        let info = self.fs.info.lock();
        fs::write_to_runs(&self.fs.device, &info, &runs, 0, &content)?;
        Ok(())
    }
}

impl Clone for NtfsFs {
    /// Another handle to the same mount: the device, the volume's own state
    /// and the record cache are the ones every handle shares.
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            info: self.info.clone(),
            mft_cache: self.mft_cache.clone(),
        }
    }
}
