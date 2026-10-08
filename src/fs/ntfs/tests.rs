//! src/fs/ntfs/tests.rs
//!
//! Unit tests for the NTFS driver: reparse-point parsing, `$EA` extended
//! attribute parsing, filename selection, `$STANDARD_INFORMATION` conversion
//! and index-entry parsing.
//!
//! (The former end-to-end suite exercised the pre-refactor `NtfsVolume`
//! public API — `list_xattrs` etc. — which the current `NtfsFs`/`NtfsVnode`
//! driver does not expose; those tests were dropped with that API.)

use alloc::vec;
use alloc::vec::Vec;

use super::types::parse_ea_entries;
use super::types::parse_reparse_point;
use super::types::FileName;
use super::types::ParsedAttr;
use super::types::StandardInfoAttr;
use super::types::ATTR_TYPE_FILENAME;
use super::types::IO_REPARSE_TAG_SYMLINK;
use crate::fs::ntfs::fs::get_best_filename;
use crate::fs::ntfs::fs::parse_index_node;
use crate::fs::vfs::FileSystem as VfsFileSystem;
use crate::fs::vfs::NodeKind;
use crate::Error;

// ═══════════════════════════════════════════════════════════════════════════════
// Byte-level helpers
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// Reading a volume
// ═══════════════════════════════════════════════════════════════════════════════

/// Open a fixture volume for reading.
fn open(fixture: &Fixture) -> super::NtfsFs {
    let device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> =
        crate::fs::block::MemoryBlockDevice::new("ntfs-fixture", fixture.image.clone(), true);
    super::NtfsFs::new(device).expect("open the fixture")
}

/// Open a fixture volume on a device that takes writes, and hand back the
/// device with it: a *second* mount of the same bytes is what says a write
/// landed.
fn writable(
    fixture: &Fixture,
) -> (
    alloc::sync::Arc<crate::fs::block::MemoryBlockDevice>,
    super::NtfsFs,
) {
    let device =
        crate::fs::block::MemoryBlockDevice::new("ntfs-writable", fixture.image.clone(), false);
    let fs_handle = super::NtfsFs::new(device.clone()).expect("open the fixture");
    (device, fs_handle)
}

/// The volume's dirty flag, read off the device.
fn dirty_flag(
    device: &alloc::sync::Arc<crate::fs::block::MemoryBlockDevice>,
    fs_handle: &super::NtfsFs,
) -> bool {
    let at = fs_handle.volume_flags_offset().expect("the volume's flags");
    let mut field = [0u8; 2];
    let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
    super::fs::read_device_bytes(&as_device, at, &mut field).expect("read the flags");
    field[0] & 0x01 != 0
}

#[test]
fn a_record_answers_with_the_number_it_was_asked_for() {
    // The whole point of the addressing: the record a reader gets is the one
    // it named.  Every record in both shapes, because the record size and the
    // cluster size are what the arithmetic turns on.
    for shape in [FRACTIONAL, WHOLE_CLUSTERS] {
        let fixture = build_volume(shape);
        let fs_handle = open(&fixture);
        for number in 0..RECORDS {
            let record = fs_handle
                .read_mft_record(number)
                .unwrap_or_else(|error| panic!("record {number} in {shape:?}: {error:?}"));
            let own = u32::from_le_bytes([record[44], record[45], record[46], record[47]]);
            assert_eq!(
                own as u64, number,
                "record {number} answered with the record numbered {own}"
            );
        }
    }
}

#[test]
fn a_records_size_comes_from_the_boot_sectors_exponent() {
    // A negative exponent is a number of *bytes*, not of clusters: 1024-byte
    // records in 4096-byte clusters is the shape `mkntfs` makes, and reading
    // it as a whole cluster is what asked for one record and got another.
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);
    let info = fs_handle.info().lock();
    assert_eq!(info.cluster_size, 4096);
    assert_eq!(info.mft_record_size, 1024);
    assert_eq!(info.index_block_size, 4096);

    // And the other branch: the same records in 512-byte clusters are two of
    // them per record, which is the exponent read the way it is meant.
    let fixture = build_volume(WHOLE_CLUSTERS);
    let fs_handle = open(&fixture);
    let info = fs_handle.info().lock();
    assert_eq!(info.cluster_size, 512);
    assert_eq!(info.mft_record_size, 1024);
    assert_eq!(info.index_block_size, 4096);
}

#[test]
fn a_mft_in_two_runs_is_followed() {
    let fixture = build_volume(FRACTIONAL);
    assert_eq!(fixture.mft_runs[0].1, 4, "the first run is four clusters");
    assert!(fixture.mft_runs[1].1 > 0, "and there is a second one");
    assert!(
        fixture.mft_runs[1].0 > fixture.mft_runs[0].0 + fixture.mft_runs[0].1,
        "with a gap after the first"
    );

    // A record in the *second* run is what a stride from the first cluster
    // cannot reach: it lands in the gap, which holds no record at all.
    let fs_handle = open(&fixture);
    let record = fs_handle
        .read_mft_record(RECORDS - 1)
        .expect("the last record");
    let own = u32::from_le_bytes([record[44], record[45], record[46], record[47]]);
    assert_eq!(own as u64, RECORDS - 1);

    // Where a stride from the first cluster would have looked instead: it
    // lands *on* a record — the magic is still `FILE` — and on a different
    // record than the one asked for, which is why nothing complained.
    let stride = fixture.mft_runs[0].0 * fixture.cluster_size()
        + (RECORDS - 1) * fixture.shape.record_size() as u64;
    let at = stride as usize;
    assert_eq!(&fixture.image[at..at + 4], b"FILE");
    let own = u32::from_le_bytes([
        fixture.image[at + 44],
        fixture.image[at + 45],
        fixture.image[at + 46],
        fixture.image[at + 47],
    ]);
    assert_ne!(own as u64, RECORDS - 1);
}

#[test]
fn a_residents_value_is_where_its_header_says() {
    // `$INDEX_ROOT` is a *named* attribute — "$I30" — and a named attribute's
    // value begins after its name, where its own header says.  Reading it from
    // a fixed offset lands inside the name.
    let fixture = build_volume(FRACTIONAL);
    let record = fixture.record(ROOT_RECORD);
    let header = super::types::MftRecordHeader::parse(record).expect("record header");
    assert!(header.is_dir());
    let attributes = super::fs::parse_attributes(&record[header.size() as usize..]);

    let index = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x90)
        .expect("the index root");
    assert_eq!(
        u32::from_le_bytes([
            index.content[0],
            index.content[1],
            index.content[2],
            index.content[3]
        ]),
        0x30,
        "the value begins with the type of the attribute it indexes"
    );
    assert_eq!(
        u32::from_le_bytes([
            index.content[4],
            index.content[5],
            index.content[6],
            index.content[7]
        ]),
        1,
        "$FILE_NAME's collation rule"
    );

    // And the record's own name parses, from the value its header points at.
    let name = super::fs::get_best_filename(&attributes).expect("the root's name");
    assert_eq!(name.name, ".");
    assert_eq!(name.parent_directory & 0xFFFF_FFFF_FFFF, ROOT_RECORD);
}

#[test]
fn the_fixture_keeps_its_own_invariants() {
    // The fixture is a volume a reader is judged against, so the properties a
    // writer would have to keep are checked on it rather than assumed: every
    // record carries its update sequence at every sector's end, ends with the
    // marker, and the bitmap says exactly the clusters the layout used.
    let fixture = build_volume(FRACTIONAL);
    for number in 0..RECORDS {
        let record = fixture.record(number);
        let sequence = u16::from_le_bytes([record[48], record[49]]);
        for sector in 1..(fixture.shape.record_size() / fixture.shape.bytes_per_sector as u32) {
            let end = sector as usize * fixture.shape.bytes_per_sector as usize;
            assert_eq!(
                u16::from_le_bytes([record[end - 2], record[end - 1]]),
                sequence,
                "record {number}'s sector {sector} ends with the sequence"
            );
        }
    }

    let bitmap_at = fixture.bitmap as usize * fixture.cluster_size() as usize;
    let bitmap = &fixture.image[bitmap_at..bitmap_at + fixture.cluster_size() as usize];
    for (cluster, used) in fixture.used.iter().enumerate() {
        let set = bitmap[cluster / 8] & (1 << (cluster % 8)) != 0;
        assert_eq!(set, *used != 0, "cluster {cluster}'s bit");
    }
}

#[test]
fn a_directory_lists_what_its_index_holds() {
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);

    // The root's entries live in an index *allocation*, and the index root is
    // a node that points at it — the shape a directory with children has.
    let mut names = Vec::new();
    for index in 0.. {
        match fs_handle.read_dir("/", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    assert_eq!(
        names,
        [
            "$MFT",
            "$MFTMirr",
            "$LogFile",
            "$Volume",
            "$AttrDef",
            "$Bitmap",
            "resident.txt",
            "two-runs.bin",
            "sub",
        ],
        "the root's entries, without its own \".\""
    );

    // The subdirectory's entries are in its index *root*, which is the other
    // shape a directory has.
    let leaf = fs_handle
        .read_dir("/sub", 0)
        .expect("the subdirectory's entry");
    assert_eq!(leaf.name, "leaf.txt");
    assert_eq!(leaf.kind, NodeKind::File);
    assert_eq!(leaf.size, 4);
    assert!(matches!(
        fs_handle.read_dir("/sub", 1),
        Err(Error::NotFound)
    ));

    // A file and a directory are listed as what they are.
    let resident = fs_handle.read_dir("/", 6).expect("resident.txt");
    assert_eq!(resident.kind, NodeKind::File);
    assert_eq!(resident.size, 5);
    let sub = fs_handle.read_dir("/", 8).expect("sub");
    assert_eq!(sub.kind, NodeKind::Directory);
}

#[test]
fn a_path_resolves_to_the_record_it_names() {
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);

    let root = fs_handle.lookup("/").expect("the root");
    assert_eq!(root.kind(), NodeKind::Directory);
    assert_eq!(root.name(), "/");

    let file = fs_handle
        .lookup("/resident.txt")
        .expect("a file at the root");
    assert_eq!(file.kind(), NodeKind::File);
    assert_eq!(file.name(), "resident.txt");
    assert_eq!(file.size(), 5);

    let sub = fs_handle.lookup("/sub").expect("a directory at the root");
    assert_eq!(sub.kind(), NodeKind::Directory);
    let leaf = fs_handle.lookup("/sub/leaf.txt").expect("a file below it");
    assert_eq!(leaf.size(), 4);
    assert_eq!(leaf.name(), "leaf.txt");

    // A name that is not there, and a path through a file, are both answers
    // and not accidents.
    assert!(matches!(fs_handle.lookup("/nope"), Err(Error::NotFound)));
    assert!(matches!(
        fs_handle.lookup("/resident.txt/inside"),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_files_data_reads_through_the_runs_its_record_names() {
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);

    // A resident file's bytes are in its own record.
    let resident = fs_handle.lookup("/resident.txt").expect("resident.txt");
    let mut buf = vec![0u8; 5];
    assert_eq!(resident.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf, b"hello");

    // A file in two runs reads the *second* run too, which is where a reader
    // that stopped at the first would come up short.
    let two_runs = fs_handle.lookup("/two-runs.bin").expect("two-runs.bin");
    let size = fixture.cluster_size() as usize * 3;
    assert_eq!(two_runs.size(), size);
    let mut buf = vec![0u8; size];
    assert_eq!(two_runs.read(0, &mut buf).expect("read"), size);
    assert!(buf[..fixture.cluster_size() as usize]
        .iter()
        .all(|b| *b == 0x11));
    assert!(
        buf[2 * fixture.cluster_size() as usize..]
            .iter()
            .all(|b| *b == 0x22),
        "the second run's bytes"
    );

    // A directory is not a file, and saying so is the answer.
    let sub = fs_handle.lookup("/sub").expect("sub");
    let mut buf = [0u8; 4];
    assert_eq!(sub.read(0, &mut buf), Err(Error::NotFound));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Writing, and what a second mount sees
// ═══════════════════════════════════════════════════════════════════════════════

/// Mount the same bytes again: a change only a node knows about does not
/// survive this.
fn remount(device: &alloc::sync::Arc<crate::fs::block::MemoryBlockDevice>) -> super::NtfsFs {
    super::NtfsFs::new(device.clone()).expect("mount it again")
}

#[test]
fn an_overwrite_reaches_the_volume() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.lookup("/resident.txt").expect("resident.txt");
    assert_eq!(node.write(0, b"HELLO").expect("write"), 5);

    let again = remount(&device);
    let reread = again.lookup("/resident.txt").expect("relookup");
    let mut buf = vec![0u8; 5];
    assert_eq!(reread.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf, b"HELLO", "the bytes are on the volume");
}

#[test]
fn a_shorter_length_is_on_the_volume() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.lookup("/resident.txt").expect("resident.txt");
    node.set_len(3).expect("truncate");
    assert_eq!(node.size(), 3);

    let again = remount(&device);
    let reread = again.lookup("/resident.txt").expect("relookup");
    assert_eq!(reread.size(), 3, "the length is on the volume");
    let mut buf = vec![0u8; 3];
    assert_eq!(reread.read(0, &mut buf).expect("read"), 3);
    assert_eq!(&buf, b"hel");
}

#[test]
fn a_file_can_be_as_long_as_the_runs_it_has() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/two-runs.bin").expect("two-runs.bin");

    // It holds three clusters in two runs; two of them are within what it has.
    node.set_len(2 * cluster).expect("shorten inside the runs");
    assert_eq!(node.size(), 2 * cluster as usize);

    let again = remount(&device);
    assert_eq!(
        again.lookup("/two-runs.bin").expect("relookup").size(),
        2 * cluster as usize
    );

    // And back to what the runs add up to: the second run's bytes were never
    // erased, which is what lets the length go back up.
    let node = again.lookup("/two-runs.bin").expect("relookup");
    node.set_len(3 * cluster).expect("grow back");
    let mut buf = vec![0u8; 3 * cluster as usize];
    assert_eq!(node.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[2 * cluster as usize..].iter().all(|b| *b == 0x22));
}

#[test]
fn a_length_the_file_has_not_the_room_for_is_refused() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/two-runs.bin").expect("two-runs.bin");

    // Allocation is the next stage; until it exists, a length past the runs is
    // not something this can pretend to have.
    assert_eq!(node.set_len(4 * cluster), Err(Error::NoSpace));
    assert_eq!(node.size(), 3 * cluster as usize, "and nothing moved");

    // A write that would need it is a short write, not an error.
    let written = node
        .write(3 * cluster - 2, &[0xAB; 8])
        .expect("a short write");
    assert_eq!(written, 2);

    let again = remount(&device);
    assert_eq!(
        again.lookup("/two-runs.bin").expect("relookup").size(),
        3 * cluster as usize
    );
}

#[test]
fn the_volume_is_dirty_until_it_is_synced() {
    use crate::fs::vfs::FileSystem as VfsFileSystem;

    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    assert!(!dirty_flag(&device, &fs_handle), "a fresh volume is clean");

    let node = fs_handle.lookup("/resident.txt").expect("resident.txt");
    node.write(0, b"HELLO").expect("write");
    assert!(
        dirty_flag(&device, &fs_handle),
        "a volume in the middle of being changed says so"
    );

    fs_handle.sync().expect("settle the volume");
    assert!(!dirty_flag(&device, &fs_handle), "and stops saying so");
}

// ═══════════════════════════════════════════════════════════════════════════════
// The fixture volume
// ═══════════════════════════════════════════════════════════════════════════════

/// The shape of a fixture volume: the two boot-sector exponents are what a
/// real volume varies by, and the two shapes below are the two the arithmetic
/// differs between.
#[derive(Clone, Copy, Debug)]
struct Shape {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    /// The MFT's record size, as the exponent field holds it: the negated
    /// binary logarithm of the bytes per record.
    mft_record_exponent: i8,
    /// The index buffer's, the same way.
    index_buffer_exponent: i8,
}

impl Shape {
    fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    fn record_size(&self) -> u32 {
        super::types::size_from_exponent(self.mft_record_exponent, self.cluster_size())
    }

    fn index_block_size(&self) -> u32 {
        super::types::size_from_exponent(self.index_buffer_exponent, self.cluster_size())
    }
}

/// The shape `mkntfs` makes by default: 4096-byte clusters and records that
/// are a *quarter* of one.
const FRACTIONAL: Shape = Shape {
    bytes_per_sector: 512,
    sectors_per_cluster: 8,
    mft_record_exponent: -10,
    index_buffer_exponent: -12,
};

/// The same records in 512-byte clusters, where they are a whole number of
/// them and the arithmetic is the other branch.
const WHOLE_CLUSTERS: Shape = Shape {
    bytes_per_sector: 512,
    sectors_per_cluster: 1,
    mft_record_exponent: -10,
    index_buffer_exponent: -12,
};

/// The records the fixture gives a name to.
const ROOT_RECORD: u64 = 5;
const RESIDENT_FILE: u64 = 24;
const TWO_RUN_FILE: u64 = 25;
const SUBDIRECTORY: u64 = 26;
const SUBDIRECTORY_FILE: u64 = 27;
const RECORDS: u64 = 28;

/// How many clusters the MFT's first run takes, so that the two-run shape is
/// the fixture's own choice rather than a consequence of the record size.
const MFT_FIRST_RUN_CLUSTERS: u64 = 4;

/// A runlist, from absolute `(lcn, clusters)` runs.
fn runlist(runs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = 0i64;
    for &(lcn, clusters) in runs {
        let delta = lcn as i64 - previous;
        previous = lcn as i64;
        let mut length = Vec::new();
        let mut count = clusters;
        while count > 0 {
            length.push((count & 0xff) as u8);
            count >>= 8;
        }
        let mut offset = Vec::new();
        let mut value = delta;
        loop {
            offset.push((value & 0xff) as u8);
            value >>= 8;
            let done = (delta >= 0 && value == 0) || (delta < 0 && value == -1);
            if done {
                break;
            }
        }
        out.push(((offset.len() as u8) << 4) | length.len() as u8);
        out.extend_from_slice(&length);
        out.extend_from_slice(&offset);
    }
    out.push(0);
    out
}

/// An attribute header, resident or not, with the value the standard puts
/// where its own header says.
fn attribute(
    attr_type: u32,
    name: &str,
    value: &[u8],
    runs: Option<&[(u64, u64)]>,
    size: u64,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let name_len = (name_bytes.len() / 2) as u8;
    let mut attr = vec![0u8; 16];
    put_u32_le(&mut attr, 0, attr_type);
    match runs {
        None => {
            // Resident: the value follows the name, when there is one.
            let name_offset = 24;
            let value_offset = name_offset + name_bytes.len() as u16;
            attr.resize(value_offset as usize, 0);
            put_u16_le(&mut attr, 4, 0); // length, patched below
            attr[8] = 0; // resident
            attr[9] = name_len;
            put_u16_le(&mut attr, 10, name_offset);
            put_u16_le(&mut attr, 14, 1); // instance
            put_u16_le(&mut attr, 20, value_offset);
            put_u32_le(&mut attr, 16, value.len() as u32);
            attr.extend_from_slice(value);
            let length = attr.len().div_ceil(8) * 8;
            attr.resize(length, 0);
            put_u32_le(&mut attr, 4, length as u32);
        }
        Some(runs) => {
            let name_offset = 64;
            let runs_offset = name_offset + name_bytes.len() as u16;
            attr.resize(64, 0);
            attr[8] = 1; // non-resident
            attr[9] = name_len;
            put_u16_le(&mut attr, 10, name_offset);
            put_u16_le(&mut attr, 14, 1);
            put_u16_le(&mut attr, 32, runs_offset);
            put_u64_le(&mut attr, 40, size); // allocated
            put_u64_le(&mut attr, 48, size); // data size
            put_u64_le(&mut attr, 56, size); // initialized
            if !name.is_empty() {
                attr.extend_from_slice(&name_bytes);
            }
            attr.resize(runs_offset as usize, 0);
            attr.extend_from_slice(&runlist(runs));
            let length = attr.len().div_ceil(8) * 8;
            attr.resize(length, 0);
            put_u32_le(&mut attr, 4, length as u32);
        }
    }
    attr
}

/// The bytes of a `$FILE_NAME` value.
fn file_name(parent: u64, name: &str, directory: bool, size: u64) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut value = vec![0u8; 66];
    put_u64_le(&mut value, 0, parent);
    put_u64_le(&mut value, 40, size); // allocated
    put_u64_le(&mut value, 48, size); // real
    put_u32_le(&mut value, 56, if directory { 0x1000_0000 } else { 0x20 });
    value[64] = (name_bytes.len() / 2) as u8;
    value[65] = 3; // Win32 & DOS
    value.extend_from_slice(&name_bytes);
    value
}

/// An index entry naming a record.
fn index_entry(record: u64, name: &str, directory: bool, size: u64) -> Vec<u8> {
    let content = file_name(ROOT_RECORD, name, directory, size);
    let mut entry = vec![0u8; 16];
    put_u64_le(&mut entry, 0, (1u64 << 48) | record); // sequence 1
    put_u16_le(&mut entry, 10, content.len() as u16);
    entry.extend_from_slice(&content);
    let length = entry.len().div_ceil(8) * 8;
    entry.resize(length, 0);
    put_u16_le(&mut entry, 8, length as u16);
    entry
}

/// The entry every index ends with: no name, and the last-entry flag.
fn index_end_entry() -> Vec<u8> {
    let mut entry = vec![0u8; 16];
    put_u16_le(&mut entry, 8, 16);
    put_u32_le(&mut entry, 12, 2);
    entry
}

/// An index root's value: the indexed attribute's type, the collation rule,
/// the buffer size, and the node's own entries.
fn index_root(body: &[u8], has_children: bool) -> Vec<u8> {
    let mut value = vec![0u8; 16];
    put_u32_le(&mut value, 0, 0x30); // $FILE_NAME
    put_u32_le(&mut value, 4, 1); // COLLATION_FILENAME
    put_u32_le(&mut value, 8, 4096);
    value[12] = 1;
    // An index *root*'s node begins right after the root header, so its
    // entries start sixteen bytes into the node.
    value.extend_from_slice(&node(body, has_children, 16));
    value
}

/// An index allocation block: "INDX", its own update sequence array, the
/// virtual cluster number it holds, and the node inside it.
fn index_block(shape: &Shape, vcn: u64, node: &[u8]) -> Vec<u8> {
    let mut block = alloc::vec![0u8; shape.index_block_size() as usize];
    block[..4].copy_from_slice(b"INDX");
    put_u16_le(&mut block, 4, 40); // the USA follows the block's header
    let usa_count = 1 + block.len() / shape.bytes_per_sector as usize;
    put_u16_le(&mut block, 6, usa_count as u16);
    put_u64_le(&mut block, 16, vcn);

    let start = 24; // the node begins after the block header
    block[start..start + node.len()].copy_from_slice(node);

    // The update sequence, the same way a record carries one.
    let sequence = 0x4321u16;
    put_u16_le(&mut block, 40, sequence);
    for i in 1..usa_count {
        let sector_end = i * shape.bytes_per_sector as usize;
        let low = block[sector_end - 2];
        let high = block[sector_end - 1];
        put_u16_le(&mut block, 40 + i * 2, u16::from_le_bytes([low, high]));
        put_u16_le(&mut block, sector_end - 2, sequence);
    }
    block
}

/// An index node's header and body, as the node holds them.
///
/// The body is the caller's: a leaf ends with the end entry, and a non-leaf
/// node ends with the entry that points at its child — which is the last
/// entry there is, so there is nothing to append.
fn node(body: &[u8], has_children: bool, entries_offset: u16) -> Vec<u8> {
    let mut node = vec![0u8; 16];
    node.resize(entries_offset as usize, 0);
    let mut body = body.to_vec();
    let length = (entries_offset as usize + body.len()).div_ceil(8) * 8;
    put_u16_le(&mut node, 0, entries_offset);
    put_u16_le(&mut node, 4, length as u16);
    put_u16_le(&mut node, 8, length as u16);
    put_u16_le(&mut node, 12, u16::from(has_children));
    node.extend_from_slice(&body);
    body.clear();
    node.resize(length, 0);
    node
}

/// The entry a non-leaf node ends with: its file reference is the virtual
/// cluster number of the child block, and it says it is the last entry.
fn node_pointer(vcn: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 24];
    put_u64_le(&mut entry, 0, vcn);
    put_u16_le(&mut entry, 8, 24);
    put_u32_le(&mut entry, 12, 3);
    entry
}

/// A record: its header, its update sequence array, and its attributes.
fn record(shape: &Shape, number: u64, flags: u16, attributes: &[u8]) -> Vec<u8> {
    let size = shape.record_size() as usize;
    let mut record = vec![0u8; size];
    record[..4].copy_from_slice(b"FILE");
    put_u16_le(&mut record, 4, 48); // usa offset
    let usa_count = 1 + size / shape.bytes_per_sector as usize;
    put_u16_le(&mut record, 6, usa_count as u16);
    put_u16_le(&mut record, 16, 1); // sequence
    put_u16_le(&mut record, 18, if flags & 0x02 != 0 { 2 } else { 1 }); // link count
    put_u16_le(&mut record, 20, 56); // attributes offset
    put_u16_le(&mut record, 22, flags);
    put_u32_le(&mut record, 28, size as u32);
    put_u32_le(&mut record, 44, number as u32);

    let end = 56 + attributes.len();
    record[56..end].copy_from_slice(attributes);
    put_u32_le(&mut record, end, 0xFFFF_FFFF); // end marker
    let used = (end + 8) as u32;
    put_u32_le(&mut record, 24, used);

    // The update sequence: the number in the array, the bytes it replaced at
    // every sector's end.
    let sequence = 0x1234u16;
    put_u16_le(&mut record, 48, sequence);
    for i in 1..usa_count {
        let sector_end = i * shape.bytes_per_sector as usize;
        let low = record[sector_end - 2];
        let high = record[sector_end - 1];
        put_u16_le(&mut record, 48 + i * 2, u16::from_le_bytes([low, high]));
        put_u16_le(&mut record, sector_end - 2, sequence);
    }
    record
}

/// A fixture volume, and where the parts a test asks about are.
struct Fixture {
    image: Vec<u8>,
    shape: Shape,
    /// The MFT's two runs, as `(lcn, clusters)`.
    mft_runs: [(u64, u64); 2],
    /// The clusters the volume's `$Bitmap` says are in use.
    used: Vec<u64>,
    index_block: u64,
    bitmap: u64,
    file_runs: [(u64, u64); 2],
}

impl Fixture {
    fn cluster_size(&self) -> u64 {
        self.shape.cluster_size() as u64
    }

    /// Where a record's bytes are: the MFT is two runs, so a record's address
    /// is a walk through them rather than a stride from the first cluster.
    fn record_offset(&self, number: u64) -> u64 {
        let size = self.shape.record_size() as u64;
        let (first_lcn, first_clusters) = self.mft_runs[0];
        let first_records = first_clusters * self.cluster_size() / size;
        if number < first_records {
            first_lcn * self.cluster_size() + number * size
        } else {
            let (second_lcn, _) = self.mft_runs[1];
            second_lcn * self.cluster_size() + (number - first_records) * size
        }
    }

    fn record(&self, number: u64) -> &[u8] {
        let at = self.record_offset(number) as usize;
        &self.image[at..at + self.shape.record_size() as usize]
    }
}

/// Build the fixture volume.
///
/// It holds the records a real volume's first records are, a `$Bitmap` whose
/// bits are set from the layout as it is made, two files — one resident and
/// one in two runs with a gap between them — a subdirectory whose entries are
/// in its index root, and a root whose entries are in an index *allocation*,
/// which is the shape a directory with children really has.
fn build_volume(shape: Shape) -> Fixture {
    let cluster_size = shape.cluster_size() as u64;
    let record_size = shape.record_size() as u64;
    let index_block_clusters = shape.index_block_size() as u64 / cluster_size;

    // Lay the pieces out one after another, keeping the first free cluster.
    let mut cursor = 1u64; // cluster 0 is the boot sector
    let mut take = |clusters: u64| {
        let at = cursor;
        cursor += clusters;
        at
    };
    let mft_first = take(MFT_FIRST_RUN_CLUSTERS);
    take(2); // a gap, so the MFT is two runs and not one
    let mft_second = take((RECORDS * record_size).div_ceil(cluster_size) - MFT_FIRST_RUN_CLUSTERS);
    let index_block_at = take(index_block_clusters);
    let bitmap_at = take(1);
    let file_first = take(1);
    take(1); // the gap between the file's two runs
    let file_second = take(2);
    let total_clusters = cursor + 2;

    let mut fixture = Fixture {
        image: alloc::vec![0u8; total_clusters as usize * cluster_size as usize],
        shape,
        mft_runs: [
            (mft_first, MFT_FIRST_RUN_CLUSTERS),
            (
                mft_second,
                (RECORDS * record_size).div_ceil(cluster_size) - MFT_FIRST_RUN_CLUSTERS,
            ),
        ],
        used: alloc::vec![0u64; total_clusters as usize],
        index_block: index_block_at,
        bitmap: bitmap_at,
        file_runs: [(file_first, 1), (file_second, 2)],
    };
    fixture.used[0] = 1;
    let (first_lcn, first_clusters) = fixture.mft_runs[0];
    let (second_lcn, second_clusters) = fixture.mft_runs[1];
    for cluster in first_lcn..first_lcn + first_clusters {
        fixture.used[cluster as usize] = 1;
    }
    for cluster in second_lcn..second_lcn + second_clusters {
        fixture.used[cluster as usize] = 1;
    }
    for cluster in index_block_at..index_block_at + index_block_clusters {
        fixture.used[cluster as usize] = 1;
    }
    for &(lcn, clusters) in &fixture.file_runs {
        for cluster in lcn..lcn + clusters {
            fixture.used[cluster as usize] = 1;
        }
    }

    // The boot sector, and the copy a real volume keeps at the end.
    let mut boot = vec![0u8; shape.bytes_per_sector as usize];
    boot[3..7].copy_from_slice(b"NTFS");
    put_u16_le(&mut boot, 11, shape.bytes_per_sector);
    boot[13] = shape.sectors_per_cluster;
    put_u64_le(
        &mut boot,
        40,
        total_clusters * shape.sectors_per_cluster as u64,
    );
    put_u64_le(&mut boot, 48, mft_first);
    put_u64_le(&mut boot, 56, second_lcn); // not a mirror, but a real address
    boot[64] = shape.mft_record_exponent as u8;
    boot[68] = shape.index_buffer_exponent as u8;
    put_u32_le(&mut boot, 72, 0x5A5A_5A5A);
    boot[510] = 0x55;
    boot[511] = 0xAA;
    let image_len = fixture.image.len();
    fixture.image[..boot.len()].copy_from_slice(&boot);
    fixture.image[image_len - boot.len()..].copy_from_slice(&boot);

    // The records: the system files a real volume's first records are, then
    // this fixture's own files, and a subdirectory whose entries are in its
    // index root.
    let mut attributes = Vec::new();
    for number in 0..RECORDS {
        let (parent, name, directory, size, data): (u64, &str, bool, u64, Vec<u8>) = match number {
            0 => (ROOT_RECORD, "$MFT", false, 0, Vec::new()),
            1 => (ROOT_RECORD, "$MFTMirr", false, 0, Vec::new()),
            2 => (ROOT_RECORD, "$LogFile", false, 0, Vec::new()),
            3 => (ROOT_RECORD, "$Volume", false, 0, Vec::new()),
            4 => (ROOT_RECORD, "$AttrDef", false, 0, Vec::new()),
            6 => (ROOT_RECORD, "$Bitmap", false, 0, Vec::new()),
            RESIDENT_FILE => (
                ROOT_RECORD,
                "resident.txt",
                false,
                b"hello".len() as u64,
                b"hello".to_vec(),
            ),
            TWO_RUN_FILE => (
                ROOT_RECORD,
                "two-runs.bin",
                false,
                3 * cluster_size,
                Vec::new(),
            ),
            SUBDIRECTORY => (ROOT_RECORD, "sub", true, 0, Vec::new()),
            SUBDIRECTORY_FILE => (
                SUBDIRECTORY,
                "leaf.txt",
                false,
                b"leaf".len() as u64,
                b"leaf".to_vec(),
            ),
            _ if number == ROOT_RECORD => (ROOT_RECORD, ".", true, 0, Vec::new()),
            _ => (ROOT_RECORD, "", false, 0, Vec::new()),
        };

        // A record nothing uses is **formatted but free**, which is what a
        // real MFT's spare records look like: their number is theirs, their
        // attributes are none, and their flags say they are not in use.
        let named = (0..=6).contains(&number)
            || number == RESIDENT_FILE
            || number == TWO_RUN_FILE
            || number == SUBDIRECTORY
            || number == SUBDIRECTORY_FILE;

        attributes.clear();
        if named {
            let standard = alloc::vec![0u8; 48];
            attributes.extend(attribute(0x10, "", &standard, None, 0)); // $STANDARD_INFORMATION
            attributes.extend(attribute(
                0x30,
                "",
                &file_name(parent, name, directory, size),
                None,
                0,
            ));
            match number {
                0 => {
                    // The MFT's own data: two runs, which is what a reader has to
                    // follow to find any record after the first.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.mft_runs),
                        RECORDS * record_size,
                    ));
                }
                3 => {
                    // The volume's own information: a version, and the flags whose
                    // lowest bit says the volume is dirty.
                    let mut information = vec![0u8; 12];
                    information[8] = 3; // major version
                    information[9] = 1; // minor version
                    attributes.extend(attribute(
                        super::types::ATTR_TYPE_VOLUME_INFORMATION,
                        "",
                        &information,
                        None,
                        0,
                    ));
                }
                RESIDENT_FILE | SUBDIRECTORY_FILE => {
                    attributes.extend(attribute(0x80, "", &data, None, 0));
                }
                TWO_RUN_FILE => {
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.file_runs),
                        3 * cluster_size,
                    ));
                }
                ROOT_RECORD | SUBDIRECTORY => {
                    // The root's entries live in an index allocation, and the
                    // subdirectory's in its index root: the two shapes a directory
                    // really has.
                    let root = number == ROOT_RECORD;

                    // The entries the directory holds, and its own "." entry.
                    let mut entries = Vec::new();
                    if root {
                        for record in [
                            0u64,
                            1,
                            2,
                            3,
                            4,
                            6,
                            RESIDENT_FILE,
                            TWO_RUN_FILE,
                            SUBDIRECTORY,
                        ] {
                            let (name, directory, size): (&str, bool, u64) = match record {
                                0 => ("$MFT", false, 0),
                                1 => ("$MFTMirr", false, 0),
                                2 => ("$LogFile", false, 0),
                                3 => ("$Volume", false, 0),
                                4 => ("$AttrDef", false, 0),
                                6 => ("$Bitmap", false, 0),
                                RESIDENT_FILE => ("resident.txt", false, 5),
                                TWO_RUN_FILE => ("two-runs.bin", false, 3 * cluster_size),
                                _ => ("sub", true, 0),
                            };
                            entries.extend_from_slice(&index_entry(record, name, directory, size));
                        }
                        entries.extend_from_slice(&index_entry(ROOT_RECORD, ".", true, 0));
                    } else {
                        entries.extend_from_slice(&index_entry(
                            SUBDIRECTORY_FILE,
                            "leaf.txt",
                            false,
                            4,
                        ));
                        entries.extend_from_slice(&index_entry(SUBDIRECTORY, ".", true, 0));
                    }

                    // A directory with children keeps them in an index
                    // *allocation*, and its index root is a node that points at
                    // the block; a small one keeps them in its index root.
                    if root {
                        let mut leaf = entries.clone();
                        leaf.extend_from_slice(&index_end_entry());
                        // A block's node sits behind the block's own update
                        // sequence array, so its entries start forty bytes into
                        // the node rather than sixteen.
                        let block_node = node(&leaf, false, 40);
                        let block = index_block(&shape, 0, &block_node);
                        let at = fixture.index_block as usize * cluster_size as usize;
                        fixture.image[at..at + block.len()].copy_from_slice(&block);

                        attributes.extend(attribute(
                            0x90,
                            "$I30",
                            &index_root(&node_pointer(0), true),
                            None,
                            0,
                        ));
                        attributes.extend(attribute(
                            0xa0,
                            "$I30",
                            &[],
                            Some(&[(fixture.index_block, index_block_clusters)]),
                            shape.index_block_size() as u64,
                        ));
                        let mut bits = vec![0u8; 8];
                        bits[0] = 1; // the one block is in use
                        attributes.extend(attribute(0xb0, "$I30", &bits, None, 0));
                    } else {
                        let mut leaf = entries.clone();
                        leaf.extend_from_slice(&index_end_entry());
                        attributes.extend(attribute(
                            0x90,
                            "$I30",
                            &index_root(&leaf, false),
                            None,
                            0,
                        ));
                    }
                }
                _ => {}
            }
        }

        let directory = number == ROOT_RECORD || number == SUBDIRECTORY;
        let flags = if named {
            if directory {
                0x03
            } else {
                0x01
            }
        } else {
            0x00
        };
        let bytes = record(&shape, number, flags, &attributes);
        let at = fixture.record_offset(number) as usize;
        fixture.image[at..at + bytes.len()].copy_from_slice(&bytes);
    }

    // The file's data, in two runs with a gap between them.
    let (first_lcn, first_clusters) = fixture.file_runs[0];
    let (second_lcn, second_clusters) = fixture.file_runs[1];
    let at = first_lcn as usize * cluster_size as usize;
    for byte in &mut fixture.image[at..at + first_clusters as usize * cluster_size as usize] {
        *byte = 0x11;
    }
    let at = second_lcn as usize * cluster_size as usize;
    for byte in &mut fixture.image[at..at + second_clusters as usize * cluster_size as usize] {
        *byte = 0x22;
    }

    // The `$Bitmap`: one bit per cluster, set for every cluster the layout
    // above used.  It is what an allocating stage has to keep true, so the
    // fixture states it rather than hiding it.
    fixture.used[bitmap_at as usize] = 1;
    let mut bitmap = alloc::vec![0u8; cluster_size as usize];
    for (index, used) in fixture.used.iter().enumerate() {
        if *used != 0 {
            bitmap[index / 8] |= 1 << (index % 8);
        }
    }
    let at = bitmap_at as usize * cluster_size as usize;
    fixture.image[at..at + bitmap.len()].copy_from_slice(&bitmap);

    fixture
}

fn put_u16_le(buf: &mut [u8], off: usize, value: u16) {
    buf[off] = value as u8;
    buf[off + 1] = (value >> 8) as u8;
}

fn put_u32_le(buf: &mut [u8], off: usize, value: u32) {
    buf[off] = value as u8;
    buf[off + 1] = (value >> 8) as u8;
    buf[off + 2] = (value >> 16) as u8;
    buf[off + 3] = (value >> 24) as u8;
}

fn put_u64_le(buf: &mut [u8], off: usize, value: u64) {
    for i in 0..8 {
        buf[off + i] = (value >> (i * 8)) as u8;
    }
}

/// Build a reparse-point data buffer containing `path` as the substitution
/// name.
///
/// Layout: u32 tag, u16 reparse_data_length, u16 reserved, then the reparse
/// data: u16 sub_name_offset, u16 sub_name_length, u16 print_name_offset,
/// u16 print_name_length, then the UTF-16LE path at data offset 16.
fn make_reparse_buf(tag: u32, path: &str) -> Vec<u8> {
    let path_bytes: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let sub_len = path_bytes.len();
    // Reparse data = 16-byte offsets header + the path.
    let data_len = 16 + sub_len;
    let mut buf = vec![0u8; 8 + data_len];
    put_u32_le(&mut buf, 0, tag);
    put_u16_le(&mut buf, 4, data_len as u16); // reparse_data_length
                                              // Reparse data header at buf[8..]:
    put_u16_le(&mut buf, 8, 16); // substitute_name_offset (relative to data)
    put_u16_le(&mut buf, 10, sub_len as u16); // substitute_name_length
                                              // print_name_offset/length at 12..16 stay 0.
                                              // Path at data[16..] = buf[8 + 16..].
    buf[24..24 + sub_len].copy_from_slice(&path_bytes);
    buf
}

/// Build a resident `$FILE_NAME` attribute body.
fn make_filename_body(name: &str, namespace: u8, flags: u32, parent: u64) -> Vec<u8> {
    let mut body = vec![0u8; 66 + name.len() * 2];
    put_u64_le(&mut body, 0, parent);
    put_u32_le(&mut body, 56, flags);
    body[64] = name.len() as u8;
    body[65] = namespace;
    for (i, u) in name.encode_utf16().enumerate() {
        body[66 + i * 2] = u as u8;
        body[66 + i * 2 + 1] = (u >> 8) as u8;
    }
    body
}

// ═══════════════════════════════════════════════════════════════════════════════
// Reparse-point parsing
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn parse_reparse_point_symlink() {
    let buf = make_reparse_buf(IO_REPARSE_TAG_SYMLINK, "/usr/local/bin");
    let (tag, target) = parse_reparse_point(&buf).expect("should parse");
    assert_eq!(tag, IO_REPARSE_TAG_SYMLINK);
    assert_eq!(target.as_deref(), Some("/usr/local/bin"));
}

#[test]
fn parse_reparse_point_dosdevices_prefix() {
    let buf = make_reparse_buf(0xA000_000C, "\\DosDevices\\E:\\data");
    let (_tag, target) = parse_reparse_point(&buf).expect("should parse");
    assert_eq!(target.as_deref(), Some("E:\\data"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// EA parsing
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn parse_ea_entries_empty() {
    let entries = parse_ea_entries(&[]);
    assert!(entries.is_empty());
}

#[test]
fn parse_ea_entries_too_short() {
    let entries = parse_ea_entries(&[0; 3]);
    assert!(entries.is_empty());
}

#[test]
fn parse_ea_entries_single() {
    // Build a minimal EA with one entry: name "a" (1), value "b" (1).
    // Entry data: 8 + 1 + 1 = 10, pad to 12.
    // ea_length = 4 + 12 = 16, next_entry_offset = 0.
    let mut ea = vec![0u8; 16];
    put_u32_le(&mut ea, 0, 16); // ea_length
    put_u32_le(&mut ea, 4, 0); // next_entry_offset (last)
    ea[8] = 0; // flags
    ea[9] = 1; // name_len
    put_u16_le(&mut ea, 10, 1); // value_len
    ea[12] = b'a';
    ea[13] = b'b';
    let entries = parse_ea_entries(&ea);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, b"user.a");
    assert_eq!(entries[0].value, b"b");
}

#[test]
fn parse_ea_entries_two() {
    // Entry 1: name "x" (1), value "y" (1) → 8+1+1=10, pad to 12, next=12
    // Entry 2: name "p" (1), value "q" (1) → 8+1+1=10, pad to 12, next=0
    // ea_length = 4 + 12 + 12 = 28
    let mut ea = vec![0u8; 28];
    put_u32_le(&mut ea, 0, 28); // ea_length
                                // Entry 1 at offset 4
    put_u32_le(&mut ea, 4, 12); // next_entry_offset
    ea[8] = 0; // flags
    ea[9] = 1; // name_len
    put_u16_le(&mut ea, 10, 1); // value_len
    ea[12] = b'x';
    ea[13] = b'y';
    // Entry 2 at offset 16
    put_u32_le(&mut ea, 16, 0); // next_entry_offset (last)
    ea[20] = 0; // flags
    ea[21] = 1; // name_len
    put_u16_le(&mut ea, 22, 1); // value_len
    ea[24] = b'p';
    ea[25] = b'q';
    let entries = parse_ea_entries(&ea);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, b"user.x");
    assert_eq!(entries[0].value, b"y");
    assert_eq!(entries[1].name, b"user.p");
    assert_eq!(entries[1].value, b"q");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Namespace-aware filename selection + $STANDARD_INFORMATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn filename_parse_namespace_and_dir_flag() {
    let body = make_filename_body("Documents", 1, 0x1000_0000, 5);
    let f = FileName::parse(&body).expect("parse filename");
    assert_eq!(f.name, "Documents");
    assert_eq!(f.namespace, 1);
    assert!(f.preferred_namespace());
    assert!(f.is_directory());

    let dos = make_filename_body("DOCUME~1", 2, 0, 5);
    let f2 = FileName::parse(&dos).expect("parse dos filename");
    assert_eq!(f2.namespace, 2);
    assert!(!f2.preferred_namespace());
    assert!(!f2.is_directory());
}

#[test]
fn standard_info_parse_timestamps_and_dir() {
    let mut body = vec![0u8; 68];
    // NTFS ticks for 2024-01-01 ≈ 1782576000 Unix secs → ticks.
    put_u64_le(&mut body, 0, 133_000_000_000_000_000); // created
    put_u64_le(&mut body, 8, 133_000_000_100_000_000); // modified
    put_u64_le(&mut body, 16, 133_000_000_200_000_000); // mft_changed
    put_u64_le(&mut body, 24, 133_000_000_300_000_000); // accessed
    put_u32_le(&mut body, 32, 0x1000_0000); // FILE_ATTRIBUTE_DIRECTORY
    let si = StandardInfoAttr::parse(&body).expect("parse standard info");
    assert!(si.is_directory());
    assert_eq!(si.created, 133_000_000_000_000_000);
    assert_eq!(si.modified, 133_000_000_100_000_000);
    // Converted Unix seconds should be finite and sane.
    let unix = StandardInfoAttr::to_unix_secs(si.created);
    assert!(unix > 1_600_000_000.0 && unix < 2_000_000_000.0);
}

#[test]
fn get_best_filename_prefers_win32_over_dos() {
    let dos = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
        offset: 0,
        value_offset: 24,
        content: make_filename_body("HELLO~1", 2, 0, 5),
        data_runs_offset: None,
        data_runs: Vec::new(),
        data_size: 0,
    };
    let win32 = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
        offset: 0,
        value_offset: 24,
        content: make_filename_body("hello.txt", 3, 0, 5),
        data_runs_offset: None,
        data_runs: Vec::new(),
        data_size: 0,
    };
    let best = get_best_filename(&[dos.clone(), win32]).expect("best filename");
    assert_eq!(best.name, "hello.txt");
    assert_eq!(best.namespace, 3);
}

#[test]
fn parse_index_node_reads_the_names_its_entries_carry() {
    // An entry's name begins 16 bytes into it, and the field beside the
    // entry's length is that name's *length*: the two are the same number only
    // while a name is sixteen bytes long.
    let make_entry = |name: &str, namespace: u8, last: bool| -> Vec<u8> {
        let name_bytes = make_filename_body(name, namespace, 0, 5);
        let entry_len = (16 + name_bytes.len()).div_ceil(8) * 8;
        let mut entry = vec![0u8; entry_len];
        put_u64_le(&mut entry, 0, 42); // MFT ref
        put_u16_le(&mut entry, 8, entry_len as u16);
        put_u16_le(&mut entry, 10, name_bytes.len() as u16); // the name's length
        put_u32_le(&mut entry, 12, u32::from(last) * 2);
        entry[16..16 + name_bytes.len()].copy_from_slice(&name_bytes);
        entry
    };
    let first = make_entry("HELLO~1", 2, false);
    let second = make_entry("hello.txt", 1, true);

    // The node: its header, then the entries.
    let mut buf = vec![0u8; 16];
    let length = (16 + first.len() + second.len()) as u16;
    put_u16_le(&mut buf, 0, 16); // where the entries begin
    put_u16_le(&mut buf, 4, length); // how long the node is
    put_u16_le(&mut buf, 8, length); // how much is allocated
    buf.extend_from_slice(&first);
    buf.extend_from_slice(&second);

    let node = parse_index_node(&buf, 0);
    assert!(!node.has_children);
    assert_eq!(node.entries.len(), 2, "the last-entry flag ends the node");
    let names: Vec<&str> = node
        .entries
        .iter()
        .filter_map(|entry| entry.name.as_ref().map(|name| name.name.as_str()))
        .collect();
    assert_eq!(names, ["HELLO~1", "hello.txt"]);
    assert!(node.entries.iter().all(|entry| entry.reference == 42));
}
