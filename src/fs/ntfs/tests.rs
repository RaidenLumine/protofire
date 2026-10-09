//! src/fs/ntfs/tests.rs
//!
//! Unit tests for the NTFS driver: reparse-point parsing, `$EA` extended
//! attribute parsing, filename selection, `$STANDARD_INFORMATION` conversion
//! and index-entry parsing.
//!
//! (The former end-to-end suite exercised the pre-refactor `NtfsVolume`
//! public API — `list_xattrs` etc. — which the current `NtfsFs`/`NtfsVnode`
//! driver does not expose; those tests were dropped with that API.)

use alloc::string::String;
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

    // And the MFT's own bitmap names the records in use — the volume's list of
    // what has been handed out, which a claim has to keep true.  It is a file
    // of its own, with runs, and the bits are where its runs say.
    let mft = fixture.record(0);
    let header = super::types::MftRecordHeader::parse(mft).expect("the MFT's record");
    let attributes = super::fs::parse_attributes(&mft[header.size() as usize..]);
    let bits = attributes
        .iter()
        .find(|attr| attr.attr_type == 0xb0)
        .expect("the MFT's bitmap");
    assert!(
        bits.data_runs_offset.is_some(),
        "the MFT's bitmap is a file"
    );
    let at = fixture.mft_bitmap_runs[0].0 as usize * fixture.cluster_size() as usize;
    let bits = &fixture.image[at..at + bits.data_size as usize];
    for number in 0..RECORDS {
        let set = bits[number as usize / 8] & (1 << (number % 8)) != 0;
        assert_eq!(
            set,
            is_in_use(number, false),
            "record {number}'s bit in the MFT"
        );
    }

    // The records that carry an `$ATTRIBUTE_LIST` agree with it: every entry
    // names an attribute the record it points at really holds, and the record
    // it points at is an extension of the one that listed it.
    for (base, extension) in [
        (LISTED_FILE, LISTED_FILE_EXT),
        (MOVED_FILE, MOVED_FILE_EXT),
        (NAMED_FILE, NAMED_FILE_EXT),
    ] {
        let record = fixture.record(base);
        let header = super::types::MftRecordHeader::parse(record).expect("a record header");
        let attributes = super::fs::parse_attributes(&record[header.size() as usize..]);
        let list = attributes
            .iter()
            .find(|attr| attr.attr_type == 0x20)
            .expect("the attribute list");
        let value = if list.data_runs_offset.is_none() {
            list.content.clone()
        } else {
            let at = fixture.list_runs[0].0 as usize * fixture.cluster_size() as usize;
            fixture.image[at..at + list.data_size as usize].to_vec()
        };
        let entries = super::fs::parse_attribute_list(&value);
        assert!(!entries.is_empty(), "a list with entries");
        for entry in &entries {
            let holder = fixture.record(entry.holder);
            let header = super::types::MftRecordHeader::parse(holder).expect("a holder header");
            let held = super::fs::parse_attributes(&holder[header.size() as usize..]);
            assert!(
                held.iter().any(|attribute| {
                    attribute.attr_type == entry.attr_type
                        && attribute.instance == entry.instance
                        && attribute.name.as_deref() == entry.name.as_deref()
                }),
                "record {} holds what the entry names: {:#x}",
                entry.holder,
                entry.attr_type
            );
        }
        let holder = fixture.record(extension);
        assert_eq!(
            u64::from_le_bytes([
                holder[32], holder[33], holder[34], holder[35], holder[36], holder[37], holder[38],
                holder[39]
            ]) & 0x0000_FFFF_FFFF_FFFF,
            base,
            "and the record a list points at names the record it belongs to"
        );
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
            "$UpCase",
            "resident.txt",
            "two-runs.bin",
            "tight.bin",
            "full.bin",
            "full-dir",
            "split.bin",
            "moved.bin",
            "tree",
            "sub",
            "named.bin",
            "running-index",
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
    let resident = fs_handle.read_dir("/", 7).expect("resident.txt");
    assert_eq!(resident.kind, NodeKind::File);
    assert_eq!(resident.size, 5);
    let tight = fs_handle.read_dir("/", 9).expect("tight.bin");
    assert_eq!(tight.kind, NodeKind::File);
    let full = fs_handle.read_dir("/", 10).expect("full.bin");
    assert_eq!(full.kind, NodeKind::File);
    let sub = fs_handle.read_dir("/", 15).expect("sub");
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
fn a_growth_claims_clusters_and_says_so_in_the_bitmap() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/two-runs.bin").expect("two-runs.bin");
    assert_eq!(node.size(), 3 * cluster as usize);

    // One more cluster than the file has: the volume has free space, so the
    // growth claims it.
    node.set_len(4 * cluster).expect("grow");
    assert_eq!(node.size(), 4 * cluster as usize);

    // A cluster the file just took has never held its bytes, so it reads as
    // zeros — and writing it makes them the file's.
    let mut buf = vec![0u8; 4 * cluster as usize];
    assert_eq!(node.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[3 * cluster as usize..].iter().all(|b| *b == 0));
    node.write(3 * cluster, b"END")
        .expect("write the new cluster");
    let mut buf = vec![0u8; 4 * cluster as usize];
    node.read(0, &mut buf).expect("read it back");
    assert_eq!(&buf[3 * cluster as usize..3 * cluster as usize + 3], b"END");

    // A second mount agrees, and the volume's bitmap says the cluster is taken.
    let again = remount(&device);
    let reread = again.lookup("/two-runs.bin").expect("relookup");
    assert_eq!(reread.size(), 4 * cluster as usize);
    let mut buf = vec![0u8; 4 * cluster as usize];
    assert_eq!(reread.read(0, &mut buf).expect("read"), buf.len());
    assert_eq!(&buf[3 * cluster as usize..3 * cluster as usize + 3], b"END");

    let bitmap = again.read_bitmap().expect("the bitmap");
    let taken: usize = bitmap.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = fixture.used.iter().filter(|used| **used != 0).count();
    assert_eq!(taken, was + 1, "the cluster it claimed is the one more");
}

#[test]
fn a_growth_the_volume_has_no_room_for_is_refused() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/two-runs.bin").expect("two-runs.bin");

    // The fixture's free clusters are in two runs: two of them together, and
    // one on its own.  The two are what it can give, and a claim of three has
    // no run to land in.
    node.set_len(5 * cluster).expect("grow into the free space");
    assert_eq!(node.set_len(8 * cluster), Err(Error::NoSpace));
    assert_eq!(node.size(), 5 * cluster as usize, "and nothing moved");

    // A write that would need the refused clusters is a short write — and one
    // that starts past the end of a file that cannot grow takes nothing at
    // all, which is the same answer with nothing left of it.
    let written = node
        .write(8 * cluster - 2, &[0xAB; 8])
        .expect("a short write");
    assert_eq!(written, 0);

    let again = remount(&device);
    assert_eq!(
        again.lookup("/two-runs.bin").expect("relookup").size(),
        5 * cluster as usize
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

#[test]
fn a_field_write_leaves_the_sequence_array_where_it_was() {
    // (Before the relocation test below, which is the one that *does* move the
    // sequence array.)
    // Which is what lets a field write be a field write: the update sequence
    // array's territory is the end of each sector, a field does not reach it,
    // and a reader that unpacks the record finds the sequence it expects.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.lookup("/resident.txt").expect("resident.txt");
    node.write(0, b"HELLO").expect("write");
    node.set_len(4).expect("truncate");

    let info = fs_handle.info().lock();
    let at = fs_handle
        .record_offset(&info, RESIDENT_FILE)
        .expect("offset");
    let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
    let mut record = vec![0u8; info.mft_record_size as usize];
    super::fs::read_device_bytes(&as_device, at, &mut record).expect("read the record");

    let sequence = u16::from_le_bytes([record[48], record[49]]);
    let sector = info.bs.bytes_per_sector as usize;
    for end in (sector..=record.len()).step_by(sector) {
        assert_eq!(
            u16::from_le_bytes([record[end - 2], record[end - 1]]),
            sequence,
            "the sequence at the end of the sector ending at {end}"
        );
    }
}

#[test]
fn an_attribute_that_outgrows_its_room_moves_and_takes_its_neighbours_with_it() {
    // The fixture's tight file has a two-run `$DATA` with no room to spare and
    // a `$EA_INFORMATION` after it: one more run cannot fit where the run list
    // is, so the attribute moves — and so does everything after it.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/tight.bin").expect("tight.bin");
    assert_eq!(node.size(), 2 * cluster as usize);

    node.set_len(3 * cluster).expect("grow");
    assert_eq!(node.size(), 3 * cluster as usize);

    // What the read path sees first: the file is longer, its first two runs'
    // bytes are there, and the cluster it took reads as zeros.
    let mut buf = vec![0u8; 3 * cluster as usize];
    assert_eq!(node.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[..cluster as usize].iter().all(|b| *b == 0x33));
    assert!(buf[2 * cluster as usize..].iter().all(|b| *b == 0));

    // A second mount agrees, and the record it reads is a record: the
    // attribute that followed the moved one is still there, whole.
    let again = remount(&device);
    let reread = again.lookup("/tight.bin").expect("relookup");
    assert_eq!(reread.size(), 3 * cluster as usize);

    let info = again.info().lock();
    let at = again.record_offset(&info, TIGHT_FILE).expect("offset");
    let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
    let mut raw = vec![0u8; info.mft_record_size as usize];
    super::fs::read_device_bytes(&as_device, at, &mut raw).expect("read the record");

    // Packed, as a record on a volume is: the sequence at every sector's end.
    let sequence = u16::from_le_bytes([raw[48], raw[49]]);
    let sector = info.bs.bytes_per_sector as usize;
    for end in (sector..=raw.len()).step_by(sector) {
        assert_eq!(
            u16::from_le_bytes([raw[end - 2], raw[end - 1]]),
            sequence,
            "the sequence at the end of the sector ending at {end}"
        );
    }

    // And unpacking it gives the attributes back: the moved `$DATA` names
    // three clusters in three runs, and the `$EA_INFORMATION` is where the
    // shift left it.
    let header = super::types::MftRecordHeader::parse(&raw).expect("header");
    super::fs::apply_usa_fixup(
        &mut raw,
        header.usa_offset as usize,
        header.usa_count as usize,
        sector,
    );
    let attributes = super::fs::parse_attributes(&raw[header.size() as usize..]);
    let data = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x80)
        .expect("the data attribute");
    assert_eq!(u64::from(data.data_size), 3 * cluster);
    assert_eq!(
        data.data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>(),
        3
    );
    let eas = attributes
        .iter()
        .find(|attr| attr.attr_type == 0xd0)
        .expect("the attribute that followed it");
    assert_eq!(eas.content.len(), 8);
}

#[test]
fn a_record_with_no_room_puts_an_attribute_in_an_extension_record() {
    // A record that has no room left at all is not short of *records*: it is
    // full, and the mechanism the format has for that is the attribute list.
    // The attribute that has to grow moves out first — which is what the
    // measured volume did with a directory's index root — and the largest
    // others go with it when its own bytes are not enough to hold the list.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/full.bin").expect("full.bin");
    assert_eq!(node.size(), 2 * cluster as usize);

    node.set_len(3 * cluster)
        .expect("a growth it makes room for");
    assert_eq!(node.size(), 3 * cluster as usize);

    // A second mount reads the longer file: its three clusters, the last one
    // the growth took and which has never held its bytes.
    let again = remount(&device);
    let reread = again.lookup("/full.bin").expect("relookup");
    assert_eq!(reread.size(), 3 * cluster as usize);
    let mut buf = vec![0u8; 3 * cluster as usize];
    assert_eq!(reread.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[..2 * cluster as usize].iter().all(|byte| *byte == 0x33));
    assert!(buf[2 * cluster as usize..].iter().all(|byte| *byte == 0));

    // The record it left carries a list, and both the `$DATA` that had to grow
    // and the filler that made room for the list are in a record of its own —
    // one the volume has spoken for, and which no directory names.
    let record = again.read_mft_record(FULL_FILE).expect("the record");
    let header = super::types::MftRecordHeader::parse(&record).expect("a header");
    let attributes = super::fs::parse_attributes(&record[header.size() as usize..]);
    assert!(
        attributes.iter().any(|attr| attr.attr_type == 0x20),
        "the record carries a list"
    );
    for moved_type in [0x80, 0xe0] {
        assert!(
            !attributes.iter().any(|attr| attr.attr_type == moved_type),
            "the attribute that moved has left it"
        );
    }
    let list = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x20)
        .expect("the list");
    let entries = super::fs::parse_attribute_list(&list.content);
    assert_eq!(
        entries.len(),
        4,
        "the standard information, the name, the data, and the filler"
    );
    let moved = entries
        .iter()
        .find(|entry| entry.attr_type == 0x80)
        .expect("the data's entry");
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.attr_type == 0xe0)
            .expect("the filler's entry")
            .holder,
        moved.holder,
        "and the filler went to the same record"
    );
    let holder = again
        .read_mft_record(moved.holder)
        .expect("the record they moved to");
    assert_eq!(
        u64::from_le_bytes([
            holder[32], holder[33], holder[34], holder[35], holder[36], holder[37], holder[38],
            holder[39]
        ]) & 0x0000_FFFF_FFFF_FFFF,
        FULL_FILE,
        "and that record says which record it belongs to"
    );
    let held = super::types::MftRecordHeader::parse(&holder).expect("a header");
    let held = super::fs::parse_attributes(&holder[held.size() as usize..]);
    for moved_type in [0x80, 0xe0] {
        assert!(
            held.iter().any(|attr| attr.attr_type == moved_type),
            "and holds what moved"
        );
    }

    // The volume has one more record in use than the fixture made.
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    let in_use: usize = bits.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = (0..RECORDS)
        .filter(|number| is_in_use(*number, false))
        .count();
    assert_eq!(in_use, was + 1, "the record the attributes went to");

    // And the `$DATA` that moved is one a writer can still change: a second
    // growth writes into the record it landed in.
    node.set_len(4 * cluster).expect("a second growth");
    assert_eq!(node.size(), 4 * cluster as usize);
}
#[test]
fn a_lookup_folds_case_through_the_volumes_table() {
    // A name is found by the case a real NTFS would find it by, because the
    // volume carries the table names are folded through.  Without it these
    // lookups are the bytes as they are stored and both are `NotFound`.
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);
    assert_eq!(
        fs_handle
            .lookup("/RESIDENT.TXT")
            .expect("at the root")
            .size(),
        5
    );
    assert_eq!(
        fs_handle
            .lookup("/Sub/Leaf.TXT")
            .expect("below a directory")
            .size(),
        4
    );
}

#[test]
fn a_created_file_is_on_the_volume() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.create_file("/new.txt").expect("create a file");
    assert_eq!(node.name(), "new.txt");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), 0);
    assert!(
        dirty_flag(&device, &fs_handle),
        "the volume says it is being changed"
    );

    // A second mount finds it: the name is in the index, and the record it
    // names is a record the volume holds.
    let again = remount(&device);
    let reread = again.lookup("/new.txt").expect("relookup");
    assert_eq!(reread.kind(), NodeKind::File);
    assert_eq!(reread.size(), 0);
    let mut buf = [0u8; 4];
    assert_eq!(reread.read(0, &mut buf).expect("read"), 0);

    // Its record is one the volume had formatted but not in use.
    let (number, _) = again.resolve("/new.txt").expect("resolve");
    assert_eq!(number, 16, "the first record past the volume's own");

    // And the volume's own list of what is in use names it, which is what a
    // volume that mounts this one afterwards would believe.
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[number as usize / 8] & (1 << (number % 8)),
        1 << (number % 8),
        "the MFT's bitmap claimed the record"
    );

    // And the root lists it, which is the index saying the same thing.
    let mut names = Vec::new();
    for index in 0.. {
        match again.read_dir("/", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    assert!(
        names.iter().any(|name| name == "new.txt"),
        "the root lists it: {names:?}"
    );
}

#[test]
fn a_new_name_is_placed_where_the_collation_puts_it() {
    // "a.txt" sorts before "B.txt" only when the names are folded: compared as
    // they are stored, 'B' is the smaller byte.  The fixture carries the
    // volume's `$UpCase` table, so the order is the format's.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_file("/a.txt").expect("create a.txt");
    fs_handle.create_file("/B.txt").expect("create B.txt");

    let again = remount(&device);
    let mut names = Vec::new();
    for index in 0.. {
        match again.read_dir("/", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    let a = names
        .iter()
        .position(|name| name == "a.txt")
        .expect("a.txt is listed");
    let b = names
        .iter()
        .position(|name| name == "B.txt")
        .expect("B.txt is listed");
    assert!(a < b, "the folded order comes first: {names:?}");
}

#[test]
fn a_name_that_is_already_there_is_not_created_twice() {
    let fixture = build_volume(FRACTIONAL);
    let (_device, fs_handle) = writable(&fixture);
    assert_eq!(
        fs_handle.create_file("/resident.txt").err(),
        Some(Error::AlreadyExists)
    );
    // A directory is there too, and it is found the same way.
    assert_eq!(
        fs_handle.create_file("/sub").err(),
        Some(Error::AlreadyExists)
    );
    assert_eq!(
        fs_handle.create_dir("/sub").err(),
        Some(Error::AlreadyExists)
    );
    assert_eq!(
        fs_handle.create_dir("/resident.txt").err(),
        Some(Error::AlreadyExists)
    );
}

#[test]
fn a_name_added_to_a_directory_grows_its_index_root() {
    // A small directory keeps its children in its index *root*, and a record
    // gives that value as much room as it has: a new name makes the value
    // longer, everything after the attribute shifts up, and the record goes
    // back whole — which is what a real volume does, and not an allocation
    // block.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    assert_eq!(
        fs_handle
            .read_dir("/sub", 0)
            .expect("the entry it had")
            .name,
        "leaf.txt"
    );
    fs_handle
        .create_file("/sub/another.txt")
        .expect("a name in a directory whose record has room");

    // A second mount reads the new entry, and the one next to it too: growing
    // the value moved what followed it rather than losing it.
    let again = remount(&device);
    assert_eq!(
        again
            .lookup("/sub/another.txt")
            .expect("the new entry")
            .size(),
        0
    );
    assert_eq!(
        again
            .lookup("/sub/leaf.txt")
            .expect("the entry it had")
            .size(),
        4
    );
    let mut names = Vec::new();
    for index in 0.. {
        match again.read_dir("/sub", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    assert!(names.iter().any(|name| name == "another.txt"), "{names:?}");
    assert!(names.iter().any(|name| name == "leaf.txt"), "{names:?}");
}

#[test]
fn a_name_a_full_record_has_no_room_for_makes_its_own_room() {
    // A directory whose record *is* full: the value the name goes into cannot
    // grow there, and the room is made the way a file's is — an attribute moves
    // into a record of its own, and an `$ATTRIBUTE_LIST` says where.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .create_file("/full-dir/another.txt")
        .expect("a name in a directory whose record is full");

    // A second mount finds the name, and the directory it is in still reads.
    let again = remount(&device);
    assert_eq!(
        again
            .lookup("/full-dir/another.txt")
            .expect("the new name")
            .size(),
        0
    );
    let mut names = Vec::new();
    for index in 0.. {
        match again.read_dir("/full-dir", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    assert!(names.iter().any(|name| name == "another.txt"), "{names:?}");

    // The record carried a list *before* the name arrived — an attribute had
    // moved out of it once already — so this was the list being *extended*: the
    // index root is what needed the room, it is what moved, and its entry now
    // names the record it went to.
    let record = again.read_mft_record(FULL_DIRECTORY).expect("the record");
    let header = super::types::MftRecordHeader::parse(&record).expect("a header");
    let attributes = super::fs::parse_attributes(&record[header.size() as usize..]);
    assert!(
        !attributes
            .iter()
            .any(|attr| attr.attr_type == 0x90 || attr.attr_type == 0x90),
        "the index root has left the record"
    );
    let list = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x20)
        .expect("the list it already had");
    let entries = super::fs::parse_attribute_list(&list.content);
    assert_eq!(entries.len(), 4, "and names the same four attributes");
    let root = entries
        .iter()
        .find(|entry| entry.attr_type == 0x90)
        .expect("the index root's entry");
    assert_ne!(
        root.holder, FULL_DIRECTORY,
        "which is no longer the record the list is in"
    );
    let holder = again
        .read_mft_record(root.holder)
        .expect("the record it moved to");
    let held = super::types::MftRecordHeader::parse(&holder).expect("a header");
    assert!(
        super::fs::parse_attributes(&holder[held.size() as usize..])
            .iter()
            .any(|attr| attr.attr_type == 0x90),
        "and holds it"
    );
    assert!(
        entries
            .iter()
            .filter(|entry| entry.attr_type == 0xe0)
            .all(|entry| entry.holder == FULL_DIRECTORY),
        "while the filler stayed"
    );
}

/// Every name a directory lists, in the order it lists them.
fn the_listing(fs_handle: &super::NtfsFs, path: &str) -> Vec<String> {
    let mut names = Vec::new();
    for index in 0.. {
        match fs_handle.read_dir(path, index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    names
}

/// A record's bytes as the volume holds them — packed, the update sequence
/// still at every sector's end — which is what a crash leaves and what a test
/// that recreates one writes back.
fn record_as_the_volume_holds_it(
    fs_handle: &super::NtfsFs,
    device: &alloc::sync::Arc<crate::fs::block::MemoryBlockDevice>,
    number: u64,
) -> Vec<u8> {
    let (at, size) = {
        let info = fs_handle.info().lock();
        (
            fs_handle
                .record_offset(&info, number)
                .expect("the record's offset"),
            info.mft_record_size as usize,
        )
    };
    let mut bytes = alloc::vec![0u8; size];
    let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
    super::fs::read_device_bytes(&as_device, at, &mut bytes).expect("read the record");
    bytes
}

#[test]
fn entries_that_filled_two_records_leave_for_a_block() {
    // A directory whose record is full moves its index root into a record of
    // its own — the way a file's attribute moves — and when *that* record
    // fills with entries too, the format's answer is the allocation block:
    // every entry leaves for a block of their own, and the root's node keeps
    // only the pointer to it.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);

    // Names until the flip, keeping the bytes of the two records as they were
    // the moment before it: those bytes are what a crash between the flip's
    // own writes leaves.
    let mut names: Vec<String> = Vec::new();
    let mut before_the_flip: Option<(Vec<u8>, Vec<u8>)> = None;
    for index in 0..40 {
        let name = alloc::format!("filled-{index:02}.txt");
        let holder = fs_handle
            .attributes_of(FULL_DIRECTORY)
            .expect("the attributes")
            .iter()
            .find(|attr| attr.attr_type == 0x90)
            .expect("the index root")
            .holder;
        let before = (
            record_as_the_volume_holds_it(&fs_handle, &device, FULL_DIRECTORY),
            record_as_the_volume_holds_it(&fs_handle, &device, holder),
        );
        fs_handle
            .create_file(&alloc::format!("/full-dir/{name}"))
            .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
        names.push(name);
        let flipped = fs_handle
            .attributes_of(FULL_DIRECTORY)
            .expect("the attributes")
            .iter()
            .any(|attr| attr.attr_type == 0xa0 && !attr.data_runs.is_empty());
        if flipped {
            before_the_flip = Some(before);
            break;
        }
    }
    let Some((base_before, holder_before)) = before_the_flip else {
        panic!("the entries left for a block within forty names");
    };

    // Two more names land in the block, and one of them goes again.
    fs_handle.create_file("/full-dir/after-a.txt").expect("a");
    fs_handle.create_file("/full-dir/after-b.txt").expect("b");
    fs_handle
        .remove_path("/full-dir/after-a.txt")
        .expect("a goes");
    names.push(String::from("after-b.txt"));

    // A second mount lists every name that is still there, and finds each by
    // its path: the walk descends the root's pointer into the block.
    let again = remount(&device);
    for name in &names {
        again
            .lookup(&alloc::format!("/full-dir/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    let listed = the_listing(&again, "/full-dir");
    assert_eq!(listed.len(), names.len(), "{listed:?}");

    // The volume's own shape: the two attributes that describe the allocation
    // live in a record of their own, the base's list names them there, and
    // the index bitmap says the one block is in use.
    let attributes = again.attributes_of(FULL_DIRECTORY).expect("the attributes");
    let holder = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x90)
        .expect("the root")
        .holder;
    let allocation = attributes
        .iter()
        .find(|attr| attr.attr_type == 0xa0)
        .expect("the allocation");
    let bitmap = attributes
        .iter()
        .find(|attr| attr.attr_type == 0xb0)
        .expect("the index bitmap");
    assert_ne!(holder, FULL_DIRECTORY, "the root left the base record");
    assert_ne!(
        allocation.holder, holder,
        "the allocation is not where the root is"
    );
    assert_eq!(allocation.holder, bitmap.holder, "the two are together");
    assert_eq!(bitmap.content.first(), Some(&1), "the one block's bit");
    let block_size = again.info().lock().index_block_size as u64;
    assert_eq!(allocation.data_size as u64, block_size, "one block");
    let base_record = again.read_mft_record(FULL_DIRECTORY).expect("the base");
    let base_header = super::types::MftRecordHeader::parse(&base_record).expect("a header");
    let list = super::fs::parse_attributes(&base_record[base_header.size() as usize..])
        .into_iter()
        .find(|attr| attr.attr_type == 0x20)
        .expect("the list");
    for attr_type in [0xa0, 0xb0] {
        let entry = super::fs::parse_attribute_list(&list.content)
            .into_iter()
            .find(|entry| entry.attr_type == attr_type)
            .unwrap_or_else(|| panic!("the list names {attr_type:#x}"));
        assert_eq!(entry.holder, allocation.holder, "where the two went");
    }

    // The crash a listing survives: the two records as they were before the
    // flip are the state between the flip's writes — the record and the block
    // down, the list not yet naming them, the root's node not yet pointing —
    // and a mount lists the names the root's value still holds.  The records
    // the names had claimed stay claimed, which is the leak the order was
    // chosen for.
    {
        let info = again.info().lock();
        let base_at = again
            .record_offset(&info, FULL_DIRECTORY)
            .expect("the base");
        let holder_at = again.record_offset(&info, holder).expect("the holder");
        drop(info);
        let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
        super::fs::write_device_bytes(&as_device, base_at, &base_before).expect("the base back");
        super::fs::write_device_bytes(&as_device, holder_at, &holder_before)
            .expect("the holder back");
    }
    let recovered = remount(&device);
    let flipping_name = names
        .iter()
        .rev()
        .find(|name| name.starts_with("filled-"))
        .expect("the flipping name")
        .clone();
    let still_there: Vec<String> = names
        .iter()
        .filter(|name| **name != flipping_name && **name != "after-b.txt")
        .cloned()
        .collect();
    let relisted = the_listing(&recovered, "/full-dir");
    assert_eq!(relisted.len(), still_there.len(), "{relisted:?}");
    for name in &still_there {
        assert!(relisted.contains(name), "{name} missing: {relisted:?}");
    }
    assert!(!relisted.contains(&flipping_name), "{relisted:?}");
}

#[test]
fn a_small_directory_that_fills_a_moved_root_fills_a_block_next() {
    // The subdirectory's entries begin in its index root, and a name at a
    // time grows that value until its record is full — the root moves into a
    // record of its own, which is the way a file's attribute moves — and the
    // record fills with entries in its turn.  What a volume does then is keep
    // the entries in an allocation block, and so does this one.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);

    let mut names = vec![String::from("leaf.txt")];
    let mut flipped = false;
    for index in 0..40 {
        let name = alloc::format!("grown-{index:02}.txt");
        fs_handle
            .create_file(&alloc::format!("/sub/{name}"))
            .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
        names.push(name);
        flipped = fs_handle
            .attributes_of(SUBDIRECTORY)
            .expect("the attributes")
            .iter()
            .any(|attr| attr.attr_type == 0xa0 && !attr.data_runs.is_empty());
        if flipped {
            break;
        }
    }
    assert!(flipped, "the entries left for a block within forty names");

    // A second mount finds every name — the last few through the root's
    // pointer into the block — and the shape the volume now keeps: the base
    // record holds the list and nothing of the index but that, and the root
    // and the two attributes that describe the allocation are in records of
    // their own.
    let again = remount(&device);
    for name in &names {
        again
            .lookup(&alloc::format!("/sub/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    let listed = the_listing(&again, "/sub");
    assert_eq!(listed.len(), names.len(), "{listed:?}");

    let attributes = again.attributes_of(SUBDIRECTORY).expect("the attributes");
    let holder = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x90)
        .expect("the root")
        .holder;
    let allocation = attributes
        .iter()
        .find(|attr| attr.attr_type == 0xa0)
        .expect("the allocation");
    assert_ne!(holder, SUBDIRECTORY, "the root left the base record");
    assert_ne!(allocation.holder, SUBDIRECTORY, "and so did the allocation");
    assert_ne!(allocation.holder, holder, "each in a record of its own");
    let base_record = again.read_mft_record(SUBDIRECTORY).expect("the base");
    let base_header = super::types::MftRecordHeader::parse(&base_record).expect("a header");
    let inline = super::fs::parse_attributes(&base_record[base_header.size() as usize..]);
    assert!(
        !inline.iter().any(|attr| {
            attr.attr_type == 0x90 || attr.attr_type == 0xa0 || attr.attr_type == 0xb0
        }),
        "the index left the base record entirely: {inline:?}"
    );
    assert!(
        inline.iter().any(|attr| attr.attr_type == 0x20),
        "the list is what stayed"
    );

    // And the block fills in its turn.  This is the split's own case with the
    // node above the blocks living in a record of its own — a different record
    // from the directory's — so the key the split promotes is written there and
    // the block it makes is a block of the allocation.
    let before = index_blocks_in_use(&fs_handle, SUBDIRECTORY);
    let pad = "p".repeat(60);
    for index in 0..40 {
        let name = alloc::format!("split-{index:03}-{pad}.txt");
        fs_handle
            .create_file(&alloc::format!("/sub/{name}"))
            .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
        names.push(name);
        if index_blocks_in_use(&fs_handle, SUBDIRECTORY) > before {
            break;
        }
    }
    assert_eq!(
        index_blocks_in_use(&fs_handle, SUBDIRECTORY),
        before + 1,
        "the block split within forty names"
    );

    let again = remount(&device);
    for name in &names {
        again
            .lookup(&alloc::format!("/sub/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    assert_eq!(
        the_listing(&again, "/sub").len(),
        names.len(),
        "every name is listed once"
    );

    // A name comes back out with the node above in that record too: the same
    // walk — the entry's own block, or the key the split promoted — with the
    // node above where the list put it.
    let gone = names.pop().expect("the name the split made last");
    fs_handle
        .remove_path(&alloc::format!("/sub/{gone}"))
        .expect("a name comes out again");
    let again = remount(&device);
    assert!(
        matches!(
            again.lookup(&alloc::format!("/sub/{gone}")),
            Err(Error::NotFound)
        ),
        "the name that went is not there"
    );
    for name in &names {
        again
            .lookup(&alloc::format!("/sub/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    assert_eq!(
        the_listing(&again, "/sub").len(),
        names.len(),
        "and nothing else moved"
    );
}

#[test]
fn a_file_can_be_renamed_where_it_is() {
    // A name lives twice: in the parent's index and in the record's own
    // `$FILE_NAME`.  A rename moves both, and a second mount is what says so.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .rename("/resident.txt", "/renamed.txt")
        .expect("rename");

    let again = remount(&device);
    let node = again.lookup("/renamed.txt").expect("the new name");
    assert_eq!(node.name(), "renamed.txt");
    let mut buf = vec![0u8; 5];
    assert_eq!(node.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf, b"hello", "the file is the file it was");
    assert!(matches!(
        again.lookup("/resident.txt"),
        Err(Error::NotFound)
    ));
    let listed = the_listing(&again, "/");
    assert!(listed.contains(&String::from("renamed.txt")), "{listed:?}");
    assert!(
        !listed.contains(&String::from("resident.txt")),
        "{listed:?}"
    );

    // The record's own name is the new one, and the parent it names is the
    // record it is still in.
    let attributes = again.attributes_of(RESIDENT_FILE).expect("the attributes");
    let name = super::fs::get_best_filename(&attributes).expect("the record's name");
    assert_eq!(name.name, "renamed.txt");
    assert_eq!(name.parent_directory & 0xFFFF_FFFF_FFFF, ROOT_RECORD);
}

#[test]
fn a_file_can_be_moved_to_another_directory() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .rename("/resident.txt", "/sub/moved.txt")
        .expect("move it");

    let again = remount(&device);
    let node = again.lookup("/sub/moved.txt").expect("its new path");
    let mut buf = vec![0u8; 5];
    assert_eq!(node.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf, b"hello");
    assert!(matches!(
        again.lookup("/resident.txt"),
        Err(Error::NotFound)
    ));
    assert!(!the_listing(&again, "/").contains(&String::from("resident.txt")));
    assert!(the_listing(&again, "/sub").contains(&String::from("moved.txt")));

    // The record names the directory it moved into.
    let attributes = again.attributes_of(RESIDENT_FILE).expect("the attributes");
    let name = super::fs::get_best_filename(&attributes).expect("the record's name");
    assert_eq!(name.name, "moved.txt");
    assert_eq!(name.parent_directory & 0xFFFF_FFFF_FFFF, SUBDIRECTORY);
}

#[test]
fn a_directory_can_be_renamed_with_what_it_holds_untouched() {
    // A directory's number does not change, so nothing inside it moves: the
    // name it is listed by is the only thing that does.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.rename("/sub", "/renamed").expect("rename it");

    let again = remount(&device);
    assert_eq!(
        again.lookup("/renamed").expect("the new name").kind(),
        NodeKind::Directory
    );
    let leaf = again.lookup("/renamed/leaf.txt").expect("its child");
    assert_eq!(leaf.size(), 4);
    assert!(matches!(again.lookup("/sub"), Err(Error::NotFound)));
    let listed = the_listing(&again, "/");
    assert!(listed.contains(&String::from("renamed")), "{listed:?}");
    assert!(!listed.contains(&String::from("sub")), "{listed:?}");
}

#[test]
fn a_name_in_a_tree_moves_with_its_record() {
    // A rename is the two index changes and the record's own `$FILE_NAME`, and
    // a directory whose index is a tree is no different: the new name is routed
    // to the block its key belongs in, and the old one comes out of whichever
    // node holds it — a promoted key included, which is the entry a split put
    // in the node above.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    // A name a block holds.
    fs_handle
        .rename("/tree/alpha.txt", "/tree/zebra.txt")
        .expect("a name a block holds");
    // And the promoted key itself, which lives in the node above.
    fs_handle
        .rename("/tree/middle.txt", "/tree/native.txt")
        .expect("a name the node above holds");

    let again = remount(&device);
    assert_eq!(
        the_listing(&again, "/tree"),
        [
            String::from("native.txt"),
            String::from("omega.txt"),
            String::from("zebra.txt"),
        ],
        "the names a rename left, in the tree's order"
    );
    for name in ["native.txt", "omega.txt", "zebra.txt"] {
        again
            .lookup(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    for gone in ["alpha.txt", "middle.txt"] {
        assert!(
            matches!(
                again.lookup(&alloc::format!("/tree/{gone}")),
                Err(Error::NotFound)
            ),
            "{gone} is not a name any more"
        );
    }
}

/// Take the name a record's index entry gives, and the name its **own** bytes
/// carry, so a rename can be checked in both places.
fn the_name_the_record_carries(fs_handle: &super::NtfsFs, record: u64) -> String {
    let name = fs_handle
        .attributes_of(record)
        .expect("the attributes")
        .into_iter()
        .find(|attribute| attribute.attr_type == 0x30)
        .expect("the record's own name");
    super::types::FileName::parse(&name.content)
        .expect("a name value")
        .name
}

#[test]
fn a_rename_writes_a_name_that_an_attribute_list_moved() {
    // A record's own `$FILE_NAME` is not always in the record: one that filled
    // up moves the name into an extension record, and an `$ATTRIBUTE_LIST`
    // says where it went.  A rename writes the name **there** — the record the
    // list names, not the one the file is — and the index entry with it, so a
    // second mount finds the new name by its path and reads the new name out
    // of the extension record.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let holder = fs_handle
        .attributes_of(NAMED_FILE)
        .expect("the attributes")
        .into_iter()
        .find(|attribute| attribute.attr_type == 0x30)
        .expect("the name")
        .holder;
    assert_eq!(
        holder, NAMED_FILE_EXT,
        "the name is in the extension record"
    );
    assert_eq!(
        the_name_the_record_carries(&fs_handle, NAMED_FILE),
        "named.bin"
    );

    fs_handle
        .rename("/named.bin", "/renamed.bin")
        .expect("rename it");

    let again = remount(&device);
    assert_eq!(
        again.resolve("/renamed.bin").expect("the new name").0,
        NAMED_FILE
    );
    assert!(matches!(again.lookup("/named.bin"), Err(Error::NotFound)));
    assert_eq!(
        the_name_the_record_carries(&again, NAMED_FILE),
        "renamed.bin",
        "and the name it carries is the new one"
    );
    assert!(
        again
            .attributes_of(NAMED_FILE)
            .expect("the attributes")
            .into_iter()
            .find(|attribute| attribute.attr_type == 0x30)
            .expect("the name")
            .holder
            == NAMED_FILE_EXT,
        "still where the list says it is"
    );
}

#[test]
fn a_name_that_is_taken_is_not_renamed_onto() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    assert_eq!(
        fs_handle.rename("/resident.txt", "/two-runs.bin"),
        Err(Error::AlreadyExists)
    );

    // And nothing moved: the file is where it was, and the name it did not
    // take still names the record it did.
    let again = remount(&device);
    assert_eq!(
        again.lookup("/resident.txt").expect("still there").size(),
        5
    );
    assert_eq!(
        again.lookup("/two-runs.bin").expect("untouched").size(),
        3 * fixture.cluster_size() as usize
    );
}

#[test]
fn a_change_of_spelling_is_a_change_of_name() {
    // Two names that fold together are one key in the index, so the old
    // spelling has to leave before the new one arrives — and the record's own
    // name carries the spelling the caller asked for.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .rename("/resident.txt", "/RESIDENT.TXT")
        .expect("respell it");

    let again = remount(&device);
    assert_eq!(
        again
            .lookup("/RESIDENT.TXT")
            .expect("the new spelling")
            .size(),
        5
    );
    let listed = the_listing(&again, "/");
    assert!(listed.contains(&String::from("RESIDENT.TXT")), "{listed:?}");
    assert!(
        !listed.contains(&String::from("resident.txt")),
        "{listed:?}"
    );
    let attributes = again.attributes_of(RESIDENT_FILE).expect("the attributes");
    assert_eq!(
        super::fs::get_best_filename(&attributes)
            .expect("the record's name")
            .name,
        "RESIDENT.TXT"
    );
}

#[test]
fn a_directory_is_not_moved_into_itself() {
    let fixture = build_volume(FRACTIONAL);
    let (_device, fs_handle) = writable(&fixture);
    assert_eq!(
        fs_handle.rename("/sub", "/sub/inside"),
        Err(Error::InvalidArgument),
        "a tree no walk can leave"
    );
    assert_eq!(
        fs_handle.rename("/resident.txt", "/two-runs.bin/inner"),
        Err(Error::InvalidArgument),
        "and a name is not put in a file"
    );
    assert_eq!(
        fs_handle.rename("/resident.txt", "/two-runs.bin"),
        Err(Error::AlreadyExists),
        "and a name another record has is taken"
    );
    assert_eq!(
        fs_handle.rename("/", "/elsewhere"),
        Err(Error::InvalidArgument),
        "the root has no name to change"
    );
}

#[test]
fn a_name_too_long_for_its_record_makes_room() {
    // The record is full, so the record's own name has nowhere to grow: the
    // largest attribute that is not the name moves into a record of its own,
    // and the name follows into the room it left.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let long = "a-name-so-long-that-the-record-cannot-hold-it.txt";
    fs_handle
        .rename("/full.bin", &alloc::format!("/{long}"))
        .expect("rename it");

    let again = remount(&device);
    assert_eq!(
        again
            .lookup(&alloc::format!("/{long}"))
            .expect("the new name")
            .size(),
        2 * fixture.cluster_size() as usize
    );
    assert!(matches!(again.lookup("/full.bin"), Err(Error::NotFound)));
    let base_record = again.read_mft_record(FULL_FILE).expect("the record");
    let base_header = super::types::MftRecordHeader::parse(&base_record).expect("a header");
    assert!(
        super::fs::parse_attributes(&base_record[base_header.size() as usize..])
            .iter()
            .any(|attr| attr.attr_type == 0x20),
        "the record made room by the route that leaves a list"
    );
}

/// The index bitmap of the directory whose bitmap is a **file**, read where its
/// runs say: which blocks the directory's own bits name as in use.
fn running_index_bits(fs_handle: &super::NtfsFs) -> Vec<u8> {
    let bitmap = fs_handle
        .attributes_of(RUNNING_INDEX_DIRECTORY)
        .expect("the attributes")
        .into_iter()
        .find(|attribute| attribute.attr_type == 0xb0)
        .expect("the index bitmap");
    assert!(
        bitmap.data_runs_offset.is_some(),
        "the fixture's bitmap is a file"
    );
    let info = fs_handle.info().lock();
    let mut bits = alloc::vec![0u8; bitmap.data_size as usize];
    super::fs::read_from_runs(
        fs_handle.device(),
        &info,
        &bitmap.data_runs,
        u64::from(bitmap.data_size),
        0,
        &mut bits,
    )
    .expect("read the bitmap where its runs say");
    bits
}

/// Create names in that directory until its block fills and splits, and answer
/// the names made.
fn fill_the_running_index(fs_handle: &super::NtfsFs) -> Vec<String> {
    let pad = "p".repeat(60);
    let mut names = Vec::new();
    let before = running_index_bits(fs_handle)[0].count_ones();
    for index in 0..60 {
        let name = alloc::format!("rune-{index:03}-{pad}.txt");
        fs_handle
            .create_file(&alloc::format!("/running-index/{name}"))
            .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
        names.push(name);
        if running_index_bits(fs_handle)[0].count_ones() > before {
            break;
        }
    }
    names
}

/// How many bytes of blocks a directory's `$INDEX_ALLOCATION` holds.
fn index_allocation_size(fs_handle: &super::NtfsFs, record: u64) -> u64 {
    fs_handle
        .attributes_of(record)
        .expect("the attributes")
        .iter()
        .find(|attribute| attribute.attr_type == 0xa0)
        .expect("the allocation")
        .data_size as u64
}

/// A directory's index bitmap, as the record holds it.
fn index_bitmap(fs_handle: &super::NtfsFs, record: u64) -> Vec<u8> {
    fs_handle
        .attributes_of(record)
        .expect("the attributes")
        .into_iter()
        .find(|attribute| attribute.attr_type == 0xb0)
        .expect("the index bitmap")
        .content
}

/// How many blocks a directory's index bitmap says are in use.
///
/// One rises with every split and falls with every block a deletion gives back,
/// which is what makes it the signal a test can watch: the allocation's own
/// size does not move when the split takes a block that was already there.
fn index_blocks_in_use(fs_handle: &super::NtfsFs, record: u64) -> u32 {
    index_bitmap(fs_handle, record)
        .iter()
        .map(|byte| byte.count_ones())
        .sum()
}

/// Create names in the tree directory until one of its blocks fills and splits,
/// and answer the names it made.
///
/// The names are long on purpose.  An index entry is mostly its name, so long
/// ones fill a block after a handful of creations — and a handful the fixture's
/// own MFT has free records for.  Short names would need some thirty-five
/// creations, and this volume runs out of records before the block runs out of
/// room, so the split would never be reached.
fn fill_the_tree(fs_handle: &super::NtfsFs) -> Vec<String> {
    let pad = "p".repeat(60);
    let mut names = Vec::new();
    let before = index_blocks_in_use(fs_handle, TREE_DIRECTORY);
    for index in 0..60 {
        let name = alloc::format!("many-{index:03}-{pad}.txt");
        fs_handle
            .create_file(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("create {name}: {error:?}"));
        names.push(name);
        if index_blocks_in_use(fs_handle, TREE_DIRECTORY) > before {
            break;
        }
    }
    names
}

#[test]
fn a_directory_whose_index_is_a_tree_lists_in_tree_order() {
    // A directory whose index is a **tree**: two blocks with the key that
    // separates them in the root's node — the shape a directory of many names
    // has, measured on a volume `mkntfs` makes.  The key's own record lives in
    // the root and in no block, because a split promotes it, so a walk has to
    // take the children *and* the keys, in the order they sort in.
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);
    assert_eq!(
        the_listing(&fs_handle, "/tree"),
        [
            String::from("alpha.txt"),
            String::from("middle.txt"),
            String::from("omega.txt"),
        ],
        "the tree's names, in the order the tree keeps them"
    );

    // Every name is found, whichever node holds it — and the promoted key is a
    // name like any other, with its own record.
    for (name, record) in [
        ("alpha.txt", TREE_ALPHA),
        ("middle.txt", TREE_MIDDLE),
        ("omega.txt", TREE_OMEGA),
    ] {
        let node = fs_handle
            .lookup(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
        assert_eq!(node.kind(), NodeKind::File);
        assert_eq!(
            fs_handle
                .resolve(&alloc::format!("/tree/{name}"))
                .expect("resolve")
                .0,
            record,
            "the name names the record it names"
        );
    }
}

#[test]
fn a_tree_directory_takes_a_name_where_it_belongs() {
    // A tree routes by key, so an insertion reaches the block the name belongs
    // in: a name below the promoted key goes to the block that holds the lesser
    // ones, and a name above it to the one with no key over it.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_file("/tree/aardvark.txt").expect("below");
    fs_handle.create_file("/tree/zulu.txt").expect("above");
    fs_handle
        .remove_path("/tree/omega.txt")
        .expect("a leaf's name comes out");

    // A second mount lists them in the tree's order — the promoted key still in
    // the middle of it — and finds each name by its path.
    let again = remount(&device);
    assert_eq!(
        the_listing(&again, "/tree"),
        [
            String::from("aardvark.txt"),
            String::from("alpha.txt"),
            String::from("middle.txt"),
            String::from("zulu.txt"),
        ],
        "in the order the tree keeps them"
    );
    for name in ["aardvark.txt", "middle.txt", "zulu.txt"] {
        again
            .lookup(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    assert!(matches!(
        again.lookup("/tree/omega.txt"),
        Err(Error::NotFound)
    ));
}

#[test]
fn an_index_bitmap_that_is_a_file_holds_the_directory_s_blocks() {
    // A directory's index bitmap is a value in its record until it outgrows
    // one, and then it is a **file** of its own.  The fixture's directory is
    // that shape, and the bits are read where its runs say both times a change
    // asks: looking for a block a split can take again, and setting the bit the
    // block it made needs.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    assert_eq!(
        running_index_bits(&fs_handle)[0] & 0b1,
        0b1,
        "the fixture's one block is in use, in a bitmap with runs"
    );
    assert_eq!(
        the_listing(&fs_handle, "/running-index"),
        [String::from("rune.txt")],
        "and the block the root points at is the one read"
    );

    // Filling it splits it: the split looks for a free block in the bitmap —
    // the file's bit 0 is set, so there is none to take — appends the block
    // after the allocation's own, and sets that block's bit where the runs say.
    let created = fill_the_running_index(&fs_handle);
    assert_eq!(
        running_index_bits(&fs_handle)[0] & 0b11,
        0b11,
        "the block the split made, in the bitmap that is a file"
    );

    let again = remount(&device);
    let mut expected = created;
    expected.push(String::from("rune.txt"));
    expected.sort();
    assert_eq!(
        the_listing(&again, "/running-index"),
        expected,
        "every name is still there, read through the second block"
    );

    // And a bit past the value it has: the bitmap is one byte, the block
    // numbered eight needs the second, and the growth goes through the runs
    // that hold it — one cluster's worth of room, which is what a file's
    // clusters are for.
    let blocks = index_allocation_size(&fs_handle, RUNNING_INDEX_DIRECTORY);
    fs_handle
        .set_index_block_bit(RUNNING_INDEX_DIRECTORY, 8, true)
        .expect("a bit past the last byte");
    let bits = running_index_bits(&fs_handle);
    assert_eq!(bits.len(), 2, "the byte the bit needed");
    assert_eq!(bits[1] & 0b1, 0b1, "and the bit in it");
    assert_eq!(
        index_allocation_size(&fs_handle, RUNNING_INDEX_DIRECTORY),
        blocks,
        "the bitmap's own growth did not touch the allocation's blocks"
    );
}

#[test]
fn a_full_block_splits_and_promotes_its_middle_key() {
    // A block that fills with names is what the format splits: half its entries
    // go to a block of their own, the entry between the halves becomes a key of
    // the node above, and the index bitmap gains a bit for the new block.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let before = index_allocation_size(&fs_handle, TREE_DIRECTORY);
    let names = fill_the_tree(&fs_handle);

    // One more block, and its bit in the index bitmap.
    let block_size = fs_handle.info().lock().index_block_size as u64;
    assert_eq!(
        index_allocation_size(&fs_handle, TREE_DIRECTORY),
        before + block_size,
        "the block the split made"
    );
    let bitmap = index_bitmap(&fs_handle, TREE_DIRECTORY);
    // The tree's bitmap was one byte, and the block the split made is the
    // allocation's ninth: its bit needs a byte the value did not have, so the
    // value grew rather than the bit being dropped.
    assert_eq!(bitmap.len(), 2, "the byte the new block's bit needs");
    assert_eq!(bitmap[1] & 0b1, 0b1, "and its bit");

    // A second mount lists every name in the tree's order — the key the split
    // promoted among them — and finds each of them by its path.
    let again = remount(&device);
    let listed = the_listing(&again, "/tree");
    let mut every = names.clone();
    every.extend([
        String::from("alpha.txt"),
        String::from("middle.txt"),
        String::from("omega.txt"),
    ]);
    assert_eq!(listed.len(), every.len(), "{listed:?}");
    let mut sorted = every;
    sorted.sort();
    assert_eq!(listed, sorted, "the tree's order is the names' order");
    for name in &listed {
        again
            .lookup(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
}

#[test]
fn a_block_a_deletion_gave_back_is_taken_again() {
    // A block that a merge gave back is not left to waste.  The next split takes
    // it rather than growing the allocation, because a block that is already the
    // allocation's is one the volume's clusters are already claimed for — and a
    // directory whose index only ever grew would keep claiming clusters for
    // blocks nothing is stored in.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let before = index_allocation_size(&fs_handle, TREE_DIRECTORY);
    assert_eq!(
        index_blocks_in_use(&fs_handle, TREE_DIRECTORY),
        8,
        "the fixture's eight bits"
    );

    // The name in the tree's second block comes out, the block is empty, and
    // the two merge: one bit in the index bitmap goes with the block.
    fs_handle
        .remove_path("/tree/omega.txt")
        .expect("a block's name comes out");
    assert_eq!(
        index_bitmap(&fs_handle, TREE_DIRECTORY)[0] & 0b11,
        0b01,
        "the bit came back"
    );
    assert_eq!(
        index_blocks_in_use(&fs_handle, TREE_DIRECTORY),
        7,
        "one block fewer"
    );

    // Filling a block again splits, and the block that went is the one the tree
    // takes: the allocation does not grow, and the bit is set again.
    let made = fill_the_tree(&fs_handle);
    assert_eq!(
        index_allocation_size(&fs_handle, TREE_DIRECTORY),
        before,
        "the allocation did not grow"
    );
    assert_eq!(
        index_bitmap(&fs_handle, TREE_DIRECTORY)[0] & 0b11,
        0b11,
        "the block is back"
    );

    // And a second mount lists every name the directory holds, in order.
    let again = remount(&device);
    let mut expected = made;
    expected.extend([String::from("alpha.txt"), String::from("middle.txt")]);
    expected.sort();
    assert_eq!(
        the_listing(&again, "/tree"),
        expected,
        "every name is still there"
    );
}

#[test]
fn a_promoted_key_comes_out_and_its_block_gives_way() {
    // The name a split promoted lives in the node above the blocks, and taking
    // it out is a key coming out of a node that has children.  Its entry
    // carries the child whose keys are less than it, so the entry cannot simply
    // go: what takes its place is that child's **last** name, the key's
    // predecessor, which is then taken out of the block — and the block it
    // leaves may be one the tree no longer has to keep.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .remove_path("/tree/middle.txt")
        .expect("a promoted key comes out");

    // Every other name is where it was, the one that went is not there, and a
    // second mount agrees.
    let again = remount(&device);
    assert_eq!(
        the_listing(&again, "/tree"),
        [String::from("alpha.txt"), String::from("omega.txt")],
        "the predecessor took the key's place and stayed a name"
    );
    for name in ["alpha.txt", "omega.txt"] {
        again
            .lookup(&alloc::format!("/tree/{name}"))
            .unwrap_or_else(|error| panic!("lookup {name}: {error:?}"));
    }
    assert!(matches!(
        again.lookup("/tree/middle.txt"),
        Err(Error::NotFound)
    ));

    // The block the key's child was in held nothing once the predecessor left
    // it, and what the two blocks hold fits one again: the block next to it is
    // given back, and its bit in the index bitmap goes with it.
    assert_eq!(
        index_bitmap(&again, TREE_DIRECTORY)[0] & 0b11,
        0b01,
        "the block that went back"
    );
}

#[test]
fn a_block_that_empties_moves_its_key_down_and_gives_its_bit_back() {
    // A block whose last name comes out holds nothing, and the key that
    // separated it from the block before it moves *down* into that block: the
    // name stays a name, the tree keeps its order, and the empty block is given
    // back.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle
        .remove_path("/tree/omega.txt")
        .expect("a block's name comes out");

    let again = remount(&device);
    assert_eq!(
        the_listing(&again, "/tree"),
        [String::from("alpha.txt"), String::from("middle.txt")],
        "the key moved down and is still a name"
    );
    assert!(matches!(
        again.lookup("/tree/omega.txt"),
        Err(Error::NotFound)
    ));
    assert_eq!(
        index_bitmap(&again, TREE_DIRECTORY)[0] & 0b11,
        0b01,
        "the block that went back"
    );
}

#[test]
fn a_pair_that_still_needs_two_blocks_is_not_merged() {
    // A block is merged back with its neighbour only when what the two hold
    // fits one block: after a split the two halves are nearly full, and taking
    // one name out of them is not enough for that — so the tree keeps its shape
    // and neither block's bit is given back.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let mut names = fill_the_tree(&fs_handle);
    names.extend([
        String::from("alpha.txt"),
        String::from("middle.txt"),
        String::from("omega.txt"),
    ]);
    assert_eq!(
        index_bitmap(&fs_handle, TREE_DIRECTORY)[0] & 0b11,
        0b11,
        "the tree's two blocks are in use"
    );

    // A name that sorts below every one the split made goes into the block the
    // promoted key points at, and taking it out again leaves that block and its
    // neighbour as full as they were — too full for the two to be one.
    fs_handle
        .create_file("/tree/aardvark.txt")
        .expect("a name below the split's");
    fs_handle
        .remove_path("/tree/aardvark.txt")
        .expect("and out again");
    assert_eq!(
        index_bitmap(&fs_handle, TREE_DIRECTORY)[0] & 0b11,
        0b11,
        "neither block was given back: the pair still needs two"
    );

    let again = remount(&device);
    names.sort();
    assert_eq!(
        the_listing(&again, "/tree"),
        names,
        "every other name is still there, in the tree's order"
    );
}

#[test]
fn a_file_made_empty_takes_a_small_write_where_it_lies() {
    // A file made empty is *resident*: its bytes are in its record, which is
    // where an empty file lives.  A small write grows that value where it
    // lies, so the file takes content without ever leaving the record.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.create_file("/made.txt").expect("create a file");
    assert_eq!(node.size(), 0);
    assert_eq!(node.write(0, b"hello").expect("write"), 5);
    assert_eq!(node.size(), 5);

    let again = remount(&device);
    let reread = again.lookup("/made.txt").expect("relookup");
    assert_eq!(reread.size(), 5);
    let mut buf = [0u8; 5];
    assert_eq!(reread.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf, b"hello");

    let (number, _) = again.resolve("/made.txt").expect("resolve");
    let attributes = again.attributes_of(number).expect("the attributes");
    assert!(
        attributes
            .iter()
            .find(|attr| attr.attr_type == 0x80)
            .expect("the data")
            .data_runs_offset
            .is_none(),
        "and the value is still in the record"
    );
}

#[test]
fn a_file_that_outgrows_its_record_takes_runs_under_its_value() {
    // Past the record's own room the value *converts*: the file's bytes leave
    // the record for clusters the volume hands out, which is what a file that
    // has outgrown its record lives in.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let node = fs_handle.create_file("/big.txt").expect("create a file");
    let content = vec![0x5Au8; 2000];
    assert_eq!(node.write(0, &content).expect("write"), content.len());
    assert_eq!(node.size(), content.len());

    let again = remount(&device);
    let reread = again.lookup("/big.txt").expect("relookup");
    assert_eq!(reread.size(), content.len());
    let mut buf = vec![0u8; content.len()];
    assert_eq!(reread.read(0, &mut buf).expect("read"), buf.len());
    assert!(
        buf.iter().all(|byte| *byte == 0x5A),
        "the bytes are its own"
    );

    // The attribute has runs now, and the clusters it took are the volume's no
    // more: one cluster, which is what 2000 bytes needs.
    let (number, _) = again.resolve("/big.txt").expect("resolve");
    let attributes = again.attributes_of(number).expect("the attributes");
    let data = attributes
        .iter()
        .find(|attr| attr.attr_type == 0x80)
        .expect("the data");
    assert!(data.data_runs_offset.is_some(), "the value left the record");
    assert_eq!(u64::from(data.data_size), content.len() as u64);
    let bitmap = again.read_bitmap().expect("the volume's bitmap");
    let taken: usize = bitmap.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = fixture.used.iter().filter(|used| **used != 0).count();
    assert_eq!(taken, was + 1, "the one cluster it took");

    // And it can grow again, now the way a file with runs does.
    let grown = reread.set_len(4000);
    assert!(grown.is_ok(), "{grown:?}");
    assert_eq!(again.lookup("/big.txt").expect("relookup").size(), 4000);
}

#[test]
fn a_created_directory_is_on_the_volume() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_dir("/made").expect("create a directory");

    // A second mount finds it, calls it a directory, and finds it *empty*: a
    // directory's entries are its children, and the "." and ".." a listing
    // shows are the reader's own.
    let again = remount(&device);
    let made = again.lookup("/made").expect("the new directory");
    assert_eq!(made.kind(), NodeKind::Directory);
    assert_eq!(made.size(), 0);
    assert!(matches!(again.read_dir("/made", 0), Err(Error::NotFound)));

    // Its record is one the volume had free, and the volume's own list of what
    // is in use names it.
    let (number, _) = again.resolve("/made").expect("resolve");
    assert_eq!(number, 16, "the first record past the volume's own");
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[number as usize / 8] & (1 << (number % 8)),
        1 << (number % 8),
        "the MFT's bitmap claimed the record"
    );
}

#[test]
fn a_file_can_be_created_in_a_new_directory() {
    // The point of a directory: a name goes into the one just made, which is
    // where its index root has to grow.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_dir("/made").expect("create a directory");
    fs_handle
        .create_file("/made/inside.txt")
        .expect("a file in it");

    let again = remount(&device);
    assert_eq!(
        again.lookup("/made/inside.txt").expect("the file").kind(),
        NodeKind::File
    );
    let listed = again.read_dir("/made", 0).expect("the entry in it");
    assert_eq!(listed.name, "inside.txt");
    assert_eq!(listed.kind, NodeKind::File);
}

#[test]
fn a_removed_directory_is_gone() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_dir("/made").expect("create a directory");
    fs_handle.remove_path("/made").expect("remove it");
    assert!(matches!(fs_handle.lookup("/made"), Err(Error::NotFound)));

    // A second mount agrees, and the record is free again.
    let again = remount(&device);
    assert!(matches!(again.lookup("/made"), Err(Error::NotFound)));
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[16 / 8] & (1 << (16 % 8)),
        0,
        "the MFT's bitmap gave the record back"
    );
}

#[test]
fn a_removed_file_is_gone_and_its_clusters_come_back() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    assert_eq!(
        fs_handle.lookup("/two-runs.bin").expect("before").size(),
        3 * cluster as usize
    );
    fs_handle.remove_path("/two-runs.bin").expect("remove");
    assert!(matches!(
        fs_handle.lookup("/two-runs.bin"),
        Err(Error::NotFound)
    ));

    // A second mount agrees; the clusters the file held are free again; and
    // the record is formatted but not in use, with a sequence that has moved
    // on — which is what makes the number it had stop meaning it.
    let again = remount(&device);
    assert!(matches!(
        again.lookup("/two-runs.bin"),
        Err(Error::NotFound)
    ));
    let bitmap = again.read_bitmap().expect("the bitmap");
    let taken: usize = bitmap.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = fixture.used.iter().filter(|used| **used != 0).count();
    assert_eq!(taken, was - 3, "the three clusters it held");

    let info = again.info().lock();
    let at = again.record_offset(&info, TWO_RUN_FILE).expect("offset");
    let as_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> = device.clone();
    let mut raw = vec![0u8; info.mft_record_size as usize];
    super::fs::read_device_bytes(&as_device, at, &mut raw).expect("read the record");
    assert_eq!(
        u16::from_le_bytes([raw[22], raw[23]]) & 0x0001,
        0,
        "not in use"
    );
    assert_eq!(
        u16::from_le_bytes([raw[16], raw[17]]),
        2,
        "its sequence went up"
    );
    drop(info);

    // And the volume's own list says the record is free again.
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[TWO_RUN_FILE as usize / 8] & (1 << (TWO_RUN_FILE % 8)),
        0,
        "the MFT's bitmap gave the record back"
    );

    let mut names = Vec::new();
    for index in 0.. {
        match again.read_dir("/", index) {
            Ok(entry) => names.push(entry.name),
            Err(_) => break,
        }
    }
    assert!(
        !names.iter().any(|name| name == "two-runs.bin"),
        "the name went with it: {names:?}"
    );
}

#[test]
fn a_file_whose_data_is_split_reads_whole() {
    // The mapping pairs of a fragmented file do not fit one record, so the
    // attribute is *split* by virtual cluster number: the record that names it
    // holds the first part, and an extension record of its holds the second.  A
    // reader that stops at the first part reads a shorter file, and reads it
    // without complaint.
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);
    let cluster = fixture.cluster_size() as usize;
    let node = fs_handle.lookup("/split.bin").expect("split.bin");
    assert_eq!(node.size(), 3 * cluster, "the whole attribute's length");

    let mut buf = vec![0u8; 3 * cluster];
    assert_eq!(node.read(0, &mut buf).expect("read"), buf.len());
    assert!(
        buf[..cluster].iter().all(|byte| *byte == 0x66),
        "the part its own record holds"
    );
    assert!(
        buf[cluster..].iter().all(|byte| *byte == 0x77),
        "the part the list names"
    );

    // And a read that starts inside the second part comes from the other
    // record.
    let mut tail = vec![0u8; cluster];
    assert_eq!(
        node.read(2 * cluster as u64, &mut tail).expect("read"),
        cluster
    );
    assert!(tail.iter().all(|byte| *byte == 0x77));
}

#[test]
fn a_file_whose_data_has_moved_reads_whole() {
    // The shape measured on a real volume: a record the attributes did not fit
    // writes an `$ATTRIBUTE_LIST` and puts one attribute in an extension record
    // *whole* — and the list itself is a file of its own there.
    let fixture = build_volume(FRACTIONAL);
    let fs_handle = open(&fixture);
    let cluster = fixture.cluster_size() as usize;
    let node = fs_handle.lookup("/moved.bin").expect("moved.bin");
    assert_eq!(node.size(), 2 * cluster);

    let mut buf = vec![0u8; 2 * cluster];
    assert_eq!(node.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[..cluster].iter().all(|byte| *byte == 0x88));
    assert!(buf[cluster..].iter().all(|byte| *byte == 0x99));

    // The record that holds it is one the volume has spoken for — its bit is
    // set in the MFT's bitmap — and it has no name of its own for any
    // directory to list.
    let bits = fs_handle
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[MOVED_FILE_EXT as usize / 8] & (1 << (MOVED_FILE_EXT % 8)),
        1 << (MOVED_FILE_EXT % 8),
        "the extension record is in use"
    );
    let record = fixture.record(MOVED_FILE_EXT);
    let header = super::types::MftRecordHeader::parse(record).expect("a header");
    let attributes = super::fs::parse_attributes(&record[header.size() as usize..]);
    assert!(
        !attributes.iter().any(|attr| attr.attr_type == 0x30),
        "and has no name"
    );
}

#[test]
fn a_listed_file_is_read_but_not_grown() {
    // A file whose `$DATA` an `$ATTRIBUTE_LIST` has *moved whole* into an
    // extension record is one a growth still works on: the run list is one
    // record's worth of attribute, and that record is where the fields are
    // written.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/moved.bin").expect("moved.bin");
    assert_eq!(node.size(), 2 * cluster as usize);
    node.set_len(3 * cluster)
        .expect("a growth in the extension");
    assert_eq!(node.size(), 3 * cluster as usize);

    let again = remount(&device);
    let reread = again.lookup("/moved.bin").expect("relookup");
    assert_eq!(reread.size(), 3 * cluster as usize);
    let mut buf = vec![0u8; 3 * cluster as usize];
    assert_eq!(reread.read(0, &mut buf).expect("read"), buf.len());
    assert!(buf[..cluster as usize].iter().all(|byte| *byte == 0x88));
    assert!(buf[cluster as usize..2 * cluster as usize]
        .iter()
        .all(|byte| *byte == 0x99));
    assert!(buf[2 * cluster as usize..].iter().all(|byte| *byte == 0));
}

#[test]
fn a_split_file_is_read_but_not_grown() {
    // A record whose attributes are *listed* is one this driver reads and does
    // not rewrite yet: the attributes are not all in its bytes, and the ones
    // that are can be the first part of an attribute that continues in another
    // record.
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let node = fs_handle.lookup("/split.bin").expect("split.bin");
    assert_eq!(node.set_len(4 * cluster), Err(Error::NotImplemented));

    // An overwrite inside the length does not touch the attribute at all — the
    // bytes go through the runs — so that still lands, in *both* parts.
    assert_eq!(node.write(0, b"AB").expect("write"), 2);
    assert_eq!(node.write(2 * cluster, b"CD").expect("write"), 2);

    let again = remount(&device);
    let reread = again.lookup("/split.bin").expect("relookup");
    let mut buf = vec![0u8; 3 * cluster as usize];
    assert_eq!(reread.read(0, &mut buf).expect("read"), buf.len());
    assert_eq!(&buf[..2], b"AB", "the part in its own record");
    assert_eq!(
        &buf[2 * cluster as usize..2 * cluster as usize + 2],
        b"CD",
        "and the part in the extension record"
    );
}

#[test]
fn removing_a_listed_file_gives_its_extension_record_back() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.remove_path("/moved.bin").expect("remove");
    assert!(matches!(
        fs_handle.lookup("/moved.bin"),
        Err(Error::NotFound)
    ));

    // The extension record is a record the volume had spoken for, and the
    // removal is what gives it back — with the clusters of both the data and
    // the list.
    let again = remount(&device);
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    for number in [MOVED_FILE, MOVED_FILE_EXT] {
        assert_eq!(
            bits[number as usize / 8] & (1 << (number % 8)),
            0,
            "record {number} is free again"
        );
    }
    let bitmap = again.read_bitmap().expect("the volume's bitmap");
    let taken: usize = bitmap.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = fixture.used.iter().filter(|used| **used != 0).count();
    assert_eq!(
        taken,
        was - 3,
        "the two clusters of data and the one the list is in"
    );
}

#[test]
fn a_directory_that_still_holds_something_is_not_removed() {
    // A directory that still has children cannot go: their names are in *its*
    // index, and a walk that reached it would find entries whose parent the
    // volume no longer has.
    let fixture = build_volume(FRACTIONAL);
    let (_device, fs_handle) = writable(&fixture);
    assert_eq!(fs_handle.remove_path("/sub").err(), Some(Error::Busy));
    assert!(
        fs_handle.lookup("/sub/leaf.txt").is_ok(),
        "and what it held is still there"
    );
}

#[test]
fn a_creation_grows_the_mft_when_no_record_is_free() {
    // A volume whose records are all spoken for: the creation has to *grow*
    // the MFT, and the record it gets is one the growth made.
    let fixture = build_volume_with(FRACTIONAL, true);
    let (device, fs_handle) = writable(&fixture);
    let cluster = fixture.cluster_size();
    let record_size = fixture.shape.record_size() as u64;

    let before = {
        let mut info = fs_handle.info().lock();
        info.resolve_mft_runs(&fs_handle.device)
            .expect("the MFT's runs");
        info.mft_data_size
    };
    assert_eq!(
        before,
        RECORDS * record_size,
        "the records it was built with"
    );

    let node = fs_handle
        .create_file("/grown.txt")
        .expect("a creation that grows the MFT");
    assert_eq!(node.size(), 0);

    // A second mount finds it, and the MFT it reads is the longer one: whole
    // records, at least a cluster's worth of them, and the record the name
    // got is the first the growth made.
    let again = remount(&device);
    let (number, _) = again.resolve("/grown.txt").expect("resolve");
    assert_eq!(number, RECORDS, "the first record past the ones it had");
    let mut info = again.info().lock();
    info.resolve_mft_runs(&again.device)
        .expect("the MFT's runs");
    let after = info.mft_data_size;
    assert!(
        after >= before + cluster,
        "the MFT grew by a cluster's worth: {before} -> {after}"
    );
    assert_eq!(after % record_size, 0, "and in whole records");
    drop(info);

    // The volume's own lists say the same: its MFT bitmap names the new
    // record, and the cluster the MFT took is not the volume's any more.
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[number as usize / 8] & (1 << (number % 8)),
        1 << (number % 8),
        "the MFT's bitmap claimed the record"
    );
    let bitmap = again.read_bitmap().expect("the volume's bitmap");
    let taken: usize = bitmap.iter().map(|byte| byte.count_ones() as usize).sum();
    let was: usize = fixture.used.iter().filter(|used| **used != 0).count();
    assert_eq!(taken, was + 1, "the one cluster the growth claimed");

    // The growth made room for more than one record: the next name lands right
    // after the first, with no second growth.
    let second = fs_handle.create_file("/next.txt").expect("a second file");
    assert_eq!(second.size(), 0);
    assert_eq!(
        fs_handle.resolve("/next.txt").expect("resolve").0,
        RECORDS + 1,
        "the record after the first one the growth made"
    );
}

#[test]
fn the_mft_is_not_grown_while_a_record_is_free() {
    let fixture = build_volume(FRACTIONAL);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_file("/new.txt").expect("create a file");

    let again = remount(&device);
    assert_eq!(
        again.resolve("/new.txt").expect("resolve").0,
        16,
        "a record the volume already had"
    );
    let mut info = again.info().lock();
    info.resolve_mft_runs(&again.device)
        .expect("the MFT's runs");
    assert_eq!(
        info.mft_data_size,
        RECORDS * fixture.shape.record_size() as u64,
        "and the MFT is the one it was"
    );
}

#[test]
fn a_record_the_mft_grew_for_can_be_given_back() {
    // The record a growth made is a record like any other: a removal frees it,
    // and the next name takes it back.
    let fixture = build_volume_with(FRACTIONAL, true);
    let (device, fs_handle) = writable(&fixture);
    fs_handle.create_file("/grown.txt").expect("grow");
    fs_handle.remove_path("/grown.txt").expect("remove it");
    assert!(matches!(
        fs_handle.lookup("/grown.txt"),
        Err(Error::NotFound)
    ));

    let again = remount(&device);
    assert!(matches!(again.lookup("/grown.txt"), Err(Error::NotFound)));
    let bits = again
        .mft_bitmap()
        .expect("the MFT's bitmap")
        .expect("a bitmap");
    assert_eq!(
        bits[RECORDS as usize / 8] & (1 << (RECORDS % 8)),
        0,
        "the record the growth made is free again"
    );

    // And the same mount that grew it can answer with it again, which is what
    // its own idea of the MFT being the longer one means.
    fs_handle.create_file("/again.txt").expect("create again");
    assert_eq!(fs_handle.resolve("/again.txt").expect("resolve").0, RECORDS);
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
/// The volume's `$UpCase` table, which a name is folded through.
const UPCASE_RECORD: u64 = 10;
const RESIDENT_FILE: u64 = 24;
const TWO_RUN_FILE: u64 = 25;
const SUBDIRECTORY: u64 = 26;
const SUBDIRECTORY_FILE: u64 = 27;
/// A file whose `$DATA` has no room to grow and is followed by another
/// attribute: the shape that makes a growth *move* the attribute.
const TIGHT_FILE: u64 = 28;
/// A file whose record is **full**: the shape a run list cannot grow in, and
/// the one an attribute list — not the MFT — is for.
const FULL_FILE: u64 = 29;
/// A directory whose record is **full**: the shape a name has nowhere to go
/// in, where the format's answer is an allocation block of its own.
const FULL_DIRECTORY: u64 = 30;
/// A file whose `$DATA` is **split** by virtual cluster number: the record that
/// names it holds the first part, and an extension record of its holds the
/// second — which is the shape a fragmented file's mapping pairs make when
/// they no longer fit one record.
const LISTED_FILE: u64 = 31;
const LISTED_FILE_EXT: u64 = 32;
/// A file whose `$DATA` has **moved** out of its own record whole, which is the
/// shape a directory's `$INDEX_ROOT` takes on a volume taken apart above.
const MOVED_FILE: u64 = 33;
const MOVED_FILE_EXT: u64 = 34;
/// A file whose `$FILE_NAME` an `$ATTRIBUTE_LIST` moved into an extension
/// record: the shape a record that filled up leaves behind, and the one a
/// rename has to write the name in — there, and not in the base record.
const NAMED_FILE: u64 = 39;
const NAMED_FILE_EXT: u64 = 40;
/// A directory whose index bitmap is a **file** of its own: the shape a real
/// volume's directory reaches when the bitmap outgrows its record, and the one
/// whose bits have to be read and written where its runs say.
const RUNNING_INDEX_DIRECTORY: u64 = 41;
const RUNNING_INDEX_FILE: u64 = 42;
/// A directory whose index is a **tree**: two blocks, and the root's node
/// holding the key that separates them — the shape a directory of many names
/// has, measured on a volume `mkntfs` makes.  Its children are named in the
/// tree and in no other directory.
const TREE_DIRECTORY: u64 = 35;
const TREE_ALPHA: u64 = 36;
/// The separator key's own record: its name lives in the root's node and in no
/// block, which is what a promoted key is.
const TREE_MIDDLE: u64 = 37;
const TREE_OMEGA: u64 = 38;
const RECORDS: u64 = 43;

/// How many blocks the tree directory's allocation has room for.
///
/// Its tree holds two of them; the rest are blocks the allocation *has* and
/// the index bitmap says are free — the shape a directory reaches when
/// deletions have left blocks behind, and the one that makes a split need a
/// byte of the bitmap rather than a bit in a byte it already has.
const TREE_ALLOCATION_BLOCKS: u64 = 8;

/// The records the tree directory names, which no other directory does.
const TREE_CHILDREN: [u64; 3] = [TREE_ALPHA, TREE_MIDDLE, TREE_OMEGA];

/// The records that hold another record's attributes.
const EXTENSION_RECORDS: [u64; 3] = [LISTED_FILE_EXT, MOVED_FILE_EXT, NAMED_FILE_EXT];

/// How long a `$UpCase` table is: 65,536 code units.
const UPCASE_BYTES: u64 = 0x1_0000 * 2;

/// How many clusters the MFT's first run takes, so that the two-run shape is
/// the fixture's own choice rather than a consequence of the record size.
const MFT_FIRST_RUN_CLUSTERS: u64 = 4;

/// Whether a record is one the fixture has in use.
///
/// The records a volume keeps for itself, the folding table, this fixture's
/// own files — and not the rest, which are formatted but free.  `$MFT`'s own
/// bitmap is built from this, so the two say the same thing.
fn is_named(number: u64, spares_in_use: bool) -> bool {
    (0..=6).contains(&number)
        || number == UPCASE_RECORD
        || number == RESIDENT_FILE
        || number == TWO_RUN_FILE
        || number == TIGHT_FILE
        || number == FULL_FILE
        || number == FULL_DIRECTORY
        || number == SUBDIRECTORY
        || number == SUBDIRECTORY_FILE
        || number == LISTED_FILE
        || number == MOVED_FILE
        || number == NAMED_FILE
        || number == RUNNING_INDEX_DIRECTORY
        || number == RUNNING_INDEX_FILE
        || number == TREE_DIRECTORY
        || TREE_CHILDREN.contains(&number)
        // An extension record is not a name of its own, so making every record
        // in use does not name one.
        || (spares_in_use && number < RECORDS && !EXTENSION_RECORDS.contains(&number))
}

/// Whether a record is one the fixture has *in use*, named or not.
///
/// An extension record holds another record's attributes: the volume has
/// spoken for it, so its bit is set in `$MFT`'s bitmap, and no directory names
/// it — a record with a base reference is not a file of its own.
fn is_in_use(number: u64, spares_in_use: bool) -> bool {
    is_named(number, spares_in_use) || EXTENSION_RECORDS.contains(&number)
}

/// The name a record takes when the fixture makes every record in use.
///
/// A record that is in use is a record some directory names, so the ones a
/// volume would have kept free need names of their own.
fn spare_name(number: u64) -> &'static str {
    match number {
        7 => "spare-07",
        8 => "spare-08",
        9 => "spare-09",
        11 => "spare-11",
        12 => "spare-12",
        13 => "spare-13",
        14 => "spare-14",
        15 => "spare-15",
        16 => "spare-16",
        17 => "spare-17",
        18 => "spare-18",
        19 => "spare-19",
        20 => "spare-20",
        21 => "spare-21",
        22 => "spare-22",
        23 => "spare-23",
        _ => "",
    }
}

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
            // The name's own bytes, which a named attribute carries between
            // its header and its value.
            attr[name_offset as usize..value_offset as usize].copy_from_slice(&name_bytes);
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
/// One `$ATTRIBUTE_LIST` entry: an attribute, and the record that holds it.
///
/// The entry's header is 26 bytes and the entry is padded to eight, which is
/// the shape a real volume's entries have; the sequence number the reference
/// carries is the one every fixture record was made with.
fn list_entry(attr_type: u32, name: &str, instance: u16, holder: u64, lowest_vcn: u64) -> Vec<u8> {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut entry = vec![0u8; 26];
    put_u32_le(&mut entry, 0, attr_type);
    entry[6] = (name_bytes.len() / 2) as u8;
    entry[7] = 26; // where a name begins
    put_u64_le(&mut entry, 8, lowest_vcn);
    put_u64_le(&mut entry, 16, (1u64 << 48) | holder);
    put_u16_le(&mut entry, 24, instance);
    entry.extend_from_slice(&name_bytes);
    let length = entry.len().div_ceil(8) * 8;
    entry.resize(length, 0);
    put_u16_le(&mut entry, 4, length as u16);
    entry
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

/// The entry a non-leaf node ends with: no name, the last-entry flag, and the
/// child block's virtual cluster number — which is the entry's *last* eight
/// bytes, where the format puts it, and not the reference field a name entry
/// keeps its record in: a real volume's pointer entries leave that zero.
fn node_pointer(vcn: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 24];
    put_u16_le(&mut entry, 8, 24);
    put_u32_le(&mut entry, 12, 3);
    put_u64_le(&mut entry, 16, vcn);
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
                                    // A directory has one name and so one hard link, which is what a real
                                    // volume's own `mkdir` leaves.
    put_u16_le(&mut record, 18, 1);
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

#[test]
#[ignore = "driven by scripts/check-ntfs-image.sh, which makes the volume it needs"]
fn a_volume_mkntfs_wrote_is_read_and_written_back() {
    // Every other test here mounts a volume this driver built.  This one mounts
    // a volume **`mkntfs` built**: the host injects a file the driver knows
    // nothing about, the driver reads it, creates one of its own, and the
    // image it leaves is handed to `ntfs-3g`'s own reader by the script that
    // runs this test.  The fixture's format facts were measured against such a
    // volume by hand; this is what holds them there.
    //
    // Ignored, so `cargo test` alone does not demand an image and the tools
    // that make one; the check drives it with the three paths it needs and
    // fails outright if any of them is missing, which is the direction a
    // skipped test cannot go.
    // The trait, through the path the rest of this file's helpers use: the
    // census of cross-module edges counts a spelling, and this one is already
    // in it.
    use crate::fs::block::BlockDevice as _;

    let path = std::env::var("PROTOFIRE_NTFS_IMAGE")
        .expect("the check runs this test with a volume to mount");
    let expected =
        std::env::var("PROTOFIRE_NTFS_CONTENT").expect("the check names the content it injected");
    let content =
        std::env::var("PROTOFIRE_NTFS_WRITE").expect("the check names the content to write");
    let out =
        std::env::var("PROTOFIRE_NTFS_OUT").expect("the check names where the written volume goes");

    let image = std::fs::read(&path).expect("the volume mkntfs made");
    let device = crate::fs::block::MemoryBlockDevice::new("real", image, false);
    let fs_handle = super::NtfsFs::new(device.clone()).expect("mount it");

    // What the host put there: a name and bytes this driver never wrote.
    let listed = the_listing(&fs_handle, "/");
    assert!(
        listed.contains(&String::from("hello.txt")),
        "the host's file is listed: {listed:?}"
    );
    let node = fs_handle.lookup("/hello.txt").expect("the host's file");
    assert_eq!(node.size(), expected.len(), "and its length");
    let mut bytes = alloc::vec![0u8; node.size() as usize];
    assert_eq!(node.read(0, &mut bytes).expect("read it"), bytes.len());
    assert_eq!(bytes, expected.as_bytes(), "and its bytes");

    // And what the driver writes: a file of its own, and the volume it is in.
    let made = fs_handle
        .create_file("/written.txt")
        .expect("a file of the driver's own");
    assert_eq!(
        made.write(0, content.as_bytes()).expect("write it"),
        content.len()
    );
    fs_handle.sync().expect("settle the volume");

    let mut written = alloc::vec![0u8; (device.block_count() * 512) as usize];
    device
        .read_blocks(0, &mut written)
        .expect("read the volume");
    std::fs::write(&out, &written).expect("leave it where the check can judge it");

    // A **second mount** of what this one left, reading back through the
    // reader: the same proof every other test here ends with, on a volume
    // `mkntfs` made rather than on the fixture.
    let again = super::NtfsFs::new(crate::fs::block::MemoryBlockDevice::new(
        "written", written, false,
    ))
    .expect("mount what was written");
    let reread = again.lookup("/written.txt").expect("the file it made");
    assert_eq!(reread.size(), content.len());
    let mut bytes = alloc::vec![0u8; reread.size() as usize];
    assert_eq!(reread.read(0, &mut bytes).expect("read it"), bytes.len());
    assert_eq!(bytes, content.as_bytes());
}

/// A **compressed** stream on a volume `mkntfs` made, refused rather than
/// misread: [RFC
/// 0013](../../docs/rfcs/0013-refuse-the-ntfs-streams-this-driver-cannot-read.
/// md)'s first stage, on a volume this driver did not build and with a file no
/// part of it wrote.
#[test]
#[ignore = "driven by scripts/check-ntfs-image.sh, which makes the volumes it needs"]
fn a_compressed_stream_on_a_real_volume_is_refused() {
    // `mkntfs -C` makes a volume whose files are compressed, so the `$DATA` of
    // the file `ntfscp` puts in it carries the compressed flag and its runs
    // name clusters holding an LZNT1 bitstream.  The reader answered a read of
    // it with those bytes, at the file's own length, which a caller cannot
    // tell from the file's bytes; it refuses now, and the file stays listed,
    // because a name is not a stream.
    let path = std::env::var("PROTOFIRE_NTFS_COMPRESSED")
        .expect("the check runs this test with a compressed volume");
    let name = std::env::var("PROTOFIRE_NTFS_COMPRESSED_NAME")
        .expect("the check names the compressed file it injected");

    let image = std::fs::read(&path).expect("the volume mkntfs -C made");
    let device = crate::fs::block::MemoryBlockDevice::new("compressed", image, false);
    let fs_handle = super::NtfsFs::new(device).expect("mount it");

    let listed = the_listing(&fs_handle, "/");
    assert!(
        listed.contains(&String::from(name.trim_start_matches('/'))),
        "the compressed file is still listed: {listed:?}"
    );
    let node = fs_handle.lookup(&name).expect("the compressed file");
    assert!(
        node.size() > 0,
        "and it has a length, which is in its record"
    );
    let mut bytes = alloc::vec![0u8; 64];
    assert!(
        matches!(node.read(0, &mut bytes), Err(Error::NotImplemented)),
        "a read of it is refused rather than answered with the bitstream"
    );
    assert!(
        matches!(node.write(0, b"x"), Err(Error::NotImplemented)),
        "and so is a write"
    );
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
    /// The two runs of the file whose `$DATA` has no room to grow.
    tight_runs: [(u64, u64); 2],
    /// The two runs of the file whose *record* has none.
    full_runs: [(u64, u64); 2],
    /// Where the `$UpCase` table is.
    upcase_runs: [(u64, u64); 1],
    /// Where `$MFT`'s own bitmap is — a file of its own, the way a real
    /// volume's is.
    mft_bitmap_runs: [(u64, u64); 1],
    /// The two parts of the file whose `$DATA` is split by virtual cluster
    /// number: one cluster in its own record, two in an extension record.
    split_runs: [(u64, u64); 2],
    /// The runs of the file whose `$DATA` has moved whole: both of them in an
    /// extension record.
    moved_runs: [(u64, u64); 2],
    /// Where the entries of a *non-resident* `$ATTRIBUTE_LIST` are.
    list_runs: [(u64, u64); 1],
    /// Where the tree directory's two index blocks are, one after the other.
    tree_blocks: u64,
    /// The block a directory's entries are in when its index bitmap is a file,
    /// and the runs of that bitmap — a cluster of its own, which is what makes
    /// it a file rather than a value in the record.
    running_block: u64,
    running_bitmap: (u64, u64),
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
    build_volume_with(shape, false)
}

/// The same volume, with every record the fixture has **in use**.
///
/// A volume whose MFT has no free record is what a creation has to *grow* the
/// MFT for, so the fixture can be built either way: the records a real volume
/// keeps formatted but free are then names of their own, which is what a
/// volume that has used them up looks like.
fn build_volume_with(shape: Shape, spares_in_use: bool) -> Fixture {
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
    let tight_first = take(1);
    take(1); // a gap, so its run list is two runs and not one
    let tight_second = take(1);
    let full_first = take(1);
    take(1); // the same shape, in a record with no room at all
    let full_second = take(1);
    let upcase_at = take(UPCASE_BYTES / cluster_size);
    let mft_bitmap_at = take(1);
    let split_first = take(1);
    take(1); // the second part is somewhere else, like a fragmented file's
    let split_second = take(2);
    let moved_first = take(1);
    let moved_second = take(1);
    let list_at = take(1);
    let tree_blocks = take(TREE_ALLOCATION_BLOCKS * index_block_clusters);
    // A directory whose index bitmap is a file of its own: one cluster holds
    // its block, and one holds the bitmap — which is what makes it a file.
    let running_block = take(2 * index_block_clusters);
    let running_bitmap = (take(1), 1);
    // Free clusters, each alone: a growth claims a run it fits in, and a claim
    // of several clusters has none — which is what the refusal tests rely on.
    let mut spare_used = Vec::new();
    for _ in 0..16 {
        take(1); // free, and alone
        spare_used.push(take(1)); // given out, so the next one is alone too
    }
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
        tight_runs: [(tight_first, 1), (tight_second, 1)],
        full_runs: [(full_first, 1), (full_second, 1)],
        upcase_runs: [(upcase_at, UPCASE_BYTES / cluster_size)],
        mft_bitmap_runs: [(mft_bitmap_at, 1)],
        split_runs: [(split_first, 1), (split_second, 2)],
        moved_runs: [(moved_first, 1), (moved_second, 1)],
        list_runs: [(list_at, 1)],
        tree_blocks,
        running_block,
        running_bitmap,
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
    for cluster in tree_blocks..tree_blocks + TREE_ALLOCATION_BLOCKS * index_block_clusters {
        fixture.used[cluster as usize] = 1;
    }
    for cluster in running_block..running_block + 2 * index_block_clusters {
        fixture.used[cluster as usize] = 1;
    }
    fixture.used[running_bitmap.0 as usize] = 1;
    for cluster in &spare_used {
        fixture.used[*cluster as usize] = 1;
    }
    for &(lcn, clusters) in fixture
        .file_runs
        .iter()
        .chain(&fixture.tight_runs)
        .chain(&fixture.full_runs)
        .chain(&fixture.upcase_runs)
        .chain(&fixture.mft_bitmap_runs)
        .chain(&fixture.split_runs)
        .chain(&fixture.moved_runs)
        .chain(&fixture.list_runs)
    {
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
    let mut mft_bits = alloc::vec![0u8; (RECORDS as usize).div_ceil(8)];
    for number in 0..RECORDS {
        if is_in_use(number, spares_in_use) {
            mft_bits[number as usize / 8] |= 1 << (number % 8);
        }
    }
    let mut attributes = Vec::new();
    // The lists the two listed files carry: every attribute of the file and the
    // record that holds it — the file's own record, or an extension record of
    // its.  The list does not name *itself*, which is what the volume this was
    // measured against does too.
    let split_list: Vec<u8> = [
        list_entry(0x10, "", 1, LISTED_FILE, 0),
        list_entry(0x30, "", 1, LISTED_FILE, 0),
        list_entry(0x80, "", 1, LISTED_FILE, 0),
        list_entry(0x80, "", 1, LISTED_FILE_EXT, 1),
    ]
    .concat();
    let moved_list: Vec<u8> = [
        list_entry(0x10, "", 1, MOVED_FILE, 0),
        list_entry(0x30, "", 1, MOVED_FILE, 0),
        list_entry(0x80, "", 1, MOVED_FILE_EXT, 0),
    ]
    .concat();
    // A list that names the *name* where it went: the base record holds no
    // `$FILE_NAME` at all, and the extension record holds nothing else.
    let named_list: Vec<u8> = [
        list_entry(0x10, "", 1, NAMED_FILE, 0),
        list_entry(0x30, "", 1, NAMED_FILE_EXT, 0),
        list_entry(0x80, "", 1, NAMED_FILE, 0),
    ]
    .concat();

    for number in 0..RECORDS {
        let (parent, name, directory, size, data): (u64, &str, bool, u64, Vec<u8>) = match number {
            0 => (ROOT_RECORD, "$MFT", false, 0, Vec::new()),
            1 => (ROOT_RECORD, "$MFTMirr", false, 0, Vec::new()),
            2 => (ROOT_RECORD, "$LogFile", false, 0, Vec::new()),
            3 => (ROOT_RECORD, "$Volume", false, 0, Vec::new()),
            4 => (ROOT_RECORD, "$AttrDef", false, 0, Vec::new()),
            6 => (ROOT_RECORD, "$Bitmap", false, 0, Vec::new()),
            UPCASE_RECORD => (ROOT_RECORD, "$UpCase", false, UPCASE_BYTES, Vec::new()),
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
            TIGHT_FILE => (
                ROOT_RECORD,
                "tight.bin",
                false,
                2 * cluster_size,
                Vec::new(),
            ),
            FULL_FILE => (ROOT_RECORD, "full.bin", false, 2 * cluster_size, Vec::new()),
            FULL_DIRECTORY => (ROOT_RECORD, "full-dir", true, 0, Vec::new()),
            LISTED_FILE => (
                ROOT_RECORD,
                "split.bin",
                false,
                3 * cluster_size,
                Vec::new(),
            ),
            MOVED_FILE => (
                ROOT_RECORD,
                "moved.bin",
                false,
                2 * cluster_size,
                Vec::new(),
            ),
            // The name belongs to the file and lives in the extension record,
            // which is why both records carry it: the list is what says where
            // it went.
            NAMED_FILE | NAMED_FILE_EXT => (ROOT_RECORD, "named.bin", false, 0, Vec::new()),
            TREE_DIRECTORY => (ROOT_RECORD, "tree", true, 0, Vec::new()),
            RUNNING_INDEX_DIRECTORY => (ROOT_RECORD, "running-index", true, 0, Vec::new()),
            RUNNING_INDEX_FILE => (RUNNING_INDEX_DIRECTORY, "rune.txt", false, 0, Vec::new()),
            TREE_ALPHA => (TREE_DIRECTORY, "alpha.txt", false, 0, Vec::new()),
            TREE_MIDDLE => (TREE_DIRECTORY, "middle.txt", false, 0, Vec::new()),
            TREE_OMEGA => (TREE_DIRECTORY, "omega.txt", false, 0, Vec::new()),
            SUBDIRECTORY => (ROOT_RECORD, "sub", true, 0, Vec::new()),
            SUBDIRECTORY_FILE => (
                SUBDIRECTORY,
                "leaf.txt",
                false,
                b"leaf".len() as u64,
                b"leaf".to_vec(),
            ),
            _ if number == ROOT_RECORD => (ROOT_RECORD, ".", true, 0, Vec::new()),
            // With the spares in use this is one of them, and it needs a name
            // like any other record a directory holds.
            _ => (ROOT_RECORD, spare_name(number), false, 0, Vec::new()),
        };

        // A record nothing uses is **formatted but free**, which is what a
        // real MFT's spare records look like: their number is theirs, their
        // attributes are none, and their flags say they are not in use.
        let named = is_named(number, spares_in_use);
        let extension = EXTENSION_RECORDS.contains(&number);

        attributes.clear();
        if named || extension {
            let standard = alloc::vec![0u8; 48];
            // An extension record holds another record's attributes and
            // nothing of its own: no standard information, and no name for any
            // directory to list.
            if named {
                attributes.extend(attribute(0x10, "", &standard, None, 0));
                // One record's name is not in it: an `$ATTRIBUTE_LIST` moved
                // it into an extension record, which is what its own arm below
                // builds.
                if number != NAMED_FILE {
                    attributes.extend(attribute(
                        0x30,
                        "",
                        &file_name(parent, name, directory, size),
                        None,
                        0,
                    ));
                }
            }
            match number {
                0 => {
                    // The MFT's own data: two runs, which is what a reader has to
                    // follow to find any record after the first — and room for
                    // one more run, which is where a growth appends the
                    // clusters it takes.
                    let mut data = attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.mft_runs),
                        RECORDS * record_size,
                    );
                    let length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    put_u32_le(&mut data, 4, length + 16);
                    data.extend_from_slice(&[0u8; 16]);
                    attributes.extend(data);
                    // And the MFT's own bitmap: one bit per record, set for the
                    // records the volume has in use.  It is what a real volume
                    // allocates from, so a created file has to turn one on — and
                    // it is a *file* of its own, with runs, the way a real
                    // volume's is.
                    let mut bitmap = attribute(
                        0xb0,
                        "",
                        &[],
                        Some(&fixture.mft_bitmap_runs),
                        mft_bits.len() as u64,
                    );
                    put_u64_le(&mut bitmap, 40, cluster_size); // allocated size
                    attributes.extend(bitmap);
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
                6 => {
                    // The cluster bitmap is a *file*: one cluster of bits, which is
                    // what an allocating stage reads and writes.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&[(fixture.bitmap, 1)]),
                        cluster_size,
                    ));
                }
                UPCASE_RECORD => {
                    // The folding table is a file too, and it is what a name
                    // is compared through: without it the index's order is the
                    // driver's own rather than the volume's.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.upcase_runs),
                        UPCASE_BYTES,
                    ));
                }
                RESIDENT_FILE | SUBDIRECTORY_FILE => {
                    attributes.extend(attribute(0x80, "", &data, None, 0));
                }
                TWO_RUN_FILE => {
                    // A writer leaves an attribute room to grow, and this one's
                    // run list has some: that is the room an appended run
                    // uses.  An attribute *without* the room is the relocation
                    // case, which is the stage after this one.
                    let mut data =
                        attribute(0x80, "", &[], Some(&fixture.file_runs), 3 * cluster_size);
                    let length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                    put_u32_le(&mut data, 4, length + 16);
                    data.extend_from_slice(&[0u8; 16]);
                    attributes.extend(data);
                }
                FULL_FILE => {
                    // A two-run `$DATA` with no room, and then an attribute
                    // sized to fill the record: any growth of the run list has
                    // nowhere to go.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.full_runs),
                        2 * cluster_size,
                    ));
                    let room = 1024 - 8 - 56 - attributes.len() - 24;
                    attributes.extend(attribute(0xe0, "", &alloc::vec![0u8; room], None, 0));
                }
                FULL_DIRECTORY => {
                    // An index *root* with nothing in it, a **list** that already
                    // names everything the record holds — an attribute moved out
                    // of it once before — and then an attribute sized to fill
                    // the record: a name whose entry needs the root's value
                    // longer has to *extend* that list.
                    attributes.extend(attribute(
                        0x90,
                        "$I30",
                        &index_root(&index_end_entry(), false),
                        None,
                        0,
                    ));
                    let list: Vec<u8> = [
                        list_entry(0x10, "", 1, FULL_DIRECTORY, 0),
                        list_entry(0x30, "", 1, FULL_DIRECTORY, 0),
                        list_entry(0x90, "$I30", 1, FULL_DIRECTORY, 0),
                        list_entry(0xe0, "", 1, FULL_DIRECTORY, 0),
                    ]
                    .concat();
                    attributes.extend(attribute(0x20, "", &list, None, 0));
                    let room = 1024 - 8 - 56 - attributes.len() - 24;
                    attributes.extend(attribute(0xe0, "", &alloc::vec![0u8; room], None, 0));
                }
                TIGHT_FILE => {
                    // Two runs, no room to spare, and an attribute *after* it:
                    // the shape a growth has to move.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.tight_runs),
                        2 * cluster_size,
                    ));
                    attributes.extend(attribute(0xd0, "", &[0u8; 8], None, 0));
                }
                LISTED_FILE => {
                    // The first part of a `$DATA` split by virtual cluster
                    // number: one run here, and the rest in the record the list
                    // names.
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.split_runs[..1]),
                        3 * cluster_size,
                    ));
                    attributes.extend(attribute(0x20, "", &split_list, None, 0));
                }
                LISTED_FILE_EXT => {
                    // The second part: a run list that begins at the cluster
                    // number the first part ended on.
                    let mut data = attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.split_runs[1..]),
                        3 * cluster_size,
                    );
                    put_u64_le(&mut data, 16, 1); // lowest VCN: what came before
                    put_u64_le(&mut data, 24, 2); // and the last one it covers
                    attributes.extend(data);
                }
                MOVED_FILE => {
                    // The list is a *file* of its own here, which is the shape
                    // the volume this was measured against writes.
                    let mut list = attribute(
                        0x20,
                        "",
                        &[],
                        Some(&fixture.list_runs),
                        moved_list.len() as u64,
                    );
                    put_u64_le(&mut list, 40, cluster_size); // allocated size
                    attributes.extend(list);
                }
                NAMED_FILE => {
                    // The record's own bytes hold the list and the file's
                    // data, and no name: the name is the extension record's.
                    attributes.extend(attribute(0x20, "", &named_list, None, 0));
                    attributes.extend(attribute(0x80, "", &[], None, 0));
                }
                NAMED_FILE_EXT => {
                    attributes.extend(attribute(
                        0x30,
                        "",
                        &file_name(parent, name, directory, size),
                        None,
                        0,
                    ));
                }
                RUNNING_INDEX_DIRECTORY => {
                    // The index root points at **one** block, and the bitmap
                    // that names the blocks is a *file*: one byte, in clusters
                    // of its own, which is where the split's bit has to land.
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
                        Some(&[(fixture.running_block, 2 * index_block_clusters)]),
                        shape.index_block_size() as u64,
                    ));
                    let mut bitmap =
                        attribute(0xb0, "$I30", &[], Some(&[fixture.running_bitmap]), 1);
                    put_u64_le(&mut bitmap, 40, cluster_size); // allocated size
                    attributes.extend(bitmap);

                    // And the block the root points at, with the name it
                    // holds: one entry, so filling it is what a test does.
                    let mut entries = index_entry(RUNNING_INDEX_FILE, "rune.txt", false, 0);
                    entries.extend_from_slice(&index_end_entry());
                    let block = index_block(&shape, 0, &node(&entries, false, 40));
                    let at = fixture.running_block as usize * cluster_size as usize;
                    fixture.image[at..at + block.len()].copy_from_slice(&block);
                }
                RUNNING_INDEX_FILE => {
                    attributes.extend(attribute(0x80, "", &[], None, 0));
                }
                TREE_DIRECTORY => {
                    // A directory whose index is a *tree*: two blocks with a
                    // separator key between them, which is the shape a
                    // directory of many names has — and the key's own record
                    // lives in the root's node and in no block, because a
                    // split promotes it.
                    let at = fixture.tree_blocks as usize * cluster_size as usize;
                    let mut first = index_entry(TREE_ALPHA, "alpha.txt", false, 0);
                    first.extend_from_slice(&index_end_entry());
                    let block = index_block(&shape, 0, &node(&first, false, 40));
                    fixture.image[at..at + block.len()].copy_from_slice(&block);
                    let at = at + index_block_clusters as usize * cluster_size as usize;
                    let mut second = index_entry(TREE_OMEGA, "omega.txt", false, 0);
                    second.extend_from_slice(&index_end_entry());
                    let block =
                        index_block(&shape, index_block_clusters, &node(&second, false, 40));
                    fixture.image[at..at + block.len()].copy_from_slice(&block);

                    let key = file_name(TREE_DIRECTORY, "middle.txt", false, 0);
                    let mut separator = vec![0u8; 16];
                    put_u64_le(&mut separator, 0, (1u64 << 48) | TREE_MIDDLE);
                    put_u16_le(&mut separator, 10, key.len() as u16);
                    put_u32_le(&mut separator, 12, 1); // points at a node
                    separator.extend_from_slice(&key);
                    // Its child's number ends the entry: the padding the key
                    // leaves sits between the two.
                    let length = (separator.len() + 8).div_ceil(8) * 8;
                    separator.resize(length, 0);
                    put_u16_le(&mut separator, 8, length as u16);
                    put_u64_le(&mut separator, length - 8, 0);

                    let mut root_entries = separator;
                    root_entries.extend_from_slice(&node_pointer(index_block_clusters));
                    attributes.extend(attribute(
                        0x90,
                        "$I30",
                        &index_root(&root_entries, true),
                        None,
                        0,
                    ));
                    attributes.extend(attribute(
                        0xa0,
                        "$I30",
                        &[],
                        Some(&[(
                            fixture.tree_blocks,
                            TREE_ALLOCATION_BLOCKS * index_block_clusters,
                        )]),
                        TREE_ALLOCATION_BLOCKS * shape.index_block_size() as u64,
                    ));
                    // One byte names eight blocks, and the tree's node points
                    // at two of them.  The other six are the shape this
                    // driver's own split leaves between its two writes: the
                    // blocks are the allocation's and the bitmap says they hold
                    // a node, but the node above has not been written yet — so
                    // the tree does not grow past them, and it does not take
                    // them back either.
                    let mut bits = vec![0u8; 1];
                    bits[0] = 0b1111_1111;
                    attributes.extend(attribute(0xb0, "$I30", &bits, None, 0));
                }
                TREE_ALPHA | TREE_MIDDLE | TREE_OMEGA => {
                    attributes.extend(attribute(0x80, "", &[], None, 0));
                }
                MOVED_FILE_EXT => {
                    attributes.extend(attribute(
                        0x80,
                        "",
                        &[],
                        Some(&fixture.moved_runs),
                        2 * cluster_size,
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
                        let mut listed: Vec<u64> = alloc::vec![
                            0,
                            1,
                            2,
                            3,
                            4,
                            6,
                            UPCASE_RECORD,
                            RESIDENT_FILE,
                            TWO_RUN_FILE,
                            TIGHT_FILE,
                            FULL_FILE,
                            FULL_DIRECTORY,
                            LISTED_FILE,
                            MOVED_FILE,
                            TREE_DIRECTORY,
                            SUBDIRECTORY,
                            NAMED_FILE,
                            RUNNING_INDEX_DIRECTORY,
                        ];
                        if spares_in_use {
                            // Every record in use is a record some directory
                            // names — but an extension record is not a name of
                            // its own.
                            for record in 0..RECORDS {
                                if !listed.contains(&record)
                                    && record != ROOT_RECORD
                                    && !EXTENSION_RECORDS.contains(&record)
                                    && !TREE_CHILDREN.contains(&record)
                                {
                                    listed.push(record);
                                }
                            }
                        }
                        for record in listed {
                            let (name, directory, size): (&str, bool, u64) = match record {
                                0 => ("$MFT", false, 0),
                                1 => ("$MFTMirr", false, 0),
                                2 => ("$LogFile", false, 0),
                                3 => ("$Volume", false, 0),
                                4 => ("$AttrDef", false, 0),
                                6 => ("$Bitmap", false, 0),
                                UPCASE_RECORD => ("$UpCase", false, UPCASE_BYTES),
                                RESIDENT_FILE => ("resident.txt", false, 5),
                                TWO_RUN_FILE => ("two-runs.bin", false, 3 * cluster_size),
                                TIGHT_FILE => ("tight.bin", false, 2 * cluster_size),
                                FULL_FILE => ("full.bin", false, 2 * cluster_size),
                                FULL_DIRECTORY => ("full-dir", true, 0),
                                LISTED_FILE => ("split.bin", false, 3 * cluster_size),
                                MOVED_FILE => ("moved.bin", false, 2 * cluster_size),
                                NAMED_FILE => ("named.bin", false, 0),
                                RUNNING_INDEX_DIRECTORY => ("running-index", true, 0),
                                TREE_DIRECTORY => ("tree", true, 0),
                                SUBDIRECTORY => ("sub", true, 0),
                                _ => (spare_name(record), false, 0),
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

        let directory = number == ROOT_RECORD
            || number == SUBDIRECTORY
            || number == FULL_DIRECTORY
            || number == TREE_DIRECTORY
            || number == RUNNING_INDEX_DIRECTORY;
        let flags = if named {
            if directory {
                0x03
            } else {
                0x01
            }
        } else if extension {
            0x01 // in use, and nothing else
        } else {
            0x00
        };
        let mut bytes = record(&shape, number, flags, &attributes);
        if extension {
            // An extension record is one that names the record it belongs to:
            // the base reference is the field that says so, and a record that
            // has one has no name and no link to count.
            let base = if number == LISTED_FILE_EXT {
                LISTED_FILE
            } else if number == NAMED_FILE_EXT {
                NAMED_FILE
            } else {
                MOVED_FILE
            };
            put_u64_le(&mut bytes, 32, (1u64 << 48) | base);
            put_u16_le(&mut bytes, 18, 0); // link count
        }
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
    for &(lcn, clusters) in fixture.tight_runs.iter().chain(&fixture.full_runs) {
        let at = lcn as usize * cluster_size as usize;
        for byte in &mut fixture.image[at..at + clusters as usize * cluster_size as usize] {
            *byte = 0x33;
        }
    }

    // The listed files' bytes: one value in each part of the split file, and
    // one in each run of the moved one, so a reader that stops at the first
    // part reads the wrong thing and not something that looks right.
    for &(lcn, clusters, value) in &[
        (fixture.split_runs[0].0, 1, 0x66u8),
        (fixture.split_runs[1].0, 2, 0x77),
        (fixture.moved_runs[0].0, 1, 0x88),
        (fixture.moved_runs[1].0, 1, 0x99),
    ] {
        let at = lcn as usize * cluster_size as usize;
        for byte in &mut fixture.image[at..at + clusters as usize * cluster_size as usize] {
            *byte = value;
        }
    }
    // And the entries of the list that is a file of its own.
    let at = fixture.list_runs[0].0 as usize * cluster_size as usize;
    fixture.image[at..at + moved_list.len()].copy_from_slice(&moved_list);

    // The bitmap a directory's index bitmap is: one byte, with the block its
    // root points at already in use, written where its runs say.
    let at = fixture.running_bitmap.0 as usize * cluster_size as usize;
    fixture.image[at] = 0b1;

    // The `$UpCase` table: every code unit folded the way a real volume folds
    // it — the Latin letters up, everything else as it is — so the fixture's
    // index order is the format's and not the driver's.
    let mut table = alloc::vec![0u8; UPCASE_BYTES as usize];
    for code in 0u32..0x1_0000 {
        let folded = if (0x61..=0x7a).contains(&code) {
            code - 0x20
        } else {
            code
        };
        let at = code as usize * 2;
        table[at..at + 2].copy_from_slice(&(folded as u16).to_le_bytes());
    }
    let at = fixture.upcase_runs[0].0 as usize * cluster_size as usize;
    fixture.image[at..at + table.len()].copy_from_slice(&table);

    // And the MFT's own bitmap, in the cluster its attribute names.
    let at = fixture.mft_bitmap_runs[0].0 as usize * cluster_size as usize;
    fixture.image[at..at + mft_bits.len()].copy_from_slice(&mft_bits);

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
        instance: 2,
        flags: 0,
        holder: 24,
        name: None,
        offset: 0,
        value_offset: 24,
        attr_len: 0,
        content: make_filename_body("HELLO~1", 2, 0, 5),
        data_runs_offset: None,
        data_runs: Vec::new(),
        data_size: 0,
    };
    let win32 = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
        instance: 3,
        flags: 0,
        holder: 24,
        name: None,
        offset: 0,
        value_offset: 24,
        attr_len: 0,
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

#[test]
fn a_child_pointer_is_read_from_the_end_of_its_entry() {
    // A pointer entry has no key, and the reference field a name entry keeps
    // its record in is left zero: the child block's virtual cluster number is
    // the entry's *last* eight bytes.  A reader that took the child's address
    // from the reference field found zero there — which is the right block
    // only while the child is the volume's first.  A pointer *with* a key is
    // the same entry with the key filled in: an internal node's entry carries
    // both, which is what makes a tree walk possible.
    let mut entry = vec![0u8; 24];
    put_u16_le(&mut entry, 8, 24);
    put_u32_le(&mut entry, 12, 3);
    put_u64_le(&mut entry, 16, 7);

    let mut buf = vec![0u8; 16];
    put_u16_le(&mut buf, 0, 16);
    let length = (16 + entry.len()) as u16;
    put_u16_le(&mut buf, 4, length);
    put_u16_le(&mut buf, 8, length);
    buf[12] = 1; // the node has children
    buf.extend_from_slice(&entry);

    let node = parse_index_node(&buf, 0);
    assert!(node.has_children);
    let pointer = node
        .entries
        .iter()
        .find(|entry| entry.child.is_some())
        .expect("the pointer entry");
    assert_eq!(
        pointer.child,
        Some(7),
        "the child is the entry's last eight bytes"
    );
    assert_eq!(pointer.reference, 0, "and a keyless entry names no record");
    assert!(pointer.name.is_none());

    // The same entry with a key: the record comes from the first eight bytes
    // and the child from the last ones.
    let key = file_name(TREE_DIRECTORY, "middle.txt", false, 0);
    let mut entry = vec![0u8; 16];
    put_u64_le(&mut entry, 0, (1u64 << 48) | TREE_MIDDLE);
    put_u16_le(&mut entry, 10, key.len() as u16);
    put_u32_le(&mut entry, 12, 1); // points at a node
    entry.extend_from_slice(&key);
    // The child's number ends the entry, so the padding a key of any length
    // leaves sits between the key and it.
    let length = (entry.len() + 8).div_ceil(8) * 8;
    entry.resize(length, 0);
    put_u16_le(&mut entry, 8, length as u16);
    put_u64_le(&mut entry, length - 8, 3);

    let mut buf = vec![0u8; 16];
    put_u16_le(&mut buf, 0, 16);
    let length = (16 + entry.len()) as u16;
    put_u16_le(&mut buf, 4, length);
    put_u16_le(&mut buf, 8, length);
    buf[12] = 1;
    buf.extend_from_slice(&entry);

    let node = parse_index_node(&buf, 0);
    let separator = node.entries.first().expect("the separator entry");
    assert_eq!(separator.reference, TREE_MIDDLE, "the key's record");
    assert_eq!(separator.child, Some(3), "and its child");
    assert_eq!(
        separator.name.as_ref().map(|name| name.name.as_str()),
        Some("middle.txt"),
        "a keyed pointer carries a real key"
    );
}
