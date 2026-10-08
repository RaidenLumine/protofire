//! src/fs/iso9660/tests.rs
//!
//! Unit tests for the ISO 9660 driver.
//!
//! The tests build a minimal in-memory ISO image by hand:
//!
//! ```text
//! sector 16 : PVD ("CD001", label "TESTVOL", block size 2048)
//! sector 17 : zeroed (no Joliet SVD)
//! sector 20 : root directory extent (152 bytes)
//!             "."  (35), ".." (35), "SUB" dir (37), "HELLO.TXT;1" (45)
//! sector 25 : SUB directory extent (115 bytes)
//!             "."  (35), ".." (35), "NOTES.TXT;1" (45)
//! sector 30 : HELLO.TXT content
//! sector 31 : NOTES.TXT content
//! sector 32-47: spare, which the volume does not claim and growth allocates
//! ```
//!
//! An image opened on a *writable* device is not the image above any more: the
//! open declares the extension its System Use areas need, which puts the
//! reference in sector 32, rebuilds the root extent in sector 33, and moves
//! the path tables' root entry — so a test that looks at the medium asks the
//! descriptor where the root is rather than assuming sector 20.
//!
//! The boot-catalog tests additionally splice in a Boot Record descriptor
//! (sector 18), a volume descriptor terminator (sector 19), and an El
//! Torito boot catalog (sector 22).

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::block::BlockDevice;
use crate::fs::block::MemoryBlockDevice;
use crate::fs::vfs::FileSystem as VfsFileSystem;
use crate::fs::vfs::NodeKind;
use crate::Error;

use super::fs;
use super::types::parse_boot_catalog;
use super::types::DIR_RECORD_DATA_LENGTH_OFFSET;
use super::types::PVD_SECTOR;
use super::types::SECTOR_SIZE;
use super::Iso9660Volume;

// ── Image geometry ──────────────────────────────────────────────────────

/// Sectors in the image.  The volume claims the first 32 and the rest is the
/// room a growth allocates into.  Opening it for writing rebuilds the root
/// extent and adds the block the extension reference continues in, so the
/// room the write tests grow into is a little smaller than the image.
const IMAGE_SECTORS: usize = 48;
/// Blocks the volume *claims*, which is what its descriptor says.
const VOLUME_BLOCKS: u32 = 32;

const ROOT_EXTENT_SECTOR: u64 = 20;
const ROOT_EXTENT_SIZE: u32 = 152; // 35 + 35 + 37 + 45
const SUB_EXTENT_SECTOR: u64 = 25;
const SUB_EXTENT_SIZE: u32 = 115; // 35 + 35 + 45
const HELLO_SECTOR: u64 = 30;
const NOTES_SECTOR: u64 = 31;

const HELLO: &[u8] = b"Hello from ISO 9660!\n";
const NOTES: &[u8] = b"Notes in a subdirectory.\n";

// ── Image builders ──────────────────────────────────────────────────────

/// Serialise a standard ISO 9660 directory record.
fn make_dir_record(extent_loc: u64, extent_size: u32, flags: u8, name: &[u8]) -> Vec<u8> {
    let fi_len = name.len() as u8;
    let pad = if fi_len.is_multiple_of(2) { 0u8 } else { 1u8 };
    let dr_len = 33 + fi_len + pad;
    let mut rec = vec![0u8; dr_len as usize];
    rec[0] = dr_len;
    rec[2..6].copy_from_slice(&(extent_loc as u32).to_le_bytes());
    rec[10..14].copy_from_slice(&extent_size.to_le_bytes());
    rec[25] = flags;
    rec[32] = fi_len;
    rec[33..33 + name.len()].copy_from_slice(name);
    rec
}

/// Serialise the root directory record embedded in the PVD.
///
/// The PVD field is exactly 34 bytes, so `dr_len` must be 34 — the generic
/// `make_dir_record` would produce 35 for the 1-byte "." identifier, which
/// `DirRecord::parse` would reject (dr_len > buffer length).
fn make_root_record(extent_loc: u64, extent_size: u32) -> Vec<u8> {
    let mut rec = vec![0u8; 34];
    rec[0] = 34;
    rec[2..6].copy_from_slice(&(extent_loc as u32).to_le_bytes());
    rec[10..14].copy_from_slice(&extent_size.to_le_bytes());
    rec[25] = 0x02; // directory
    rec[32] = 1; // fi_len
    rec[33] = 0x00; // "." identifier
    rec
}

/// Build the 2048-byte Primary Volume Descriptor.
fn build_pvd() -> [u8; SECTOR_SIZE] {
    let mut buf = [0u8; SECTOR_SIZE];
    buf[0] = 0x01; // desc_type: primary volume descriptor
    buf[1..6].copy_from_slice(b"CD001");
    buf[6] = 0x01; // desc_version

    // volume_id at bytes 40..72 — pad with spaces (ISO convention).
    buf[40..47].copy_from_slice(b"TESTVOL");
    for b in buf[40..72].iter_mut() {
        if *b == 0 {
            *b = b' ';
        }
    }

    // logical block size (LE u16) at bytes 128..132.
    buf[128..130].copy_from_slice(&2048u16.to_le_bytes());

    // volume space size at bytes 80..88: how much of the medium this volume
    // claims, stored twice.  A volume that does not say cannot be grown.
    buf[80..84].copy_from_slice(&VOLUME_BLOCKS.to_le_bytes());
    buf[84..88].copy_from_slice(&VOLUME_BLOCKS.to_be_bytes());

    // Embedded root directory record at bytes 156..190.
    let root = make_root_record(ROOT_EXTENT_SECTOR, ROOT_EXTENT_SIZE);
    buf[156..190].copy_from_slice(&root);

    buf[881] = 0x01; // file_structure_version
    buf
}

/// Copy `data` into `image` at the given logical sector.
fn put_sector(image: &mut [u8], sector: u64, data: &[u8]) {
    let start = sector as usize * SECTOR_SIZE;
    let end = start + data.len();
    assert!(end <= image.len(), "sector {sector} out of image bounds");
    image[start..end].copy_from_slice(data);
}

/// Build the base (non-bootable) test image.
fn build_test_image() -> Vec<u8> {
    let mut image = vec![0u8; IMAGE_SECTORS * SECTOR_SIZE];

    put_sector(&mut image, PVD_SECTOR, &build_pvd());
    // Sector 17 stays zeroed — no Joliet SVD.

    // Root directory extent.
    let mut root_extent = Vec::new();
    root_extent.extend(make_dir_record(
        ROOT_EXTENT_SECTOR,
        ROOT_EXTENT_SIZE,
        0x02,
        b"\x00",
    ));
    root_extent.extend(make_dir_record(
        ROOT_EXTENT_SECTOR,
        ROOT_EXTENT_SIZE,
        0x02,
        b"\x01",
    ));
    root_extent.extend(make_dir_record(
        SUB_EXTENT_SECTOR,
        SUB_EXTENT_SIZE,
        0x02,
        b"SUB",
    ));
    root_extent.extend(make_dir_record(
        HELLO_SECTOR,
        HELLO.len() as u32,
        0x00,
        b"HELLO.TXT;1",
    ));
    assert_eq!(root_extent.len() as u32, ROOT_EXTENT_SIZE);
    put_sector(&mut image, ROOT_EXTENT_SECTOR, &root_extent);

    // SUB directory extent.
    let mut sub_extent = Vec::new();
    sub_extent.extend(make_dir_record(
        SUB_EXTENT_SECTOR,
        SUB_EXTENT_SIZE,
        0x02,
        b"\x00",
    ));
    sub_extent.extend(make_dir_record(
        ROOT_EXTENT_SECTOR,
        ROOT_EXTENT_SIZE,
        0x02,
        b"\x01",
    ));
    sub_extent.extend(make_dir_record(
        NOTES_SECTOR,
        NOTES.len() as u32,
        0x00,
        b"NOTES.TXT;1",
    ));
    assert_eq!(sub_extent.len() as u32, SUB_EXTENT_SIZE);
    put_sector(&mut image, SUB_EXTENT_SECTOR, &sub_extent);

    // File contents.
    put_sector(&mut image, HELLO_SECTOR, HELLO);
    put_sector(&mut image, NOTES_SECTOR, NOTES);

    image
}

/// Build a bootable image: Boot Record at sector 18, volume-descriptor
/// terminator at sector 19, and a boot catalog at sector 22.
fn build_bootable_image() -> Vec<u8> {
    let mut image = build_test_image();

    // Boot Record descriptor.
    let mut boot_rec = [0u8; SECTOR_SIZE];
    boot_rec[0] = 0x00;
    boot_rec[1..6].copy_from_slice(b"CD001");
    boot_rec[6] = 0x01;
    boot_rec[71..75].copy_from_slice(&22u32.to_le_bytes()); // catalog LBA
    put_sector(&mut image, 18, &boot_rec);

    // Volume descriptor set terminator.
    let mut term = [0u8; SECTOR_SIZE];
    term[0] = 0xFF;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 0x01;
    put_sector(&mut image, 19, &term);

    // Boot catalog.
    let mut catalog = [0u8; SECTOR_SIZE];
    catalog[0] = 0x01; // validation entry header id
    catalog[1] = 0x00; // platform id
    catalog[30] = 0x55; // key bytes
    catalog[31] = 0xAA;
    catalog[32] = 0x88; // initial/default entry: bootable
    catalog[33] = 0x00; // media: no emulation
    catalog[34..36].copy_from_slice(&0x07C0u16.to_le_bytes()); // load segment
    catalog[38..40].copy_from_slice(&4u16.to_le_bytes()); // sector count
    catalog[40..44].copy_from_slice(&16u32.to_le_bytes()); // load RBA
    put_sector(&mut image, 22, &catalog);

    image
}

fn open_volume(device: Arc<dyn crate::fs::block::BlockDevice>) -> Iso9660Volume {
    Iso9660Volume::open(device).expect("open iso9660 volume")
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[test]
fn volume_opens_with_volume_label() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);
    assert_eq!(volume.name(), "TESTVOL");
    assert_eq!(volume.volume_label(), "TESTVOL");
}

#[test]
fn root_is_directory() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    let root = volume.lookup("/").expect("lookup /");
    assert_eq!(root.kind(), NodeKind::Directory);
    assert_eq!(root.size(), ROOT_EXTENT_SIZE as usize);
}

#[test]
fn read_dir_lists_root_entries() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    let sub = volume.read_dir("/", 0).expect("entry 0");
    assert_eq!(sub.kind, NodeKind::Directory);
    assert_eq!(sub.name, "sub");
    assert_eq!(sub.size, SUB_EXTENT_SIZE as usize);

    let hello = volume.read_dir("/", 1).expect("entry 1");
    assert_eq!(hello.kind, NodeKind::File);
    assert_eq!(hello.name, "hello.txt");
    assert_eq!(hello.size, HELLO.len());

    assert!(matches!(volume.read_dir("/", 2), Err(Error::NotFound)));
}

#[test]
fn lookup_and_read_file() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    // Lookup is case-insensitive; names are decoded (lowercased, ";1"
    // stripped).
    let node = volume.lookup("/HELLO.TXT").expect("lookup /HELLO.TXT");
    assert_eq!(node.name(), "hello.txt");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), HELLO.len());

    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(n, HELLO.len());
    assert_eq!(&buf[..n], HELLO);

    // Reading past EOF returns 0.
    let mut tail = [0u8; 4];
    assert_eq!(node.read(HELLO.len() as u64, &mut tail).expect("eof"), 0);
}

// ─── Writing file data (RFC 0011, stage 1) ─────────────────────────────

/// The volume and its device, writable: the write tests need a device that
/// takes the write, which is the one thing the read tests never do.
fn writable_volume() -> (Arc<MemoryBlockDevice>, Iso9660Volume) {
    let device = MemoryBlockDevice::new("iso-write", build_test_image(), false);
    let volume = open_volume(device.clone());
    (device, volume)
}

#[test]
fn an_overwrite_inside_a_file_is_what_the_reader_reads_back() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");

    let replacement = b"JELLO";
    assert_eq!(
        node.write(0, replacement).expect("overwrite"),
        replacement.len()
    );

    // The reader sees the new bytes and keeps the rest of the file.
    let mut buf = vec![0u8; HELLO.len()];
    assert_eq!(node.read(0, &mut buf).expect("read"), HELLO.len());
    assert_eq!(&buf[..replacement.len()], replacement);
    assert_eq!(&buf[replacement.len()..], &HELLO[replacement.len()..]);

    // And it is on the medium: the sector the extent lives in carries it, and
    // the padding after the file inside that sector is untouched — the file is
    // 21 bytes of a 2048-byte sector, so this is the read-modify-write path.
    // The device's blocks are 512 bytes and an ISO sector is 2048, so the
    // extent's sector is four device blocks in.
    let mut sector = vec![0u8; SECTOR_SIZE];
    let lba = HELLO_SECTOR * (SECTOR_SIZE as u64) / crate::fs::block::BLOCK_SIZE as u64;
    device.read_blocks(lba, &mut sector).expect("read sector");
    assert_eq!(&sector[..replacement.len()], replacement);
    assert_eq!(
        &sector[replacement.len()..HELLO.len()],
        &HELLO[replacement.len()..]
    );
    assert!(
        sector[HELLO.len()..].iter().all(|byte| *byte == 0),
        "the sector's padding was rewritten"
    );
}

#[test]
fn an_extent_write_keeps_every_byte_it_was_not_given() {
    // A three-sector extent over an image whose every byte is distinguishable,
    // so a write that straddles two file sectors is visible byte for byte
    // outside the range as well as inside it.
    let image: Vec<u8> = (0..8 * SECTOR_SIZE).map(|i| (i % 251) as u8).collect();
    let before = image.clone();
    let device = MemoryBlockDevice::new("iso-extent", image, false);

    let extent_location = 2u32;
    let extent_size = (3 * SECTOR_SIZE) as u32;
    // Eight bytes starting four before the extent's second sector: both
    // sectors are only partly covered, so both take the read-modify-write path
    // in one call.
    let offset = (SECTOR_SIZE - 4) as u64;
    let replacement = [0xAAu8; 8];
    assert_eq!(
        fs::write_extent(
            &(device.clone() as Arc<dyn crate::fs::block::BlockDevice>),
            SECTOR_SIZE as u16,
            extent_location,
            extent_size,
            offset,
            &replacement,
        )
        .expect("write extent"),
        replacement.len()
    );

    let mut after = vec![0u8; before.len()];
    device.read_blocks(0, &mut after).expect("read image back");

    let start = extent_location as usize * SECTOR_SIZE + offset as usize;
    assert_eq!(&after[start..start + replacement.len()], &replacement);
    for (index, (old, new)) in before.iter().zip(after.iter()).enumerate() {
        if (start..start + replacement.len()).contains(&index) {
            continue;
        }
        assert_eq!(old, new, "byte {index} outside the write changed");
    }
}

#[test]
fn a_write_past_the_end_grows_the_file() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    let data = [0xAAu8; 8];

    // A write at the end grows the file by what it takes, so a caller can
    // write a file the way it writes any other.
    assert_eq!(node.write(HELLO.len() as u64, &data).expect("append"), 8);
    assert_eq!(node.size(), HELLO.len() + 8);

    let mut buf = vec![0u8; node.size()];
    assert_eq!(node.read(0, &mut buf).expect("read"), node.size());
    assert_eq!(&buf[..HELLO.len()], HELLO);
    assert_eq!(&buf[HELLO.len()..], &data);

    // A second mount sees the length and the bytes: both are on the medium.
    let reopened = open_volume(device);
    let again = reopened.lookup("/HELLO.TXT").expect("relookup");
    assert_eq!(again.size(), HELLO.len() + 8);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf).expect("read again"), again.size());
    assert_eq!(&buf[..HELLO.len()], HELLO);
    assert_eq!(&buf[HELLO.len()..], &data);
}

#[test]
fn a_read_only_device_refuses_an_overwrite() {
    // `/system` is a read-only slice of the boot disk: the refusal is the
    // device's, so a writable filesystem on a read-only device still refuses.
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device);
    let node = volume.lookup("/HELLO.TXT").expect("lookup");

    assert_eq!(node.write(0, b"JELLO"), Err(Error::PermissionDenied));
}

#[test]
fn a_directory_refuses_a_write() {
    let (_device, volume) = writable_volume();
    let dir = volume.lookup("/SUB").expect("lookup /SUB");
    assert_eq!(dir.write(0, b"x"), Err(Error::InvalidArgument));
}

// ─── Creating and removing files (RFC 0011, stage 3b) ──────────────────

/// The root directory's extent, as the descriptor names it.
///
/// A writable volume's open rebuilds that extent elsewhere, so a test that
/// looks at the medium has to ask where it is rather than assume the address
/// the fixture was built with.
fn root_extent(device: &Arc<MemoryBlockDevice>) -> (u32, u32) {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let pvd = fs::read_pvd(&as_device).expect("read pvd");
    let (root, _) = super::types::DirRecord::parse(&pvd.root_dir_record, 0).expect("root record");
    (root.extent_location, root.extent_size)
}

/// A directory's records, read off the medium.
fn records_in(
    device: &Arc<MemoryBlockDevice>,
    extent_location: u32,
    extent_size: u32,
) -> Vec<super::types::DirRecord> {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let mut data = vec![0u8; extent_size as usize];
    fs::read_extent(
        &as_device,
        SECTOR_SIZE as u16,
        extent_location,
        extent_size,
        0,
        &mut data,
    )
    .expect("read the extent");

    let mut records = Vec::new();
    let mut at = 0usize;
    while let Some((record, next)) = super::types::DirRecord::parse(&data, at) {
        records.push(record);
        at = next;
    }
    records
}

/// One record of a directory, by its identifier.
fn record_named(
    device: &Arc<MemoryBlockDevice>,
    extent_location: u32,
    extent_size: u32,
    identifier: &[u8],
) -> super::types::DirRecord {
    records_in(device, extent_location, extent_size)
        .into_iter()
        .find(|record| record.identifier == identifier)
        .unwrap_or_else(|| panic!("no record for {identifier:?}"))
}

/// The identifiers the root directory's records carry, in the order they sit
/// on the medium.
fn root_identifiers(device: &Arc<MemoryBlockDevice>) -> Vec<Vec<u8>> {
    let (location, size) = root_extent(device);
    records_in(device, location, size)
        .into_iter()
        .map(|record| record.identifier)
        .collect()
}

#[test]
fn a_created_file_is_empty_and_findable() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/NEW.TXT").expect("create");
    // The name the caller used goes into the record's `NM` entry, so that is
    // the name the file has — not the identifier's own upper-cased form.
    assert_eq!(node.name(), "NEW.TXT");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), 0);
    assert_eq!(volume.lookup("/new.txt").expect("lookup").size(), 0);

    // A second mount reads the record the create wrote into the directory.
    let reopened = open_volume(device);
    assert_eq!(reopened.lookup("/NEW.TXT").expect("relookup").size(), 0);
}

#[test]
fn a_created_file_can_be_written_and_read_back() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/data.bin").expect("create");
    let payload = b"written after the create";
    assert_eq!(node.write(0, payload).expect("write"), payload.len());
    assert_eq!(node.size(), payload.len());

    let reopened = open_volume(device);
    let again = reopened.lookup("/data.bin").expect("relookup");
    assert_eq!(again.size(), payload.len());
    let mut buf = vec![0u8; payload.len()];
    assert_eq!(again.read(0, &mut buf).expect("read"), payload.len());
    assert_eq!(buf, payload);
}

#[test]
fn a_created_file_makes_its_directory_longer() {
    let (device, volume) = writable_volume();
    let before = volume.lookup("/").expect("root").size();

    volume.create_file("/NEW.TXT").expect("create");

    // The record is the identifier's own 33 + 9 bytes plus the System Use area
    // that carries the name: `PX` (36), `NM` for `NEW.TXT` (12) and `ST` (4).
    let reopened = open_volume(device);
    assert_eq!(
        reopened.lookup("/").expect("root again").size(),
        before + 42 + 36 + 12 + 4
    );
}

#[test]
fn a_directory_that_fills_a_block_takes_another() {
    let (device, volume) = writable_volume();

    // The root's records start at byte 152 of a 2048-byte block, so filling it
    // takes about forty records and the one that does not fit starts the next
    // block — which the volume has to give the directory.
    let mut created = Vec::new();
    for index in 0..48u32 {
        let name = alloc::format!("/F{index}.TXT");
        volume.create_file(&name).expect("create");
        created.push(name);
    }

    let reopened = open_volume(device);
    for name in &created {
        assert!(reopened.lookup(name).is_ok(), "missing {name}");
    }
    assert!(
        reopened.lookup("/").expect("root").size() > SECTOR_SIZE,
        "the directory should need a second block"
    );
}

#[test]
fn creating_a_file_that_exists_is_refused() {
    let (_device, volume) = writable_volume();
    assert!(matches!(
        volume.create_file("/HELLO.TXT"),
        Err(Error::AlreadyExists)
    ));
}

#[test]
fn a_name_the_format_cannot_hold_is_kept_in_a_name_entry() {
    let (device, volume) = writable_volume();
    volume
        .create_file("/a name with spaces")
        .expect("a name an identifier has no room for");

    // The record's identifier is the mangled form a reader without Rock Ridge
    // sees, and `NM` is what a reader with it — and this driver — reports.
    assert!(
        root_identifiers(&device).contains(&b"A_NAME_WITH_SPACES;1".to_vec()),
        "the identifier stands in for the name"
    );

    let reopened = open_volume(device);
    let node = reopened.lookup("/a name with spaces").expect("lookup");
    assert_eq!(node.name(), "a name with spaces");
}

#[test]
fn two_names_that_mangle_alike_still_get_their_own_records() {
    let (device, volume) = writable_volume();
    volume.create_file("/a b").expect("create /a b");
    volume.create_file("/a_b").expect("create /a_b");

    // Both want `A_B;1`, and two records with one identifier are two entries
    // only one of which is reachable, so the second takes a suffix.
    let identifiers = root_identifiers(&device);
    assert!(identifiers.contains(&b"A_B;1".to_vec()));
    assert!(identifiers.contains(&b"A_B_1;1".to_vec()));

    let first = volume.lookup("/a b").expect("lookup /a b");
    let second = volume.lookup("/a_b").expect("lookup /a_b");
    assert_eq!(first.name(), "a b");
    assert_eq!(second.name(), "a_b");
}

#[test]
fn a_name_too_long_for_one_record_is_refused() {
    let (_device, volume) = writable_volume();
    // The name lives in the record, whose own length is a single byte: the
    // entries cannot fit in 255 of them, so the create is refused rather than
    // writing the name in part.
    let long = alloc::format!("/{}", "n".repeat(300));
    assert!(matches!(
        volume.create_file(&long),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn removing_a_file_takes_its_record_out_of_the_directory() {
    let (device, volume) = writable_volume();
    let before = volume.lookup("/").expect("root").size();
    volume.remove_path("/HELLO.TXT").expect("remove");
    assert!(matches!(volume.lookup("/HELLO.TXT"), Err(Error::NotFound)));
    assert!(volume.lookup("/SUB/NOTES.TXT").is_ok());

    // A second mount agrees, and the directory is shorter by exactly the
    // record that left it — 45 bytes of `HELLO.TXT;1`.
    let reopened = open_volume(device);
    assert!(matches!(
        reopened.lookup("/HELLO.TXT"),
        Err(Error::NotFound)
    ));
    assert!(reopened.lookup("/SUB/NOTES.TXT").is_ok());
    assert_eq!(reopened.lookup("/").expect("root").size(), before - 45);
}

#[test]
fn removing_a_directory_is_refused() {
    let (_device, volume) = writable_volume();
    // `/SUB` holds `NOTES.TXT`, and a directory that still holds something
    // cannot go: its child's record would be pointing at a parent nothing
    // names.
    assert_eq!(volume.remove_path("/SUB"), Err(Error::Busy));
}

#[test]
fn creating_and_removing_are_refused_on_a_read_only_device() {
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device);
    assert!(volume.create_file("/NEW.TXT").is_err());
    assert_eq!(
        volume.remove_path("/HELLO.TXT"),
        Err(Error::PermissionDenied)
    );
}

// ─── Creating and removing directories (RFC 0011, stage 3c) ────────────

/// The directories a path table names, as `(number, parent, identifier,
/// extent)`.  A record's number is its position, so it is not read from the
/// table — it *is* the table's order.
fn parse_path_table(bytes: &[u8], big_endian: bool) -> Vec<(u16, u16, Vec<u8>, u32)> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let len_di = bytes[at] as usize;
        if len_di == 0 {
            // The table is shorter than the space it is stored in.
            break;
        }
        let extent = if big_endian {
            u32::from_be_bytes(bytes[at + 2..at + 6].try_into().expect("four bytes"))
        } else {
            u32::from_le_bytes(bytes[at + 2..at + 6].try_into().expect("four bytes"))
        };
        let parent = if big_endian {
            u16::from_be_bytes(bytes[at + 6..at + 8].try_into().expect("two bytes"))
        } else {
            u16::from_le_bytes(bytes[at + 6..at + 8].try_into().expect("two bytes"))
        };
        let identifier = bytes[at + 8..at + 8 + len_di].to_vec();
        entries.push((entries.len() as u16 + 1, parent, identifier, extent));
        at += 8 + len_di + (len_di % 2);
    }
    entries
}

/// The records a path table holds, as `(number, parent, identifier, extent)`.
type PathTableRecords = Vec<(u16, u16, Vec<u8>, u32)>;

/// Both path tables, read back off the volume.
fn path_tables(device: &Arc<MemoryBlockDevice>) -> (PathTableRecords, PathTableRecords) {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let pvd = fs::read_pvd(&as_device).expect("read pvd");
    let size = u32::from_le_bytes(pvd.path_table_size[..4].try_into().expect("four bytes"));
    let l = fs::field_le(pvd.l_path_table_loc);
    let m = fs::field_be(pvd.m_path_table_loc);

    let mut little = vec![0u8; size as usize];
    fs::read_extent(&as_device, SECTOR_SIZE as u16, l, size, 0, &mut little)
        .expect("read the little-endian table");
    let mut big = vec![0u8; size as usize];
    fs::read_extent(&as_device, SECTOR_SIZE as u16, m, size, 0, &mut big)
        .expect("read the big-endian table");

    (
        parse_path_table(&little, false),
        parse_path_table(&big, true),
    )
}

/// Check the properties a reader depends on, in both tables.
fn assert_path_tables_name(device: &Arc<MemoryBlockDevice>, expected: &[(Vec<u8>, u32)]) {
    let (little, big) = path_tables(device);
    assert_eq!(little.len(), big.len(), "the two tables disagree");
    for (left, right) in little.iter().zip(big.iter()) {
        assert_eq!(left, right, "the two tables disagree");
    }

    assert_eq!(little[0].2, vec![0x00], "the root is the first record");
    assert_eq!(little[0].1, 1, "the root's parent is itself");
    for (index, (number, parent, _, _)) in little.iter().enumerate() {
        assert_eq!(*number as usize, index + 1, "a number is its position");
        assert!(*parent <= *number, "a parent is numbered before its child");
    }

    for (identifier, extent) in expected {
        let found = little.iter().filter(|entry| &entry.2 == identifier).count();
        assert_eq!(found, 1, "a directory is named once");
        assert!(
            little
                .iter()
                .any(|entry| &entry.2 == identifier && entry.3 == *extent),
            "a directory's extent is the one its record says"
        );
    }

    // Within one parent the identifiers are ordered, which is the part of the
    // standard's order a level-order walk does not give for free.
    for window in little.windows(2) {
        if window[0].1 == window[1].1 {
            assert!(
                window[0].2 <= window[1].2,
                "siblings are not in identifier order"
            );
        }
    }
}

#[test]
fn a_created_directory_is_empty_and_findable() {
    let (device, volume) = writable_volume();
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let extent = fs::volume_blocks(&as_device).expect("volume size");
    volume.create_dir("/NEWDIR").expect("create dir");

    let node = volume.lookup("/newdir").expect("lookup");
    assert_eq!(node.kind(), NodeKind::Directory);
    // It holds its own two records and nothing else, so listing it lists
    // nothing: the reader skips "." and "..".
    assert!(matches!(
        volume.read_dir("/newdir", 0),
        Err(Error::NotFound)
    ));

    // A second mount sees it, and the path tables name it.
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root_extent(&device).0),
            (b"SUB".to_vec(), SUB_EXTENT_SECTOR as u32),
            (b"NEWDIR".to_vec(), extent),
        ],
    );
    let reopened = open_volume(device);
    assert_eq!(
        reopened.lookup("/NEWDIR").expect("relookup").kind(),
        NodeKind::Directory
    );
}

#[test]
fn a_created_directory_holds_files() {
    let (device, volume) = writable_volume();
    volume.create_dir("/holding").expect("create dir");
    let node = volume
        .create_file("/holding/item.bin")
        .expect("create file");
    assert_eq!(node.write(0, b"inside").expect("write"), 6);

    let reopened = open_volume(device);
    let file = reopened.lookup("/holding/item.bin").expect("relookup");
    assert_eq!(file.size(), 6);
    let mut buf = vec![0u8; 6];
    assert_eq!(file.read(0, &mut buf).expect("read"), 6);
    assert_eq!(buf, b"inside");
}

#[test]
fn the_path_table_orders_siblings_by_identifier() {
    let (device, volume) = writable_volume();
    // Created in the order a walk would *not* list them.
    volume.create_dir("/zebra").expect("create zebra");
    volume.create_dir("/alpha").expect("create alpha");

    let (little, _) = path_tables(&device);
    let names: Vec<&Vec<u8>> = little.iter().map(|entry| &entry.2).collect();
    let alpha = names
        .iter()
        .position(|name| *name == b"ALPHA")
        .expect("alpha");
    let zebra = names
        .iter()
        .position(|name| *name == b"ZEBRA")
        .expect("zebra");
    let sub = names.iter().position(|name| *name == b"SUB").expect("sub");
    assert!(alpha < sub && sub < zebra, "siblings are out of order");
    assert!(little.iter().all(|entry| entry.1 <= entry.0));
}

#[test]
fn removing_an_empty_directory_takes_it_out_of_the_tree_and_the_tables() {
    let (device, volume) = writable_volume();
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let extent = fs::volume_blocks(&as_device).expect("volume size");
    volume.create_dir("/gone").expect("create dir");
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root_extent(&device).0),
            (b"SUB".to_vec(), SUB_EXTENT_SECTOR as u32),
            (b"GONE".to_vec(), extent),
        ],
    );

    volume.remove_path("/gone").expect("remove dir");
    assert!(matches!(volume.lookup("/gone"), Err(Error::NotFound)));

    // The tables no longer name it, and a second mount agrees.
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root_extent(&device).0),
            (b"SUB".to_vec(), SUB_EXTENT_SECTOR as u32),
        ],
    );
    let reopened = open_volume(device);
    assert!(matches!(reopened.lookup("/GONE"), Err(Error::NotFound)));
    assert!(reopened.lookup("/SUB/NOTES.TXT").is_ok());
}

#[test]
fn a_read_only_device_refuses_a_created_directory() {
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device);
    assert!(volume.create_dir("/NEWDIR").is_err());
}

// ─── The extensions reference (RFC 0011, stage 3f) ─────────────────────

/// The signatures a System Use area's entries carry, in the order they sit.
fn area_entries(system_use: &[u8]) -> Vec<Vec<u8>> {
    let mut signatures = Vec::new();
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        signatures.push(rest[..2].to_vec());
        rest = &rest[len..];
    }
    signatures
}

/// The bytes a System Use area's `CE` entry names, read off the medium.
fn area_continuation(device: &Arc<MemoryBlockDevice>, system_use: &[u8]) -> Vec<u8> {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        if &rest[..2] == b"CE" {
            let number =
                |at: usize| u32::from_le_bytes(rest[at..at + 4].try_into().expect("four bytes"));
            let (block, offset, size) = (number(4), number(12), number(20));
            let mut bytes = vec![0u8; size as usize];
            fs::read_extent(
                &as_device,
                SECTOR_SIZE as u16,
                block,
                offset + size,
                u64::from(offset),
                &mut bytes,
            )
            .expect("read the continuation");
            return bytes;
        }
        rest = &rest[len..];
    }
    panic!("no continuation entry");
}

#[test]
fn opening_a_writable_volume_declares_the_extension() {
    let (device, _volume) = writable_volume();
    let (location, size) = root_extent(&device);

    // The root's own "." record is where a volume says what its System Use
    // areas are: `SP` that they are SUSP's at all, `PX` for its attributes,
    // and `CE` naming where the reference continues — the entry is far longer
    // than a record can hold.
    let first = record_named(&device, location, size, &[0x00]);
    assert_eq!(
        area_entries(&first.system_use),
        vec![
            b"SP".to_vec(),
            b"PX".to_vec(),
            b"CE".to_vec(),
            b"ST".to_vec()
        ]
    );

    let reference = area_continuation(&device, &first.system_use);
    assert_eq!(&reference[..2], b"ER");
    assert_eq!(reference[2] as usize, reference.len());
    assert_eq!(&reference[8..18], b"RRIP_1991A");
}

#[test]
fn the_extension_is_declared_once() {
    let (device, _volume) = writable_volume();
    let (location, size) = root_extent(&device);
    let first = record_named(&device, location, size, &[0x00]).record_len;

    // Opening a volume already says what its entries are adds nothing to it.
    drop(open_volume(device.clone()));

    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, &[0x00]).record_len,
        first
    );
}

#[test]
fn a_read_only_volume_is_left_as_it_was() {
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device.clone());
    assert!(volume.lookup("/HELLO.TXT").is_ok());

    // Nothing was written: the root is the fixture's own extent, its "." record
    // has no System Use area at all, and the volume claims what it claimed.
    assert_eq!(
        root_extent(&device),
        (ROOT_EXTENT_SECTOR as u32, ROOT_EXTENT_SIZE)
    );
    let (location, size) = root_extent(&device);
    // The fixture's own "." record is a byte longer than the format's, so the
    // area it appears to have is one zero byte — and no entries.
    assert!(area_entries(&record_named(&device, location, size, &[0x00]).system_use).is_empty());
    let as_device: Arc<dyn BlockDevice> = device.clone();
    assert_eq!(
        fs::volume_blocks(&as_device).expect("volume size"),
        VOLUME_BLOCKS
    );
}

#[test]
fn the_rebuilt_root_still_lists_what_it_listed() {
    let (device, volume) = writable_volume();

    // The upgrade builds the root elsewhere; every entry is still there, a
    // second mount agrees, and the path tables name the new address.
    assert!(volume.lookup("/HELLO.TXT").is_ok());
    assert!(volume.lookup("/SUB/NOTES.TXT").is_ok());
    let root = root_extent(&device).0;
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root),
            (b"SUB".to_vec(), SUB_EXTENT_SECTOR as u32),
        ],
    );

    // The root's own ".." names the root and the subdirectory's names its
    // parent, so both follow the move: a reader that goes back up lands on the
    // extent the volume now points at, not the one it left.
    assert_eq!(parent_record_extent(&device, root), root);
    assert_eq!(
        parent_record_extent(&device, SUB_EXTENT_SECTOR as u32),
        root
    );

    let reopened = open_volume(device);
    assert!(reopened.lookup("/HELLO.TXT").is_ok());
    assert!(reopened.lookup("/SUB/NOTES.TXT").is_ok());
    assert_eq!(reopened.read_dir("/", 0).expect("first entry").name, "sub");
}

#[test]
fn a_volume_with_no_room_for_the_reference_still_mounts() {
    // A medium that is exactly the volume: the block the reference would
    // continue in is not there, so the volume is left as it was.
    let tight = build_test_image()[..VOLUME_BLOCKS as usize * SECTOR_SIZE].to_vec();
    let device = MemoryBlockDevice::new("iso-tight", tight, false);
    let volume = open_volume(device.clone());

    assert_eq!(
        root_extent(&device),
        (ROOT_EXTENT_SECTOR as u32, ROOT_EXTENT_SIZE)
    );
    assert!(volume.lookup("/HELLO.TXT").is_ok());

    // And it is still writable: a create is a record appended to a directory
    // that already has the room for it.
    volume.create_file("/after.bin").expect("create");
    let reopened = open_volume(device);
    assert!(reopened.lookup("/after.bin").is_ok());
}

#[test]
fn a_broken_root_size_does_not_stop_a_writable_open() {
    // The root's size is a field of the descriptor's own root record, so it is
    // the first thing a broken image can lie about — and the upgrade would
    // allocate what it says.  It is bounded the way a directory read is, and
    // the volume opens without it.
    let mut image = build_test_image();
    let field = PVD_SECTOR as usize * SECTOR_SIZE + 156 + DIR_RECORD_DATA_LENGTH_OFFSET;
    image[field..field + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    image[field + 4..field + 8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());

    let device = MemoryBlockDevice::new("iso-lying", image, false);
    let _volume = open_volume(device.clone());

    // Nothing was written for it, and the volume claims what it claimed.
    assert_eq!(root_extent(&device).1, 0xFFFF_FFFF);
    let as_device: Arc<dyn BlockDevice> = device.clone();
    assert_eq!(
        fs::volume_blocks(&as_device).expect("volume size"),
        VOLUME_BLOCKS
    );
}

// ─── Renaming and moving (RFC 0011, stage 3d) ──────────────────────────

/// The extent a directory's own ".." record points at, read off the medium.
///
/// One block of the directory is enough for the tests' directories, and the
/// records end at a zero length, so this does not have to know the extent's
/// recorded size.
fn parent_record_extent(device: &Arc<MemoryBlockDevice>, dir_extent: u32) -> u32 {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let mut data = vec![0u8; SECTOR_SIZE];
    fs::read_extent(
        &as_device,
        SECTOR_SIZE as u16,
        dir_extent,
        SECTOR_SIZE as u32,
        0,
        &mut data,
    )
    .expect("read the directory");

    let mut at = 0usize;
    while at < data.len() {
        let len = data[at] as usize;
        if len == 0 {
            break;
        }
        if data[at + 32] == 1 && data[at + 33] == 0x01 {
            return u32::from_le_bytes(data[at + 2..at + 6].try_into().expect("four bytes"));
        }
        at += len;
    }
    panic!("the directory has no parent record");
}

/// The extent a path table gives a directory, by identifier.
fn table_extent(device: &Arc<MemoryBlockDevice>, identifier: &[u8]) -> u32 {
    let (little, _) = path_tables(device);
    little
        .iter()
        .find(|entry| entry.2 == identifier)
        .unwrap_or_else(|| panic!("no path-table entry for {identifier:?}"))
        .3
}

#[test]
fn renaming_a_file_keeps_its_contents() {
    let (device, volume) = writable_volume();
    volume.rename("/HELLO.TXT", "/RENAMED.TXT").expect("rename");

    assert!(matches!(volume.lookup("/HELLO.TXT"), Err(Error::NotFound)));
    let node = volume.lookup("/RENAMED.TXT").expect("lookup");
    assert_eq!(node.size(), HELLO.len());
    let mut buf = vec![0u8; HELLO.len()];
    assert_eq!(node.read(0, &mut buf).expect("read"), HELLO.len());
    assert_eq!(buf, HELLO);

    // The name is a record in the directory, so a second mount sees it.
    let reopened = open_volume(device);
    assert!(matches!(
        reopened.lookup("/HELLO.TXT"),
        Err(Error::NotFound)
    ));
    assert!(reopened.lookup("/RENAMED.TXT").is_ok());
}

#[test]
fn a_rename_can_give_a_name_the_identifier_cannot_hold() {
    let (_device, volume) = writable_volume();
    volume
        .rename("/HELLO.TXT", "/a moved file")
        .expect("rename");

    let node = volume.lookup("/a moved file").expect("lookup");
    assert_eq!(node.name(), "a moved file");
    assert_eq!(node.size(), HELLO.len());
}

#[test]
fn a_rename_keeps_the_attributes_the_record_carried() {
    let (_device, volume) = writable_volume();
    let created = volume.create_file("/kept.txt").expect("create");
    assert_eq!(created.metadata().expect("metadata").security.mode, 0o644);

    volume.rename("/kept.txt", "/moved.txt").expect("rename");

    // The record's System Use area is carried over whole, so the POSIX
    // attributes the create wrote are still there: a record rebuilt without
    // them would report the default that a record with no `PX` entry gets.
    let node = volume.lookup("/moved.txt").expect("lookup");
    assert_eq!(node.name(), "moved.txt");
    assert_eq!(node.metadata().expect("metadata").security.mode, 0o644);
}

#[test]
fn moving_a_file_into_a_directory_takes_its_record_with_it() {
    let (_device, volume) = writable_volume();
    volume.rename("/HELLO.TXT", "/SUB/HELLO.TXT").expect("move");

    assert!(matches!(volume.lookup("/HELLO.TXT"), Err(Error::NotFound)));
    let node = volume.lookup("/SUB/HELLO.TXT").expect("lookup");
    let mut buf = vec![0u8; HELLO.len()];
    assert_eq!(node.read(0, &mut buf).expect("read"), HELLO.len());
    assert_eq!(buf, HELLO);

    // The neighbour it joined is still there.
    assert!(volume.lookup("/SUB/NOTES.TXT").is_ok());
}

#[test]
fn renaming_a_directory_keeps_it_and_the_tables_agree() {
    let (device, volume) = writable_volume();
    volume.rename("/SUB", "/RENAMED").expect("rename");

    assert!(matches!(volume.lookup("/SUB"), Err(Error::NotFound)));
    assert!(volume.lookup("/RENAMED/NOTES.TXT").is_ok());

    // A directory is in the path tables, and they must not still name the old
    // identifier.
    let (little, _) = path_tables(&device);
    let names: Vec<&Vec<u8>> = little.iter().map(|entry| &entry.2).collect();
    assert!(names.contains(&&b"RENAMED".to_vec()));
    assert!(!names.contains(&&b"SUB".to_vec()));
}

#[test]
fn moving_a_directory_rewrites_its_parent_record() {
    let (device, volume) = writable_volume();
    volume.create_dir("/outer").expect("create outer");
    volume.create_dir("/mover").expect("create mover");
    let outer_extent = table_extent(&device, b"OUTER");
    assert_ne!(
        parent_record_extent(&device, table_extent(&device, b"MOVER")),
        outer_extent,
        "the mover starts somewhere else"
    );

    volume.rename("/mover", "/outer/mover").expect("move");

    // ".." is the moved directory's own record of its parent, and this is the
    // one thing about it that a move changes.
    let moved_extent = table_extent(&device, b"MOVER");
    assert_eq!(
        parent_record_extent(&device, moved_extent),
        outer_extent,
        "\"..\" still points at the directory it left"
    );
    assert!(volume.lookup("/outer/mover").is_ok());
    assert!(matches!(volume.lookup("/mover"), Err(Error::NotFound)));
}

#[test]
fn moving_a_directory_into_itself_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(
        volume.rename("/SUB", "/SUB/inner"),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn renaming_onto_an_existing_name_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(
        volume.rename("/HELLO.TXT", "/SUB"),
        Err(Error::AlreadyExists)
    );
}

#[test]
fn a_read_only_device_refuses_a_rename() {
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device);
    assert_eq!(
        volume.rename("/HELLO.TXT", "/RENAMED.TXT"),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn a_directory_that_moves_takes_its_childrens_parent_with_it() {
    let (device, volume) = writable_volume();
    volume.create_dir("/holding").expect("create holding");
    volume.create_dir("/holding/inner").expect("create inner");
    let root_extent = table_extent(&device, &[0x00]);
    assert_eq!(
        parent_record_extent(&device, table_extent(&device, b"HOLDING")),
        root_extent,
        "a new directory's parent is the root"
    );

    // Filling the root's first block makes it take a second — and the root is
    // not the last extent on the volume, so it *moves*, which is what leaves a
    // child's ".." naming the address it left.
    for index in 0..48u32 {
        volume
            .create_file(&alloc::format!("/F{index}.TXT"))
            .expect("create");
    }

    let moved_root = table_extent(&device, &[0x00]);
    assert_ne!(moved_root, root_extent, "the root should have moved");
    assert_eq!(
        parent_record_extent(&device, table_extent(&device, b"HOLDING")),
        moved_root,
        "\"..\" still names the address the root left"
    );
}

// ─── Changing a file's length (RFC 0011, stage 2) ──────────────────────

/// A named record's eight-byte data-length field, read off the medium rather
/// than through the parser: the format stores the length twice, and a reader
/// is free to check either half.
fn record_length_field(device: &Arc<MemoryBlockDevice>, identifier: &[u8]) -> [u8; 8] {
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let (location, size) = root_extent(device);
    let mut data = vec![0u8; size as usize];
    fs::read_extent(&as_device, SECTOR_SIZE as u16, location, size, 0, &mut data)
        .expect("read the root extent");

    let mut at = 0usize;
    while let Some((record, next)) = super::types::DirRecord::parse(&data, at) {
        if record.identifier == identifier {
            let field = at + DIR_RECORD_DATA_LENGTH_OFFSET;
            return data[field..field + 8].try_into().expect("eight bytes");
        }
        at = next;
    }
    panic!("no record for {identifier:?}");
}

#[test]
fn truncating_a_file_rewrites_the_length_its_record_carries() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");

    node.set_len(5).expect("truncate");
    assert_eq!(node.size(), 5);
    let mut buf = vec![0u8; HELLO.len()];
    assert_eq!(node.read(0, &mut buf).expect("read"), 5);
    assert_eq!(&buf[..5], &HELLO[..5]);

    // A second mount reads the record the write rewrote, which is what says
    // the length is on the medium rather than only in this node.
    let reopened = open_volume(device.clone());
    assert_eq!(reopened.lookup("/HELLO.TXT").expect("relookup").size(), 5);

    // The field carries it in both halves: the format stores it twice and a
    // reader is free to check either.
    let field = record_length_field(&device, b"HELLO.TXT;1");
    assert_eq!(u32::from_le_bytes(field[..4].try_into().unwrap()), 5);
    assert_eq!(u32::from_be_bytes(field[4..].try_into().unwrap()), 5);

    // A shrink does not lose the block: the length can go back up to the end
    // of the block it already has, and the bytes it hid were never erased.
    node.set_len(SECTOR_SIZE as u64).expect("grow back");
    let mut again = vec![0u8; HELLO.len()];
    assert_eq!(node.read(0, &mut again).expect("read again"), HELLO.len());
    assert_eq!(again, HELLO);
}

#[test]
fn growing_a_file_stays_inside_the_block_it_already_has() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");

    // 21 bytes occupy one 2048-byte block, and every extent begins on a block
    // boundary, so the rest of that block belongs to this file alone.
    node.set_len(SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), SECTOR_SIZE);

    let mut buf = vec![0u8; SECTOR_SIZE];
    assert_eq!(node.read(0, &mut buf).expect("read"), SECTOR_SIZE);
    assert_eq!(&buf[..HELLO.len()], HELLO);
    assert!(
        buf[HELLO.len()..].iter().all(|byte| *byte == 0),
        "the block's tail is not this file's to grow into"
    );

    // Nothing was allocated for it: the file is still where it was.
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"HELLO.TXT;1").extent_location,
        HELLO_SECTOR as u32,
        "an in-block growth must not move the file"
    );
    let reopened = open_volume(device);
    assert_eq!(
        reopened.lookup("/HELLO.TXT").expect("relookup").size(),
        SECTOR_SIZE
    );
}

#[test]
fn growing_past_the_block_moves_a_file_that_has_something_after_it() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let end = fs::volume_blocks(&as_device).expect("volume size");

    // HELLO's extent is one block and NOTES begins in the next one, and an
    // extent is one contiguous run — so the file moves to the end of the
    // volume, which is where this allocator hands out blocks.
    node.set_len(2 * SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), 2 * SECTOR_SIZE);
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"HELLO.TXT;1").extent_location,
        end,
        "the record must point at the space the file moved to"
    );

    let mut buf = vec![0u8; node.size()];
    assert_eq!(node.read(0, &mut buf).expect("read"), node.size());
    assert_eq!(&buf[..HELLO.len()], HELLO);

    // The neighbour it used to sit beside is untouched ...
    let notes = volume.lookup("/SUB/NOTES.TXT").expect("lookup notes");
    let mut notes_buf = vec![0u8; NOTES.len()];
    assert_eq!(
        notes.read(0, &mut notes_buf).expect("read notes"),
        NOTES.len()
    );
    assert_eq!(notes_buf, NOTES);

    // ... and a second mount reads the file the record now points at.
    let reopened = open_volume(device);
    let again = reopened.lookup("/HELLO.TXT").expect("relookup");
    assert_eq!(again.size(), 2 * SECTOR_SIZE);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf).expect("read again"), again.size());
    assert_eq!(&buf[..HELLO.len()], HELLO);
}

#[test]
fn growing_past_the_block_extends_the_last_file_in_place() {
    let (device, volume) = writable_volume();
    // The file a create makes is empty and points at where the volume's space
    // ends — the upgrade that opened this volume took the block after NOTES —
    // so the blocks that follow it belong to no one, and growing it takes them
    // where it is, with no copy.
    let node = volume.create_file("/last.bin").expect("create");
    let as_device: Arc<dyn BlockDevice> = device.clone();
    let end = fs::volume_blocks(&as_device).expect("volume size");
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"LAST.BIN;1").extent_location,
        end,
        "an empty file starts where the volume's space ends"
    );

    node.set_len(SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), SECTOR_SIZE);
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"LAST.BIN;1").extent_location,
        end,
        "a file that is already last must not move"
    );
    assert_eq!(
        fs::volume_blocks(&as_device).expect("volume size"),
        end + 1,
        "the volume grew over the block the file took"
    );

    let reopened = open_volume(device);
    let again = reopened.lookup("/last.bin").expect("relookup");
    assert_eq!(again.size(), SECTOR_SIZE);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf).expect("read again"), again.size());
    assert!(
        buf.iter().all(|byte| *byte == 0),
        "the blocks it grew into were the medium's own"
    );
}

#[test]
fn growth_the_medium_cannot_hold_is_refused() {
    let (_device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("lookup");

    // The image is 40 blocks and the volume claims 32, so a length that would
    // need the rest of the medium and more has nowhere to go.
    assert_eq!(
        node.set_len(64 * SECTOR_SIZE as u64),
        Err(Error::NoSpace),
        "a length the medium cannot hold"
    );
}

#[test]
fn a_write_that_cannot_grow_is_short() {
    // The same image on a medium that is exactly the volume's size: what the
    // file would need to grow into is not there, so the write takes what it
    // can rather than failing.
    let tight = build_test_image()[..VOLUME_BLOCKS as usize * SECTOR_SIZE].to_vec();
    let device = MemoryBlockDevice::new("iso-tight", tight, false);
    let volume = open_volume(device);
    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    let data = [0xAAu8; 8];

    assert_eq!(node.write(SECTOR_SIZE as u64, &data).expect("write"), 0);
    assert_eq!(node.size(), HELLO.len());
}

#[test]
fn a_directory_refuses_a_length_change() {
    let (_device, volume) = writable_volume();
    let dir = volume.lookup("/SUB").expect("lookup /SUB");
    assert_eq!(dir.set_len(1), Err(Error::InvalidArgument));
}

#[test]
fn a_read_only_device_refuses_a_length_change() {
    let device = MemoryBlockDevice::new("iso-ro", build_test_image(), true);
    let volume = open_volume(device);
    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    assert_eq!(node.set_len(1), Err(Error::PermissionDenied));
}

#[test]
fn lookup_file_in_subdirectory() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    let node = volume
        .lookup("/SUB/NOTES.TXT")
        .expect("lookup /SUB/NOTES.TXT");
    assert_eq!(node.name(), "notes.txt");
    assert_eq!(node.kind(), NodeKind::File);

    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(n, NOTES.len());
    assert_eq!(&buf[..n], NOTES);
}

#[test]
fn stat_returns_file_metadata() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    let md = volume.stat("/HELLO.TXT").expect("stat");
    assert_eq!(md.kind, NodeKind::File);
    assert_eq!(md.size, HELLO.len());

    let sub_md = volume.stat("/SUB").expect("stat /SUB");
    assert_eq!(sub_md.kind, NodeKind::Directory);
    assert_eq!(sub_md.size, SUB_EXTENT_SIZE as usize);
}

#[test]
fn read_only_volume_rejects_mutations() {
    let device = MemoryBlockDevice::new("iso-test", build_test_image(), true);
    let volume = open_volume(device);

    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    assert!(matches!(
        node.write(0, b"overwrite"),
        Err(Error::PermissionDenied)
    ));

    assert!(matches!(
        volume.create_file("/new"),
        Err(Error::PermissionDenied)
    ));
    assert!(matches!(
        volume.create_dir("/newdir"),
        Err(Error::PermissionDenied)
    ));
    assert!(matches!(
        volume.remove_path("/HELLO.TXT"),
        Err(Error::PermissionDenied)
    ));
    assert!(matches!(
        volume.rename("/HELLO.TXT", "/moved"),
        Err(Error::PermissionDenied)
    ));
}

#[test]
fn boot_catalog_validation_entry_and_parsing() {
    // A raw sector mimicking an El Torito boot catalog: validation entry
    // (header id 0x01, key bytes 0x55/0xAA at 30-31) plus one bootable
    // initial/default entry.
    let mut catalog = [0u8; SECTOR_SIZE];
    catalog[0] = 0x01;
    catalog[1] = 0x00;
    catalog[30] = 0x55;
    catalog[31] = 0xAA;
    catalog[32] = 0x88; // bootable
    catalog[33] = 0x00; // no emulation
    catalog[34..36].copy_from_slice(&0x07C0u16.to_le_bytes());
    catalog[38..40].copy_from_slice(&4u16.to_le_bytes());
    catalog[40..44].copy_from_slice(&16u32.to_le_bytes());

    let entries = parse_boot_catalog(&catalog);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry.bootable);
    assert_eq!(entry.media_type, 0);
    assert_eq!(entry.load_segment, 0x07C0);
    assert_eq!(entry.sector_count, 4);
    assert_eq!(entry.load_rba, 16);

    // A catalog whose key bytes are wrong is rejected.
    let mut bad = catalog;
    bad[31] = 0x00;
    assert!(parse_boot_catalog(&bad).is_empty());

    // A catalog with no validation entry at all is rejected.
    let mut empty = [0u8; SECTOR_SIZE];
    empty[30] = 0x55;
    empty[31] = 0xAA;
    assert!(parse_boot_catalog(&empty).is_empty());
}

#[test]
fn bootable_volume_reports_boot_entries() {
    let image = build_bootable_image();
    let device = MemoryBlockDevice::new("iso-boot", image, true);
    let volume = open_volume(device);

    // Normal reads still work on the bootable image.
    assert_eq!(volume.volume_label(), "TESTVOL");
    let node = volume.lookup("/HELLO.TXT").expect("lookup");
    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..n], HELLO);

    // The boot catalog is discovered through the Boot Record descriptor.
    let entries = volume.boot_entries();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry.bootable);
    assert_eq!(entry.media_type, 0);
    assert_eq!(entry.load_segment, 0x07C0);
    assert_eq!(entry.sector_count, 4);
    assert_eq!(entry.load_rba, 16);

    // A plain (non-bootable) image reports no boot entries.
    let plain = MemoryBlockDevice::new("iso-plain", build_test_image(), true);
    let plain_volume = open_volume(plain);
    assert!(plain_volume.boot_entries().is_empty());
}
