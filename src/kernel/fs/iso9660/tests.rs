//! src/kernel/fs/iso9660/tests.rs
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
//! ```
//!
//! The boot-catalog tests additionally splice in a Boot Record descriptor
//! (sector 18), a volume descriptor terminator (sector 19), and an El
//! Torito boot catalog (sector 22).

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::MemoryBlockDevice;
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::vfs::NodeKind;
use crate::Error;

use super::types::parse_boot_catalog;
use super::types::PVD_SECTOR;
use super::types::SECTOR_SIZE;
use super::Iso9660Volume;

// ── Image geometry ──────────────────────────────────────────────────────

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
    const IMAGE_SECTORS: usize = 32;
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

fn open_volume(device: Arc<dyn crate::kernel::fs::block::BlockDevice>) -> Iso9660Volume {
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
