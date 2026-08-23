//! src/kernel/fs/ntfs/tests.rs
//! Regression tests for the NTFS read-only driver: reparse-point parsing,
//! `$EA` extended-attribute parsing, and an end-to-end image containing a
//! non-resident `$DATA` attribute plus a resident `$EA` attribute.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::types::{
    parse_ea_entries, parse_reparse_point, ATTR_TYPE_DATA, ATTR_TYPE_EA, ATTR_TYPE_END,
    ATTR_TYPE_FILENAME, ATTR_TYPE_INDEX_ROOT, ATTR_TYPE_STANDARD_INFO, IO_REPARSE_TAG_SYMLINK,
    MFT_RECORD_DIRECTORY, MFT_RECORD_IN_USE,
};
use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants for the E2E NTFS image
// ═══════════════════════════════════════════════════════════════════════════════

/// Cluster size in bytes (boot sector: 512 B/sector × 8 sectors/cluster).
const E2E_CLUSTER_SIZE: u32 = 4096;
/// MFT record size in bytes (boot sector: 1 cluster/record).
const E2E_MFT_RECORD_SIZE: u32 = 4096;
/// Root directory lives in MFT record 5 (driver convention).
const E2E_ROOT_MFT: u64 = 5;
/// HELLO.TXT MFT record.
const E2E_FILE_MFT: u64 = 32;
/// First LCN of the HELLO.TXT / XATTR.TXT non-resident `$DATA` run.
const E2E_FILE_LCN: u64 = 64;
/// Contents of the file stored at cluster `E2E_FILE_LCN`.
const E2E_FILE_CONTENT: &[u8] = b"Hello from the protofire NTFS test volume!\n";

// ═══════════════════════════════════════════════════════════════════════════════
// Byte-level helpers
// ═══════════════════════════════════════════════════════════════════════════════

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

/// Minimum number of little-endian bytes needed to hold `value` (for data-run headers).
fn bytes_needed(value: u64) -> usize {
    let mut v = value;
    let mut n = 1;
    while v >= 256 {
        v >>= 8;
        n += 1;
    }
    n
}

/// Build a reparse-point data buffer containing `path` as the substitution name.
///
/// Layout: u32 tag, u16 data_length, u16 reserved, u16 sub_name_offset,
/// u16 sub_name_length, u16 print_name_offset, u16 print_name_length,
/// then the UTF-16LE path.
fn make_reparse_buf(tag: u32, path: &str) -> Vec<u8> {
    let mut raw: Vec<u16> = path.encode_utf16().collect();
    let path_bytes: Vec<u8> = raw.drain(..).flat_map(|c| c.to_le_bytes()).collect();
    let sub_len = path_bytes.len();
    let mut buf = vec![0u8; 16 + sub_len];
    put_u32_le(&mut buf, 0, tag);
    put_u16_le(&mut buf, 8, 16); // substitute_name_offset
    put_u16_le(&mut buf, 10, sub_len as u16); // substitute_name_length
    buf[16..16 + sub_len].copy_from_slice(&path_bytes);
    buf
}

/// Write an MFT record header: magic, USA fields, first-attribute offset, flags.
fn write_mft_header(record: &mut [u8], flags: u16, first_attr_offset: u16) {
    record[0..4].copy_from_slice(b"FILE");
    put_u16_le(record, 4, 48); // usa_offset
    put_u16_le(record, 6, 0); // usa_count (0 → no USA fixup in driver)
    put_u16_le(record, 20, first_attr_offset);
    put_u16_le(record, 22, flags);
}

/// Write a resident attribute; returns total attribute length (attr_len).
fn write_resident_attr(buf: &mut [u8], off: usize, attr_type: u32, content: &[u8]) -> usize {
    let attr_len = 24 + content.len();
    put_u32_le(buf, off, attr_type);
    put_u32_le(buf, off + 4, attr_len as u32);
    buf[off + 8] = 0; // non_resident = false
    buf[off + 9] = 0; // name_len
    put_u16_le(buf, off + 10, 0); // name_offset
    put_u16_le(buf, off + 12, 0); // flags
    put_u16_le(buf, off + 14, 0); // instance
    put_u32_le(buf, off + 16, content.len() as u32); // content_size
    put_u16_le(buf, off + 20, 24); // content_offset
    buf[off + 24..off + 24 + content.len()].copy_from_slice(content);
    attr_len
}

/// `$STANDARD_INFO` — the driver only checks presence, content can be zeroes.
fn write_standard_info(record: &mut [u8], pos: usize) -> usize {
    let content = vec![0u8; 48];
    write_resident_attr(record, pos, ATTR_TYPE_STANDARD_INFO, &content)
}

/// `$FILENAME` resident attribute with a UTF-16LE name.
fn write_filename_attr(
    record: &mut [u8],
    pos: usize,
    parent_mft: u64,
    name: &str,
    _flags: u32,
) -> usize {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let mut content = vec![0u8; 66 + utf16.len() * 2];
    put_u64_le(&mut content, 0, parent_mft); // parent MFT reference
    content[64] = utf16.len() as u8; // name length in characters
    for (i, ch) in utf16.iter().enumerate() {
        put_u16_le(&mut content, 66 + i * 2, *ch);
    }
    write_resident_attr(record, pos, ATTR_TYPE_FILENAME, &content)
}

/// `$INDEX_ROOT` resident attribute containing one node of index entries.
///
/// `entries` is a list of `(mft_ref, name, is_last)`. The index header is
/// 16 zero bytes; each entry carries an embedded `$FILENAME` content at
/// content offset 16.
fn write_index_root_attr(
    record: &mut [u8],
    pos: usize,
    parent_mft: u64,
    entries: &[(u64, &str, bool)],
) -> usize {
    let mut content = vec![0u8; 16]; // index header (attr type, collation, block size, padding)
    for (mft, name, is_last) in entries {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = 66 + utf16.len() * 2;
        let entry_len = (16 + name_bytes + 7) & !7;
        let e = content.len();
        content.resize(e + entry_len, 0);
        put_u64_le(&mut content, e, *mft); // MFT reference
        put_u16_le(&mut content, e + 8, entry_len as u16);
        put_u16_le(&mut content, e + 10, 16); // content_offset (start of $FILENAME)
        put_u32_le(&mut content, e + 12, if *is_last { 0x02 } else { 0 }); // flags
                                                                           // Embedded $FILENAME content at e+16.
        put_u64_le(&mut content, e + 16, parent_mft);
        content[e + 16 + 64] = utf16.len() as u8;
        for (i, ch) in utf16.iter().enumerate() {
            put_u16_le(&mut content, e + 16 + 66 + i * 2, *ch);
        }
    }
    write_resident_attr(record, pos, ATTR_TYPE_INDEX_ROOT, &content)
}

/// `$DATA` non-resident attribute: single data run pointing at `lcn`.
fn write_nonresident_data_attr(record: &mut [u8], pos: usize, size: u64, lcn: u64) -> usize {
    let clusters = size.div_ceil(E2E_CLUSTER_SIZE as u64);
    let len_bytes = bytes_needed(clusters);
    let off_bytes = bytes_needed(lcn);
    let mut runs = Vec::new();
    runs.push((len_bytes as u8) | ((off_bytes as u8) << 4));
    for i in 0..len_bytes {
        runs.push(((clusters >> (i * 8)) & 0xff) as u8);
    }
    for i in 0..off_bytes {
        runs.push(((lcn >> (i * 8)) & 0xff) as u8);
    }
    runs.push(0x00); // run-list terminator

    const HEADER: usize = 64;
    let attr_len = HEADER + runs.len();
    put_u32_le(record, pos, ATTR_TYPE_DATA);
    put_u32_le(record, pos + 4, attr_len as u32);
    record[pos + 8] = 1; // non_resident = true
    record[pos + 9] = 0; // name_len
    put_u16_le(record, pos + 10, 0); // name_offset
    put_u16_le(record, pos + 12, 0); // flags
    put_u16_le(record, pos + 14, 0); // instance
    put_u64_le(record, pos + 16, 0); // lowest_vcn
    put_u64_le(record, pos + 24, 0); // highest_vcn
    put_u16_le(record, pos + 32, HEADER as u16); // data_runs_offset
    record[pos + 34] = 0; // compression_unit
    put_u64_le(record, pos + 40, size); // allocated_size
    put_u64_le(record, pos + 48, size); // data_size
    put_u64_le(record, pos + 56, size); // initialized_size
    record[pos + HEADER..pos + HEADER + runs.len()].copy_from_slice(&runs);
    attr_len
}

/// Byte offset of MFT record `n` in the image (MFT starts at cluster 0).
fn mft_record_offset(n: u64) -> usize {
    (n * E2E_MFT_RECORD_SIZE as u64) as usize
}

// ═══════════════════════════════════════════════════════════════════════════════
// E2E image builders
// ═══════════════════════════════════════════════════════════════════════════════

fn write_e2e_boot_sector(img: &mut [u8]) {
    img[3..7].copy_from_slice(b"NTFS");
    put_u16_le(img, 11, 512); // bytes_per_sector
    img[13] = 8; // sectors_per_cluster → cluster = 4096
    let total_sectors = (img.len() / 512) as u64;
    put_u64_le(img, 40, total_sectors);
    put_u64_le(img, 48, 0); // mft_lcn (MFT starts at byte 0)
    put_u64_le(img, 56, 0); // mft_mirr_lcn
    img[64] = 1; // clusters_per_mft_record → 4096-byte records
    img[68] = 1; // clusters_per_index_buffer
    put_u32_le(img, 72, 0x1234_5678); // volume_serial
}

fn write_e2e_root_dir_record(img: &mut [u8]) {
    let off = mft_record_offset(E2E_ROOT_MFT);
    let record = &mut img[off..off + E2E_MFT_RECORD_SIZE as usize];
    write_mft_header(record, MFT_RECORD_IN_USE | MFT_RECORD_DIRECTORY, 56);
    let mut pos = 56usize;
    pos += write_standard_info(record, pos);
    pos += write_index_root_attr(
        record,
        pos,
        E2E_ROOT_MFT,
        &[(E2E_FILE_MFT, "HELLO.TXT", true)],
    );
    pos += write_filename_attr(record, pos, E2E_ROOT_MFT, ".", 0);
    put_u32_le(record, pos, ATTR_TYPE_END);
}

fn write_e2e_file_record(img: &mut [u8]) {
    let off = mft_record_offset(E2E_FILE_MFT);
    let record = &mut img[off..off + E2E_MFT_RECORD_SIZE as usize];
    write_mft_header(record, MFT_RECORD_IN_USE, 56);
    let mut pos = 56usize;
    pos += write_nonresident_data_attr(record, pos, E2E_FILE_CONTENT.len() as u64, E2E_FILE_LCN);
    pos += write_standard_info(record, pos);
    pos += write_filename_attr(record, pos, E2E_ROOT_MFT, "HELLO.TXT", 0);
    put_u32_le(record, pos, ATTR_TYPE_END);
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
// E2E test image builder — with xattrs ($EA attribute)
// ═══════════════════════════════════════════════════════════════════════════════

const E2E_XATTR_FILE_MFT: u64 = 33;

/// Write a resident `$EA` attribute containing two xattr entries.
///
/// Returns bytes written (= attr_len).
fn write_ea_attr(buf: &mut [u8], off: usize) -> usize {
    // Build EA content:
    //   u32 ea_length (total including this field)
    //   Entry 1: name "test" (4), value "hello" (5) → 8 + 4 + 5 = 17, pad to 20
    //   Entry 2: name "foo"  (3), value "bar"  (3) → 8 + 3 + 3 = 14, pad to 16
    //   Total: 4 + 20 + 16 = 40

    let mut ea_content = vec![0u8; 40];

    // ea_length
    put_u32_le(&mut ea_content, 0, 40);

    // Entry 1: name "test", value "hello"
    put_u32_le(&mut ea_content, 4, 20); // next_entry_offset
    ea_content[8] = 0; // flags
    ea_content[9] = 4; // name_len
    put_u16_le(&mut ea_content, 10, 5); // value_len
    ea_content[12..16].copy_from_slice(b"test");
    ea_content[16..21].copy_from_slice(b"hello");
    // bytes 21..23 pad to 24 (4-byte from ea start = offset 4+20=24)

    // Entry 2: name "foo", value "bar"
    let base = 24;
    put_u32_le(&mut ea_content, base, 0); // next_entry_offset = 0 (last)
    ea_content[base + 4] = 0; // flags
    ea_content[base + 5] = 3; // name_len
    put_u16_le(&mut ea_content, base + 6, 3); // value_len
    ea_content[base + 8..base + 11].copy_from_slice(b"foo");
    ea_content[base + 11..base + 14].copy_from_slice(b"bar");

    write_resident_attr(buf, off, ATTR_TYPE_EA, &ea_content) as usize
}

fn build_ntfs_xattr_e2e_image() -> Vec<u8> {
    let total_bytes = (E2E_FILE_LCN as usize + 2) * E2E_CLUSTER_SIZE as usize;
    let mut img = vec![0u8; total_bytes];
    write_e2e_boot_sector(&mut img);
    write_e2e_root_dir_record(&mut img);
    write_e2e_file_record(&mut img);
    write_e2e_xattr_file_record(&mut img);
    // File data at cluster 64.
    let data_off = (E2E_FILE_LCN * E2E_CLUSTER_SIZE as u64) as usize;
    img[data_off..data_off + E2E_FILE_CONTENT.len()].copy_from_slice(E2E_FILE_CONTENT);
    img
}

fn write_e2e_root_dir_with_xattr_entry(img: &mut [u8]) {
    let off = mft_record_offset(E2E_ROOT_MFT);
    let record = &mut img[off..off + E2E_MFT_RECORD_SIZE as usize];
    write_mft_header(record, MFT_RECORD_IN_USE | MFT_RECORD_DIRECTORY, 56);
    let mut pos = 56usize;
    pos += write_standard_info(record, pos);
    pos += write_index_root_attr(
        record,
        pos,
        E2E_ROOT_MFT,
        &[
            (E2E_FILE_MFT, "HELLO.TXT", false),
            (E2E_XATTR_FILE_MFT, "XATTR.TXT", true),
        ],
    );
    pos += write_filename_attr(record, pos, E2E_ROOT_MFT, ".", 0);
    put_u32_le(record, pos, ATTR_TYPE_END);
}

fn write_e2e_xattr_file_record(img: &mut [u8]) {
    let off = mft_record_offset(E2E_XATTR_FILE_MFT);
    let record = &mut img[off..off + E2E_MFT_RECORD_SIZE as usize];
    write_mft_header(record, MFT_RECORD_IN_USE, 56);

    let mut pos = 56usize;
    // $DATA first (non-resident).
    pos += write_nonresident_data_attr(record, pos, E2E_FILE_CONTENT.len() as u64, E2E_FILE_LCN);
    // $STANDARD_INFO
    pos += write_standard_info(record, pos);
    // $FILENAME
    pos += write_filename_attr(record, pos, E2E_ROOT_MFT, "XATTR.TXT", 0);
    // $EA with two xattr entries.
    pos += write_ea_attr(record, pos);
    put_u32_le(record, pos, ATTR_TYPE_END);
}

fn open_e2e_xattr_volume() -> super::NtfsVolume {
    let mut img = build_ntfs_xattr_e2e_image();
    // Overwrite root dir record with one that has both entries.
    write_e2e_root_dir_with_xattr_entry(&mut img);
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-ntfs-xattr", img, false);
    super::NtfsVolume::open(dev).expect("open NTFS volume with xattrs")
}

// ═══════════════════════════════════════════════════════════════════════════════
// E2E tests — extended attributes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ntfs_e2e_list_xattrs_on_file_with_ea() {
    let vol = open_e2e_xattr_volume();
    let vnode = vol.lookup("/xattr.txt").expect("lookup");
    let xattrs = vnode.list_xattrs().expect("list_xattrs");
    assert_eq!(xattrs.len(), 2);
    // Find entries by name (order is as stored in $EA).
    let test_attr = xattrs
        .iter()
        .find(|x| x.name == b"user.test")
        .expect("user.test");
    assert_eq!(&test_attr.value[..], b"hello");
    let foo_attr = xattrs
        .iter()
        .find(|x| x.name == b"user.foo")
        .expect("user.foo");
    assert_eq!(&foo_attr.value[..], b"bar");
}

#[test]
fn ntfs_e2e_list_xattrs_via_volume() {
    let vol = open_e2e_xattr_volume();
    let xattrs = vol
        .list_xattrs("/xattr.txt")
        .expect("list_xattrs via volume");
    assert_eq!(xattrs.len(), 2);
    let names: Vec<&[u8]> = xattrs.iter().map(|x| x.name.as_slice()).collect();
    assert!(names.contains(&b"user.test".as_slice()));
    assert!(names.contains(&b"user.foo".as_slice()));
}

#[test]
fn ntfs_e2e_list_xattrs_on_file_without_ea() {
    let vol = open_e2e_xattr_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let xattrs = vnode.list_xattrs().expect("list_xattrs on file without EA");
    assert!(xattrs.is_empty());
}

#[test]
fn ntfs_e2e_list_xattrs_on_root_directory() {
    let vol = open_e2e_xattr_volume();
    let vnode = vol.lookup("/").expect("lookup root");
    let xattrs = vnode.list_xattrs().expect("list_xattrs on root");
    // Root directory in test image has no $EA attribute.
    assert!(xattrs.is_empty());
}

#[test]
fn ntfs_e2e_xattr_file_still_readable() {
    let vol = open_e2e_xattr_volume();
    let vnode = vol.lookup("/xattr.txt").expect("lookup");
    // Data should still be readable even though $EA is present.
    let mut buf = vec![0u8; E2E_FILE_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, E2E_FILE_CONTENT.len());
    assert_eq!(&buf[..n], E2E_FILE_CONTENT);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests — EA parsing
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

#[test]
fn filename_parse_namespace_and_dir_flag() {
    let body = make_filename_body("Documents", 1, 0x1000_0000, 5);
    let f = super::types::FileName::parse(&body).expect("parse filename");
    assert_eq!(f.name, "Documents");
    assert_eq!(f.namespace, 1);
    assert!(f.preferred_namespace());
    assert!(f.is_directory());

    let dos = make_filename_body("DOCUME~1", 2, 0, 5);
    let f2 = super::types::FileName::parse(&dos).expect("parse dos filename");
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
    let si = super::types::StandardInfoAttr::parse(&body).expect("parse standard info");
    assert!(si.is_directory());
    assert_eq!(si.created, 133_000_000_000_000_000);
    assert_eq!(si.modified, 133_000_000_100_000_000);
    // Converted Unix seconds should be finite and sane.
    let unix = super::types::StandardInfoAttr::to_unix_secs(si.created);
    assert!(unix > 1_600_000_000 && unix < 2_000_000_000);
}

#[test]
fn get_best_filename_prefers_win32_over_dos() {
    use super::types::{ParsedAttr, ATTR_TYPE_FILENAME};
    let dos = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
        content: make_filename_body("HELLO~1", 2, 0, 5),
        data_runs_offset: None,
        data_size: 0,
    };
    let win32 = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
        content: make_filename_body("hello.txt", 3, 0, 5),
        data_runs_offset: None,
        data_size: 0,
    };
    let best = super::fs::get_best_filename(&[dos.clone(), win32]).expect("best filename");
    assert_eq!(best.name, "hello.txt");
    assert_eq!(best.namespace, 3);
}

#[test]
fn parse_index_entries_dedups_namespaces() {
    // Two index entries for the same MFT record (42): a pure-DOS 8.3 name and
    // a Win32 long name.  Only the Win32 name should survive.
    let make_entry = |name: &str, namespace: u8| -> Vec<u8> {
        let name_bytes = make_filename_body(name, namespace, 0, 5);
        let entry_len = 16 + name_bytes.len();
        let mut e = vec![0u8; entry_len];
        put_u64_le(&mut e, 0, 42); // MFT ref
        put_u16_le(&mut e, 8, entry_len as u16);
        put_u16_le(&mut e, 10, 16); // content offset
                                    // flags at 12..16 (0 = not last for entry 1; set by caller)
        e[16..16 + name_bytes.len()].copy_from_slice(&name_bytes);
        e
    };
    let mut e1 = make_entry("HELLO~1", 2);
    let e2 = make_entry("hello.txt", 1);
    put_u32_le(&mut e1, 12, 0x02); // last-entry flag on the DOS entry
    let mut buf = Vec::new();
    buf.extend_from_slice(&e1);
    buf.extend_from_slice(&e2);

    let entries = super::fs::parse_index_entries(&buf).expect("parse index");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "hello.txt");
    assert_eq!(entries[0].1, 42);
}
