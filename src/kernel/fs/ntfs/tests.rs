//! src/kernel/fs/ntfs/tests.rs
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

use super::types::{
    parse_ea_entries, parse_reparse_point, FileName, ParsedAttr, StandardInfoAttr,
    ATTR_TYPE_FILENAME, IO_REPARSE_TAG_SYMLINK,
};
use crate::kernel::fs::ntfs::fs::{get_best_filename, parse_index_entries};

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
        content: make_filename_body("HELLO~1", 2, 0, 5),
        data_runs_offset: None,
        data_runs: Vec::new(),
        data_size: 0,
    };
    let win32 = ParsedAttr {
        attr_type: ATTR_TYPE_FILENAME,
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
                                   // Prepend the 16-byte `$INDEX_ROOT` header: first entry at 16, total
                                   // index size spans both entries.
    let mut buf = vec![0u8; 16];
    put_u16_le(&mut buf, 8, 16); // first entry offset
    put_u16_le(&mut buf, 10, (16 + e1.len() + e2.len()) as u16); // index size
    buf.extend_from_slice(&e1);
    buf.extend_from_slice(&e2);

    let entries = parse_index_entries(&buf).expect("parse index");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "hello.txt");
    assert_eq!(entries[0].1, 42);
}
