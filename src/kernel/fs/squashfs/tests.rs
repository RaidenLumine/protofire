//! src/kernel/fs/squashfs/tests.rs
//!
//! End-to-end tests for the SquashFS filesystem driver.
//!
//! Test image layout:
//!   Metadata block 0 (byte 96):   inode table (6 inodes)
//!   Metadata block 1 (byte 8288): root dir metadata (4 entries)
//!   Metadata block 2 (byte 16480): subdir metadata (1 entry)
//!   Data block 20 (byte 82016):   "Hello from SquashFS!\n"
//!   Data block 21 (byte 86112):   "Second file in root!\n"
//!   Data block 22 (byte 90208):   "Deep file in subdir!\n"

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::NodeKind;
use crate::Error;

use super::SquashfsVolume;

const META_BLOCK_SIZE: u64 = 8192;
const DATA_BLOCK_SIZE: u64 = 4096;
const SUPERBLOCK_SIZE: u64 = 96;
const FILE1_CONTENT: &[u8] = b"Hello from SquashFS!\n";
const FILE2_CONTENT: &[u8] = b"Second file in root!\n";
const FILE3_CONTENT: &[u8] = b"Deep file in subdir!\n";

// Inode offsets within inode table.
const INO_HELLO: u32 = 20;
const INO_WORLD: u32 = 44;
const INO_SUBDIR: u32 = 68;
const INO_DEEP: u32 = 88;
const INO_LINK: u32 = 112;

fn build_squashfs_image() -> Vec<u8> {
    let total = 95000usize;
    let mut img = vec![0u8; total];
    write_superblock(&mut img);
    write_inode_table(&mut img);
    write_root_directory(&mut img);
    write_subdir_directory(&mut img);
    write_file_data(&mut img);
    img
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn put_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Write an uncompressed metadata block at the given metadata block index.
/// Returns the byte offset of the block.
fn write_meta_block(img: &mut [u8], block_idx: u64, data: &[u8]) -> usize {
    let off = SUPERBLOCK_SIZE as usize + block_idx as usize * META_BLOCK_SIZE as usize;
    put_u16(img, off, data.len() as u16); // uncompressed size
    img[off + 2..off + 2 + data.len()].copy_from_slice(data);
    off
}

// ── Superblock ─────────────────────────────────────────────────────────────

fn write_superblock(img: &mut [u8]) {
    let sb = &mut img[..96];
    put_u32(sb, 0, 0x7371_7368); // magic "hsqs"
    put_u32(sb, 4, 6); // inode_count = 6
    put_u32(sb, 12, 4096); // block_size
    put_u16(sb, 20, 2); // compression = LZ4
    put_u64(sb, 24, 95000); // bytes_used
    put_u32(sb, 32, 0); // fragment_entry_count
    put_u64(sb, 48, 95000); // id_table_start
    put_u32(sb, 68, 0); // root_inode_offset = 0
}

// ── Inode table (metadata block 0) ─────────────────────────────────────────

fn write_inode_table(img: &mut [u8]) {
    // Root dir inode at offset 0 (type 1, 20 bytes total)
    let mut table = vec![0; 20];
    put_u16(&mut table, 0, 1); // inode_type = directory
    put_u16(&mut table, 2, 0o755); // mode
    put_u32(&mut table, 4, 1); // nlink
    put_u32(&mut table, 8, 80); // file_size = root dir metadata size
    put_u32(&mut table, 12, 1); // start_block = metadata block 1
    put_u32(&mut table, 16, 0); // parent_inode

    // File inode "hello.txt" at offset 20 (type 2, no fragments, 24 bytes)
    let off = table.len();
    table.resize(off + 24, 0);
    put_u16(&mut table, off, 2); // inode_type = file
    put_u16(&mut table, off + 2, 0o644); // mode
    put_u32(&mut table, off + 4, 1); // nlink
    put_u64(&mut table, off + 8, FILE1_CONTENT.len() as u64);
    put_u32(&mut table, off + 16, 0xFFFF_FFFF); // no fragments
    put_u32(&mut table, off + 20, 20); // start_block = data block 20
    assert_eq!(table.len(), 44);

    // File inode "world.txt" at offset 44 (type 2, no fragments, 24 bytes)
    let off = table.len();
    table.resize(off + 24, 0);
    put_u16(&mut table, off, 2);
    put_u16(&mut table, off + 2, 0o644);
    put_u32(&mut table, off + 4, 1);
    put_u64(&mut table, off + 8, FILE2_CONTENT.len() as u64);
    put_u32(&mut table, off + 16, 0xFFFF_FFFF);
    put_u32(&mut table, off + 20, 21); // data block 21
    assert_eq!(table.len(), 68);

    // Dir inode "subdir" at offset 68 (type 1, 20 bytes)
    let off = table.len();
    table.resize(off + 20, 0);
    put_u16(&mut table, off, 1); // directory
    put_u16(&mut table, off + 2, 0o755);
    put_u32(&mut table, off + 4, 1);
    put_u32(&mut table, off + 8, 19); // file_size = subdir metadata size
    put_u32(&mut table, off + 12, 2); // start_block = metadata block 2
    put_u32(&mut table, off + 16, 0);
    assert_eq!(table.len(), 88);

    // File inode "deep.txt" at offset 88 (type 2, no fragments, 24 bytes)
    let off = table.len();
    table.resize(off + 24, 0);
    put_u16(&mut table, off, 2);
    put_u16(&mut table, off + 2, 0o644);
    put_u32(&mut table, off + 4, 1);
    put_u64(&mut table, off + 8, FILE3_CONTENT.len() as u64);
    put_u32(&mut table, off + 16, 0xFFFF_FFFF);
    put_u32(&mut table, off + 20, 22); // data block 22
    assert_eq!(table.len(), 112);

    // Symlink inode "link" at offset 112 (type 3, 10 + target_len bytes)
    let target = b"hello.txt";
    let off = table.len();
    table.resize(off + 10 + target.len(), 0);
    put_u16(&mut table, off, 3); // inode_type = symlink
    put_u16(&mut table, off + 2, 0o777); // mode
    put_u32(&mut table, off + 4, 1); // nlink
    put_u32(&mut table, off + 6, target.len() as u32); // target_len
    table[off + 10..off + 10 + target.len()].copy_from_slice(target);

    write_meta_block(img, 0, &table);
}

// ── Root directory metadata (metadata block 1) ─────────────────────────────
//
// Each entry is its own group because the parser shares inode_offset within a
// group.  Group header = entry_data_bytes - 1.

fn write_root_directory(img: &mut [u8]) {
    let mut data = Vec::new();

    // Group 1: "hello.txt" → inode offset 20
    write_dir_group(&mut data, INO_HELLO, 2, b"hello.txt");
    // Group 2: "world.txt" → inode offset 44
    write_dir_group(&mut data, INO_WORLD, 2, b"world.txt");
    // Group 3: "subdir" → inode offset 68
    write_dir_group(&mut data, INO_SUBDIR, 2, b"subdir");
    // Group 4: "link" → inode offset 112
    write_dir_group(&mut data, INO_LINK, 2, b"link");

    write_meta_block(img, 1, &data);
}

fn write_dir_group(data: &mut Vec<u8>, inode_offset: u32, etype: u16, name: &[u8]) {
    let entry_bytes = 2 + name.len() + 1; // type(2) + name + null
    let header: u16 = (entry_bytes - 1) as u16;

    let start = data.len();
    data.resize(start + 8 + entry_bytes, 0);
    put_u16(data, start, header);
    // bytes start+2..start+4: unused
    put_u32(data, start + 4, inode_offset);
    put_u16(data, start + 8, etype);
    data[start + 10..start + 10 + name.len()].copy_from_slice(name);
    // null terminator at start+10+name.len() already 0
}

// ── Subdir directory metadata (metadata block 2) ───────────────────────────

fn write_subdir_directory(img: &mut [u8]) {
    let mut data = Vec::new();

    // One group: "deep.txt" → inode offset 88
    write_dir_group(&mut data, INO_DEEP, 2, b"deep.txt");

    write_meta_block(img, 2, &data);
}

// ── File data ──────────────────────────────────────────────────────────────

fn write_file_data(img: &mut [u8]) {
    // Data blocks: each block has a 2-byte uncompressed-size header.
    let write_data_block = |img: &mut [u8], block_idx: u64, content: &[u8]| {
        let off = SUPERBLOCK_SIZE as usize + block_idx as usize * DATA_BLOCK_SIZE as usize;
        put_u16(img, off, content.len() as u16);
        img[off + 2..off + 2 + content.len()].copy_from_slice(content);
    };

    write_data_block(img, 20, FILE1_CONTENT);
    write_data_block(img, 21, FILE2_CONTENT);
    write_data_block(img, 22, FILE3_CONTENT);
}

// ── Test helpers ───────────────────────────────────────────────────────────

fn open_volume() -> SquashfsVolume {
    let img = build_squashfs_image();
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-squashfs", img, false);
    SquashfsVolume::open(dev).expect("open SquashFS volume")
}

// ── Basic tests ────────────────────────────────────────────────────────────

#[test]
fn squashfs_open_and_name() {
    let vol = open_volume();
    assert_eq!(vol.name(), "squashfs");
}

#[test]
fn squashfs_root_is_directory() {
    let vol = open_volume();
    let vnode = vol.lookup("/").expect("lookup root");
    assert_eq!(vnode.kind(), NodeKind::Directory);
}

// ── File read tests ────────────────────────────────────────────────────────

#[test]
fn squashfs_read_root_file() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup hello.txt");
    assert_eq!(vnode.kind(), NodeKind::File);
    assert_eq!(vnode.size(), FILE1_CONTENT.len());
    let mut buf = vec![0u8; FILE1_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, FILE1_CONTENT.len());
    assert_eq!(&buf[..n], FILE1_CONTENT);
}

#[test]
fn squashfs_read_second_file() {
    let vol = open_volume();
    let vnode = vol.lookup("/world.txt").expect("lookup world.txt");
    assert_eq!(vnode.kind(), NodeKind::File);
    let mut buf = vec![0u8; FILE2_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, FILE2_CONTENT.len());
    assert_eq!(&buf[..n], FILE2_CONTENT);
}

#[test]
fn squashfs_read_partial() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let mut buf = [0u8; 5];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, 5);
    assert_eq!(&buf, b"Hello");
}

#[test]
fn squashfs_read_nonzero_offset() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let mut buf = [0u8; 5];
    let n = vnode.read(6, &mut buf).expect("read at offset 6");
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"from ");
}

#[test]
fn squashfs_read_beyond_eof() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let mut buf = [0u8; 16];
    let n = vnode
        .read(FILE1_CONTENT.len() as u64, &mut buf)
        .expect("read");
    assert_eq!(n, 0);
}

#[test]
fn squashfs_empty_buffer_read() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let mut buf = [0u8; 0];
    let n = vnode.read(0, &mut buf).expect("empty read");
    assert_eq!(n, 0);
}

// ── Directory tests ────────────────────────────────────────────────────────

#[test]
fn squashfs_read_dir_root() {
    let vol = open_volume();
    let entry = vol.read_dir("/", 0).expect("read_dir 0");
    assert_eq!(entry.name, "hello.txt");
    assert_eq!(entry.kind, NodeKind::File);
}

// ── Subdirectory tests ─────────────────────────────────────────────────────

#[test]
fn squashfs_subdir_lookup() {
    let vol = open_volume();
    let vnode = vol.lookup("/subdir").expect("lookup subdir");
    assert_eq!(vnode.kind(), NodeKind::Directory);
}

#[test]
fn squashfs_subdir_read_file() {
    let vol = open_volume();
    let vnode = vol.lookup("/subdir/deep.txt").expect("lookup deep file");
    assert_eq!(vnode.kind(), NodeKind::File);
    let mut buf = vec![0u8; FILE3_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, FILE3_CONTENT.len());
    assert_eq!(&buf[..n], FILE3_CONTENT);
}

#[test]
fn squashfs_subdir_read_dir() {
    let vol = open_volume();
    let entry = vol.read_dir("/subdir", 0).expect("read_dir subdir 0");
    assert_eq!(entry.name, "deep.txt");
    assert_eq!(entry.kind, NodeKind::File);
}

#[test]
fn squashfs_subdir_stat() {
    let vol = open_volume();
    let meta = vol.stat("/subdir/deep.txt").expect("stat");
    assert_eq!(meta.kind, NodeKind::File);
    assert_eq!(meta.size, FILE3_CONTENT.len());
}

// ── Symlink tests ──────────────────────────────────────────────────────────

#[test]
fn squashfs_symlink_lookup() {
    let vol = open_volume();
    let vnode = vol.lookup("/link").expect("lookup symlink");
    assert_eq!(vnode.kind(), NodeKind::Symlink);
}

#[test]
fn squashfs_symlink_readlink() {
    let vol = open_volume();
    let vnode = vol.lookup("/link").expect("lookup symlink");
    let target = vnode.readlink().expect("readlink");
    assert_eq!(target, b"hello.txt");
}

#[test]
fn squashfs_symlink_not_followed() {
    // Looking up a symlink returns the symlink node itself, not the target.
    let vol = open_volume();
    let vnode = vol.lookup("/link").expect("lookup symlink");
    assert_eq!(vnode.kind(), NodeKind::Symlink);
}

// ── Stat tests ─────────────────────────────────────────────────────────────

#[test]
fn squashfs_stat() {
    let vol = open_volume();
    let meta = vol.stat("/hello.txt").expect("stat");
    assert_eq!(meta.kind, NodeKind::File);
    assert_eq!(meta.size, FILE1_CONTENT.len());
}

#[test]
fn squashfs_stat_root_directory() {
    let vol = open_volume();
    let meta = vol.stat("/").expect("stat root");
    assert_eq!(meta.kind, NodeKind::Directory);
}

#[test]
fn squashfs_stat_subdir() {
    let vol = open_volume();
    let meta = vol.stat("/subdir").expect("stat subdir");
    assert_eq!(meta.kind, NodeKind::Directory);
}

#[test]
fn squashfs_not_found() {
    let vol = open_volume();
    assert!(matches!(
        vol.lookup("/nonexistent.txt"),
        Err(Error::NotFound)
    ));
}

#[test]
fn squashfs_not_found_in_subdir() {
    let vol = open_volume();
    assert!(matches!(
        vol.lookup("/subdir/nope.txt"),
        Err(Error::NotFound)
    ));
}

// ── Permission denied tests ────────────────────────────────────────────────

#[test]
fn squashfs_write_permission_denied() {
    let vol = open_volume();
    let vnode = vol.lookup("/hello.txt").expect("lookup");
    let result = vnode.write(0, b"test");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

#[test]
fn squashfs_create_file_permission_denied() {
    let vol = open_volume();
    let result = vol.create_file("/new.txt");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

#[test]
fn squashfs_create_dir_permission_denied() {
    let vol = open_volume();
    let result = vol.create_dir("/newdir");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

#[test]
fn squashfs_rename_permission_denied() {
    let vol = open_volume();
    let result = vol.rename("/hello.txt", "/renamed.txt");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

#[test]
fn squashfs_remove_path_permission_denied() {
    let vol = open_volume();
    let result = vol.remove_path("/hello.txt");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

#[test]
fn squashfs_symlink_write_permission_denied() {
    let vol = open_volume();
    let vnode = vol.lookup("/link").expect("lookup symlink");
    let result = vnode.write(0, b"test");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZSTD compression tests
// ═══════════════════════════════════════════════════════════════════════════════

const ZSTD_FILE_CONTENT: &[u8] = b"Hello from SquashFS ZSTD!\n";

/// Build a pre-computed ZSTD Raw_Block frame for `data`.
///
/// Layout:
///   4 bytes  magic (28 B5 2F FD)
///   1 byte   FHD (0x04: content checksum, window follows)
///   1 byte   window descriptor (0x10: windowLog=12 → 4KB window)
///   3 bytes  block header (last, raw, size = data.len())
///   N bytes  raw data
///   4 bytes  content checksum (zero — not verified by our decoder)
fn build_zstd_raw_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 1 + 1 + 3 + data.len() + 4);
    // Magic
    frame.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    // FHD: single_segment=0, content_checksum=1, did_flag=0
    frame.push(0x04);
    // Window descriptor: exponent=2 (4KB), mantissa=0 → 0x10
    frame.push(0x10);
    // Block header: last_block=1, block_type=0 (RAW), size = data.len()
    let size = data.len() as u32;
    let bh0 = 1u8 | ((size as u8) << 3);
    let bh1 = (size >> 5) as u8;
    let bh2 = (size >> 13) as u8;
    frame.push(bh0);
    frame.push(bh1);
    frame.push(bh2);
    // Raw data
    frame.extend_from_slice(data);
    // Content checksum (4 bytes, zero)
    frame.extend_from_slice(&[0u8; 4]);
    frame
}

fn build_squashfs_zstd_image() -> Vec<u8> {
    let total = 90000usize;
    let mut img = vec![0u8; total];

    // Superblock with ZSTD compression.
    {
        let sb = &mut img[..96];
        put_u32(sb, 0, 0x7371_7368); // magic "hsqs"
        put_u32(sb, 4, 2); // inode_count = 2 (root dir + file)
        put_u32(sb, 12, 4096); // block_size
        put_u16(sb, 20, 4); // compression = ZSTD
        put_u64(sb, 24, total as u64); // bytes_used
        put_u32(sb, 32, 0); // fragment_entry_count
        put_u64(sb, 48, total as u64); // id_table_start
        put_u32(sb, 68, 0); // root_inode_offset = 0
    }

    // Inode table (metadata block 0, uncompressed).
    {
        // Root dir inode at offset 0 (type 1, 20 bytes)
        let mut table = vec![0; 20];
        put_u16(&mut table, 0, 1); // inode_type = directory
        put_u16(&mut table, 2, 0o755);
        put_u32(&mut table, 4, 1); // nlink
        put_u32(&mut table, 8, 30); // file_size = root dir metadata size
        put_u32(&mut table, 12, 1); // start_block = metadata block 1
        put_u32(&mut table, 16, 0); // parent_inode

        // File inode "zstdfile" at offset 20 (type 2, no fragments, 24 bytes)
        let off = table.len();
        table.resize(off + 24, 0);
        put_u16(&mut table, off, 2); // inode_type = file
        put_u16(&mut table, off + 2, 0o644);
        put_u32(&mut table, off + 4, 1);
        put_u64(&mut table, off + 8, ZSTD_FILE_CONTENT.len() as u64);
        put_u32(&mut table, off + 16, 0xFFFF_FFFF); // no fragments
        put_u32(&mut table, off + 20, 20); // data block 20

        // Write uncompressed metadata block 0.
        let off = SUPERBLOCK_SIZE as usize;
        put_u16(&mut img, off, table.len() as u16); // uncompressed
        img[off + 2..off + 2 + table.len()].copy_from_slice(&table);
    }

    // Root directory metadata (metadata block 1, uncompressed).
    {
        let mut data = Vec::new();
        // One group: "zstdfile" → inode offset 20 (file inode), type=2
        let name = b"zstdfile";
        let entry_bytes = 2 + name.len() + 1; // type(2) + name + null
        let header: u16 = (entry_bytes - 1) as u16;
        data.resize(8 + entry_bytes, 0);
        put_u16(&mut data, 0, header);
        put_u32(&mut data, 4, 20); // inode_offset
        put_u16(&mut data, 8, 2); // entry type
        data[10..10 + name.len()].copy_from_slice(name);

        let off = SUPERBLOCK_SIZE as usize + META_BLOCK_SIZE as usize;
        put_u16(&mut img, off, data.len() as u16); // uncompressed
        img[off + 2..off + 2 + data.len()].copy_from_slice(&data);
    }

    // File data block (data block 20, ZSTD compressed).
    {
        let zstd_frame = build_zstd_raw_frame(ZSTD_FILE_CONTENT);
        let block_off = SUPERBLOCK_SIZE as usize + 20 * DATA_BLOCK_SIZE as usize;
        // SquashFS compressed block header: length with 0x8000 bit.
        let header_val = zstd_frame.len() as u16 | 0x8000u16;
        put_u16(&mut img, block_off, header_val);
        img[block_off + 2..block_off + 2 + zstd_frame.len()].copy_from_slice(&zstd_frame);
    }

    img
}

fn open_zstd_volume() -> SquashfsVolume {
    let img = build_squashfs_zstd_image();
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-squashfs-zstd", img, false);
    SquashfsVolume::open(dev).expect("open ZSTD SquashFS volume")
}

#[test]
fn squashfs_zstd_open_and_name() {
    let vol = open_zstd_volume();
    assert_eq!(vol.name(), "squashfs");
}

#[test]
fn squashfs_zstd_root_is_directory() {
    let vol = open_zstd_volume();
    let vnode = vol.lookup("/").expect("lookup root");
    assert_eq!(vnode.kind(), NodeKind::Directory);
}

#[test]
fn squashfs_zstd_read_file() {
    let vol = open_zstd_volume();
    let vnode = vol.lookup("/zstdfile").expect("lookup zstdfile");
    assert_eq!(vnode.kind(), NodeKind::File);
    assert_eq!(vnode.size(), ZSTD_FILE_CONTENT.len());
    let mut buf = vec![0u8; ZSTD_FILE_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, ZSTD_FILE_CONTENT.len());
    assert_eq!(&buf[..n], ZSTD_FILE_CONTENT);
}

#[test]
fn squashfs_zstd_read_partial() {
    let vol = open_zstd_volume();
    let vnode = vol.lookup("/zstdfile").expect("lookup");
    let mut buf = [0u8; 5];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(n, 5);
    assert_eq!(&buf, b"Hello");
}

#[test]
fn squashfs_zstd_read_nonzero_offset() {
    let vol = open_zstd_volume();
    let vnode = vol.lookup("/zstdfile").expect("lookup");
    let mut buf = [0u8; 4];
    let n = vnode.read(11, &mut buf).expect("read at offset 11");
    assert_eq!(n, 4);
    assert_eq!(&buf[..n], b"Squa");
}

#[test]
fn squashfs_zstd_stat() {
    let vol = open_zstd_volume();
    let meta = vol.stat("/zstdfile").expect("stat");
    assert_eq!(meta.kind, NodeKind::File);
    assert_eq!(meta.size, ZSTD_FILE_CONTENT.len());
}

#[test]
fn squashfs_zstd_read_dir() {
    let vol = open_zstd_volume();
    let entry = vol.read_dir("/", 0).expect("read_dir 0");
    assert_eq!(entry.name, "zstdfile");
    assert_eq!(entry.kind, NodeKind::File);
}

#[test]
fn squashfs_zstd_not_found() {
    let vol = open_zstd_volume();
    assert!(matches!(
        vol.lookup("/nonexistent.txt"),
        Err(Error::NotFound)
    ));
}

#[test]
fn squashfs_zstd_write_permission_denied() {
    let vol = open_zstd_volume();
    let vnode = vol.lookup("/zstdfile").expect("lookup");
    let result = vnode.write(0, b"test");
    assert!(matches!(result, Err(Error::PermissionDenied)));
}
