//! src/kernel/fs/btrfs/tests.rs
//!
//! Regression tests for the Btrfs driver.
//! Host-side tests for the read-only Btrfs driver: compressed extents,
//! multi-device logical→physical translation, and standard VFS operations.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::crypto::crc32c;
use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::btrfs::BtrfsVolume;
use crate::kernel::fs::vfs::{FileSystem as VfsFileSystem, NodeKind};
use crate::Error;

use super::types::{
    KEY_DIR_ITEM, KEY_EXTENT_DATA, KEY_INODE_ITEM, KEY_ROOT_ITEM, SUPERBLOCK_OFFSET,
};

// ── shared constants ──────────────────────────────────────────────────────

const NODE_SIZE: u32 = 4096;
const ROOT_DIR_INO: u64 = 6;
const FS_TREE_OBJECTID: u64 = 5;

const COMPRESSED_FILE_CONTENT: &[u8] = b"Hello ZSTD Raw Block!";

/// Pre-computed ZSTD frame for `COMPRESSED_FILE_CONTENT` (21 bytes),
/// compressed with `zstd -3` (matches the kernel's zstd_decompress tests).
const COMPRESSED_FILE_BLOB: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, // magic
    0x04, // FHD: checksum, no single-segment
    0x58, // window descriptor
    0xa9, 0x00, 0x00, // block header: last, raw, size=21
    // Raw data: "Hello ZSTD Raw Block!"
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x5a, 0x53, 0x54, 0x44, 0x20, 0x52, 0x61, 0x77, 0x20, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x21, // Content checksum (XXH32)
    0xe5, 0x98, 0xb9, 0x24,
];

const MDEV_FILE1_CONTENT: &[u8] = b"Hello from device 0\n";
const MDEV_FILE2_CONTENT: &[u8] = b"Hello from device 1\n";

const MDEV_FILE1_INO: u64 = 256;
const MDEV_FILE2_INO: u64 = 257;

// ── Multi-device test layout ─────────────────────────────────────────────
// Device 0 carries the superblock, chunk tree, root tree, fs tree, and the
// data for `dev0.txt`.  Device 1 carries only data for `dev1.txt`, reached
// through chunk B.
const DEV0_CHUNK_TREE_ADDR: u64 = 0x11000;
const DEV0_ROOT_TREE_ADDR: u64 = 0x12000;
const DEV0_FS_TREE_ADDR: u64 = 0x13000;
const DEV0_META_RANGE_END: u64 = 0x30000;
const DEV1_CHUNK_SIZE: u64 = 0x2000;
const DEV1_FILE_LOGICAL: u64 = 0x31000;
const DEV1_FILE_PHYS_OFFSET: u64 = 0x1000;

// ── Compressed single-device test layout ─────────────────────────────────
const ROOT_TREE_ADDR: u64 = 0x11000;
const FS_TREE_ADDR: u64 = 0x12000;
const COMPRESSED_DATA_ADDR: u64 = 0x20000;
const FILE_INO: u64 = 256;

// ── low-level byte writers ───────────────────────────────────────────────

fn put_u16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

/// Write a B-tree node header.  The header lives at offset 0 of the node:
/// csum (0-3), padding (4-63), bytenr (64), generation (72), owner (80),
/// nritems (88), level (92).
fn write_node_header(buf: &mut [u8], bytenr: u64, generation: u64, nritems: u32, owner: u64) {
    put_u64(buf, 64, bytenr);
    put_u64(buf, 72, generation);
    put_u64(buf, 80, owner);
    put_u32(buf, 88, nritems);
}

/// Write a 25-byte item header (btrfs_item) at `offset`.
fn write_item_header(
    buf: &mut [u8],
    offset: usize,
    objectid: u64,
    key_type: u8,
    key_offset: u64,
    data_offset: u32,
    data_size: u32,
) {
    put_u64(buf, offset, objectid);
    buf[offset + 8] = key_type;
    put_u64(buf, offset + 9, key_offset);
    put_u32(buf, offset + 17, data_offset);
    put_u32(buf, offset + 21, data_size);
}

fn write_root_item_data(buf: &mut [u8], root_dirid: u64, root_bytenr: u64, flags: u64) {
    put_u64(buf, 168, root_dirid);
    put_u64(buf, 176, root_bytenr);
    put_u64(buf, 208, flags);
}

fn write_inode_item(buf: &mut [u8], mode: u32, size: u64, nlink: u32) {
    put_u64(buf, 16, size);
    put_u32(buf, 72, mode);
    put_u32(buf, 88, nlink);
}

fn write_dir_item(buf: &mut [u8], inode: u64, name: &[u8], file_type: u8) {
    put_u64(buf, 0, inode);
    put_u16(buf, 27, name.len() as u16);
    buf[29] = file_type;
    buf[30..30 + name.len()].copy_from_slice(name);
}

/// Write an uncompressed regular file extent item.
fn write_extent_data(buf: &mut [u8], disk_bytenr: u64, num_bytes: u64) {
    put_u64(buf, 8, num_bytes); // ram_bytes
    buf[16] = 0; // compression = none
    buf[17] = 0; // encryption
    buf[20] = 1; // type = regular
    put_u64(buf, 21, disk_bytenr);
    put_u64(buf, 29, num_bytes); // disk_num_bytes
    put_u64(buf, 37, 0); // offset
    put_u64(buf, 45, num_bytes); // num_bytes
}

/// Write a ZSTD-compressed regular file extent item.
fn write_compressed_extent(buf: &mut [u8], disk_bytenr: u64, disk_num_bytes: u64, ram_bytes: u64) {
    put_u64(buf, 8, ram_bytes);
    buf[16] = 3; // compression = zstd
    buf[17] = 0;
    buf[20] = 1; // type = regular
    put_u64(buf, 21, disk_bytenr);
    put_u64(buf, 29, disk_num_bytes);
    put_u64(buf, 37, 0); // offset
    put_u64(buf, 45, ram_bytes); // num_bytes
}

/// Compute and store the CRC32C node checksum.
fn fixup_node_csum(dev: &mut [u8], addr: usize, size: usize) {
    let node = &mut dev[addr..addr + size];
    let saved: [u8; 32] = node[..32].try_into().expect("node header");
    node[..32].fill(0);
    let computed = crc32c(node);
    node[..32].copy_from_slice(&saved);
    put_u32(node, 0, computed);
}

// ── Compressed single-device volume ──────────────────────────────────────

fn build_compressed_volume_image() -> Vec<u8> {
    let dev_size = 0x22000usize;
    let mut dev = vec![0u8; dev_size];

    // ── Superblock ───────────────────────────────────────────────────────
    {
        let off = SUPERBLOCK_OFFSET as usize;
        let sb = &mut dev[off..off + 4096];
        sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        put_u64(sb, 0x30, SUPERBLOCK_OFFSET);
        put_u64(sb, 0x38, 1);
        put_u64(sb, 0x48, ROOT_TREE_ADDR); // root_tree_root
        put_u64(sb, 0x50, 0); // chunk_tree_root (single device → identity)
        put_u64(sb, 0x58, 0);
        put_u64(sb, 0x60, dev_size as u64);
        put_u64(sb, 0x70, ROOT_DIR_INO);
        put_u64(sb, 0x78, 1); // num_devices
        put_u32(sb, 0x88, 4096); // sector_size
        put_u32(sb, 0x8C, NODE_SIZE);
        put_u32(sb, 0x90, NODE_SIZE);
        put_u32(sb, 0x9C, 4096); // stripe_size
        put_u64(sb, 0xB0, 1); // chunk_root_gen
    }

    // ── Root tree leaf (1 ROOT_ITEM for FS_TREE) ─────────────────────────
    {
        let off = ROOT_TREE_ADDR as usize;
        let leaf = &mut dev[off..off + NODE_SIZE as usize];
        write_node_header(leaf, ROOT_TREE_ADDR, 1, 1, 0);
        let data_size: u32 = 300;
        let d1 = NODE_SIZE - data_size;
        write_item_header(leaf, 101, FS_TREE_OBJECTID, KEY_ROOT_ITEM, 0, d1, data_size);
        write_root_item_data(&mut leaf[d1 as usize..], ROOT_DIR_INO, FS_TREE_ADDR, 0);
    }

    // ── FS tree leaf (4 items) ───────────────────────────────────────────
    //
    // Items:
    //  1. {6,   1,   0}   INODE_ITEM root dir
    //  2. {6,   84,  0}   DIR_ITEM "compressed.txt"
    //  3. {256, 1,   0}   INODE_ITEM file (compressed.txt)
    //  4. {256, 108, 0}   EXTENT_DATA file (zstd, logical 0x20000)
    {
        let off = FS_TREE_ADDR as usize;
        let leaf = &mut dev[off..off + NODE_SIZE as usize];
        write_node_header(leaf, FS_TREE_ADDR, 5, 4, 0);

        let d_ext: u32 = 53;
        let d_inode: u32 = 160;
        let d_dir: u32 = 44; // 30 + 14 ("compressed.txt")

        let d4 = NODE_SIZE - d_ext;
        let d3 = d4 - d_inode;
        let d2 = d3 - d_dir;
        let d1 = d2 - d_inode;

        let mut hdr = 101usize;
        write_item_header(leaf, hdr, ROOT_DIR_INO, KEY_INODE_ITEM, 0, d1, d_inode);
        hdr += 25;
        write_item_header(leaf, hdr, ROOT_DIR_INO, KEY_DIR_ITEM, 0, d2, d_dir);
        hdr += 25;
        write_item_header(leaf, hdr, FILE_INO, KEY_INODE_ITEM, 0, d3, d_inode);
        hdr += 25;
        write_item_header(leaf, hdr, FILE_INO, KEY_EXTENT_DATA, 0, d4, d_ext);

        write_inode_item(&mut leaf[d1 as usize..], 0o040755, 0, 2);
        write_dir_item(&mut leaf[d2 as usize..], FILE_INO, b"compressed.txt", 1);
        write_inode_item(
            &mut leaf[d3 as usize..],
            0o100644,
            COMPRESSED_FILE_CONTENT.len() as u64,
            1,
        );
        write_compressed_extent(
            &mut leaf[d4 as usize..],
            COMPRESSED_DATA_ADDR,
            COMPRESSED_FILE_BLOB.len() as u64,
            COMPRESSED_FILE_CONTENT.len() as u64,
        );
    }

    // ── File data (compressed blob) ──────────────────────────────────────
    let blob_off = COMPRESSED_DATA_ADDR as usize;
    dev[blob_off..blob_off + COMPRESSED_FILE_BLOB.len()].copy_from_slice(COMPRESSED_FILE_BLOB);

    fixup_node_csum(&mut dev, ROOT_TREE_ADDR as usize, NODE_SIZE as usize);
    fixup_node_csum(&mut dev, FS_TREE_ADDR as usize, NODE_SIZE as usize);

    dev
}

fn open_compressed_volume() -> BtrfsVolume {
    let image = build_compressed_volume_image();
    let device = MemoryBlockDevice::new("test-btrfs-compressed", image, false);
    BtrfsVolume::open(vec![device as Arc<dyn BlockDevice>]).expect("open compressed Btrfs volume")
}

#[test]
fn btrfs_compressed_file_read() {
    let vol = open_compressed_volume();
    let vnode = vol.lookup("/compressed.txt").expect("lookup");
    let mut buf = vec![0u8; COMPRESSED_FILE_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read compressed");
    assert_eq!(n, COMPRESSED_FILE_CONTENT.len());
    assert_eq!(&buf[..n], COMPRESSED_FILE_CONTENT);
}

#[test]
fn btrfs_compressed_file_read_partial() {
    let vol = open_compressed_volume();
    let vnode = vol.lookup("/compressed.txt").expect("lookup");
    let mut buf = [0u8; 10];
    let n = vnode.read(5, &mut buf).expect("read partial");
    assert_eq!(n, 10);
    assert_eq!(&buf, &COMPRESSED_FILE_CONTENT[5..15]);
}

#[test]
fn btrfs_compressed_file_stat() {
    let vol = open_compressed_volume();
    let meta = vol.stat("/compressed.txt").expect("stat");
    assert_eq!(meta.kind, NodeKind::File);
    assert_eq!(meta.size, COMPRESSED_FILE_CONTENT.len());
}

// ── Multi-device tests ──────────────────────────────────────────────────────

/// Write a chunk item (btrfs_chunk) into `buf`.
///
/// On-disk layout (header 48 bytes + N×32 byte stripes):
///   0-7    size
///   8-15   owner (0)
///   16-23  stripe_length (set to sector_size for simplicity)
///   24-31  type (0 = SINGLE profile, DATA)
///   32-35  io_align
///   36-39  io_width
///   40-43  sector_size
///   44-45  num_stripes (u16)
///   46-47  sub_stripes (0)
///   48+    stripes
fn write_chunk_item(buf: &mut [u8], size: u64, stripe: (u64, u64)) {
    let (devid, offset) = stripe;
    buf[..48].fill(0);
    put_u64(buf, 0, size);
    // stripe_length: use 4096 (sector_size)
    put_u64(buf, 16, 4096);
    // type: 1 = SYSTEM (bit 0), we use 1 so the chunk is recognised.
    put_u64(buf, 24, 1);
    put_u32(buf, 32, 4096); // io_align
    put_u32(buf, 36, 4096); // io_width
    put_u32(buf, 40, 4096); // sector_size
    put_u16(buf, 44, 1); // num_stripes = 1
                         // Stripe at offset 48:
    put_u64(buf, 48, devid);
    put_u64(buf, 56, offset);
}

fn build_btrfs_multi_device_images() -> (Vec<u8>, Vec<u8>) {
    let dev0_size = 0x22000usize;
    let dev1_size = 0x2000usize;
    let mut dev0 = vec![0u8; dev0_size];
    let mut dev1 = vec![0u8; dev1_size];

    // ── Device 0: Superblock ───────────────────────────────────────────────
    {
        let off = SUPERBLOCK_OFFSET as usize;
        let sb = &mut dev0[off..off + 4096];
        sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        put_u64(sb, 0x30, SUPERBLOCK_OFFSET);
        put_u64(sb, 0x38, 1);
        put_u64(sb, 0x48, DEV0_ROOT_TREE_ADDR);
        put_u64(sb, 0x50, DEV0_CHUNK_TREE_ADDR); // chunk_tree_root → chunk tree
        put_u64(sb, 0x58, 0);
        put_u64(sb, 0x60, dev0_size as u64 + dev1_size as u64);
        put_u64(sb, 0x68, dev0_size as u64 + dev1_size as u64 - 0x10000);
        put_u64(sb, 0x70, ROOT_DIR_INO);
        put_u64(sb, 0x78, 2); // num_devices = 2
        put_u32(sb, 0x88, 4096);
        put_u32(sb, 0x8C, NODE_SIZE);
        put_u32(sb, 0x90, NODE_SIZE);
        put_u32(sb, 0x9C, 4096);
        put_u64(sb, 0xB0, 1);
        put_u64(sb, 0xB8, 0);
        put_u64(sb, 0xC0, 0);
    }

    // ── Device 0: Chunk tree leaf (2 CHUNK_ITEMs) ──────────────────────────
    {
        let off = DEV0_CHUNK_TREE_ADDR as usize;
        let leaf = &mut dev0[off..off + NODE_SIZE as usize];
        write_node_header(leaf, DEV0_CHUNK_TREE_ADDR, 256, 2, 0);

        // chunk_item data size: 48 + 1×32 = 80 bytes each
        let chunk_data_size: u32 = 80;
        let d2 = NODE_SIZE - chunk_data_size; // chunk B (device 1)
        let d1 = d2 - chunk_data_size; // chunk A (device 0)

        // Item 1: CHUNK_ITEM {256, 228, 0x0} → device 0
        write_item_header(leaf, 101, 256, 228, 0, d1, chunk_data_size);
        write_chunk_item(&mut leaf[d1 as usize..], DEV0_META_RANGE_END, (0, 0));

        // Item 2: CHUNK_ITEM {256, 228, 0x30000} → device 1
        write_item_header(
            leaf,
            126,
            256,
            228,
            DEV0_META_RANGE_END,
            d2,
            chunk_data_size,
        );
        write_chunk_item(&mut leaf[d2 as usize..], DEV1_CHUNK_SIZE, (1, 0));
    }

    // ── Device 0: Root tree leaf (1 ROOT_ITEM for FS_TREE) ─────────────────
    {
        let off = DEV0_ROOT_TREE_ADDR as usize;
        let leaf = &mut dev0[off..off + NODE_SIZE as usize];
        write_node_header(leaf, DEV0_ROOT_TREE_ADDR, 1, 1, 0);
        let data_size: u32 = 300;
        let d1 = NODE_SIZE - data_size;
        write_item_header(leaf, 101, 5, 132, 0, d1, data_size);
        write_root_item_data(&mut leaf[d1 as usize..], ROOT_DIR_INO, DEV0_FS_TREE_ADDR, 0);
    }

    // ── Device 0: FS tree leaf (6 items) ───────────────────────────────────
    //
    // Items:
    //  1. {6,   1,   0}  INODE_ITEM root dir
    //  2. {6,   84,  0}  DIR_ITEM "dev0.txt"
    //  3. {6,   84,  1}  DIR_ITEM "dev1.txt"
    //  4. {256, 1,   0}  INODE_ITEM file1
    //  5. {256, 108, 0}  EXTENT_DATA file1 (logical 0x20000 → device 0)
    //  6. {257, 1,   0}  INODE_ITEM file2
    //  7. {257, 108, 0}  EXTENT_DATA file2 (logical 0x31000 → device 1)
    {
        let off = DEV0_FS_TREE_ADDR as usize;
        let leaf = &mut dev0[off..off + NODE_SIZE as usize];
        write_node_header(leaf, DEV0_FS_TREE_ADDR, 5, 7, 0);

        let d_inode: u32 = 160;
        let d_ext: u32 = 53;
        let d_dir0: u32 = 38; // "dev0.txt"
        let d_dir1: u32 = 38; // "dev1.txt"

        let d7 = NODE_SIZE - d_ext;
        let d6 = d7 - d_inode;
        let d5 = d6 - d_ext;
        let d4 = d5 - d_inode;
        let d3 = d4 - d_dir1;
        let d2 = d3 - d_dir0;
        let d1 = d2 - d_inode;

        let mut hdr = 101usize;
        // Item 1: INODE_ITEM root dir (ino=6)
        write_item_header(leaf, hdr, ROOT_DIR_INO, 1, 0, d1, d_inode);
        hdr += 25;
        // Item 2: DIR_ITEM "dev0.txt" → ino=256
        write_item_header(leaf, hdr, ROOT_DIR_INO, 84, 0, d2, d_dir0);
        hdr += 25;
        // Item 3: DIR_ITEM "dev1.txt" → ino=257
        write_item_header(leaf, hdr, ROOT_DIR_INO, 84, 1, d3, d_dir1);
        hdr += 25;
        // Item 4: INODE_ITEM file1 (ino=256)
        write_item_header(leaf, hdr, MDEV_FILE1_INO, 1, 0, d4, d_inode);
        hdr += 25;
        // Item 5: EXTENT_DATA file1 (logical 0x20000)
        write_item_header(leaf, hdr, MDEV_FILE1_INO, 108, 0, d5, d_ext);
        hdr += 25;
        // Item 6: INODE_ITEM file2 (ino=257)
        write_item_header(leaf, hdr, MDEV_FILE2_INO, 1, 0, d6, d_inode);
        hdr += 25;
        // Item 7: EXTENT_DATA file2 (logical 0x31000)
        write_item_header(leaf, hdr, MDEV_FILE2_INO, 108, 0, d7, d_ext);

        // Item data
        write_inode_item(&mut leaf[d1 as usize..], 0o040755, 0, 2);
        write_dir_item(&mut leaf[d2 as usize..], MDEV_FILE1_INO, b"dev0.txt", 1);
        write_dir_item(&mut leaf[d3 as usize..], MDEV_FILE2_INO, b"dev1.txt", 1);
        write_inode_item(
            &mut leaf[d4 as usize..],
            0o100644,
            MDEV_FILE1_CONTENT.len() as u64,
            1,
        );
        write_extent_data(
            &mut leaf[d5 as usize..],
            0x20000, // logical address → Chunk A → device 0 physical 0x20000
            MDEV_FILE1_CONTENT.len() as u64,
        );
        write_inode_item(
            &mut leaf[d6 as usize..],
            0o100644,
            MDEV_FILE2_CONTENT.len() as u64,
            1,
        );
        write_extent_data(
            &mut leaf[d7 as usize..],
            DEV1_FILE_LOGICAL, // logical 0x31000 → Chunk B → device 1 physical 0x1000
            MDEV_FILE2_CONTENT.len() as u64,
        );
    }

    // ── Device 0: File data ────────────────────────────────────────────────
    let f1_off = 0x20000usize;
    dev0[f1_off..f1_off + MDEV_FILE1_CONTENT.len()].copy_from_slice(MDEV_FILE1_CONTENT);

    // ── Device 1: File data ────────────────────────────────────────────────
    let f2_off = DEV1_FILE_PHYS_OFFSET as usize;
    dev1[f2_off..f2_off + MDEV_FILE2_CONTENT.len()].copy_from_slice(MDEV_FILE2_CONTENT);

    // ── Fix up CRC32C checksums ────────────────────────────────────────────
    fixup_node_csum(&mut dev0, DEV0_CHUNK_TREE_ADDR as usize, NODE_SIZE as usize);
    fixup_node_csum(&mut dev0, DEV0_ROOT_TREE_ADDR as usize, NODE_SIZE as usize);
    fixup_node_csum(&mut dev0, DEV0_FS_TREE_ADDR as usize, NODE_SIZE as usize);

    (dev0, dev1)
}

fn open_multi_device_volume() -> BtrfsVolume {
    let (img0, img1) = build_btrfs_multi_device_images();
    let dev0: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-btrfs-mdev0", img0, false);
    let dev1: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-btrfs-mdev1", img1, false);
    BtrfsVolume::open(vec![dev0, dev1]).expect("open multi-device Btrfs volume")
}

// ── Multi-device tests ──────────────────────────────────────────────────────

#[test]
fn btrfs_multi_device_open_and_name() {
    let vol = open_multi_device_volume();
    assert_eq!(vol.name(), "btrfs");
}

#[test]
fn btrfs_multi_device_read_file_on_device_0() {
    let vol = open_multi_device_volume();
    let vnode = vol.lookup("/dev0.txt").expect("lookup dev0.txt");
    assert_eq!(vnode.kind(), NodeKind::File);
    assert_eq!(vnode.size(), MDEV_FILE1_CONTENT.len());
    let mut buf = vec![0u8; MDEV_FILE1_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read dev0.txt");
    assert_eq!(n, MDEV_FILE1_CONTENT.len());
    assert_eq!(&buf[..n], MDEV_FILE1_CONTENT);
}

#[test]
fn btrfs_multi_device_read_file_on_device_1() {
    let vol = open_multi_device_volume();
    let vnode = vol.lookup("/dev1.txt").expect("lookup dev1.txt");
    assert_eq!(vnode.kind(), NodeKind::File);
    assert_eq!(vnode.size(), MDEV_FILE2_CONTENT.len());
    let mut buf = vec![0u8; MDEV_FILE2_CONTENT.len() + 10];
    let n = vnode.read(0, &mut buf).expect("read dev1.txt");
    assert_eq!(n, MDEV_FILE2_CONTENT.len());
    assert_eq!(&buf[..n], MDEV_FILE2_CONTENT);
}

#[test]
fn btrfs_multi_device_read_partial() {
    let vol = open_multi_device_volume();
    let vnode = vol.lookup("/dev1.txt").expect("lookup dev1.txt");
    let mut buf = [0u8; 5];
    let n = vnode.read(3, &mut buf).expect("read partial on dev1");
    assert_eq!(n, 5);
    assert_eq!(&buf, &MDEV_FILE2_CONTENT[3..8]);
}

#[test]
fn btrfs_multi_device_stat_both_files() {
    let vol = open_multi_device_volume();
    let meta0 = vol.stat("/dev0.txt").expect("stat dev0");
    assert_eq!(meta0.kind, NodeKind::File);
    assert_eq!(meta0.size, MDEV_FILE1_CONTENT.len());
    let meta1 = vol.stat("/dev1.txt").expect("stat dev1");
    assert_eq!(meta1.kind, NodeKind::File);
    assert_eq!(meta1.size, MDEV_FILE2_CONTENT.len());
}

#[test]
fn btrfs_multi_device_read_dir() {
    let vol = open_multi_device_volume();
    let e0 = vol.read_dir("/", 0).expect("read_dir 0");
    assert_eq!(e0.name, "dev0.txt");
    assert_eq!(e0.kind, NodeKind::File);
    let e1 = vol.read_dir("/", 1).expect("read_dir 1");
    assert_eq!(e1.name, "dev1.txt");
    assert_eq!(e1.kind, NodeKind::File);
}

#[test]
fn btrfs_multi_device_root_is_directory() {
    let vol = open_multi_device_volume();
    let vnode = vol.lookup("/").expect("lookup root");
    assert_eq!(vnode.kind(), NodeKind::Directory);
}

#[test]
fn btrfs_multi_device_not_found() {
    let vol = open_multi_device_volume();
    assert!(matches!(
        vol.lookup("/nonexistent.txt"),
        Err(Error::NotFound)
    ));
}

#[test]
fn btrfs_multi_device_write_permission_denied() {
    let vol = open_multi_device_volume();
    let vnode = vol.lookup("/dev0.txt").expect("lookup");
    assert!(matches!(
        vnode.write(0, b"test"),
        Err(Error::PermissionDenied)
    ));
}
