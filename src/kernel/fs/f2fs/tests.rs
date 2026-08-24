//! src/kernel/fs/f2fs/tests.rs
//!
//! Unit tests for the F2FS driver.
//!
//! The tests build a minimal in-memory F2FS image by hand using the same
//! on-disk serialisation helpers the driver itself uses, so the geometry
//! (superblock → checkpoint → SIT/NAT → main area) is exercised end to end:
//!
//! ```text
//! block 0  : superblock
//! block 1  : checkpoint copy 0 (check_ver = 1 — the winner)
//! block 2  : checkpoint copy 1 (check_ver = 0)
//! block 3  : SIT (segment 0 has 4 valid blocks, segment 1 is free)
//! block 4  : NAT (nid3 → block 6 root, nid4 → block 8 hello.txt)
//! block 5  : SSA (unused by v1, zeroed)
//! block 6  : root inode (nid 3)
//! block 7  : root directory data ("hello.txt" entry)
//! block 8  : hello.txt inode (nid 4)
//! block 9  : hello.txt data
//! block 10+…: rest of the two 512-block segments
//! ```

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::{FileSystem as VfsFileSystem, NodeKind};
use crate::Error;

use super::constants::*;
use super::types::*;
use super::F2fsVolume;

/// F2FS block size (2 ^ log_blocksize = 4096).
const F2FS_BLOCK_SIZE: usize = F2FS_DEFAULT_BLOCK_SIZE;

/// Total number of F2FS blocks in the test image.
const IMAGE_BLOCKS: u32 = 1030;

/// Main-area start block (segment0_blkaddr).
const MAIN_BLOCK: u32 = 6;

const CP0_BLOCK: u32 = 1;
const CP1_BLOCK: u32 = 2;
const SIT_BLOCK: u32 = 3;
const NAT_BLOCK: u32 = 4;
const SSA_BLOCK: u32 = 5;

const ROOT_INODE_BLOCK: u32 = 6;
const ROOT_DIR_DATA_BLOCK: u32 = 7;
const HELLO_INODE_BLOCK: u32 = 8;
const HELLO_DATA_BLOCK: u32 = 9;

/// NID of the hello.txt inode.
const HELLO_NID: u32 = 4;

/// Content of the hello.txt file.
const HELLO: &[u8] = b"Hello, f2fs!\n";

/// Build a fresh, empty inode struct with `i_addr` initialised to holes.
fn empty_inode(mode: u16) -> F2fsInode {
    F2fsInode {
        i_mode: mode,
        i_uid: 0,
        i_gid: 0,
        i_links: 1,
        i_size: 0,
        i_blocks: 0,
        i_atime: 0,
        i_ctime: 0,
        i_mtime: 0,
        i_atime_nsec: 0,
        i_ctime_nsec: 0,
        i_mtime_nsec: 0,
        i_xattr_nid: 0,
        i_flags: 0,
        i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
    }
}

/// Write one F2FS block's worth of bytes into the image at `blkaddr`.
fn put_block(image: &mut [u8], blkaddr: u32, data: &[u8]) {
    let start = blkaddr as usize * F2FS_BLOCK_SIZE;
    let end = start + F2FS_BLOCK_SIZE;
    assert!(end <= image.len(), "block {blkaddr} out of image bounds");
    image[start..end].copy_from_slice(data);
}

/// Serialise a block-sized buffer helper for an inode.
fn inode_block(inode: &F2fsInode) -> Vec<u8> {
    let mut block = vec![0u8; F2FS_BLOCK_SIZE];
    write_f2fs_inode(inode, &mut block);
    block
}

/// Build the minimal in-memory F2FS test image described in the module
/// documentation.
fn build_test_image() -> Vec<u8> {
    let mut image = vec![0u8; IMAGE_BLOCKS as usize * F2FS_BLOCK_SIZE];

    // ── Superblock (block 0) ─────────────────────────────────────────
    let sb = F2fsSuperblock {
        magic: F2FS_MAGIC,
        major_ver: 1,
        minor_ver: 0,
        log_sectorsize: 9,
        log_sectors_per_block: 3,
        log_blocksize: 12,
        log_blocks_per_seg: 9,
        segs_per_sec: 1,
        secs_per_zone: 1,
        checksum_offset: 0,
        block_count: IMAGE_BLOCKS as u64,
        section_count: 2,
        segment_count: 2,
        segment_count_main: 2,
        segment0_blkaddr: MAIN_BLOCK,
        cp_blkaddr: CP0_BLOCK,
        sit_blkaddr: SIT_BLOCK,
        nat_blkaddr: NAT_BLOCK,
        ssa_blkaddr: SSA_BLOCK,
        main_blkaddr: MAIN_BLOCK,
        root_ino: F2FS_NID_ROOT,
        node_ino: 1,
        meta_ino: 2,
        cp_payload: 0,
        feature: 0,
        nat_entry_cnt: 8,
        sit_entry_cnt: 2,
        node_count: 4,
    };
    {
        let mut block = vec![0u8; F2FS_BLOCK_SIZE];
        write_f2fs_superblock(&sb, &mut block);
        put_block(&mut image, 0, &block);
    }

    // ── Checkpoints (blocks 1 and 2) ─────────────────────────────────
    let cp_winner = F2fsCheckpoint {
        check_ver: 1,
        nat_ver: 1,
        sit_ver: 1,
        next_free_nid: 5,
        valid_block_count: 4,
        valid_node_count: 2,
        valid_inode_count: 2,
        nat_journal_entries: 0,
        nat_journal: Vec::new(),
        sit_journal_entries: 0,
        sit_journal: Vec::new(),
        orphan_inodes: Vec::new(),
        cp_copy: 0,
    };
    {
        let mut block = vec![0u8; F2FS_BLOCK_SIZE];
        write_f2fs_checkpoint(&cp_winner, &mut block);
        put_block(&mut image, CP0_BLOCK, &block);

        let mut loser = cp_winner.clone();
        loser.check_ver = 0;
        block.fill(0);
        write_f2fs_checkpoint(&loser, &mut block);
        put_block(&mut image, CP1_BLOCK, &block);
    }

    // ── SIT (block 3) ────────────────────────────────────────────────
    {
        let mut block = vec![0u8; F2FS_BLOCK_SIZE];
        let mut seg0 = F2fsSitEntry {
            vblocks: 4,
            valid_map: [0u8; 64],
        };
        seg0.valid_map[0] = 0x0F; // main blocks 6..9 (offsets 0..3)
        write_sit_entry(&seg0, &mut block[0..66]);
        let seg1 = F2fsSitEntry {
            vblocks: 0,
            valid_map: [0u8; 64],
        };
        write_sit_entry(&seg1, &mut block[66..132]);
        put_block(&mut image, SIT_BLOCK, &block);
    }

    // ── NAT (block 4): nid3 → root inode, nid4 → hello.txt inode ─────
    {
        let mut block = vec![0u8; F2FS_BLOCK_SIZE];
        let root_entry = F2fsNatEntry {
            block_addr: ROOT_INODE_BLOCK,
            ino: F2FS_NID_ROOT,
        };
        write_nat_entry(&root_entry, &mut block[3 * F2FS_NAT_ENTRY_SIZE..]);
        let hello_entry = F2fsNatEntry {
            block_addr: HELLO_INODE_BLOCK,
            ino: HELLO_NID,
        };
        write_nat_entry(&hello_entry, &mut block[4 * F2FS_NAT_ENTRY_SIZE..]);
        put_block(&mut image, NAT_BLOCK, &block);
    }

    // ── SSA (block 5): unused in v1, remains zeroed ──────────────────

    // ── Root inode (nid 3, block 6) ──────────────────────────────────
    {
        let mut root = empty_inode(F2FS_S_IFDIR | 0o755);
        root.i_links = 2;
        root.i_size = dir_entry_size("hello.txt".len()) as u64;
        root.i_blocks = (F2FS_BLOCK_SIZE as u64).div_ceil(512); // 1 block
        root.i_addr[0] = ROOT_DIR_DATA_BLOCK;
        put_block(&mut image, ROOT_INODE_BLOCK, &inode_block(&root));
    }

    // ── Root directory data (block 7): the "hello.txt" entry ─────────
    {
        let mut block = vec![0u8; F2FS_BLOCK_SIZE];
        write_f2fs_dir_entry(HELLO_NID, "hello.txt", F2FS_FT_REG_FILE, 0, &mut block);
        put_block(&mut image, ROOT_DIR_DATA_BLOCK, &block);
    }

    // ── hello.txt inode (nid 4, block 8) ─────────────────────────────
    {
        let mut file = empty_inode(F2FS_S_IFREG | 0o644);
        file.i_size = HELLO.len() as u64;
        file.i_blocks = (HELLO.len() as u64).div_ceil(512);
        file.i_addr[0] = HELLO_DATA_BLOCK;
        put_block(&mut image, HELLO_INODE_BLOCK, &inode_block(&file));
    }

    // ── hello.txt data (block 9) ─────────────────────────────────────
    {
        let start = HELLO_DATA_BLOCK as usize * F2FS_BLOCK_SIZE;
        image[start..start + HELLO.len()].copy_from_slice(HELLO);
    }

    image
}

fn open_volume(device: Arc<dyn BlockDevice>) -> F2fsVolume {
    F2fsVolume::open(device).expect("open f2fs volume")
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[test]
fn volume_opens_with_correct_name() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);
    assert_eq!(volume.name(), "f2fs:testf2fs");
}

#[test]
fn root_is_a_directory() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);
    let root = volume.lookup("/").expect("lookup /");
    assert_eq!(root.name(), "root");
    assert_eq!(root.kind(), NodeKind::Directory);
}

#[test]
fn stat_returns_file_metadata() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);

    let root_md = volume.stat("/").expect("stat /");
    assert_eq!(root_md.kind, NodeKind::Directory);
    assert_eq!(root_md.size, dir_entry_size("hello.txt".len()));

    let file_md = volume.stat("/hello.txt").expect("stat /hello.txt");
    assert_eq!(file_md.kind, NodeKind::File);
    assert_eq!(file_md.size, HELLO.len());
}

#[test]
fn read_dir_lists_entries() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);

    let e0 = volume.read_dir("/", 0).expect("entry 0");
    assert_eq!(e0.kind, NodeKind::File);
    assert_eq!(e0.name, "hello.txt");
    assert_eq!(e0.size, HELLO.len());

    assert!(matches!(volume.read_dir("/", 1), Err(Error::NotFound)));
}

#[test]
fn lookup_and_read_file() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);

    let node = volume.lookup("/hello.txt").expect("lookup /hello.txt");
    assert_eq!(node.name(), "hello.txt");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), HELLO.len());

    let metadata = node.metadata().expect("metadata");
    assert_eq!(metadata.kind, NodeKind::File);
    assert_eq!(metadata.size, HELLO.len());

    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(n, HELLO.len());
    assert_eq!(&buf[..n], HELLO);
}

#[test]
fn create_write_and_read_file() {
    let device = MemoryBlockDevice::new("testf2fs", build_test_image(), false);
    let volume = open_volume(device);

    let node = volume.create_file("/newfile.txt").expect("create file");
    assert_eq!(node.name(), "newfile.txt");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), 0);

    let payload = b"write me to disk";
    let written = node.write(0, payload).expect("write");
    assert_eq!(written, payload.len());
    assert_eq!(node.size(), payload.len());

    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read back");
    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], payload);

    // The new file is now visible in the root directory listing.
    let e1 = volume.read_dir("/", 1).expect("entry 1");
    assert_eq!(e1.kind, NodeKind::File);
    assert_eq!(e1.name, "newfile.txt");
    assert_eq!(e1.size, payload.len());

    // And it resolves through path lookup too.
    let by_path = volume.lookup("/newfile.txt").expect("lookup");
    let mut again = [0u8; 64];
    let n2 = by_path.read(0, &mut again).expect("read via path");
    assert_eq!(&again[..n2], payload);
}

#[test]
fn read_only_device_rejects_writes() {
    let device = MemoryBlockDevice::new("testf2fs-ro", build_test_image(), true);
    let volume = open_volume(device);

    // Reads still work on a read-only volume.
    let node = volume.lookup("/hello.txt").expect("lookup");
    let mut buf = [0u8; 64];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..n], HELLO);

    // Mutations are rejected with PermissionDenied.
    assert!(matches!(
        volume.create_file("/nope"),
        Err(Error::PermissionDenied)
    ));
    assert!(matches!(
        node.write(0, b"nope"),
        Err(Error::PermissionDenied)
    ));
}
