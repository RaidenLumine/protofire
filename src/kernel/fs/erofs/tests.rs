//! src/kernel/fs/erofs/tests.rs
//!
//! Regression tests for the EROFS driver.
//! End-to-end tests for the EROFS (read-only) filesystem driver.
//!
//! Test image layout (4096-byte logical blocks, superblock at byte 1024):
//!   Block 64:            compact inode table (32 bytes per NID)
//!     NID 1 (off 32):    root directory → data block 65
//!     NID 2 (off 64):    hello.txt (regular file) → data block 66
//!     NID 3 (off 96):    subdir (directory) → data block 67
//!     NID 4 (off 128):   link (symlink → "hello.txt", inline target)
//!     NID 5 (off 160):   large.bin (5000-byte file) → blocks 68-69
//!     NID 6 (off 192):   deep.txt (file inside subdir) → block 70
//!   Block 65:            root directory (".", "..", "hello.txt",
//!                        "subdir", "link", "large.bin")
//!   Block 66:            "Hello from EROFS!\n"
//!   Block 67:            subdir directory (".", "..", "deep.txt")
//!   Blocks 68-69:        large.bin payload
//!   Block 70:            "Deep file in subdir!\n"

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block::MemoryBlockDevice;
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::NodeKind;

use super::types::EROFS_FEATURE_INCOMPAT_NID_TABLE;
use super::types::EROFS_FT_DIR;
use super::types::EROFS_FT_REG_FILE;
use super::types::EROFS_FT_SYMLINK;
use super::types::EROFS_MAGIC;
use super::types::EROFS_S_IFDIR;
use super::types::EROFS_S_IFLNK;
use super::types::EROFS_S_IFREG;
use super::EroFsVolume;

const BLOCK_SIZE: usize = 4096;
const META_BLKADDR: u32 = 64;

const HELLO_CONTENT: &[u8] = b"Hello from EROFS!\n";
const DEEP_CONTENT: &[u8] = b"Deep file in subdir!\n";
const LARGE_SIZE: usize = 5000;
const LINK_TARGET: &[u8] = b"hello.txt";

// Inode byte offsets within the metadata block (NID n → offset n * 32).
const OFF_ROOT: usize = 32;
const OFF_HELLO: usize = 64;
const OFF_SUBDIR: usize = 96;
const OFF_LINK: usize = 128;
const OFF_LARGE: usize = 160;
const OFF_DEEP: usize = 192;

// ── Image builder ───────────────────────────────────────────────────────────

fn build_erofs_image() -> Vec<u8> {
    let mut img = vec![0u8; 128 * BLOCK_SIZE];
    write_superblock(&mut img);
    write_inodes(&mut img);
    write_root_dir(&mut img);
    write_subdir(&mut img);
    write_file_data(&mut img);
    img
}

fn put_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// Write a compact EROFS inode (32 bytes) at the given byte offset.
fn write_inode(img: &mut [u8], off: usize, format: u16, size: u32, nlink: u32, i_u: &[u32]) {
    put_u16(img, off, format);
    put_u32(img, off + 4, nlink);
    put_u32(img, off + 8, size);
    for (slot, &val) in i_u.iter().enumerate() {
        put_u32(img, off + 16 + slot * 4, val);
    }
}

fn write_superblock(img: &mut [u8]) {
    let sb = 1024usize;
    put_u32(img, sb, EROFS_MAGIC);
    img[sb + 0x0C] = 12; // blkszbits → 4096
    put_u16(img, sb + 0x0E, 1); // root_nid = 1
    put_u64(img, sb + 0x10, 10); // inos
    put_u32(img, sb + 0x24, 128); // blocks
    put_u32(img, sb + 0x28, META_BLKADDR); // meta_blkaddr
    img[sb + 0x40..sb + 0x45].copy_from_slice(b"test\0"); // volume name
    put_u32(img, sb + 0x50, EROFS_FEATURE_INCOMPAT_NID_TABLE);
}

fn write_inodes(img: &mut [u8]) {
    let meta = META_BLKADDR as usize * BLOCK_SIZE;
    // NID 1: root directory → data block 65.
    write_inode(
        img,
        meta + OFF_ROOT,
        EROFS_S_IFDIR | 0o755,
        BLOCK_SIZE as u32,
        2,
        &[65],
    );
    // NID 2: hello.txt → data block 66.
    write_inode(
        img,
        meta + OFF_HELLO,
        EROFS_S_IFREG | 0o644,
        HELLO_CONTENT.len() as u32,
        1,
        &[66],
    );
    // NID 3: subdir → data block 67.
    write_inode(
        img,
        meta + OFF_SUBDIR,
        EROFS_S_IFDIR | 0o755,
        BLOCK_SIZE as u32,
        2,
        &[67],
    );
    // NID 4: symlink — target stored inline in i_u.
    write_inode(
        img,
        meta + OFF_LINK,
        EROFS_S_IFLNK | 0o777,
        LINK_TARGET.len() as u32,
        1,
        &[0, 0, 0, 0],
    );
    let link_off = meta + OFF_LINK + 16;
    img[link_off..link_off + LINK_TARGET.len()].copy_from_slice(LINK_TARGET);
    // NID 5: large.bin → data blocks 68 and 69.
    write_inode(
        img,
        meta + OFF_LARGE,
        EROFS_S_IFREG | 0o644,
        LARGE_SIZE as u32,
        1,
        &[68, 69],
    );
    // NID 6: deep.txt → data block 70.
    write_inode(
        img,
        meta + OFF_DEEP,
        EROFS_S_IFREG | 0o644,
        DEEP_CONTENT.len() as u32,
        1,
        &[70],
    );
}

/// Write a directory block: 12-byte entry headers at the front, names packed
/// backwards from the tail of the block.
fn write_dir_block(img: &mut [u8], block: usize, entries: &[(&[u8], u64, u16)]) {
    let base = block * BLOCK_SIZE;

    // Pack names from the end of the block backwards.
    let mut off = BLOCK_SIZE;
    let mut name_offs = Vec::new();
    for (name, _, _) in entries {
        off -= name.len();
        name_offs.push(off);
    }
    for ((name, _, _), &noff) in entries.iter().zip(name_offs.iter()) {
        img[base + noff..base + noff + name.len()].copy_from_slice(name);
    }

    // 12-byte headers: nid (u64), name_off (u16), file_type (u16).
    let mut hoff = 0usize;
    for ((_, nid, ftype), &noff) in entries.iter().zip(name_offs.iter()) {
        put_u64(img, base + hoff, *nid);
        put_u16(img, base + hoff + 8, noff as u16);
        put_u16(img, base + hoff + 10, *ftype);
        hoff += 12;
    }
}

fn write_root_dir(img: &mut [u8]) {
    let entries: [(&[u8], u64, u16); 6] = [
        (b".", 1, EROFS_FT_DIR as u16),
        (b"..", 1, EROFS_FT_DIR as u16),
        (b"hello.txt", 2, EROFS_FT_REG_FILE as u16),
        (b"subdir", 3, EROFS_FT_DIR as u16),
        (b"link", 4, EROFS_FT_SYMLINK as u16),
        (b"large.bin", 5, EROFS_FT_REG_FILE as u16),
    ];
    write_dir_block(img, 65, &entries);
}

fn write_subdir(img: &mut [u8]) {
    let entries: [(&[u8], u64, u16); 3] = [
        (b".", 3, EROFS_FT_DIR as u16),
        (b"..", 1, EROFS_FT_DIR as u16),
        (b"deep.txt", 6, EROFS_FT_REG_FILE as u16),
    ];
    write_dir_block(img, 67, &entries);
}

fn write_file_data(img: &mut [u8]) {
    // hello.txt payload (block 66).
    let hello_off = 66 * BLOCK_SIZE;
    img[hello_off..hello_off + HELLO_CONTENT.len()].copy_from_slice(HELLO_CONTENT);

    // large.bin payload (blocks 68-69): 5000 bytes of a repeating pattern.
    let large = vec![0xABu8; LARGE_SIZE];
    img[68 * BLOCK_SIZE..69 * BLOCK_SIZE].copy_from_slice(&large[..BLOCK_SIZE]);
    img[69 * BLOCK_SIZE..69 * BLOCK_SIZE + (LARGE_SIZE - BLOCK_SIZE)]
        .copy_from_slice(&large[BLOCK_SIZE..]);

    // deep.txt payload (block 70).
    let deep_off = 70 * BLOCK_SIZE;
    img[deep_off..deep_off + DEEP_CONTENT.len()].copy_from_slice(DEEP_CONTENT);
}

// ── Test helper ─────────────────────────────────────────────────────────────

fn open_test_volume() -> EroFsVolume {
    let img = build_erofs_image();
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-erofs", img, true);
    EroFsVolume::open(dev).expect("open EROFS volume")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    #[test]
    fn erofs_vfs_read_dir_root() {
        let vol = open_test_volume();
        let mut names: Vec<String> = Vec::new();
        #[allow(clippy::while_let_loop)]
        let mut i = 0;
        #[allow(clippy::while_let_loop)]
        loop {
            match vol.read_dir("/", i) {
                Ok(entry) => {
                    names.push(entry.name.clone());
                    i += 1;
                }
                Err(_) => break,
            }
        }
        assert!(names.contains(&".".into()));
        assert!(names.contains(&"..".into()));
        assert!(names.contains(&"hello.txt".into()));
        assert!(names.contains(&"subdir".into()));
        assert!(names.contains(&"link".into()));
        assert!(names.contains(&"large.bin".into()));
    }

    #[test]
    fn erofs_lookup_hello_and_read() {
        let vol = open_test_volume();
        let vnode = vol.lookup("/hello.txt").expect("lookup hello.txt");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.size(), HELLO_CONTENT.len());

        let mut buf = vec![0u8; HELLO_CONTENT.len() + 10];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(n, HELLO_CONTENT.len());
        assert_eq!(&buf[..n], HELLO_CONTENT);
    }

    #[test]
    fn erofs_stat_file() {
        let vol = open_test_volume();
        let meta = vol.stat("/hello.txt").expect("stat hello.txt");
        assert_eq!(meta.kind, NodeKind::File);
        assert_eq!(meta.size, HELLO_CONTENT.len());
    }

    #[test]
    fn erofs_read_dir_subdir() {
        let vol = open_test_volume();
        let mut names: Vec<String> = Vec::new();
        let mut i = 0;
        while let Ok(entry) = vol.read_dir("/subdir", i) {
            names.push(entry.name.clone());
            i += 1;
        }
        assert!(names.contains(&"deep.txt".into()));
    }

    #[test]
    fn erofs_lookup_symlink_and_readlink() {
        let vol = open_test_volume();
        let vnode = vol.lookup("/link").expect("lookup symlink");
        assert_eq!(vnode.kind(), NodeKind::Symlink);
        let target = vnode.readlink().expect("readlink");
        assert_eq!(target, LINK_TARGET);
    }

    #[test]
    fn erofs_lookup_large_bin_size_and_read() {
        let vol = open_test_volume();
        let vnode = vol.lookup("/large.bin").expect("lookup large.bin");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.size(), LARGE_SIZE);

        let mut buf = vec![0u8; 64];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(n, 64);
        assert!(buf[..n].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn erofs_not_found() {
        let vol = open_test_volume();
        assert!(matches!(
            vol.lookup("/nonexistent.txt"),
            Err(crate::Error::NotFound)
        ));
    }
}
