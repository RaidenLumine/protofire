//! src/kernel/fs/fat32/tests.rs
//! End-to-end read/write tests for the FAT32 filesystem driver.
//!
//! Test image is a small writable FAT32 volume (512-byte sectors,
//! 1 sector per cluster):
//!   Sectors 0-31:   reserved region (boot sector in sector 0)
//!   Sectors 32-39:  FAT tables (2 copies × 4 sectors)
//!   Sectors 40+:    data region (cluster 2 = root directory)

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::NodeKind;

use super::types::write_short_entry;
use super::FatVolume;

const BYTES_PER_SECTOR: usize = 512;
const SECTORS_PER_CLUSTER: u8 = 1;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 2;
const SECTORS_PER_FAT: u32 = 4;
const TOTAL_SECTORS: u32 = 240;
const ROOT_CLUSTER: u32 = 2;
const ATTR_DIRECTORY: u8 = 0x10;

// ── Image builder ───────────────────────────────────────────────────────────

fn put_u16(img: &mut [u8], off: usize, val: u16) {
    img[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put_u32(img: &mut [u8], off: usize, val: u32) {
    img[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn data_start_lba() -> u32 {
    RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT
}

fn build_writable_fat32_image() -> Vec<u8> {
    let total = TOTAL_SECTORS as usize * BYTES_PER_SECTOR;
    let mut img = vec![0u8; total];

    // ── Boot sector ───────────────────────────────────────────────────────
    let boot = &mut img[..BYTES_PER_SECTOR];
    boot[0..3].copy_from_slice(b"\xEB\x3C\x90"); // jump (not validated)
    boot[3..11].copy_from_slice(b"MSDOS5.0"); // OEM name (not validated)
    put_u16(boot, 11, BYTES_PER_SECTOR as u16);
    boot[13] = SECTORS_PER_CLUSTER;
    put_u16(boot, 14, RESERVED_SECTORS);
    boot[16] = NUM_FATS;
    put_u16(boot, 17, 0); // root entries (0 for FAT32)
    put_u16(boot, 19, 0); // total sectors 16 (0 for FAT32)
    boot[21] = 0xF8; // media descriptor
    put_u16(boot, 22, 0); // sectors per FAT 16 (0 for FAT32)
    put_u32(boot, 32, TOTAL_SECTORS);
    put_u32(boot, 36, SECTORS_PER_FAT);
    put_u32(boot, 44, ROOT_CLUSTER);
    put_u16(boot, 48, 1); // FSInfo sector
    put_u16(boot, 50, 6); // backup boot sector
    boot[66] = 0x29; // extended boot signature
    put_u32(boot, 67, 0x1234_5678); // volume id
    boot[71..82].copy_from_slice(b"TESTVOL    "); // volume label
    boot[82..90].copy_from_slice(b"FAT32   "); // FS type string
    boot[510] = 0x55;
    boot[511] = 0xAA;

    // ── FAT tables (two identical copies) ─────────────────────────────────
    let fat_base = RESERVED_SECTORS as usize * BYTES_PER_SECTOR;
    for fat in 0..NUM_FATS as usize {
        let base = fat_base + fat * SECTORS_PER_FAT as usize * BYTES_PER_SECTOR;
        put_u32(&mut img, base, 0x0FFF_FFF8); // FAT[0] media descriptor
        put_u32(&mut img, base + 4, 0xFFFF_FFFF); // FAT[1]
        put_u32(&mut img, base + 8, 0x0FFF_FFFF); // FAT[2] root dir EOC
    }

    // ── Root directory (cluster 2) ────────────────────────────────────────
    let root_off = data_start_lba() as usize * BYTES_PER_SECTOR;
    let dot = [
        b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
    ];
    write_short_entry(&mut img, root_off, &dot, ATTR_DIRECTORY, ROOT_CLUSTER, 0);
    let dotdot = [
        b'.', b'.', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ', b' ',
    ];
    write_short_entry(
        &mut img,
        root_off + 32,
        &dotdot,
        ATTR_DIRECTORY,
        ROOT_CLUSTER,
        0,
    );
    // EOD marker at byte 64 (already zeroed).

    img
}

// ── Test helper ─────────────────────────────────────────────────────────────

fn make_writable_volume(image: Vec<u8>) -> FatVolume {
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-fat32-rw", image, false);
    FatVolume::open(dev).expect("open FAT32 volume")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    #[test]
    fn create_and_read_file() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        let vnode = vol.create_file("/newfile.txt").expect("create_file");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.name(), "newfile.txt");
        assert_eq!(vnode.size(), 0);
    }

    #[test]
    fn create_dir_and_list() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        vol.create_dir("/mydir").expect("create_dir");
        let vnode = vol.lookup("/mydir").expect("lookup dir");
        assert_eq!(vnode.kind(), NodeKind::Directory);
    }

    #[test]
    fn write_and_read_file() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        let vnode = vol.create_file("/data.bin").expect("create_file");
        let data = b"Hello, FAT32 world!";
        let n = vnode.write(0, data).expect("write");
        assert_eq!(n, data.len());

        let mut buf = [0u8; 64];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }
}
