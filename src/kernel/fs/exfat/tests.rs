//! src/kernel/fs/exfat/tests.rs
//!
//! End-to-end read/write tests for the exFAT filesystem driver.
//!
//! The test image is a small writable exFAT volume (512-byte sectors,
//! 1 sector per cluster):
//!   Sectors 0-11:   boot region (boot sector + extended sectors + checksum)
//!   Sectors 12-19:  FAT table (8 sectors)
//!   Sector 20:      cluster 2 — root directory
//!   Sector 21:      cluster 3 — allocation bitmap
//!   Sector 22:      cluster 4 — up-case table
//!   Sectors 23+:    cluster 5+ — free (used for files/dirs created in tests)

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::NodeKind;

use super::types::{
    write_u16_le, write_u32_le, write_u64_le, BOOT_SIGNATURE_OFFSET, B_BYTES_PER_SECTOR_SHIFT,
    B_CHECKSUM_OFFSET, B_CHECKSUM_SECTOR, B_CLUSTER_COUNT, B_CLUSTER_HEAP_OFFSET, B_FAT_LENGTH,
    B_FAT_OFFSET, B_FS_REVISION, B_NUM_FATS, B_OEM_NAME, B_ROOT_DIR_CLUSTER,
    B_SECTORS_PER_CLUSTER_SHIFT, B_VOLUME_FLAGS, B_VOLUME_LENGTH, B_VOLUME_SERIAL,
    EXFAT_ENTRY_BITMAP, EXFAT_ENTRY_STREAM, EXFAT_ENTRY_UPCASE, FIRST_DATA_CLUSTER, S_DATA_LEN,
    S_FIRST_CLUSTER, S_VALID_DATA_LEN,
};
use super::ExfatVolume;

const BYTES_PER_SECTOR: usize = 512;
const FAT_OFFSET: u32 = 12;
const FAT_LENGTH: u32 = 8;
const CLUSTER_HEAP_OFFSET: u32 = 20;
const CLUSTER_COUNT: u32 = 96;
const ROOT_DIR_CLUSTER: u32 = 2;
const BITMAP_CLUSTER: u32 = 3;
const UPCASE_CLUSTER: u32 = 4;
const VOLUME_LENGTH: u32 = CLUSTER_HEAP_OFFSET + CLUSTER_COUNT;

// ── Image builder ───────────────────────────────────────────────────────────

fn put_u32(img: &mut [u8], off: usize, val: u32) {
    img[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn cluster_lba(cluster: u32) -> u32 {
    CLUSTER_HEAP_OFFSET + (cluster - FIRST_DATA_CLUSTER)
}

fn build_exfat_rw_image() -> Vec<u8> {
    let total = VOLUME_LENGTH as usize * BYTES_PER_SECTOR;
    let mut img = vec![0u8; total];

    // ── Boot sector ───────────────────────────────────────────────────────
    let boot = &mut img[..BYTES_PER_SECTOR];
    boot[B_OEM_NAME..B_OEM_NAME + 8].copy_from_slice(b"EXFAT   ");
    write_u64_le(boot, B_VOLUME_LENGTH, VOLUME_LENGTH as u64);
    write_u32_le(boot, B_FAT_OFFSET, FAT_OFFSET);
    write_u32_le(boot, B_FAT_LENGTH, FAT_LENGTH);
    write_u32_le(boot, B_CLUSTER_HEAP_OFFSET, CLUSTER_HEAP_OFFSET);
    write_u32_le(boot, B_CLUSTER_COUNT, CLUSTER_COUNT);
    write_u32_le(boot, B_ROOT_DIR_CLUSTER, ROOT_DIR_CLUSTER);
    write_u32_le(boot, B_VOLUME_SERIAL, 0x1234_5678);
    write_u16_le(boot, B_FS_REVISION, 0x0100); // revision 1.00
    write_u16_le(boot, B_VOLUME_FLAGS, 0);
    boot[B_BYTES_PER_SECTOR_SHIFT] = 9; // 2^9 = 512 bytes/sector
    boot[B_SECTORS_PER_CLUSTER_SHIFT] = 0; // 1 sector/cluster
    boot[B_NUM_FATS] = 1;
    boot[BOOT_SIGNATURE_OFFSET] = 0x55;
    boot[BOOT_SIGNATURE_OFFSET + 1] = 0xAA;

    // ── Boot checksum: sum of sectors 0..10, stored in sector 11 @ 0x1FC ──
    let sum: u32 = img[..BYTES_PER_SECTOR * B_CHECKSUM_SECTOR]
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    let cs_off = BYTES_PER_SECTOR * B_CHECKSUM_SECTOR + B_CHECKSUM_OFFSET;
    img[cs_off..cs_off + 4].copy_from_slice(&sum.to_le_bytes());

    // ── FAT table ──────────────────────────────────────────────────────────
    let fat_base = FAT_OFFSET as usize * BYTES_PER_SECTOR;
    put_u32(&mut img, fat_base, 0xFFFF_FFF8); // FAT[0] media descriptor
    put_u32(&mut img, fat_base + 4, 0xFFFF_FFFF); // FAT[1]
    put_u32(&mut img, fat_base + 8, 0xFFFF_FFFF); // FAT[2] root dir EOC
    put_u32(&mut img, fat_base + 12, 0xFFFF_FFFF); // FAT[3] bitmap EOC
    put_u32(&mut img, fat_base + 16, 0xFFFF_FFFF); // FAT[4] up-case EOC

    // ── Allocation bitmap (cluster 3) ──────────────────────────────────────
    // Clusters 2, 3 and 4 are allocated; all others are free.
    let bitmap_off = cluster_lba(BITMAP_CLUSTER) as usize * BYTES_PER_SECTOR;
    img[bitmap_off] = 0x07;

    // ── Up-case table (cluster 4) ──────────────────────────────────────────
    let upcase_off = cluster_lba(UPCASE_CLUSTER) as usize * BYTES_PER_SECTOR;
    img[upcase_off..upcase_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // ── Root directory (cluster 2) ─────────────────────────────────────────
    let root = cluster_lba(ROOT_DIR_CLUSTER) as usize * BYTES_PER_SECTOR;
    // Bitmap entry set: 0x81 + stream 0xC0 (first_cluster=3, data_length=12).
    img[root] = EXFAT_ENTRY_BITMAP;
    img[root + 32] = EXFAT_ENTRY_STREAM;
    write_u32_le(&mut img[root..], 32 + S_FIRST_CLUSTER, BITMAP_CLUSTER);
    write_u32_le(&mut img[root..], 32 + S_VALID_DATA_LEN, 12);
    write_u32_le(&mut img[root..], 32 + S_DATA_LEN, 12);
    // Up-case entry set: 0x82 + stream 0xC0 (first_cluster=4, data_length=256).
    img[root + 64] = EXFAT_ENTRY_UPCASE;
    img[root + 96] = EXFAT_ENTRY_STREAM;
    write_u32_le(&mut img[root..], 96 + S_FIRST_CLUSTER, UPCASE_CLUSTER);
    write_u32_le(&mut img[root..], 96 + S_VALID_DATA_LEN, 256);
    write_u32_le(&mut img[root..], 96 + S_DATA_LEN, 256);
    // EOD entry at offset 128 (already zeroed).

    img
}

// ── Test helper ─────────────────────────────────────────────────────────────

fn make_volume(image: Vec<u8>) -> ExfatVolume {
    let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-exfat-rw", image, false);
    ExfatVolume::open(dev).expect("open exFAT volume")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    // ─── Read-write tests (with bitmap) ──────────────────────────────────

    #[test]
    fn rw_create_and_read_file() {
        let image = build_exfat_rw_image();
        let vol = make_volume(image);
        let vnode = vol.create_file("/newfile.txt").expect("create_file");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.size(), 0);

        let n = vnode.write(0, b"Hello exFAT!").expect("write");
        assert_eq!(n, 12);

        let mut buf = [0u8; 20];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"Hello exFAT!");
    }

    #[test]
    fn rw_create_dir_and_list() {
        let image = build_exfat_rw_image();
        let vol = make_volume(image);
        vol.create_dir("/subdir").expect("create_dir");

        let vnode = vol.lookup("/subdir").expect("lookup subdir");
        assert_eq!(vnode.kind(), NodeKind::Directory);
    }
}
