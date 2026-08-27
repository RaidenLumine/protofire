//! src/kernel/fs/fat32/tests.rs
//!
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

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::block::MemoryBlockDevice;
use crate::kernel::fs::block::BLOCK_SIZE;
use crate::kernel::fs::vfs::FileSystem as VfsFileSystem;
use crate::kernel::fs::NodeKind;
use crate::Error;

use super::types::read_u32;
use super::types::write_short_entry;
use super::types::FSINFO_FREE_COUNT_OFFSET;
use super::types::FSINFO_LEAD_SIGNATURE;
use super::types::FSINFO_NEXT_FREE_OFFSET;
use super::types::FSINFO_STRUCT_OFFSET;
use super::types::FSINFO_STRUCT_SIGNATURE;
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
    let dot = *b".          ";
    write_short_entry(&mut img, root_off, &dot, ATTR_DIRECTORY, ROOT_CLUSTER, 0);
    let dotdot = *b"..         ";
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

    #[test]
    fn append_writes_and_reads_back_in_order() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        let vnode = vol.create_file("/append.bin").expect("create_file");
        assert_eq!(vnode.write(0, b"AAA").expect("write 1"), 3);
        assert_eq!(vnode.write(3, b"BBB").expect("write 2"), 3);
        assert_eq!(vnode.write(6, b"CCC").expect("write 3"), 3);

        let mut buf = [0u8; 32];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"AAABBBCCC");
    }

    #[test]
    fn set_len_grows_zero_fills_and_shrinks() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        let vnode = vol.create_file("/trunc.bin").expect("create_file");
        vnode.write(0, b"hello").expect("write");
        assert_eq!(vnode.size(), 5);

        vnode.set_len(10).expect("grow");
        assert_eq!(vnode.size(), 10);
        let mut buf = [0u8; 16];
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"hello\0\0\0\0\0");

        vnode.set_len(3).expect("shrink");
        assert_eq!(vnode.size(), 3);
        let n = vnode.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"hel");

        vnode.set_len(0).expect("truncate to zero");
        assert_eq!(vnode.size(), 0);
    }

    #[test]
    fn reopen_reads_back_written_data() {
        let image = build_writable_fat32_image();
        let dev: Arc<dyn BlockDevice> = MemoryBlockDevice::new("test-fat32-reopen", image, false);
        {
            let vol = FatVolume::open(dev.clone()).expect("open");
            let vnode = vol.create_file("/data.txt").expect("create_file");
            vnode.write(0, b"persisted").expect("write");
        }
        let vol2 = FatVolume::open(dev).expect("reopen");
        let vnode2 = vol2.lookup("/data.txt").expect("lookup");
        let mut buf = [0u8; 16];
        let n = vnode2.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"persisted");
    }

    #[test]
    fn sync_writes_fsinfo_sector_and_backup() {
        let image = build_writable_fat32_image();
        let dev: Arc<MemoryBlockDevice> = MemoryBlockDevice::new("test-fat32-fsinfo", image, false);
        let vol = FatVolume::open(dev.clone()).expect("open");
        let vnode = vol.create_file("/f.bin").expect("create_file");
        vnode.write(0, b"payload").expect("write");
        vol.sync().expect("sync");

        // FSInfo lives at LBA 1; its backup copy at backup-boot-sector + 1
        // (= 6 + 1 = 7 for this image).
        for lba in [1u64, 7u64] {
            let mut buf = [0u8; BLOCK_SIZE];
            dev.read_blocks(lba, &mut buf).expect("read fsinfo sector");
            assert_eq!(
                read_u32(&buf, 0),
                FSINFO_LEAD_SIGNATURE,
                "lead sig LBA {lba}"
            );
            assert_eq!(
                read_u32(&buf, FSINFO_STRUCT_OFFSET),
                FSINFO_STRUCT_SIGNATURE,
                "struct sig LBA {lba}"
            );
            // 199 free data clusters initially.  create_file allocates one
            // cluster for the file itself and one more because
            // insert_dir_entry_set extends the root-directory buffer past a
            // single cluster (576 bytes), growing the root chain.
            assert_eq!(
                read_u32(&buf, FSINFO_FREE_COUNT_OFFSET),
                199 - 2,
                "free count LBA {lba}"
            );
            assert_eq!(read_u32(&buf, FSINFO_NEXT_FREE_OFFSET), 5, "hint LBA {lba}");
        }
    }

    #[test]
    fn truncate_frees_clusters_and_fsinfo_reflects_it() {
        let image = build_writable_fat32_image();
        let dev: Arc<MemoryBlockDevice> =
            MemoryBlockDevice::new("test-fat32-truncate", image, false);
        let vol = FatVolume::open(dev.clone()).expect("open");
        let vnode = vol.create_file("/grow.bin").expect("create_file");
        let big = vec![0u8; 4 * BLOCK_SIZE];
        assert_eq!(vnode.write(0, &big).expect("grow"), big.len());
        vnode.set_len(0).expect("truncate");
        vol.sync().expect("sync");

        let mut buf = [0u8; BLOCK_SIZE];
        dev.read_blocks(1, &mut buf).expect("read fsinfo sector");
        // create_file allocates the file's first cluster plus one for root-
        // directory growth (199 - 2); growth reaches four file clusters; the
        // truncation frees all four.  The root directory keeps its extra
        // cluster, leaving 198 free.
        assert_eq!(read_u32(&buf, FSINFO_FREE_COUNT_OFFSET), 198);
        assert_eq!(read_u32(&buf, FSINFO_NEXT_FREE_OFFSET), 3);
    }

    #[test]
    fn disk_full_returns_no_space() {
        let image = build_writable_fat32_image();
        let vol = make_writable_volume(image);
        let vnode = vol.create_file("/big.bin").expect("create_file");
        // create_file consumes two clusters (file + root-directory growth),
        // leaving 197 free (5..=201).  The file already owns cluster 3, so it
        // can grow to 198 clusters total = 198 * 512 bytes.
        let capacity = 198 * BLOCK_SIZE;
        let big = vec![0xABu8; capacity];
        assert_eq!(vnode.write(0, &big).expect("fill volume"), capacity);

        let err = vnode
            .write(capacity as u64, b"x")
            .expect_err("overfill must fail");
        assert_eq!(err, Error::NoSpace);
    }
}
