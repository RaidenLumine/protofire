//! tests/fat32.rs
//!
//! Host-side integration tests for a mounted FAT32 volume: durability through
//! the VFS `sync`/`flush_aged` traits, and read-back after a fresh `open` on
//! the same device.  The small writable FAT32 image mirrors the builder in
//! `src/kernel/fs/fat32/tests.rs`:
//!   Sectors 0-31:   reserved region (boot sector in sector 0)
//!   Sectors 32-39:  FAT tables (2 copies × 4 sectors)
//!   Sectors 40+:    data region (cluster 2 = root directory)

use std::sync::Arc;

use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::fat32::FatVolume;
use protofire::kernel::fs::vfs::FileSystem as VfsTrait;
use protofire::kernel::fs::FileSystem;
use protofire::kernel::fs::CREATE_NEW;

const BYTES_PER_SECTOR: usize = 512;
const SECTORS_PER_CLUSTER: u8 = 1;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 2;
const SECTORS_PER_FAT: u32 = 4;
const TOTAL_SECTORS: u32 = 240;
const ROOT_CLUSTER: u32 = 2;
const ATTR_DIRECTORY: u8 = 0x10;

fn put_u16(img: &mut [u8], off: usize, val: u16) {
    img[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put_u32(img: &mut [u8], off: usize, val: u32) {
    img[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn data_start_lba() -> u32 {
    RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT
}

fn write_short_entry(
    img: &mut [u8],
    off: usize,
    name11: &[u8; 11],
    attrs: u8,
    cluster: u32,
    size: u32,
) {
    img[off..off + 11].copy_from_slice(name11);
    img[off + 11] = attrs;
    // Creation/modification dates and times left zeroed.
    img[off + 20] = (cluster >> 16) as u8;
    img[off + 21] = (cluster >> 24) as u8;
    img[off + 26] = cluster as u8;
    img[off + 27] = (cluster >> 8) as u8;
    img[off + 28..off + 32].copy_from_slice(&size.to_le_bytes());
}

fn build_writable_fat32_image() -> Vec<u8> {
    let total = TOTAL_SECTORS as usize * BYTES_PER_SECTOR;
    let mut img = vec![0u8; total];

    let boot = &mut img[..BYTES_PER_SECTOR];
    boot[0..3].copy_from_slice(b"\xEB\x3C\x90");
    boot[3..11].copy_from_slice(b"MSDOS5.0");
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
    boot[66] = 0x29;
    put_u32(boot, 67, 0x1234_5678);
    boot[71..82].copy_from_slice(b"TESTVOL    ");
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;

    let fat_base = RESERVED_SECTORS as usize * BYTES_PER_SECTOR;
    for fat in 0..NUM_FATS as usize {
        let base = fat_base + fat * SECTORS_PER_FAT as usize * BYTES_PER_SECTOR;
        put_u32(&mut img, base, 0x0FFF_FFF8); // FAT[0] media descriptor
        put_u32(&mut img, base + 4, 0xFFFF_FFFF); // FAT[1]
        put_u32(&mut img, base + 8, 0x0FFF_FFFF); // FAT[2] root dir EOC
    }

    let root_off = data_start_lba() as usize * BYTES_PER_SECTOR;
    write_short_entry(
        &mut img,
        root_off,
        b".          ",
        ATTR_DIRECTORY,
        ROOT_CLUSTER,
        0,
    );
    write_short_entry(
        &mut img,
        root_off + 32,
        b"..         ",
        ATTR_DIRECTORY,
        ROOT_CLUSTER,
        0,
    );

    img
}

fn mount_fat32_volume(device: Arc<MemoryBlockDevice>) -> (FileSystem, Arc<dyn VfsTrait>) {
    let vol: Arc<dyn VfsTrait> = Arc::new(FatVolume::open(device.clone()).expect("open fat32"));
    let mut mounted = FileSystem::new();
    mounted.register_block_device("fat0", device);
    mounted.register("fat32:test", vol.clone());
    mounted
        .mount("fat0", "/mnt", "fat32:test", 0)
        .expect("mount fat32 at /mnt");
    (mounted, vol)
}

#[test]
fn mounted_sync_persists_across_reopen() {
    let image = build_writable_fat32_image();
    let dev: Arc<MemoryBlockDevice> = MemoryBlockDevice::new("fat-mount-sync", image, false);
    let (mounted, vol) = mount_fat32_volume(dev.clone());

    // Create + write through the mount layer.
    let mut handle = mounted
        .create_file("/mnt/data.txt", 0, 0, CREATE_NEW)
        .expect("create file via mount");
    assert_eq!(
        mounted
            .write(&mut handle, b"mounted-sync")
            .expect("write via mount"),
        12
    );

    // Durability path: sync the mounted volume, then read back through the
    // mount before tearing it down.
    vol.sync().expect("volume sync");
    let mut read_back = [0u8; 32];
    let n = mounted
        .open("/mnt/data.txt", 0)
        .and_then(|mut h| mounted.read(&mut h, &mut read_back))
        .expect("read back via mount");
    assert_eq!(&read_back[..n], b"mounted-sync");

    drop(handle);
    drop(mounted);
    drop(vol);

    // A fresh volume over the same device sees the synced data.
    let vol2 = FatVolume::open(dev).expect("reopen fat32");
    let node = vol2.lookup("/data.txt").expect("lookup data.txt");
    let mut buf = [0u8; 32];
    let n = node.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..n], b"mounted-sync");
}

#[test]
fn aged_flush_persists_across_reopen() {
    let image = build_writable_fat32_image();
    let dev: Arc<MemoryBlockDevice> = MemoryBlockDevice::new("fat-aged-flush", image, false);
    let (mounted, vol) = mount_fat32_volume(dev.clone());

    // create_file alone leaves the directory-entry and FAT allocation dirty
    // in the write-back cache: unlike `write`/`set_len`, the create path does
    // not flush synchronously, so `flush_aged` has real work to do.
    let handle = mounted
        .create_file("/mnt/aged.bin", 0, 0, CREATE_NEW)
        .expect("create file via mount");

    // Age 0 makes every dirty block eligible immediately.
    let flushed = vol.flush_aged(0).expect("aged flush");
    assert!(flushed > 0, "aged flush should write dirty blocks");

    drop(handle);
    drop(mounted);
    drop(vol);

    // The flushed directory entry survives a fresh open of the device.
    let vol2 = FatVolume::open(dev).expect("reopen fat32");
    let node = vol2.lookup("/aged.bin").expect("lookup aged.bin");
    assert_eq!(node.size(), 0);
}

#[test]
fn open_fails_on_garbage_device() {
    // A non-FAT image must be rejected at open rather than mounting garbage.
    let garbage = vec![0xA5u8; 240 * BYTES_PER_SECTOR];
    let dev: Arc<MemoryBlockDevice> = MemoryBlockDevice::new("fat-garbage", garbage, false);
    assert!(
        FatVolume::open(dev).is_err(),
        "garbage must not open as FAT32"
    );
}

#[test]
fn vnode_level_sync_flushes_metadata() {
    let image = build_writable_fat32_image();
    let dev: Arc<MemoryBlockDevice> = MemoryBlockDevice::new("fat-vnode-sync", image, false);
    let vol = FatVolume::open(dev.clone()).expect("open fat32");

    let node = vol.create_file("/meta.bin").expect("create file");
    node.write(0, b"payload").expect("write");
    node.sync().expect("vnode sync");

    drop(vol);
    let vol2 = FatVolume::open(dev).expect("reopen fat32");
    let node2 = vol2.lookup("/meta.bin").expect("lookup meta.bin");
    let mut buf = [0u8; 32];
    let n = node2.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..n], b"payload");
}
