//! tests/fs/maintenance.rs
//!
//! Host-side integration tests for mounted-volume check and repair entry
//! points.

use std::sync::Arc;

use protofire::kernel::fs::block::BlockDevice;
use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::block::BLOCK_SIZE;
use protofire::kernel::fs::simplefs::ImageEntry;
use protofire::kernel::fs::simplefs::SimpleFs;
use protofire::kernel::fs::simplefs::SimpleFsVolume;
use protofire::kernel::fs::vfs::StaticFileSystem;
use protofire::kernel::fs::FileSystem;
use protofire::kernel::fs::NodeKind;
use protofire::Error;

const INODE_SIZE: usize = 32;
const DIRENT_SIZE: usize = 64;
const ACTIVE_INODE_TABLE_OFFSET: usize = 24;
const SHADOW_INODE_TABLE_OFFSET: usize = 36;
const SHADOW_DIRENT_TABLE_OFFSET: usize = 40;
const INODE_TABLE_BLOCKS_OFFSET: usize = 44;
const DIRENT_TABLE_BLOCKS_OFFSET: usize = 48;

fn writable_image(
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_data_blocks: usize,
) -> Vec<u8> {
    SimpleFs::build_image_with_headroom(
        "maintenance-simplefs",
        &[ImageEntry {
            path: "/seed.txt",
            data: b"seed",
        }],
        extra_inodes,
        extra_dir_entries,
        extra_data_blocks,
    )
    .expect("build maintenance simplefs image")
}

fn mount_single_volume(device: Arc<MemoryBlockDevice>) -> FileSystem {
    let fs = SimpleFs::open(device.clone(), true).expect("open mounted simplefs");
    let mut mounted = FileSystem::new();
    mounted.register_block_device("test0", device);
    mounted.register("simplefs:test", Arc::new(SimpleFsVolume::new(fs)));
    mounted
        .mount("test0", "/data", "simplefs:test", 0)
        .expect("mount test simplefs");
    mounted
}

fn mount_non_repairable_volume() -> FileSystem {
    let mut mounted = FileSystem::new();
    let device = MemoryBlockDevice::new("static-maintenance-device", vec![0_u8; BLOCK_SIZE], false);
    mounted.register_block_device("static-maintenance-device", device);
    mounted.register(
        "static-maintenance-fs",
        Arc::new(StaticFileSystem::with_entries(
            "static-maintenance-fs",
            &[
                ("/", NodeKind::Directory, &[]),
                ("/README.txt", NodeKind::File, b"static"),
            ],
        )),
    );
    mounted
        .mount(
            "static-maintenance-device",
            "/static",
            "static-maintenance-fs",
            0,
        )
        .expect("mount static non-repairable fs");
    mounted
}

fn read_block(device: &dyn BlockDevice, lba: u64) -> [u8; BLOCK_SIZE] {
    let mut block = [0_u8; BLOCK_SIZE];
    device.read_blocks(lba, &mut block).expect("read block");
    block
}

fn write_block(device: &dyn BlockDevice, lba: u64, block: &[u8; BLOCK_SIZE]) {
    device.write_blocks(lba, block).expect("write block");
}

fn read_region(device: &dyn BlockDevice, lba: u64, block_count: usize) -> Vec<u8> {
    let mut buffer = vec![0_u8; block_count * BLOCK_SIZE];
    device.read_blocks(lba, &mut buffer).expect("read region");
    buffer
}

fn write_region(device: &dyn BlockDevice, lba: u64, bytes: &[u8]) {
    device.write_blocks(lba, bytes).expect("write region");
}

fn read_u32_le(block: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(block[offset..offset + 4].try_into().expect("u32 bytes"))
}

#[test]
fn check_and_repair_volume_repairs_corrupted_primary_superblock() {
    let device = MemoryBlockDevice::new("maintenance-device", writable_image(24, 24, 8), false);
    let fs = mount_single_volume(device.clone());

    let mut primary = read_block(device.as_ref(), 0);
    primary[0] = 0;
    write_block(device.as_ref(), 0, &primary);

    let report = fs
        .check_and_repair_volume("/data")
        .expect("repair mounted volume");
    assert!(report.issues_detected >= 1);
    assert!(report.repairs_applied >= 1);

    let primary_after = read_block(device.as_ref(), 0);
    let secondary_after = read_block(device.as_ref(), 1);
    assert_eq!(primary_after, secondary_after);

    let clean = fs
        .check_and_repair_volume("/data")
        .expect("recheck mounted volume");
    assert_eq!(clean.issues_detected, 0);
    assert_eq!(clean.repairs_applied, 0);
}

#[test]
fn check_and_repair_volume_repairs_corrupted_shadow_metadata_slot() {
    let device = MemoryBlockDevice::new("maintenance-device", writable_image(24, 24, 8), false);
    let fs = mount_single_volume(device.clone());

    let superblock = read_block(device.as_ref(), 0);
    let shadow_inode_table_block = read_u32_le(&superblock, SHADOW_INODE_TABLE_OFFSET) as u64;
    let zeroed = [0_u8; BLOCK_SIZE];
    write_block(device.as_ref(), shadow_inode_table_block, &zeroed);

    let report = fs
        .check_and_repair_volume("/data/users/guest")
        .expect("repair shadow metadata");
    assert!(report.issues_detected >= 1);
    assert!(report.repaired());

    let clean = fs
        .check_and_repair_volume("/data")
        .expect("recheck repaired volume");
    assert!(clean.is_clean());
}

#[test]
fn check_and_repair_volume_repairs_corrupted_active_metadata_tail() {
    let device = MemoryBlockDevice::new("maintenance-device", writable_image(24, 24, 8), false);
    let fs = mount_single_volume(device.clone());

    let superblock = read_block(device.as_ref(), 0);
    let active_inode_table_block = read_u32_le(&superblock, ACTIVE_INODE_TABLE_OFFSET) as u64;
    let inode_table_blocks = read_u32_le(&superblock, INODE_TABLE_BLOCKS_OFFSET) as usize;
    let mut inode_table = read_region(
        device.as_ref(),
        active_inode_table_block,
        inode_table_blocks,
    );
    let corruption_index = 2 * INODE_SIZE + 7;
    assert!(corruption_index < inode_table.len());
    inode_table[corruption_index] ^= 0x5a;
    write_region(device.as_ref(), active_inode_table_block, &inode_table);

    let report = fs
        .check_and_repair_volume("/data")
        .expect("repair active metadata tail");
    assert!(report.issues_detected >= 1);
    assert!(report.repaired());

    let repaired = read_region(
        device.as_ref(),
        active_inode_table_block,
        inode_table_blocks,
    );
    assert_eq!(repaired[corruption_index], 0);

    let clean = fs
        .check_and_repair_volume("/data")
        .expect("recheck repaired volume");
    assert!(clean.is_clean());
}

#[test]
fn check_and_repair_volume_repairs_corrupted_shadow_dirent_tail() {
    let device = MemoryBlockDevice::new("maintenance-device", writable_image(24, 24, 8), false);
    let fs = mount_single_volume(device.clone());

    let superblock = read_block(device.as_ref(), 0);
    let shadow_dirent_table_block = read_u32_le(&superblock, SHADOW_DIRENT_TABLE_OFFSET) as u64;
    let dirent_table_blocks = read_u32_le(&superblock, DIRENT_TABLE_BLOCKS_OFFSET) as usize;
    let mut dirent_table = read_region(
        device.as_ref(),
        shadow_dirent_table_block,
        dirent_table_blocks,
    );
    let corruption_index = DIRENT_SIZE + 9;
    assert!(corruption_index < dirent_table.len());
    dirent_table[corruption_index] ^= 0x33;
    write_region(device.as_ref(), shadow_dirent_table_block, &dirent_table);

    let report = fs
        .check_and_repair_volume("/data")
        .expect("repair shadow dirent tail");
    assert!(report.issues_detected >= 1);
    assert!(report.repaired());

    let repaired = read_region(
        device.as_ref(),
        shadow_dirent_table_block,
        dirent_table_blocks,
    );
    assert_eq!(repaired[corruption_index], 0);

    let clean = fs
        .check_and_repair_volume("/data")
        .expect("recheck repaired volume");
    assert!(clean.is_clean());
}

#[test]
fn check_and_repair_volume_rejects_virtual_root() {
    let device = MemoryBlockDevice::new("maintenance-device", writable_image(8, 8, 4), false);
    let fs = mount_single_volume(device);

    assert_eq!(fs.check_and_repair_volume("/"), Err(Error::Unsupported));
}

#[test]
fn check_and_repair_volume_rejects_non_repairable_mount_backend() {
    let fs = mount_non_repairable_volume();

    assert_eq!(
        fs.check_and_repair_volume("/static"),
        Err(Error::Unsupported)
    );
    assert_eq!(
        fs.check_and_repair_volume("/static/README.txt"),
        Err(Error::Unsupported)
    );
}
