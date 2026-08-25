//! tests/simplefs/recovery.rs
//!
//! Host-side recovery and long-sequence regression tests for writable SimpleFs
//! behavior.

mod support;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

use protofire::kernel::fs::block::BlockDevice;
use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::block::BLOCK_SIZE;
use protofire::kernel::fs::simplefs::SimpleFs;
use protofire::kernel::fs::simplefs::SimpleFsVolume;
use protofire::kernel::fs::vfs::FileSystem as VfsFileSystem;
use protofire::kernel::fs::vfs::VolumeCheckReport;
use protofire::Error;

use support::build_seed_image;
use support::build_stable_anchor_device;
use support::read_all;
use support::read_u32_le;

const SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET: usize = 24;
const SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET: usize = 28;
const SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET: usize = 36;
const SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET: usize = 40;
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 56;

fn writable_image(
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_data_blocks: usize,
) -> Vec<u8> {
    build_seed_image(
        "recovery-simplefs",
        extra_inodes,
        extra_dir_entries,
        extra_data_blocks,
    )
}

fn read_block(device: &dyn BlockDevice, lba: u64) -> Vec<u8> {
    let mut block = vec![0_u8; BLOCK_SIZE];
    device
        .read_blocks(lba, &mut block)
        .expect("read block from test device");
    block
}

fn write_block(device: &dyn BlockDevice, lba: u64, block: &[u8]) {
    device
        .write_blocks(lba, block)
        .expect("write block to test device");
}

fn superblock_u32_field(device: &dyn BlockDevice, superblock_lba: u64, offset: usize) -> u64 {
    let superblock = read_block(device, superblock_lba);
    read_u32_le(&superblock, offset) as u64
}

fn active_inode_table_block(device: &dyn BlockDevice, superblock_lba: u64) -> u64 {
    superblock_u32_field(device, superblock_lba, SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET)
}

fn active_dirent_table_block(device: &dyn BlockDevice, superblock_lba: u64) -> u64 {
    superblock_u32_field(
        device,
        superblock_lba,
        SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET,
    )
}

fn shadow_inode_table_block(device: &dyn BlockDevice, superblock_lba: u64) -> u64 {
    superblock_u32_field(device, superblock_lba, SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET)
}

fn shadow_dirent_table_block(device: &dyn BlockDevice, superblock_lba: u64) -> u64 {
    superblock_u32_field(
        device,
        superblock_lba,
        SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET,
    )
}

fn ensure_dir(volume: &SimpleFsVolume, path: &str) {
    match volume.create_dir(path) {
        Ok(()) | Err(Error::AlreadyExists) => {}
        Err(error) => panic!("create dir {path}: {error:?}"),
    }
}

fn collect_dir_names(volume: &SimpleFsVolume, path: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut index = 0;
    while let Ok(entry) = volume.read_dir(path, index) {
        entries.push(entry.name);
        index += 1;
    }
    entries
}

fn patterned_payload(round: usize) -> Vec<u8> {
    let line = format!("round-{round:02}-payload");
    let repeat = round + 3;
    let mut payload = Vec::with_capacity(line.len() * repeat);
    for index in 0..repeat {
        payload.extend_from_slice(line.as_bytes());
        payload.push(b':');
        payload.extend_from_slice(index.to_string().as_bytes());
        payload.push(b'\n');
    }
    payload
}

fn build_stable_device() -> Arc<MemoryBlockDevice> {
    build_stable_anchor_device("simplefs-recovery", "recovery-simplefs", 48, 64, 16)
}

fn build_device_with_removable_file() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new("simplefs-recovery", writable_image(64, 96, 16), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/trash").expect("create trash");
        let file = volume
            .create_file("/trash/old.bin")
            .expect("create removable file");
        file.write(0, b"retired-payload")
            .expect("write removable file");
    }
    device
}

fn build_device_after_rename_remove_sequence() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new("simplefs-recovery", writable_image(96, 128, 24), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/left").expect("create left");
        volume.create_dir("/right").expect("create right");

        let keep = volume
            .create_file("/left/keep.bin")
            .expect("create retained payload");
        keep.write(0, b"retained-payload")
            .expect("write retained payload");
        let drop = volume
            .create_file("/left/drop.bin")
            .expect("create removable payload");
        drop.write(0, b"removed-payload")
            .expect("write removable payload");

        volume
            .rename("/left/keep.bin", "/right/final.bin")
            .expect("rename retained payload");
        volume
            .remove_path("/left/drop.bin")
            .expect("remove obsolete payload");
    }
    device
}

fn build_device_after_packed_directory_mutations() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new("simplefs-recovery", writable_image(96, 128, 64), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/bulk").expect("create bulk directory");

        for index in 0..40 {
            let path = format!("/bulk/item{:02}.txt", index);
            let node = volume.create_file(&path).expect("create bulk file");
            let payload = format!("payload-{index:02}");
            assert_eq!(
                node.write(0, payload.as_bytes())
                    .expect("write bulk payload"),
                payload.len()
            );
        }

        volume
            .remove_path("/bulk/item07.txt")
            .expect("remove packed dir entry");
        volume
            .rename("/bulk/item11.txt", "/bulk/renamed11.txt")
            .expect("rename within packed dir");
    }
    device
}

fn assert_rename_remove_sequence_state(volume: &SimpleFsVolume) {
    let final_file = volume
        .lookup("/right/final.bin")
        .expect("lookup final payload");
    assert_eq!(read_all(&*final_file), b"retained-payload");
    assert!(matches!(
        volume.lookup("/left/drop.bin"),
        Err(Error::NotFound)
    ));
    assert_eq!(volume.stat("/left").expect("stat left").size, 0);
    assert_eq!(volume.stat("/right").expect("stat right").size, 1);
}

fn assert_rename_remove_sequence_without_next_file(volume: &SimpleFsVolume) {
    assert_rename_remove_sequence_state(volume);
    assert!(matches!(
        volume.lookup("/right/next.bin"),
        Err(Error::NotFound)
    ));
}

fn assert_packed_directory_mutation_state(volume: &SimpleFsVolume) {
    let mut names = collect_dir_names(volume, "/bulk");
    names.sort();

    assert_eq!(volume.stat("/bulk").expect("stat bulk directory").size, 39);
    assert!(!names.iter().any(|name| name == "item07.txt"));
    assert!(names.iter().any(|name| name == "renamed11.txt"));

    let renamed = volume
        .lookup("/bulk/renamed11.txt")
        .expect("lookup renamed file");
    assert_eq!(read_all(&*renamed), b"payload-11");
}

fn corrupt_primary_superblock_checksum(device: &dyn BlockDevice) {
    let mut primary = read_block(device, 0);
    primary[SUPERBLOCK_CHECKSUM_OFFSET] ^= 0xff;
    write_block(device, 0, &primary);
}

#[derive(Clone, Copy)]
enum FaultMode {
    BeforeWrite,
    TornWrite { prefix_len: usize },
}

#[derive(Clone, Copy)]
struct FaultInjection {
    write_number: usize,
    mode: FaultMode,
}

struct FailingBlockDevice {
    inner: Arc<MemoryBlockDevice>,
    fault: FaultInjection,
    writes_seen: Mutex<usize>,
}

impl FailingBlockDevice {
    fn new(inner: Arc<MemoryBlockDevice>, fault: FaultInjection) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fault,
            writes_seen: Mutex::new(0),
        })
    }
}

impl BlockDevice for FailingBlockDevice {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> protofire::Result<()> {
        self.inner.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> protofire::Result<()> {
        let mut writes_seen = self.writes_seen.lock().expect("writes_seen lock");
        *writes_seen += 1;

        if *writes_seen != self.fault.write_number {
            return self.inner.write_blocks(lba, data);
        }

        match self.fault.mode {
            FaultMode::BeforeWrite => Err(Error::DeviceError),
            FaultMode::TornWrite { prefix_len } => {
                let mut merged = vec![0_u8; data.len()];
                self.inner.read_blocks(lba, &mut merged)?;
                let prefix_len = prefix_len.min(data.len());
                merged[..prefix_len].copy_from_slice(&data[..prefix_len]);
                self.inner.write_blocks(lba, &merged)?;
                Err(Error::DeviceError)
            }
        }
    }
}

fn publish_complex_next_file_with_primary_superblock_failure(device: &Arc<MemoryBlockDevice>) {
    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            // create_file() zeroes the new data block before metadata publish,
            // so the primary-superblock write lands on the fifth device write.
            write_number: 5,
            mode: FaultMode::BeforeWrite,
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing complex simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert!(matches!(
        volume.create_file("/right/next.bin"),
        Err(Error::DeviceError)
    ));
}

fn synchronize_writable_baseline(device: &Arc<MemoryBlockDevice>) {
    let fs = SimpleFs::open(device.clone(), true).expect("open complex simplefs");
    let volume = SimpleFsVolume::new(fs);
    let baseline = volume
        .check_and_repair()
        .expect("synchronize complex baseline");
    assert_eq!(baseline.repairs_applied, 1);
    assert_eq!(baseline.checksum_failures, 0);
}

fn synchronize_complex_baseline(device: &Arc<MemoryBlockDevice>) {
    synchronize_writable_baseline(device);
}

fn assert_complex_shadow_drift_after_rename_remove_sequence<F, S>(
    device: Arc<MemoryBlockDevice>,
    select_shadow_block: S,
    mutate: F,
) where
    S: FnOnce(&dyn BlockDevice) -> u64,
    F: FnOnce(&mut [u8]),
{
    synchronize_complex_baseline(&device);

    let shadow_block = select_shadow_block(&*device);
    let mut block = read_block(&*device, shadow_block);
    mutate(&mut block);
    write_block(&*device, shadow_block, &block);

    let reopened = SimpleFs::open(device.clone(), true).expect("reopen with shadow metadata drift");
    let volume = SimpleFsVolume::new(reopened);
    let report = volume
        .check_and_repair()
        .expect("repair shadow metadata drift");
    assert_eq!(report.repairs_applied, 1);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired complex simplefs");
    let volume = SimpleFsVolume::new(repaired);
    assert_rename_remove_sequence_state(&volume);
}

fn assert_complex_fallback_after_newer_metadata_corruption<F, S>(
    device: Arc<MemoryBlockDevice>,
    select_active_block: S,
    mutate: F,
) where
    S: FnOnce(&dyn BlockDevice) -> u64,
    F: FnOnce(&mut [u8]),
{
    publish_complex_next_file_with_primary_superblock_failure(&device);

    let active_block = select_active_block(&*device);
    let mut block = read_block(&*device, active_block);
    mutate(&mut block);
    write_block(&*device, active_block, &block);

    let reopened =
        SimpleFs::open(device.clone(), true).expect("fallback reopen through older complex slot");
    let volume = SimpleFsVolume::new(reopened);
    assert_rename_remove_sequence_without_next_file(&volume);

    let report = volume
        .check_and_repair()
        .expect("repair fallback-opened complex simplefs state");
    assert_eq!(report.repairs_applied, 2);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired complex simplefs");
    let volume = SimpleFsVolume::new(repaired);
    assert_rename_remove_sequence_without_next_file(&volume);
}

#[test]
fn simplefs_reopen_after_failed_metadata_commit_keeps_last_stable_state() {
    let cases = [
        FaultInjection {
            write_number: 1,
            mode: FaultMode::BeforeWrite,
        },
        FaultInjection {
            write_number: 2,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        FaultInjection {
            write_number: 3,
            mode: FaultMode::TornWrite { prefix_len: 40 },
        },
    ];

    for (index, fault) in cases.into_iter().enumerate() {
        let device = build_stable_device();
        let failing = FailingBlockDevice::new(device.clone(), fault);

        let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
        let volume = SimpleFsVolume::new(fs);
        let pending_path = format!("/pending-{index}");
        assert_eq!(volume.create_dir(&pending_path), Err(Error::DeviceError));

        let reopened = SimpleFs::open(device, true).expect("reopen stable simplefs");
        let volume = SimpleFsVolume::new(reopened);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup stable anchor");
        assert_eq!(read_all(&*anchor), b"stable-state");
        assert!(matches!(volume.lookup(&pending_path), Err(Error::NotFound)));
        assert_eq!(volume.stat("/").expect("stat root").size, 2);
    }
}

#[test]
fn simplefs_failed_metadata_commit_rollback_is_visible_without_reopen() {
    let device = build_stable_device();
    let failing = FailingBlockDevice::new(
        device,
        FaultInjection {
            write_number: 1,
            mode: FaultMode::BeforeWrite,
        },
    );

    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(volume.create_dir("/pending"), Err(Error::DeviceError));
    assert!(matches!(volume.lookup("/pending"), Err(Error::NotFound)));

    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state");

    volume
        .create_dir("/recovered")
        .expect("create directory after rollback");
    assert!(volume.lookup("/recovered").is_ok());
}

#[test]
fn simplefs_reopen_after_primary_superblock_write_failure_uses_secondary_commit() {
    let device = build_stable_device();
    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 4,
            mode: FaultMode::BeforeWrite,
        },
    );

    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(volume.create_dir("/committed"), Err(Error::DeviceError));

    let reopened = SimpleFs::open(device, true).expect("reopen mirrored simplefs");
    let volume = SimpleFsVolume::new(reopened);
    assert!(volume.lookup("/committed").is_ok());
    assert_eq!(volume.stat("/").expect("stat root").size, 3);
}

#[test]
fn simplefs_remove_survives_primary_superblock_write_failure() {
    let device = build_device_with_removable_file();

    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 4,
            mode: FaultMode::BeforeWrite,
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(
        volume.remove_path("/trash/old.bin"),
        Err(Error::DeviceError)
    );

    let reopened = SimpleFs::open(device, true).expect("reopen through secondary delete commit");
    let volume = SimpleFsVolume::new(reopened);
    assert!(matches!(
        volume.lookup("/trash/old.bin"),
        Err(Error::NotFound)
    ));
    assert_eq!(volume.stat("/trash").expect("stat trash").size, 0);
}

#[test]
fn simplefs_failed_remove_rollback_is_visible_without_reopen() {
    let device = build_device_with_removable_file();

    let failing = FailingBlockDevice::new(
        device,
        FaultInjection {
            write_number: 2,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(
        volume.remove_path("/trash/old.bin"),
        Err(Error::DeviceError)
    );
    let file = volume
        .lookup("/trash/old.bin")
        .expect("lookup file after failed remove rollback");
    assert_eq!(read_all(&*file), b"retired-payload");
    assert_eq!(volume.stat("/trash").expect("stat trash").size, 1);
}

#[test]
fn simplefs_reopen_after_failed_remove_keeps_last_stable_state() {
    let device = build_device_with_removable_file();
    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 2,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(
        volume.remove_path("/trash/old.bin"),
        Err(Error::DeviceError)
    );

    let reopened =
        SimpleFs::open(device, true).expect("reopen stable simplefs after failed remove");
    let volume = SimpleFsVolume::new(reopened);
    let file = volume
        .lookup("/trash/old.bin")
        .expect("lookup file after failed remove reopen");
    assert_eq!(read_all(&*file), b"retired-payload");
    assert_eq!(volume.stat("/trash").expect("stat trash").size, 1);
}

#[test]
fn simplefs_check_and_repair_reports_single_primary_superblock_drift() {
    let device = build_stable_device();
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open baseline simplefs");
        let volume = SimpleFsVolume::new(fs);
        let baseline = volume
            .check_and_repair()
            .expect("synchronize writable baseline");
        assert_eq!(
            baseline,
            VolumeCheckReport {
                issues_detected: 1,
                repairs_applied: 1,
                orphan_data_blocks: 0,
                checksum_failures: 0,
                staging_orphans_cleaned: 0,
                orphan_blocks_cleaned: 0,
                interrupted_commits: 0,
            }
        );
    }

    corrupt_primary_superblock_checksum(&*device);

    let reopened = SimpleFs::open(device, true).expect("reopen with secondary superblock");
    let volume = SimpleFsVolume::new(reopened);
    let report = volume
        .check_and_repair()
        .expect("repair single-superblock drift");
    assert_eq!(report.repairs_applied, 1);
    assert_eq!(report.checksum_failures, 0);
}

#[test]
fn simplefs_check_and_repair_reports_shadow_inode_drift_after_rename_remove_sequence() {
    let device = build_device_after_rename_remove_sequence();
    assert_complex_shadow_drift_after_rename_remove_sequence(
        device,
        |device| shadow_inode_table_block(device, 0),
        |block| {
            block[1] ^= 0x01;
        },
    );
}

#[test]
fn simplefs_check_and_repair_reports_shadow_dirent_drift_after_rename_remove_sequence() {
    let device = build_device_after_rename_remove_sequence();
    assert_complex_shadow_drift_after_rename_remove_sequence(
        device,
        |device| shadow_dirent_table_block(device, 0),
        |block| {
            block[8] ^= 0x7f;
        },
    );
}

#[test]
fn simplefs_check_and_repair_repairs_combined_shadow_slot_drift_after_rename_remove_sequence() {
    let device = build_device_after_rename_remove_sequence();
    synchronize_complex_baseline(&device);

    let shadow_inode_table = shadow_inode_table_block(&*device, 0);
    let mut shadow_inodes = read_block(&*device, shadow_inode_table);
    shadow_inodes[1] ^= 0x01;
    write_block(&*device, shadow_inode_table, &shadow_inodes);

    let shadow_dirent_table = shadow_dirent_table_block(&*device, 0);
    let mut shadow_dirents = read_block(&*device, shadow_dirent_table);
    shadow_dirents[8] ^= 0x7f;
    write_block(&*device, shadow_dirent_table, &shadow_dirents);

    let reopened = SimpleFs::open(device.clone(), true).expect("reopen with combined shadow drift");
    let volume = SimpleFsVolume::new(reopened);
    let report = volume
        .check_and_repair()
        .expect("repair combined shadow metadata drift");
    assert_eq!(report.repairs_applied, 1);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired complex simplefs");
    let volume = SimpleFsVolume::new(repaired);
    assert_rename_remove_sequence_state(&volume);
}

#[test]
fn simplefs_check_and_repair_repairs_shadow_slot_drift_after_packed_directory_mutations() {
    let device = build_device_after_packed_directory_mutations();
    synchronize_writable_baseline(&device);

    let shadow_inode_table = shadow_inode_table_block(&*device, 0);
    let mut shadow_inodes = read_block(&*device, shadow_inode_table);
    shadow_inodes[33] ^= 0x01;
    write_block(&*device, shadow_inode_table, &shadow_inodes);

    let shadow_dirent_table = shadow_dirent_table_block(&*device, 0);
    let mut shadow_dirents = read_block(&*device, shadow_dirent_table);
    shadow_dirents[72] ^= 0x7f;
    write_block(&*device, shadow_dirent_table, &shadow_dirents);

    let reopened =
        SimpleFs::open(device.clone(), true).expect("reopen with packed-dir shadow drift");
    let volume = SimpleFsVolume::new(reopened);
    let report = volume
        .check_and_repair()
        .expect("repair packed-dir shadow metadata drift");
    assert_eq!(report.repairs_applied, 1);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired packed-dir simplefs");
    let volume = SimpleFsVolume::new(repaired);
    assert_packed_directory_mutation_state(&volume);
}

#[test]
fn simplefs_check_and_repair_reports_primary_superblock_and_shadow_dirent_drift_after_complex_sequence(
) {
    let device = build_device_after_rename_remove_sequence();
    synchronize_complex_baseline(&device);

    corrupt_primary_superblock_checksum(&*device);

    let shadow_dirent_table = shadow_dirent_table_block(&*device, 0);
    let mut shadow_dirents = read_block(&*device, shadow_dirent_table);
    shadow_dirents[8] ^= 0x7f;
    write_block(&*device, shadow_dirent_table, &shadow_dirents);

    let reopened = SimpleFs::open(device.clone(), true).expect("reopen with combined drift");
    let volume = SimpleFsVolume::new(reopened);
    let report = volume
        .check_and_repair()
        .expect("repair combined superblock and dirent drift");
    assert_eq!(report.repairs_applied, 2);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired complex simplefs");
    let volume = SimpleFsVolume::new(repaired);
    assert_rename_remove_sequence_state(&volume);
}

#[test]
fn simplefs_complex_sequence_falls_back_when_newer_active_dirent_is_corrupted() {
    let device = build_device_after_rename_remove_sequence();
    assert_complex_fallback_after_newer_metadata_corruption(
        device,
        |device| active_dirent_table_block(device, 1),
        |block| {
            block[..64].fill(0xff);
        },
    );
}

#[test]
fn simplefs_complex_sequence_falls_back_when_newer_active_inode_is_corrupted() {
    let device = build_device_after_rename_remove_sequence();
    assert_complex_fallback_after_newer_metadata_corruption(
        device,
        |device| active_inode_table_block(device, 1),
        |block| {
            block[..32].fill(0xff);
        },
    );
}

#[test]
fn simplefs_open_falls_back_to_older_valid_superblock_when_newer_metadata_is_corrupted() {
    let device = build_stable_device();
    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 4,
            mode: FaultMode::BeforeWrite,
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(volume.create_dir("/committed"), Err(Error::DeviceError));

    let active_inode_table = active_inode_table_block(&*device, 1);
    let mut active_table = read_block(&*device, active_inode_table);
    active_table[..32].fill(0xff);
    write_block(&*device, active_inode_table, &active_table);

    let reopened =
        SimpleFs::open(device.clone(), true).expect("fallback reopen through older slot");
    let volume = SimpleFsVolume::new(reopened);
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup anchor through fallback state");
    assert_eq!(read_all(&*anchor), b"stable-state");
    assert!(matches!(volume.lookup("/committed"), Err(Error::NotFound)));

    let report = volume
        .check_and_repair()
        .expect("repair fallback-opened simplefs state");
    assert_eq!(report.repairs_applied, 2);
    assert_eq!(report.checksum_failures, 0);

    let repaired = SimpleFs::open(device, true).expect("reopen repaired simplefs");
    let volume = SimpleFsVolume::new(repaired);
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup repaired anchor");
    assert_eq!(read_all(&*anchor), b"stable-state");
    assert!(matches!(volume.lookup("/committed"), Err(Error::NotFound)));
}

#[test]
fn simplefs_failed_rename_rollback_is_visible_without_reopen() {
    let device = build_stable_device();
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        let file = volume
            .create_file("/stable/rename-me.txt")
            .expect("create rename source");
        file.write(0, b"rename-source")
            .expect("write rename source");
    }

    let failing = FailingBlockDevice::new(
        device,
        FaultInjection {
            write_number: 2,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(
        volume.rename("/stable/rename-me.txt", "/stable/renamed.txt"),
        Err(Error::DeviceError)
    );
    assert!(volume.lookup("/stable/rename-me.txt").is_ok());
    assert!(matches!(
        volume.lookup("/stable/renamed.txt"),
        Err(Error::NotFound)
    ));
}

#[test]
fn simplefs_cross_directory_rename_survives_primary_superblock_write_failure() {
    let device = MemoryBlockDevice::new("simplefs-recovery", writable_image(64, 96, 16), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/left").expect("create left");
        volume.create_dir("/right").expect("create right");
        let file = volume
            .create_file("/left/payload.bin")
            .expect("create cross-directory payload");
        file.write(0, b"cross-directory-payload")
            .expect("write cross-directory payload");
    }

    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 4,
            mode: FaultMode::BeforeWrite,
        },
    );
    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(
        volume.rename("/left/payload.bin", "/right/final.bin"),
        Err(Error::DeviceError)
    );

    let reopened = SimpleFs::open(device, true).expect("reopen through secondary commit");
    let volume = SimpleFsVolume::new(reopened);
    assert!(matches!(
        volume.lookup("/left/payload.bin"),
        Err(Error::NotFound)
    ));
    let file = volume
        .lookup("/right/final.bin")
        .expect("lookup cross-directory renamed file");
    assert_eq!(read_all(&*file), b"cross-directory-payload");
    assert_eq!(volume.stat("/left").expect("stat left").size, 0);
    assert_eq!(volume.stat("/right").expect("stat right").size, 1);
}

#[test]
fn simplefs_long_mutation_sequence_survives_reopen_cycles() {
    let device = MemoryBlockDevice::new("simplefs-recovery", writable_image(160, 192, 96), false);
    let mut expected_files = BTreeMap::new();
    let mut removed_paths = BTreeSet::new();

    for round in 0..12 {
        {
            let fs = SimpleFs::open(device.clone(), true).expect("open mutable simplefs");
            let volume = SimpleFsVolume::new(fs);
            ensure_dir(&volume, "/staging");
            ensure_dir(&volume, "/archive");
            ensure_dir(&volume, "/history");

            let staging_path = format!("/staging/round-{round:02}.bin");
            let published_path = if round % 2 == 0 {
                format!("/archive/round-{round:02}.bin")
            } else {
                format!("/history/round-{round:02}.bin")
            };
            let payload = patterned_payload(round);
            let file = volume
                .create_file(&staging_path)
                .expect("create staged payload");
            assert_eq!(
                file.write(0, &payload).expect("write staged payload"),
                payload.len()
            );
            volume
                .rename(&staging_path, &published_path)
                .expect("publish staged payload");
            expected_files.insert(published_path.clone(), payload);

            if round >= 3 {
                let retired_round = round - 3;
                let retired_path = if retired_round % 2 == 0 {
                    format!("/archive/round-{retired_round:02}.bin")
                } else {
                    format!("/history/round-{retired_round:02}.bin")
                };
                volume
                    .remove_path(&retired_path)
                    .expect("remove retired payload");
                expected_files.remove(&retired_path);
                removed_paths.insert(retired_path);
            }
        }

        let reopened = SimpleFs::open(device.clone(), true).expect("reopen mutable simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_eq!(volume.stat("/staging").expect("stat staging").size, 0);

        let expected_archive = expected_files
            .keys()
            .filter(|path| path.starts_with("/archive/"))
            .count();
        let expected_history = expected_files
            .keys()
            .filter(|path| path.starts_with("/history/"))
            .count();
        assert_eq!(
            volume.stat("/archive").expect("stat archive").size,
            expected_archive
        );
        assert_eq!(
            volume.stat("/history").expect("stat history").size,
            expected_history
        );

        for (path, payload) in &expected_files {
            let file = volume.lookup(path).expect("lookup retained payload");
            assert_eq!(read_all(&*file), *payload);
        }

        for removed_path in &removed_paths {
            if expected_files.contains_key(removed_path) {
                continue;
            }
            assert!(matches!(volume.lookup(removed_path), Err(Error::NotFound)));
        }
    }
}

#[test]
fn simplefs_torn_data_write_does_not_escape_without_metadata_commit() {
    let device = build_stable_device();
    let failing = FailingBlockDevice::new(
        device.clone(),
        FaultInjection {
            write_number: 1,
            mode: FaultMode::TornWrite {
                prefix_len: BLOCK_SIZE.min(8),
            },
        },
    );

    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(anchor.write(0, b"mutated-state"), Err(Error::DeviceError));
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("relookup stable anchor after failed overwrite");
    assert_eq!(read_all(&*anchor), b"stable-state");

    let reopened = SimpleFs::open(device, true).expect("reopen after torn data write");
    let volume = SimpleFsVolume::new(reopened);
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state");
}

#[test]
fn simplefs_check_and_repair_detects_orphan_data_blocks_after_content_replace() {
    let image = build_seed_image(
        "orphan-detect",
        4, // extra inodes
        8, // extra dirents
        8, // extra data blocks — gives room for new allocation on content replace
    );
    let device = MemoryBlockDevice::new("orphan-detect-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs);

    // Before any mutation the volume should be clean.
    let initial = volume.check_and_repair().expect("initial check_and_repair");
    assert!(initial.is_clean());
    assert_eq!(volume.count_orphan_data_blocks(), 0);

    // Replace file contents — the old data block becomes an orphan because
    // SimpleFs allocates a new block for the replacement content without
    // reclaiming the previous one.
    let seed = volume.lookup("/seed.txt").expect("lookup seed");
    let written = seed
        .write(0, b"replaced-content")
        .expect("replace seed content");
    assert_eq!(written, b"replaced-content".len());
    assert_eq!(read_all(&*seed), b"replaced-content");

    assert!(
        volume.count_orphan_data_blocks() > 0,
        "orphan data block should be detected after content replace"
    );
}

#[test]
fn simplefs_orphan_blocks_reclaimed_after_repair_are_allocatable() {
    // Use extra data blocks so the old extent becomes an orphan when the file
    // content is replaced (SimpleFs allocates a new extent for the overwrite).
    let image = build_seed_image(
        "orphan-reclaim",
        4, // extra inodes
        8, // extra dirents
        8, // extra data blocks
    );
    let device = MemoryBlockDevice::new("orphan-reclaim-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs.clone());

    // Replace file contents — the old data block becomes an orphan.
    let seed = volume.lookup("/seed.txt").expect("lookup seed");
    let written = seed
        .write(0, b"replaced-content-for-reclaim-test")
        .expect("replace seed content");
    assert_eq!(written, b"replaced-content-for-reclaim-test".len());

    let orphans_before = volume.count_orphan_data_blocks();
    assert!(
        orphans_before > 0,
        "orphan data block should exist after content replace"
    );

    // check_and_repair should zero the orphan blocks, and the fix in F1
    // ensures the in-memory free-extent map is updated so the reclaimed
    // blocks are available for new allocations during this mount.
    // Note: after a write, the shadow metadata slot is naturally stale,
    // so is_clean() may return false; the repair cycle republishes it.
    let report = volume.check_and_repair().expect("check_and_repair");
    assert_eq!(report.orphan_data_blocks, orphans_before);
    assert_eq!(report.orphan_blocks_cleaned, orphans_before);
    assert!(report.repaired(), "repair cycle should have run");

    // count_orphan_data_blocks scans for unreferenced blocks (not non-zero
    // blocks), so it will still report the zeroed blocks as unreferenced.
    // The key property F1 ensures is that the zeroed blocks are back in
    // free_data_extents — allocatable during this mount without a reopen.

    // The reclaimed blocks should be allocatable: creating a new file and
    // writing to it must succeed.
    let new_file = volume
        .create_file("/reclaimed-test.bin")
        .expect("create new file");
    let data = [0xCC_u8; 512];
    let written = new_file.write(0, &data).expect("write new file");
    assert_eq!(written, 512);

    // Verify the new file's content reads back correctly.
    assert_eq!(read_all(&*new_file), &data[..]);

    // Reopen the volume to confirm the reclaimed file persisted correctly.
    drop(volume);
    drop(fs);
    let fs = SimpleFs::open(device, true).expect("reopen after repair");
    let volume2 = SimpleFsVolume::new(fs);

    // The reclaimed file should still exist with correct content.
    let reclaimed = volume2
        .lookup("/reclaimed-test.bin")
        .expect("lookup reclaimed file");
    assert_eq!(reclaimed.size(), 512);
    assert_eq!(read_all(&*reclaimed), &data[..]);
}

#[test]
fn simplefs_check_data_integrity_detects_corrupted_data_block() {
    let image = build_seed_image("integrity-check", 4, 8, 8);
    let device = MemoryBlockDevice::new("integrity-check-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs);

    // Write to the seed file so a non-zero checksum is stored.
    let seed = volume.lookup("/seed.txt").expect("lookup seed");
    seed.write(0, b"checksummed-content-v1")
        .expect("write seed content");

    // Before corruption, integrity check should pass.
    let (checked, failures) = volume.check_data_integrity();
    assert!(checked > 0);
    assert_eq!(failures, 0);

    // Scan the data region to locate the seed payload and corrupt it.
    // The seed content was written to a data block somewhere in the data
    // region.  We find it by scanning for the known content.
    let data_start = 6; // first data block for a typical headroom-8 image
    let block_count = device.block_count();
    let mut target_lba = None;
    for lba in data_start..block_count {
        let mut block = vec![0_u8; BLOCK_SIZE];
        if device.read_blocks(lba, &mut block).is_ok()
            && block.starts_with(b"checksummed-content-v1")
        {
            target_lba = Some(lba);
            break;
        }
    }
    let target_lba = target_lba.expect("find seed data block");

    // Corrupt the first byte of the data block.
    let mut block = vec![0_u8; BLOCK_SIZE];
    device
        .read_blocks(target_lba, &mut block)
        .expect("read data block");
    block[0] ^= 0xFF;
    device
        .write_blocks(target_lba, &block)
        .expect("write corrupted block");

    // check_data_integrity reads directly from the device so it sees the
    // corruption even without reopening the volume.
    let (checked, failures) = volume.check_data_integrity();
    assert!(checked > 0);
    assert!(
        failures > 0,
        "data integrity check should detect corrupted block, got failures={failures}",
    );
}

#[test]
fn simplefs_crash_during_content_replace_recovers_consistent_state_on_reopen() {
    let device = build_stable_device();

    // Trace through replace_file_contents_transactionally + flush_metadata for
    // a 1-block file write.  The write sequence is approximately:
    //   1. data-block write (new content)
    //   2. shadow-inode-table write
    //   3. shadow-dirent-table write
    //   4. secondary-superblock write
    //   5. primary-superblock write
    //
    // We inject a BeforeWrite fault at each step and verify that after
    // reopening the stable device the filesystem is consistent.
    //
    // Note: a fault at step 5 (primary superblock) still results in a
    // successful commit because the secondary superblock was already
    // written — the shadow-publish protocol tolerates one superblock
    // failure.  For steps 1-4 the old content is preserved.
    for write_number in 1..=5 {
        let fault = FaultInjection {
            write_number,
            mode: FaultMode::BeforeWrite,
        };
        let failing = FailingBlockDevice::new(device.clone(), fault);

        let fs = SimpleFs::open(failing, true)
            .unwrap_or_else(|err| panic!("open failing at write#{write_number}: {err:?}"));
        let volume = SimpleFsVolume::new(fs);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup anchor at write#{write_number}");

        let _ = anchor.write(0, b"crash-payload-v1");

        // Reopen on the stable device and verify the filesystem is usable.
        drop(volume);
        drop(anchor);
        let reopened = SimpleFs::open(device.clone(), true)
            .unwrap_or_else(|err| panic!("reopen after crash at write#{write_number}: {err:?}"));
        let volume = SimpleFsVolume::new(reopened);
        let anchor = volume.lookup("/stable/anchor.txt").unwrap_or_else(|err| {
            panic!("relookup anchor after crash at write#{write_number}: {err:?}")
        });
        // Read must succeed — no checksum failure or I/O error.
        let content = read_all(&*anchor);
        assert!(
            content == b"stable-state" || content == b"crash-payload-v1",
            "unexpected anchor content after crash at write#{write_number}: {content:?}"
        );

        // check_and_repair must report clean or repairable.
        let report = volume.check_and_repair().unwrap_or_else(|err| {
            panic!("check_and_repair after crash at write#{write_number}: {err:?}")
        });
        assert!(
            report.is_clean() || report.repaired(),
            "volume should be clean or repaired after crash at write#{write_number}",
        );
    }
}
