//! tests/simplefs/fault_matrix.rs
//!
//! Exercise a block-level fault-injection matrix for writable SimpleFs recovery
//! behavior.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use protofire::kernel::fs::block::{BlockDevice, MemoryBlockDevice, BLOCK_SIZE};
use protofire::kernel::fs::simplefs::{SimpleFs, SimpleFsVolume};
use protofire::kernel::fs::vfs::FileSystem as VfsFileSystem;
use protofire::{Error, Result};

use support::{build_seed_image, build_stable_anchor_device, read_all, read_u32_le};

const MAGIC: &[u8; 8] = b"ADAFS1\0\0";
const VERSION: u32 = 2;
const PRIMARY_SUPERBLOCK_BLOCK: u64 = 0;
const SECONDARY_SUPERBLOCK_BLOCK: u64 = 1;
const SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET: usize = 24;
const SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET: usize = 28;
const SUPERBLOCK_DATA_BLOCK_START_OFFSET: usize = 32;
const SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET: usize = 36;
const SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET: usize = 40;
const SUPERBLOCK_GENERATION_OFFSET: usize = 52;
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 56;
const PUBLISH_THEN_RETIRE_REMOVE_COMMIT_NUMBER: usize = 4;

#[derive(Clone, Copy)]
enum FaultMode {
    BeforeWrite,
    TornWrite { prefix_len: usize },
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FaultTarget {
    ExactLba(u64),
    Range { start_lba: u64, block_count: u64 },
}

#[derive(Clone, Copy)]
struct FaultPlan {
    target: FaultTarget,
    match_number: usize,
    mode: FaultMode,
}

#[derive(Clone, Copy)]
struct SimpleFsLayout {
    active_inode_table_block: u64,
    active_dirent_table_block: u64,
    shadow_inode_table_block: u64,
    shadow_dirent_table_block: u64,
    data_block_start: u64,
    generation: u32,
}

#[derive(Clone, Copy)]
enum MatrixStage {
    ShadowInodeTable,
    ShadowDirentTable,
    SecondarySuperblock,
    PrimarySuperblock,
    DataRegion,
}

#[derive(Clone, Copy)]
struct MatrixCase {
    name: &'static str,
    warmup_commits: usize,
    stage: MatrixStage,
    mode: FaultMode,
}

struct FaultSequenceState {
    target_matches: BTreeMap<FaultTarget, usize>,
    fired: Vec<bool>,
}

struct FaultInjectingBlockDevice {
    inner: Arc<MemoryBlockDevice>,
    plans: Vec<FaultPlan>,
    state: Mutex<FaultSequenceState>,
}

impl FaultInjectingBlockDevice {
    fn new(inner: Arc<MemoryBlockDevice>, plan: FaultPlan) -> Arc<Self> {
        Self::new_sequence(inner, vec![plan])
    }

    fn new_sequence(inner: Arc<MemoryBlockDevice>, plans: Vec<FaultPlan>) -> Arc<Self> {
        let plan_count = plans.len();
        Arc::new(Self {
            inner,
            plans,
            state: Mutex::new(FaultSequenceState {
                target_matches: BTreeMap::new(),
                fired: vec![false; plan_count],
            }),
        })
    }

    fn matches_target(plan: FaultPlan, lba: u64, block_count: u64) -> bool {
        let end = lba.saturating_add(block_count);
        match plan.target {
            FaultTarget::ExactLba(target_lba) => lba <= target_lba && target_lba < end,
            FaultTarget::Range {
                start_lba,
                block_count,
            } => {
                let target_end = start_lba.saturating_add(block_count);
                lba < target_end && start_lba < end
            }
        }
    }

    fn apply_torn_write(&self, lba: u64, data: &[u8], prefix_len: usize) -> Result<()> {
        let mut merged = vec![0_u8; data.len()];
        self.inner.read_blocks(lba, &mut merged)?;
        let prefix_len = prefix_len.min(data.len());
        merged[..prefix_len].copy_from_slice(&data[..prefix_len]);
        self.inner.write_blocks(lba, &merged)
    }
}

impl BlockDevice for FaultInjectingBlockDevice {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        self.inner.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let block_count = (data.len() / BLOCK_SIZE) as u64;
        let mut state = self.state.lock().expect("fault state lock");
        let mut matched_targets = BTreeMap::new();
        for plan in self.plans.iter().copied() {
            if !Self::matches_target(plan, lba, block_count) {
                continue;
            }

            let count = matched_targets.entry(plan.target).or_insert_with(|| {
                let entry = state.target_matches.entry(plan.target).or_insert(0);
                *entry += 1;
                *entry
            });
            let _ = count;
        }

        for (index, plan) in self.plans.iter().copied().enumerate() {
            if state.fired[index] {
                continue;
            }
            let Some(target_count) = matched_targets.get(&plan.target).copied() else {
                continue;
            };
            if target_count != plan.match_number {
                continue;
            }

            state.fired[index] = true;
            return match plan.mode {
                FaultMode::BeforeWrite => Err(Error::DeviceError),
                FaultMode::TornWrite { prefix_len } => {
                    self.apply_torn_write(lba, data, prefix_len)?;
                    Err(Error::DeviceError)
                }
            };
        }

        drop(state);
        self.inner.write_blocks(lba, data)
    }
}

fn build_stable_device() -> Arc<MemoryBlockDevice> {
    build_stable_anchor_device("simplefs-fault-matrix", "fault-matrix-simplefs", 64, 96, 32)
}

fn build_packed_directory_device() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new(
        "simplefs-fault-matrix",
        build_seed_image("fault-matrix-simplefs", 96, 128, 64),
        false,
    );
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
    }
    device
}

fn build_cross_directory_rename_device() -> Arc<MemoryBlockDevice> {
    let device = build_stable_device();
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/left").expect("create left");
        volume.create_dir("/right").expect("create right");
        let file = volume
            .create_file("/left/payload.bin")
            .expect("create cross-directory payload");
        assert_eq!(
            file.write(0, b"cross-directory-payload")
                .expect("write cross-directory payload"),
            "cross-directory-payload".len()
        );
    }
    device
}

fn build_publish_then_retire_device() -> Arc<MemoryBlockDevice> {
    let device = build_stable_device();
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/staging").expect("create staging");
        volume.create_dir("/archive").expect("create archive");
        volume.create_dir("/history").expect("create history");

        let retired = volume
            .create_file("/archive/retired.bin")
            .expect("create retired payload");
        assert_eq!(
            retired
                .write(0, b"retired-payload")
                .expect("write retired payload"),
            "retired-payload".len()
        );
    }
    device
}

fn apply_warmup_commits(device: &Arc<MemoryBlockDevice>, count: usize) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }

    let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs);
    let mut paths = Vec::with_capacity(count);

    for index in 0..count {
        let path = format!("/warmup-{index:02}");
        volume
            .create_dir(&path)
            .expect("create warmup metadata commit");
        paths.push(path);
    }

    paths
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

fn superblock_checksum(block: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for (index, byte) in block.iter().enumerate() {
        if (SUPERBLOCK_CHECKSUM_OFFSET..SUPERBLOCK_CHECKSUM_OFFSET + 4).contains(&index) {
            continue;
        }

        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn read_superblock_layout(device: &dyn BlockDevice, block: u64) -> Result<SimpleFsLayout> {
    let mut buffer = [0_u8; BLOCK_SIZE];
    device.read_blocks(block, &mut buffer)?;

    if buffer.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Error::InvalidArgument);
    }
    if read_u32_le(&buffer, 8) != VERSION {
        return Err(Error::InvalidArgument);
    }

    let recorded_checksum = read_u32_le(&buffer, SUPERBLOCK_CHECKSUM_OFFSET);
    if recorded_checksum != superblock_checksum(&buffer) {
        return Err(Error::InvalidArgument);
    }

    Ok(SimpleFsLayout {
        active_inode_table_block: read_u32_le(&buffer, SUPERBLOCK_ACTIVE_INODE_TABLE_OFFSET) as u64,
        active_dirent_table_block: read_u32_le(&buffer, SUPERBLOCK_ACTIVE_DIRENT_TABLE_OFFSET)
            as u64,
        shadow_inode_table_block: read_u32_le(&buffer, SUPERBLOCK_SHADOW_INODE_TABLE_OFFSET) as u64,
        shadow_dirent_table_block: read_u32_le(&buffer, SUPERBLOCK_SHADOW_DIRENT_TABLE_OFFSET)
            as u64,
        data_block_start: read_u32_le(&buffer, SUPERBLOCK_DATA_BLOCK_START_OFFSET) as u64,
        generation: read_u32_le(&buffer, SUPERBLOCK_GENERATION_OFFSET),
    })
}

fn load_current_layout(device: &dyn BlockDevice) -> Result<SimpleFsLayout> {
    let primary = read_superblock_layout(device, PRIMARY_SUPERBLOCK_BLOCK);
    let secondary = read_superblock_layout(device, SECONDARY_SUPERBLOCK_BLOCK);

    match (primary, secondary) {
        (Ok(primary), Ok(secondary)) => {
            if secondary.generation > primary.generation {
                Ok(secondary)
            } else {
                Ok(primary)
            }
        }
        (Ok(primary), Err(_)) => Ok(primary),
        (Err(_), Ok(secondary)) => Ok(secondary),
        (Err(_), Err(_)) => Err(Error::InvalidArgument),
    }
}

fn fault_target_for_case(
    stage: MatrixStage,
    layout: SimpleFsLayout,
    device_blocks: u64,
) -> FaultTarget {
    match stage {
        MatrixStage::ShadowInodeTable => FaultTarget::ExactLba(layout.shadow_inode_table_block),
        MatrixStage::ShadowDirentTable => FaultTarget::ExactLba(layout.shadow_dirent_table_block),
        MatrixStage::SecondarySuperblock => FaultTarget::ExactLba(SECONDARY_SUPERBLOCK_BLOCK),
        MatrixStage::PrimarySuperblock => FaultTarget::ExactLba(PRIMARY_SUPERBLOCK_BLOCK),
        MatrixStage::DataRegion => FaultTarget::Range {
            start_lba: layout.data_block_start,
            block_count: device_blocks.saturating_sub(layout.data_block_start),
        },
    }
}

fn fault_plan_for_commit_number(
    stage: MatrixStage,
    layout: SimpleFsLayout,
    device_blocks: u64,
    commit_number: usize,
    mode: FaultMode,
) -> FaultPlan {
    assert!(commit_number != 0, "commit number must be 1-based");

    match stage {
        MatrixStage::ShadowInodeTable => FaultPlan {
            target: FaultTarget::ExactLba(if commit_number % 2 == 1 {
                layout.shadow_inode_table_block
            } else {
                layout.active_inode_table_block
            }),
            match_number: commit_number.div_ceil(2),
            mode,
        },
        MatrixStage::ShadowDirentTable => FaultPlan {
            target: FaultTarget::ExactLba(if commit_number % 2 == 1 {
                layout.shadow_dirent_table_block
            } else {
                layout.active_dirent_table_block
            }),
            match_number: commit_number.div_ceil(2),
            mode,
        },
        MatrixStage::SecondarySuperblock
        | MatrixStage::PrimarySuperblock
        | MatrixStage::DataRegion => FaultPlan {
            target: fault_target_for_case(stage, layout, device_blocks),
            match_number: commit_number,
            mode,
        },
    }
}

fn assert_slot_rotation(
    case: MatrixCase,
    initial_layout: SimpleFsLayout,
    current_layout: SimpleFsLayout,
) {
    match case.stage {
        MatrixStage::ShadowInodeTable => {
            let expected = if case.warmup_commits.is_multiple_of(2) {
                initial_layout.shadow_inode_table_block
            } else {
                initial_layout.active_inode_table_block
            };
            assert_eq!(
                current_layout.shadow_inode_table_block, expected,
                "{} targeted the wrong inode-table slot",
                case.name
            );
        }
        MatrixStage::ShadowDirentTable => {
            let expected = if case.warmup_commits.is_multiple_of(2) {
                initial_layout.shadow_dirent_table_block
            } else {
                initial_layout.active_dirent_table_block
            };
            assert_eq!(
                current_layout.shadow_dirent_table_block, expected,
                "{} targeted the wrong dirent-table slot",
                case.name
            );
        }
        MatrixStage::SecondarySuperblock
        | MatrixStage::PrimarySuperblock
        | MatrixStage::DataRegion => {}
    }
}

fn assert_stable_state(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    missing_path: &str,
    note: &str,
) {
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    assert!(
        matches!(volume.lookup(missing_path), Err(Error::NotFound)),
        "{note}: unexpected visible path {missing_path}",
    );
}

fn assert_packed_directory_remove_not_committed(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    note: &str,
) {
    let seed = volume.lookup("/seed.txt").expect("lookup seed file");
    assert_eq!(read_all(&*seed), b"seed", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    let mut names = collect_dir_names(volume, "/bulk");
    names.sort();
    assert_eq!(names.len(), 40, "{note}: packed directory size drifted");
    assert_eq!(volume.stat("/bulk").expect("stat bulk").size, 40, "{note}");
    assert!(names.iter().any(|name| name == "item07.txt"), "{note}");
    assert!(names.iter().any(|name| name == "item11.txt"), "{note}");

    let removed = volume
        .lookup("/bulk/item07.txt")
        .expect("lookup preserved packed-dir entry");
    assert_eq!(read_all(&*removed), b"payload-07", "{note}");
    let retained = volume
        .lookup("/bulk/item11.txt")
        .expect("lookup retained packed-dir entry");
    assert_eq!(read_all(&*retained), b"payload-11", "{note}");
}

fn assert_cross_directory_rename_not_committed(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    note: &str,
) {
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    let file = volume
        .lookup("/left/payload.bin")
        .expect("lookup old cross-directory path");
    assert_eq!(read_all(&*file), b"cross-directory-payload", "{note}");
    assert!(matches!(
        volume.lookup("/right/final.bin"),
        Err(Error::NotFound)
    ));
    assert_eq!(volume.stat("/left").expect("stat left").size, 1, "{note}");
    assert_eq!(volume.stat("/right").expect("stat right").size, 0, "{note}");
}

fn assert_cross_directory_rename_committed(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    note: &str,
) {
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    assert!(matches!(
        volume.lookup("/left/payload.bin"),
        Err(Error::NotFound)
    ));
    let file = volume
        .lookup("/right/final.bin")
        .expect("lookup committed cross-directory path");
    assert_eq!(read_all(&*file), b"cross-directory-payload", "{note}");
    assert_eq!(volume.stat("/left").expect("stat left").size, 0, "{note}");
    assert_eq!(volume.stat("/right").expect("stat right").size, 1, "{note}");
}

fn execute_publish_then_retire_sequence(volume: &SimpleFsVolume) -> Result<()> {
    let file = volume
        .create_file("/staging/current.bin")
        .expect("create staged payload");
    assert_eq!(
        file.write(0, b"current-payload")
            .expect("write staged payload"),
        "current-payload".len()
    );
    volume
        .rename("/staging/current.bin", "/history/current.bin")
        .expect("publish staged payload");
    volume.remove_path("/archive/retired.bin")
}

fn assert_publish_then_retire_pre_remove_state(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    note: &str,
) {
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    assert!(matches!(
        volume.lookup("/staging/current.bin"),
        Err(Error::NotFound)
    ));
    let published = volume
        .lookup("/history/current.bin")
        .expect("lookup published payload");
    assert_eq!(read_all(&*published), b"current-payload", "{note}");
    let retired = volume
        .lookup("/archive/retired.bin")
        .expect("lookup retained retired payload");
    assert_eq!(read_all(&*retired), b"retired-payload", "{note}");
    assert_eq!(
        volume.stat("/staging").expect("stat staging").size,
        0,
        "{note}"
    );
    assert_eq!(
        volume.stat("/archive").expect("stat archive").size,
        1,
        "{note}"
    );
    assert_eq!(
        volume.stat("/history").expect("stat history").size,
        1,
        "{note}"
    );
}

fn assert_publish_then_retire_committed_state(
    volume: &SimpleFsVolume,
    warmup_paths: &[String],
    note: &str,
) {
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(read_all(&*anchor), b"stable-state", "{note}");

    for warmup_path in warmup_paths {
        assert!(
            volume.lookup(warmup_path).is_ok(),
            "{note}: missing {warmup_path}"
        );
    }

    assert!(matches!(
        volume.lookup("/staging/current.bin"),
        Err(Error::NotFound)
    ));
    let published = volume
        .lookup("/history/current.bin")
        .expect("lookup committed payload");
    assert_eq!(read_all(&*published), b"current-payload", "{note}");
    assert!(matches!(
        volume.lookup("/archive/retired.bin"),
        Err(Error::NotFound)
    ));
    assert_eq!(
        volume.stat("/staging").expect("stat staging").size,
        0,
        "{note}"
    );
    assert_eq!(
        volume.stat("/archive").expect("stat archive").size,
        0,
        "{note}"
    );
    assert_eq!(
        volume.stat("/history").expect("stat history").size,
        1,
        "{note}"
    );
}

#[test]
fn simplefs_metadata_and_secondary_superblock_fault_matrix_preserves_last_stable_state() {
    let cases = [
        MatrixCase {
            name: "shadow-inode-before-write-shadow-slot",
            warmup_commits: 0,
            stage: MatrixStage::ShadowInodeTable,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "shadow-inode-torn-write-active-slot-region",
            warmup_commits: 1,
            stage: MatrixStage::ShadowInodeTable,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        MatrixCase {
            name: "shadow-dirent-before-write-shadow-slot",
            warmup_commits: 0,
            stage: MatrixStage::ShadowDirentTable,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "shadow-dirent-torn-write-active-slot-region",
            warmup_commits: 1,
            stage: MatrixStage::ShadowDirentTable,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        MatrixCase {
            name: "secondary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::SecondarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            // Keep the torn prefix before the checksum field so the block stays invalid.
            name: "secondary-superblock-torn-write",
            warmup_commits: 0,
            stage: MatrixStage::SecondarySuperblock,
            mode: FaultMode::TornWrite { prefix_len: 40 },
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let device = build_stable_device();
        let initial_layout = load_current_layout(&*device).expect("read initial layout");
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let current_layout = load_current_layout(&*device).expect("read current layout");
        assert_slot_rotation(case, initial_layout, current_layout);

        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, current_layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
        let volume = SimpleFsVolume::new(fs);
        let pending_path = format!("/pending-matrix-{index:02}");
        assert_eq!(
            volume.create_dir(&pending_path),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_stable_state(&volume, &warmup_paths, &pending_path, case.name);

        let reopened = SimpleFs::open(device, true).expect("reopen stable simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_stable_state(&volume, &warmup_paths, &pending_path, case.name);
    }
}

#[test]
fn simplefs_packed_directory_remove_fault_matrix_preserves_last_stable_state() {
    let cases = [
        MatrixCase {
            name: "packed-remove-shadow-inode-before-write",
            warmup_commits: 0,
            stage: MatrixStage::ShadowInodeTable,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "packed-remove-shadow-dirent-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::ShadowDirentTable,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        MatrixCase {
            name: "packed-remove-secondary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::SecondarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
    ];

    for case in cases {
        let device = build_packed_directory_device();
        let initial_layout = load_current_layout(&*device).expect("read initial layout");
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let current_layout = load_current_layout(&*device).expect("read current layout");
        assert_slot_rotation(case, initial_layout, current_layout);

        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, current_layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing packed-dir simplefs");
        let volume = SimpleFsVolume::new(fs);
        assert_eq!(
            volume.remove_path("/bulk/item07.txt"),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_packed_directory_remove_not_committed(&volume, &warmup_paths, case.name);

        let reopened = SimpleFs::open(device, true).expect("reopen stable packed-dir simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_packed_directory_remove_not_committed(&volume, &warmup_paths, case.name);
    }
}

#[test]
fn simplefs_cross_directory_rename_metadata_fault_matrix_preserves_last_stable_state() {
    let cases = [
        MatrixCase {
            name: "cross-rename-shadow-inode-before-write",
            warmup_commits: 0,
            stage: MatrixStage::ShadowInodeTable,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "cross-rename-shadow-dirent-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::ShadowDirentTable,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        MatrixCase {
            name: "cross-rename-secondary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::SecondarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
    ];

    for case in cases {
        let device = build_cross_directory_rename_device();
        let initial_layout = load_current_layout(&*device).expect("read initial layout");
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let current_layout = load_current_layout(&*device).expect("read current layout");
        assert_slot_rotation(case, initial_layout, current_layout);

        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, current_layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing cross-rename simplefs");
        let volume = SimpleFsVolume::new(fs);
        assert_eq!(
            volume.rename("/left/payload.bin", "/right/final.bin"),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_cross_directory_rename_not_committed(&volume, &warmup_paths, case.name);

        let reopened = SimpleFs::open(device, true).expect("reopen stable cross-rename simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_cross_directory_rename_not_committed(&volume, &warmup_paths, case.name);
    }
}

#[test]
fn simplefs_cross_directory_rename_primary_superblock_fault_matrix_keeps_committed_state() {
    let cases = [
        MatrixCase {
            name: "cross-rename-primary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "cross-rename-primary-superblock-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::TornWrite { prefix_len: 40 },
        },
    ];

    for case in cases {
        let device = build_cross_directory_rename_device();
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let layout = load_current_layout(&*device).expect("read current layout");
        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing cross-rename simplefs");
        let volume = SimpleFsVolume::new(fs);
        assert_eq!(
            volume.rename("/left/payload.bin", "/right/final.bin"),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_cross_directory_rename_not_committed(&volume, &warmup_paths, case.name);

        let reopened =
            SimpleFs::open(device, true).expect("reopen committed cross-rename simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_cross_directory_rename_committed(&volume, &warmup_paths, case.name);
    }
}

#[test]
fn simplefs_publish_then_retire_metadata_fault_matrix_preserves_pre_remove_state() {
    let cases = [
        MatrixCase {
            name: "publish-retire-shadow-inode-before-write",
            warmup_commits: 0,
            stage: MatrixStage::ShadowInodeTable,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "publish-retire-shadow-dirent-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::ShadowDirentTable,
            mode: FaultMode::TornWrite { prefix_len: 96 },
        },
        MatrixCase {
            name: "publish-retire-secondary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::SecondarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
    ];

    for case in cases {
        let device = build_publish_then_retire_device();
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let layout = load_current_layout(&*device).expect("read current layout");
        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            // The failing `remove_path()` is the fourth metadata commit in the
            // high-level workflow: create staged file, write it, publish it,
            // then retire the old payload.
            fault_plan_for_commit_number(
                case.stage,
                layout,
                device.block_count(),
                PUBLISH_THEN_RETIRE_REMOVE_COMMIT_NUMBER,
                case.mode,
            ),
        );

        let fs = SimpleFs::open(failing, true).expect("open failing publish-retire simplefs");
        let volume = SimpleFsVolume::new(fs);
        assert_eq!(
            execute_publish_then_retire_sequence(&volume),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_publish_then_retire_pre_remove_state(&volume, &warmup_paths, case.name);

        let reopened = SimpleFs::open(device, true).expect("reopen stable publish-retire simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_publish_then_retire_pre_remove_state(&volume, &warmup_paths, case.name);
    }
}

#[test]
fn simplefs_publish_then_retire_primary_superblock_fault_matrix_commits_across_reopen() {
    let cases = [
        MatrixCase {
            name: "publish-retire-primary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "publish-retire-primary-superblock-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::TornWrite { prefix_len: 40 },
        },
    ];

    for case in cases {
        let device = build_publish_then_retire_device();
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let layout = load_current_layout(&*device).expect("read current layout");
        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            fault_plan_for_commit_number(
                case.stage,
                layout,
                device.block_count(),
                PUBLISH_THEN_RETIRE_REMOVE_COMMIT_NUMBER,
                case.mode,
            ),
        );

        let fs = SimpleFs::open(failing, true).expect("open failing publish-retire simplefs");
        let volume = SimpleFsVolume::new(fs);
        assert_eq!(
            execute_publish_then_retire_sequence(&volume),
            Err(Error::DeviceError),
            "{}",
            case.name
        );
        assert_publish_then_retire_pre_remove_state(&volume, &warmup_paths, case.name);

        let reopened =
            SimpleFs::open(device, true).expect("reopen committed publish-retire simplefs");
        let volume = SimpleFsVolume::new(reopened);
        assert_publish_then_retire_committed_state(&volume, &warmup_paths, case.name);
    }
}

#[test]
fn simplefs_primary_superblock_fault_matrix_keeps_committed_secondary_state() {
    let cases = [
        MatrixCase {
            name: "primary-superblock-before-write",
            warmup_commits: 0,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "primary-superblock-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::PrimarySuperblock,
            mode: FaultMode::TornWrite { prefix_len: 40 },
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let device = build_stable_device();
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let layout = load_current_layout(&*device).expect("read current layout");
        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
        let volume = SimpleFsVolume::new(fs);
        let committed_path = format!("/committed-matrix-{index:02}");
        assert_eq!(
            volume.create_dir(&committed_path),
            Err(Error::DeviceError),
            "{}",
            case.name
        );

        let reopened = SimpleFs::open(device, true).expect("reopen mirrored simplefs");
        let volume = SimpleFsVolume::new(reopened);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup stable anchor");
        assert_eq!(read_all(&*anchor), b"stable-state", "{}", case.name);
        for warmup_path in &warmup_paths {
            assert!(
                volume.lookup(warmup_path).is_ok(),
                "{}: missing {warmup_path}",
                case.name
            );
        }
        assert!(volume.lookup(&committed_path).is_ok(), "{}", case.name);
    }
}

#[test]
fn simplefs_data_region_fault_matrix_preserves_visible_file_contents() {
    let cases = [
        MatrixCase {
            name: "data-region-before-write",
            warmup_commits: 0,
            stage: MatrixStage::DataRegion,
            mode: FaultMode::BeforeWrite,
        },
        MatrixCase {
            name: "data-region-torn-write",
            warmup_commits: 1,
            stage: MatrixStage::DataRegion,
            mode: FaultMode::TornWrite { prefix_len: 32 },
        },
    ];

    for case in cases {
        let device = build_stable_device();
        let warmup_paths = apply_warmup_commits(&device, case.warmup_commits);
        let layout = load_current_layout(&*device).expect("read current layout");
        let failing = FaultInjectingBlockDevice::new(
            device.clone(),
            FaultPlan {
                target: fault_target_for_case(case.stage, layout, device.block_count()),
                match_number: 1,
                mode: case.mode,
            },
        );

        let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
        let volume = SimpleFsVolume::new(fs);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup stable anchor");
        assert_eq!(
            anchor.write(0, b"mutated-state"),
            Err(Error::DeviceError),
            "{}",
            case.name
        );

        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("relookup stable anchor");
        assert_eq!(read_all(&*anchor), b"stable-state", "{}", case.name);
        for warmup_path in &warmup_paths {
            assert!(
                volume.lookup(warmup_path).is_ok(),
                "{}: missing {warmup_path}",
                case.name
            );
        }

        let reopened = SimpleFs::open(device, true).expect("reopen stable simplefs");
        let volume = SimpleFsVolume::new(reopened);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup stable anchor after reopen");
        assert_eq!(read_all(&*anchor), b"stable-state", "{}", case.name);
        for warmup_path in &warmup_paths {
            assert!(
                volume.lookup(warmup_path).is_ok(),
                "{}: missing {warmup_path}",
                case.name
            );
        }
    }
}

#[test]
fn simplefs_metadata_fault_sequence_survives_repeated_shadow_slot_failures() {
    let device = build_stable_device();
    let layout = load_current_layout(&*device).expect("read current layout");
    let failing = FaultInjectingBlockDevice::new_sequence(
        device.clone(),
        vec![
            FaultPlan {
                target: fault_target_for_case(
                    MatrixStage::ShadowInodeTable,
                    layout,
                    device.block_count(),
                ),
                match_number: 1,
                mode: FaultMode::BeforeWrite,
            },
            FaultPlan {
                target: fault_target_for_case(
                    MatrixStage::ShadowInodeTable,
                    layout,
                    device.block_count(),
                ),
                match_number: 2,
                mode: FaultMode::TornWrite { prefix_len: 96 },
            },
        ],
    );

    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);
    let pending_path = "/pending-sequence";

    assert_eq!(
        volume.create_dir(pending_path),
        Err(Error::DeviceError),
        "first shadow-slot failure should abort metadata publish",
    );
    assert_stable_state(&volume, &[], pending_path, "shadow-sequence-first");

    assert_eq!(
        volume.create_dir(pending_path),
        Err(Error::DeviceError),
        "second shadow-slot failure should still preserve the last stable state",
    );
    assert_stable_state(&volume, &[], pending_path, "shadow-sequence-second");

    volume
        .create_dir(pending_path)
        .expect("third attempt should succeed after planned failures");
    assert!(volume.lookup(pending_path).is_ok());

    let reopened = SimpleFs::open(device, true).expect("reopen stable simplefs");
    let volume = SimpleFsVolume::new(reopened);
    assert!(volume.lookup(pending_path).is_ok());
}

#[test]
fn simplefs_fault_sequence_recovers_across_data_then_publish_failures() {
    let device = build_stable_device();
    let layout = load_current_layout(&*device).expect("read current layout");
    let failing = FaultInjectingBlockDevice::new_sequence(
        device.clone(),
        vec![
            FaultPlan {
                target: fault_target_for_case(
                    MatrixStage::DataRegion,
                    layout,
                    device.block_count(),
                ),
                match_number: 1,
                mode: FaultMode::TornWrite { prefix_len: 32 },
            },
            FaultPlan {
                target: fault_target_for_case(
                    MatrixStage::SecondarySuperblock,
                    layout,
                    device.block_count(),
                ),
                match_number: 1,
                mode: FaultMode::BeforeWrite,
            },
        ],
    );

    let fs = SimpleFs::open(failing, true).expect("open failing simplefs");
    let volume = SimpleFsVolume::new(fs);

    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup stable anchor");
    assert_eq!(
        anchor.write(0, b"mutated-state"),
        Err(Error::DeviceError),
        "data-stage failure should abort overwrite",
    );
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("relookup anchor after first failure");
    assert_eq!(read_all(&*anchor), b"stable-state");

    assert_eq!(
        anchor.write(0, b"mutated-state"),
        Err(Error::DeviceError),
        "publish-stage failure should also abort overwrite",
    );
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("relookup anchor after second failure");
    assert_eq!(read_all(&*anchor), b"stable-state");

    assert_eq!(
        anchor
            .write(0, b"mutated-state")
            .expect("third overwrite should succeed"),
        "mutated-state".len()
    );

    let reopened = SimpleFs::open(device, true).expect("reopen stable simplefs");
    let volume = SimpleFsVolume::new(reopened);
    let anchor = volume
        .lookup("/stable/anchor.txt")
        .expect("lookup mutated anchor after reopen");
    assert_eq!(read_all(&*anchor), b"mutated-state");
}
