//! tests/simplefs/validation.rs
//!
//! Host-side integration tests for SimpleFs image validation and mutation
//! behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use protofire::kernel::fs::block::{BlockDevice, MemoryBlockDevice, BLOCK_SIZE};
use protofire::kernel::fs::simplefs::{ImageEntry, SimpleFs, SimpleFsVolume};
use protofire::kernel::fs::vfs::{FileSystem as VfsFileSystem, NodeKind, VNode};
use protofire::Error;

const INODE_SIZE: usize = 32;
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 56;

#[derive(Clone, Copy)]
enum WriteFailureMode {
    BeforeWrite,
    TornWrite { prefix_len: usize },
}

#[derive(Clone, Copy)]
struct WriteFailurePlan {
    call: usize,
    mode: WriteFailureMode,
}

struct WriteFailureState {
    call_count: usize,
    plan: Option<WriteFailurePlan>,
}

struct FailingBlockDevice {
    name: String,
    parent: Arc<MemoryBlockDevice>,
    state: Mutex<WriteFailureState>,
}

impl FailingBlockDevice {
    fn new(name: &str, parent: Arc<MemoryBlockDevice>) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            parent,
            state: Mutex::new(WriteFailureState {
                call_count: 0,
                plan: None,
            }),
        })
    }

    fn arm_failure(&self, call: usize, mode: WriteFailureMode) {
        let mut state = self.state.lock().expect("lock failing block device");
        state.call_count = 0;
        state.plan = Some(WriteFailurePlan { call, mode });
    }

    fn clear_failure(&self) {
        let mut state = self.state.lock().expect("lock failing block device");
        state.call_count = 0;
        state.plan = None;
    }

    fn apply_torn_write(&self, lba: u64, data: &[u8], prefix_len: usize) -> protofire::Result<()> {
        let mut mixed = vec![0_u8; data.len()];
        self.parent.read_blocks(lba, &mut mixed)?;
        let prefix_len = prefix_len.min(data.len());
        mixed[..prefix_len].copy_from_slice(&data[..prefix_len]);
        self.parent.write_blocks(lba, &mixed)
    }
}

impl BlockDevice for FailingBlockDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_count(&self) -> u64 {
        self.parent.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.parent.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> protofire::Result<()> {
        self.parent.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> protofire::Result<()> {
        let plan = {
            let mut state = self.state.lock().expect("lock failing block device");
            state.call_count += 1;
            match state.plan {
                Some(plan) if plan.call == state.call_count => {
                    state.plan = None;
                    Some(plan)
                }
                _ => None,
            }
        };

        match plan {
            Some(WriteFailurePlan {
                mode: WriteFailureMode::BeforeWrite,
                ..
            }) => Err(Error::DeviceError),
            Some(WriteFailurePlan {
                mode: WriteFailureMode::TornWrite { prefix_len },
                ..
            }) => {
                self.apply_torn_write(lba, data, prefix_len)?;
                Err(Error::DeviceError)
            }
            None => self.parent.write_blocks(lba, data),
        }
    }
}

fn writable_image(
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_data_blocks: usize,
) -> Vec<u8> {
    SimpleFs::build_image_with_headroom(
        "writable-simplefs",
        &[ImageEntry {
            path: "/seed.txt",
            data: b"seed",
        }],
        extra_inodes,
        extra_dir_entries,
        extra_data_blocks,
    )
    .expect("build writable simplefs image")
}

fn nested_image() -> Vec<u8> {
    SimpleFs::build_image(
        "nested-simplefs",
        &[ImageEntry {
            path: "/apps/demo.txt",
            data: b"nested",
        }],
    )
    .expect("build nested simplefs image")
}

fn valid_image() -> Vec<u8> {
    SimpleFs::build_image(
        "demo-simplefs",
        &[ImageEntry {
            path: "/README.txt",
            data: b"hello simplefs",
        }],
    )
    .expect("build valid simplefs image")
}

fn two_file_image() -> Vec<u8> {
    SimpleFs::build_image(
        "demo-simplefs-two",
        &[
            ImageEntry {
                path: "/A.txt",
                data: b"alpha",
            },
            ImageEntry {
                path: "/B.txt",
                data: b"beta",
            },
        ],
    )
    .expect("build two-file simplefs image")
}

fn read_u32_le(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().expect("u32 in bounds"))
}

fn inode_base(image: &[u8], index: usize) -> usize {
    read_u32_le(image, 24) as usize * BLOCK_SIZE + index * INODE_SIZE
}

fn dirent_base(image: &[u8], index: usize) -> usize {
    read_u32_le(image, 28) as usize * BLOCK_SIZE + index * 64
}

fn read_all(node: &dyn VNode) -> Vec<u8> {
    let mut buffer = vec![0_u8; node.size()];
    let count = node.read(0, &mut buffer).expect("read full node");
    buffer.truncate(count);
    buffer
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

fn ensure_dir(volume: &SimpleFsVolume, path: &str) {
    match volume.stat(path) {
        Ok(metadata) => assert_eq!(metadata.kind, NodeKind::Directory),
        Err(Error::NotFound) => volume.create_dir(path).expect("create missing directory"),
        Err(error) => panic!("stat {path} failed: {error:?}"),
    }
}

fn patterned_payload(cycle: usize, slot: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; BLOCK_SIZE + 29 + cycle * 13 + slot * 47];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = ((cycle * 31 + slot * 17 + index) % 251) as u8;
    }

    payload
}

fn superblock_base(block_index: usize) -> usize {
    block_index * BLOCK_SIZE
}

fn refresh_superblock_checksum(image: &mut [u8], block_index: usize) {
    let base = superblock_base(block_index);
    image[base + SUPERBLOCK_CHECKSUM_OFFSET..base + SUPERBLOCK_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&0_u32.to_le_bytes());
    let checksum = superblock_checksum(&image[base..base + BLOCK_SIZE]);
    image[base + SUPERBLOCK_CHECKSUM_OFFSET..base + SUPERBLOCK_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());
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

fn write_superblock_u32(image: &mut [u8], offset: usize, value: u32) {
    for block_index in 0..=1 {
        let base = superblock_base(block_index) + offset;
        image[base..base + 4].copy_from_slice(&value.to_le_bytes());
        refresh_superblock_checksum(image, block_index);
    }
}

#[test]
fn simplefs_open_accepts_valid_images() {
    let device = MemoryBlockDevice::new("simplefs", valid_image(), true);
    let fs = SimpleFs::open(device, true).expect("open valid simplefs image");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(volume.name(), "demo-simplefs");
    assert_eq!(volume.stat("/").expect("stat root").size, 1);
    assert_eq!(volume.stat("/README.txt").expect("stat file").size, 14);
}

#[test]
fn simplefs_open_rejects_inverted_inode_and_dirent_tables() {
    let mut image = valid_image();
    let inode_table_block = read_u32_le(&image, 24);
    write_superblock_u32(&mut image, 28, inode_table_block - 1);

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_data_block_before_dirent_table() {
    let mut image = valid_image();
    let dirent_table_block = read_u32_le(&image, 28);
    write_superblock_u32(&mut image, 32, dirent_table_block - 1);

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_directory_entry_ranges_past_table() {
    let mut image = valid_image();
    let root_inode = inode_base(&image, 0);
    image[root_inode + 8..root_inode + 12].copy_from_slice(&(2_u32).to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_file_sizes_larger_than_allocated_blocks() {
    let mut image = valid_image();
    let file_inode = inode_base(&image, 1);
    image[file_inode + 20..file_inode + 24]
        .copy_from_slice(&((BLOCK_SIZE as u32) + 1).to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_dir_entries_with_invalid_inode_indices() {
    let mut image = valid_image();
    let first_dirent = dirent_base(&image, 0);
    image[first_dirent..first_dirent + 4].copy_from_slice(&(99_u32).to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_read_dir_rejects_out_of_bounds_indices_even_with_following_dirents() {
    let device = MemoryBlockDevice::new("simplefs", nested_image(), true);
    let fs = SimpleFs::open(device, true).expect("open nested simplefs image");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(volume.read_dir("/", 0).expect("root entry 0").name, "apps");
    assert_eq!(volume.read_dir("/", 1), Err(Error::NotFound));
}

#[test]
fn simplefs_write_rejects_offsets_beyond_u32_file_size_limit() {
    let device = MemoryBlockDevice::new("simplefs", valid_image(), false);
    let fs = SimpleFs::open(device, true).expect("open writable simplefs image");
    let volume = SimpleFsVolume::new(fs);
    let node = volume.lookup("/README.txt").expect("lookup readme node");

    assert_eq!(
        node.write(u32::MAX as u64 + 1, b"x"),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn simplefs_set_len_rejects_lengths_beyond_u32_file_size_limit() {
    let device = MemoryBlockDevice::new("simplefs", valid_image(), false);
    let fs = SimpleFs::open(device, true).expect("open writable simplefs image");
    let volume = SimpleFsVolume::new(fs);
    let node = volume.lookup("/README.txt").expect("lookup readme node");

    assert_eq!(
        node.set_len(u32::MAX as u64 + 1),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn simplefs_open_rejects_overlapping_live_file_extents() {
    let mut image = two_file_image();
    let first_inode = inode_base(&image, 1);
    let second_inode = inode_base(&image, 2);
    let first_data_block = read_u32_le(&image, first_inode + 12);

    image[second_inode + 12..second_inode + 16].copy_from_slice(&first_data_block.to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_duplicate_names_within_a_directory() {
    let mut image = two_file_image();
    let second_dirent = dirent_base(&image, 1);
    image[second_dirent + 8] = b'A';

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_case_colliding_names_when_case_insensitive() {
    let mut image = two_file_image();
    let second_dirent = dirent_base(&image, 1);
    image[second_dirent + 8] = b'a';

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, false),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_allows_case_colliding_names_when_case_sensitive() {
    let mut image = two_file_image();
    let second_dirent = dirent_base(&image, 1);
    image[second_dirent + 8] = b'a';

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(SimpleFs::open(device, true).is_ok());
}

#[test]
fn simplefs_open_rejects_directory_entries_pointing_to_root_inode() {
    let mut image = valid_image();
    let first_dirent = dirent_base(&image, 0);
    image[first_dirent..first_dirent + 4].copy_from_slice(&(0_u32).to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_multiple_parents_for_the_same_live_inode() {
    let mut image = two_file_image();
    let second_dirent = dirent_base(&image, 1);
    image[second_dirent..second_dirent + 4].copy_from_slice(&(1_u32).to_le_bytes());

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_directory_entry_kind_mismatch_with_target_inode() {
    let mut image = valid_image();
    let first_dirent = dirent_base(&image, 0);
    image[first_dirent + 4] = 1;

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_reopen_after_creating_directory_preserves_dir_entry_kind() {
    let device = MemoryBlockDevice::new("simplefs", valid_image(), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/state").expect("create state directory");
    }

    let reopened = SimpleFs::open(device, true).expect("reopen after metadata flush");
    let volume = SimpleFsVolume::new(reopened);
    let state = volume.stat("/state").expect("stat created directory");
    assert_eq!(state.kind, NodeKind::Directory);
}

#[test]
fn simplefs_reuses_deleted_inode_slots_for_repeated_file_churn() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(0, 0, 8), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume
            .create_dir("/scratch")
            .expect("create scratch directory");

        for cycle in 0..32 {
            let node = volume
                .create_file("/scratch/session.bin")
                .expect("create churn file");
            let payload = format!("cycle-{cycle:02}");
            assert_eq!(
                node.write(0, payload.as_bytes())
                    .expect("write churn payload"),
                payload.len()
            );
            volume
                .remove_path("/scratch/session.bin")
                .expect("remove churn file");
        }

        let node = volume
            .create_file("/scratch/final.bin")
            .expect("create final file");
        assert_eq!(node.write(0, b"final").expect("write final payload"), 5);
    }

    let reopened = SimpleFs::open(device, true).expect("reopen churned simplefs image");
    let volume = SimpleFsVolume::new(reopened);
    assert_eq!(volume.stat("/scratch").expect("stat scratch").size, 1);
    let node = volume
        .lookup("/scratch/final.bin")
        .expect("lookup final churn file");
    assert_eq!(read_all(&*node), b"final");
}

#[test]
fn simplefs_reuses_deleted_inode_slots_for_repeated_directory_churn() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(0, 0, 4), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume
            .create_dir("/scratch")
            .expect("create scratch directory");

        for _cycle in 0..32 {
            volume
                .create_dir("/scratch/session")
                .expect("create churn directory");
            volume
                .remove_path("/scratch/session")
                .expect("remove churn directory");
        }

        volume
            .create_dir("/scratch/final")
            .expect("create final directory");
    }

    let reopened = SimpleFs::open(device, true).expect("reopen churned simplefs image");
    let volume = SimpleFsVolume::new(reopened);
    assert_eq!(volume.stat("/scratch").expect("stat scratch").size, 1);
    assert_eq!(
        volume
            .stat("/scratch/final")
            .expect("stat final directory")
            .kind,
        NodeKind::Directory
    );
}

#[test]
fn simplefs_open_uses_secondary_superblock_when_primary_is_corrupted() {
    let mut image = valid_image();
    image[0] = 0;

    let device = MemoryBlockDevice::new("simplefs", image, true);
    let fs = SimpleFs::open(device, true).expect("open image with mirrored fallback");
    let volume = SimpleFsVolume::new(fs);
    assert_eq!(
        volume.stat("/README.txt").expect("stat mirrored file").size,
        14
    );
}

#[test]
fn simplefs_open_rejects_dirent_slots_not_owned_by_any_live_directory() {
    let mut image = two_file_image();
    let root_inode = inode_base(&image, 0);
    image[root_inode + 8..root_inode + 12].copy_from_slice(&(1_u32).to_le_bytes());

    let first_dirent = dirent_base(&image, 0);
    let second_dirent = dirent_base(&image, 1);
    image[first_dirent..first_dirent + 4].copy_from_slice(&(2_u32).to_le_bytes());
    image[second_dirent..second_dirent + 4].copy_from_slice(&(1_u32).to_le_bytes());

    assert!(matches!(
        SimpleFs::open(MemoryBlockDevice::new("simplefs", image, true), true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_reopen_preserves_large_directory_mutations() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(96, 128, 64), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
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

    let reopened = SimpleFs::open(device, true).expect("reopen writable simplefs image");
    let volume = SimpleFsVolume::new(reopened);
    let mut names = collect_dir_names(&volume, "/bulk");
    names.sort();

    assert_eq!(volume.stat("/bulk").expect("stat bulk directory").size, 39);
    assert!(!names.iter().any(|name| name == "item07.txt"));
    assert!(names.iter().any(|name| name == "renamed11.txt"));

    let renamed = volume
        .lookup("/bulk/renamed11.txt")
        .expect("lookup renamed file");
    assert_eq!(read_all(&*renamed), b"payload-11");
}

#[test]
fn simplefs_reopen_preserves_cross_directory_renames() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(32, 48, 8), false);
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/left").expect("create left");
        volume.create_dir("/right").expect("create right");
        volume.create_dir("/archive").expect("create archive");

        let payload = b"cross-directory-payload";
        let node = volume
            .create_file("/left/payload.bin")
            .expect("create payload file");
        node.write(0, payload).expect("write payload");
        volume
            .rename("/left/payload.bin", "/right/payload.bin")
            .expect("rename into right");
        volume
            .rename("/right/payload.bin", "/archive/final.bin")
            .expect("rename into archive");
    }

    let reopened = SimpleFs::open(device, true).expect("reopen renamed simplefs image");
    let volume = SimpleFsVolume::new(reopened);
    assert!(matches!(
        volume.lookup("/left/payload.bin"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        volume.lookup("/right/payload.bin"),
        Err(Error::NotFound)
    ));
    let node = volume
        .lookup("/archive/final.bin")
        .expect("lookup final payload");
    assert_eq!(read_all(&*node), b"cross-directory-payload");
}

#[test]
fn simplefs_reopen_preserves_long_file_truncate_and_regrow_zero_fill() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(16, 16, 24), false);
    let mut original = vec![0_u8; BLOCK_SIZE * 3 + 137];
    for (index, byte) in original.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume.create_dir("/logs").expect("create logs directory");
        let node = volume
            .create_file("/logs/big.bin")
            .expect("create large file");
        assert_eq!(
            node.write(0, &original).expect("write large file"),
            original.len()
        );
    }

    {
        let reopened = SimpleFs::open(device.clone(), true).expect("reopen after write");
        let volume = SimpleFsVolume::new(reopened);
        let node = volume.lookup("/logs/big.bin").expect("lookup large file");
        assert_eq!(read_all(&*node), original);
        node.set_len((BLOCK_SIZE + 29) as u64)
            .expect("truncate large file");
        node.set_len((BLOCK_SIZE * 2 + 73) as u64)
            .expect("regrow large file");
    }

    let reopened = SimpleFs::open(device, true).expect("reopen after regrow");
    let volume = SimpleFsVolume::new(reopened);
    let node = volume.lookup("/logs/big.bin").expect("lookup regrown file");
    let bytes = read_all(&*node);
    let retained_len = BLOCK_SIZE + 29;

    assert_eq!(bytes.len(), BLOCK_SIZE * 2 + 73);
    assert_eq!(&bytes[..retained_len], &original[..retained_len]);
    assert!(bytes[retained_len..].iter().all(|byte| *byte == 0));
}

#[test]
fn simplefs_open_rejects_unknown_inode_kind_values() {
    let mut image = valid_image();
    let file_inode = inode_base(&image, 1);
    image[file_inode] = 0xff;

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_open_rejects_unknown_directory_entry_kind_values() {
    let mut image = valid_image();
    let first_dirent = dirent_base(&image, 0);
    image[first_dirent + 4] = 0xff;

    let device = MemoryBlockDevice::new("simplefs", image, true);
    assert!(matches!(
        SimpleFs::open(device, true),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn simplefs_reopen_after_failed_metadata_commit_keeps_last_stable_state() {
    let backing = MemoryBlockDevice::new("simplefs", writable_image(48, 64, 16), false);
    {
        let fs = SimpleFs::open(backing.clone(), true).expect("open writable simplefs image");
        let volume = SimpleFsVolume::new(fs);
        volume
            .create_dir("/stable")
            .expect("create stable directory");
        let node = volume
            .create_file("/stable/anchor.txt")
            .expect("create anchor file");
        assert_eq!(node.write(0, b"stable-state").expect("write anchor"), 12);
    }

    let failing = FailingBlockDevice::new("simplefs-failing", backing.clone());
    let failure_cases = [
        ("inode-table", 1, WriteFailureMode::BeforeWrite),
        (
            "dirent-table",
            2,
            WriteFailureMode::TornWrite {
                prefix_len: BLOCK_SIZE,
            },
        ),
        (
            "secondary-superblock",
            3,
            WriteFailureMode::TornWrite {
                prefix_len: SUPERBLOCK_CHECKSUM_OFFSET,
            },
        ),
    ];

    for (label, call, mode) in failure_cases {
        let pending = format!("/pending-{label}");
        failing.arm_failure(call, mode);

        {
            let fs = SimpleFs::open(failing.clone(), true).expect("open with injected device");
            let volume = SimpleFsVolume::new(fs);
            assert_eq!(
                volume.create_dir(&pending),
                Err(Error::DeviceError),
                "metadata failure case {label} should abort the mutation",
            );
        }

        failing.clear_failure();

        let reopened = SimpleFs::open(backing.clone(), true)
            .expect("reopen after interrupted metadata commit");
        let volume = SimpleFsVolume::new(reopened);
        let anchor = volume
            .lookup("/stable/anchor.txt")
            .expect("lookup previously committed anchor");
        assert_eq!(
            read_all(&*anchor),
            b"stable-state",
            "stable file contents changed after {label} failure",
        );
        assert!(matches!(volume.lookup(&pending), Err(Error::NotFound),));
        assert_eq!(
            volume
                .stat("/")
                .expect("stat root after failed commit")
                .size,
            2,
            "root entry count changed after {label} failure",
        );
    }
}

#[test]
fn simplefs_long_mutation_sequence_survives_reopen_cycles() {
    let device = MemoryBlockDevice::new("simplefs", writable_image(192, 384, 192), false);
    let mut expected_files = BTreeMap::<String, Vec<u8>>::new();
    let mut removed_paths = BTreeSet::<String>::new();

    for cycle in 0..12 {
        {
            let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs image");
            let volume = SimpleFsVolume::new(fs);
            ensure_dir(&volume, "/staging");
            ensure_dir(&volume, "/archive");
            ensure_dir(&volume, "/history");

            for slot in 0..3 {
                let staged = format!("/staging/c{cycle:02}-s{slot:02}.bin");
                let final_dir = if (cycle + slot) % 2 == 0 {
                    "/archive"
                } else {
                    "/history"
                };
                let final_path = format!("{final_dir}/c{cycle:02}-s{slot:02}.bin");
                let payload = patterned_payload(cycle, slot);

                let node = volume.create_file(&staged).expect("create staged file");
                assert_eq!(
                    node.write(0, &payload).expect("write staged payload"),
                    payload.len()
                );
                volume
                    .rename(&staged, &final_path)
                    .expect("publish staged file");
                expected_files.insert(final_path, payload);
            }

            if cycle >= 2 {
                let retired_cycle = cycle - 2;
                let retired_slot = cycle % 3;
                let retired_dir = if (retired_cycle + retired_slot) % 2 == 0 {
                    "/archive"
                } else {
                    "/history"
                };
                let retired_path =
                    format!("{retired_dir}/c{retired_cycle:02}-s{retired_slot:02}.bin");

                if expected_files.remove(&retired_path).is_some() {
                    volume
                        .remove_path(&retired_path)
                        .expect("remove retired file");
                    removed_paths.insert(retired_path);
                }
            }
        }

        let reopened = SimpleFs::open(device.clone(), true).expect("reopen after mutation cycle");
        let volume = SimpleFsVolume::new(reopened);
        let mut staging_entries = collect_dir_names(&volume, "/staging");
        staging_entries.sort();

        assert!(
            staging_entries.is_empty(),
            "staging directory leaked entries after cycle {cycle}: {staging_entries:?}",
        );
        assert_eq!(
            volume.stat("/archive").expect("stat archive").size
                + volume.stat("/history").expect("stat history").size,
            expected_files.len(),
            "published file count drifted after cycle {cycle}",
        );

        for (path, payload) in &expected_files {
            let node = volume.lookup(path).unwrap_or_else(|error| {
                panic!("lookup {path} failed after cycle {cycle}: {error:?}")
            });
            assert_eq!(
                read_all(&*node),
                *payload,
                "payload drifted for {path} after cycle {cycle}",
            );
        }

        for path in &removed_paths {
            assert!(
                matches!(volume.lookup(path), Err(Error::NotFound)),
                "removed path {path} reappeared after cycle {cycle}",
            );
        }
    }
}

#[test]
fn simplefs_repeated_metadata_and_data_reads_return_consistent_data() {
    let image = SimpleFs::build_image(
        "cache-consistency",
        &[ImageEntry {
            path: "/docs/readme.txt",
            data: b"Cache consistency payload.",
        }],
    )
    .expect("build test image");
    let device = MemoryBlockDevice::new("cache-consistency-dev", image, true);
    let fs = SimpleFs::open(device, true).expect("open SimpleFs");
    let volume = SimpleFsVolume::new(fs);

    // First stat and read.
    let stat1 = volume.stat("/docs/readme.txt").expect("stat 1");
    let node1 = volume.lookup("/docs/readme.txt").expect("lookup 1");
    let data1 = read_all(&*node1);

    // Second stat and read — cache must serve consistent data.
    let stat2 = volume.stat("/docs/readme.txt").expect("stat 2");
    let node2 = volume.lookup("/docs/readme.txt").expect("lookup 2");
    let data2 = read_all(&*node2);

    assert_eq!(stat2.kind, stat1.kind);
    assert_eq!(stat2.size, stat1.size);
    assert_eq!(data2, data1);
    assert_eq!(data1, b"Cache consistency payload.");

    // Directory listing must also survive repeated reads through the cache.
    let mut entries_a = Vec::new();
    let mut idx = 0;
    while let Ok(entry) = volume.read_dir("/docs", idx) {
        entries_a.push(entry.name.clone());
        idx += 1;
    }

    let mut entries_b = Vec::new();
    let mut idx = 0;
    while let Ok(entry) = volume.read_dir("/docs", idx) {
        entries_b.push(entry.name.clone());
        idx += 1;
    }

    assert_eq!(entries_b, entries_a);
    assert!(entries_a.contains(&"readme.txt".to_string()));
}

#[test]
fn simplefs_data_checksum_survives_write_and_reopen() {
    let image = SimpleFs::build_image_with_headroom(
        "checksum-survive",
        &[ImageEntry {
            path: "/docs/readme.txt",
            data: b"before-checksum",
        }],
        4, // extra inodes
        8, // extra dirents
        8, // extra data blocks — needed for content-replace allocation
    )
    .expect("build test image");
    let device = MemoryBlockDevice::new("checksum-survive-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs);

    let node = volume.lookup("/docs/readme.txt").expect("lookup");
    node.write(0, b"after-checksum-write")
        .expect("write new content");
    assert_eq!(read_all(&*node), b"after-checksum-write");

    // Reopen and verify content is readable (checksum was persisted).
    drop(volume);
    drop(node);
    let reopened = SimpleFs::open(device, true).expect("reopen simplefs");
    let volume = SimpleFsVolume::new(reopened);
    let node = volume.lookup("/docs/readme.txt").expect("relookup");
    assert_eq!(read_all(&*node), b"after-checksum-write");
}

#[test]
fn simplefs_device_health_reports_healthy_for_memory_backed_volume() {
    use protofire::kernel::fs::block::DeviceHealth;

    let image = SimpleFs::build_image(
        "health-check",
        &[ImageEntry {
            path: "/README.txt",
            data: b"health check",
        }],
    )
    .expect("build test image");
    let device = MemoryBlockDevice::new("health-check-dev", image, true);
    let fs = SimpleFs::open(device, true).expect("open simplefs");
    let volume = SimpleFsVolume::new(fs);

    assert_eq!(volume.device_health(), DeviceHealth::Healthy);
}
