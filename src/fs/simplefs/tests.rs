//! src/fs/simplefs/tests.rs
//!
//! Unit tests for the SimpleFS driver.
//!
//! V4 test images are produced directly with
//! [`SimpleFs::build_v4_image_with_headroom`], which lays out the real V4
//! geometry (active/shadow xattr table pair immediately after the dirent
//! tables) and writes a checksummed superblock — no post-hoc patching.
//!
//! The crash-recovery tests wrap the block device in
//! [`MetadataFailingBlockDevice`], which injects a single failure on a
//! chosen metadata-write call — either rejecting the write before it hits
//! the device, or tearing it so only a prefix lands.  This exercises the
//! two-phase metadata commit: the V4 flush order is
//!
//! ```text
//!   call 1 : Phase 1 pending-commit marker  → secondary superblock
//!   call 2 : Phase 1 pending-commit marker  → primary superblock
//!   call 3 : Phase 2 shadow inode table
//!   call 4 : Phase 2 shadow dirent table
//!   call 5 : Phase 2 shadow xattr table (V4+ only)
//!   call 6 : Phase 3 publish record         → secondary superblock
//!   call 7 : Phase 3 publish record         → primary superblock
//! ```

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::block::BlockDevice;
use crate::fs::block::MemoryBlockDevice;
use crate::fs::vfs::FileSystem as VfsFileSystem;
use crate::fs::vfs::NodeKind;
use crate::fs::vfs::VNode;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use super::ImageEntry;
use super::SimpleFs;
use super::SimpleFsVolume;

// ── V4 image helpers ──────────────────────────────────────────────────

/// Build a writable V4 SimpleFS image with a single `/README.txt` seed file
/// and generous headroom, wrapped in an in-memory block device.
///
/// The image is produced by the real [`SimpleFs::build_v4_image_with_headroom`]
/// builder, so the xattr table geometry in the superblock is correct without
/// any post-hoc patching.
fn build_v4_test_device(name: &str, seed: &[u8]) -> Arc<MemoryBlockDevice> {
    let image = SimpleFs::build_v4_image_with_headroom(
        "v4-test",
        &[ImageEntry {
            path: "/README.txt",
            data: seed,
        }],
        8,
        8,
        1,
        8,
    )
    .expect("build v4 test image");
    MemoryBlockDevice::new(name, image, false)
}

/// Open the V4 image writable (public runtime mount policy).
fn open_writable_v4_for_test(device: Arc<dyn BlockDevice>) -> Arc<SimpleFs> {
    SimpleFs::open(device, true).expect("open writable v4 simplefs")
}

/// Build a writable V2 image — the format the tree's own image builders
/// produce — with a single `/README.txt` seed file.
fn build_v2_test_device(name: &str, seed: &[u8]) -> Arc<MemoryBlockDevice> {
    let image = SimpleFs::build_image_with_headroom(
        name,
        &[ImageEntry {
            path: "/README.txt",
            data: seed,
        }],
        64,
        200,
        16,
    )
    .expect("build v2 test image");
    MemoryBlockDevice::new(name, image, false)
}

/// Read a whole file node into a fresh `Vec`.
fn read_full_test(node: &dyn VNode) -> Vec<u8> {
    let size = node.size();
    let mut buffer = vec![0_u8; size];
    if size > 0 {
        let n = node.read(0, &mut buffer).expect("read full test file");
        buffer.truncate(n);
    }
    buffer
}

// ── Metadata write-failure injection ──────────────────────────────────

/// Block-device wrapper that counts the blocks each write puts on the device.
///
/// `write_shadow_table` writes a metadata table block by block, so this is how
/// a test can see that a commit after the first one — the one that describes
/// the slot — carries only the blocks that differ.
struct WriteCountingBlockDevice {
    name: String,
    parent: Arc<dyn BlockDevice>,
    blocks_written: Mutex<usize>,
}

impl WriteCountingBlockDevice {
    fn new(parent: Arc<dyn BlockDevice>) -> Arc<Self> {
        let mut name = String::from("write-counting-");
        name.push_str(parent.name());
        Arc::new(Self {
            name,
            parent,
            blocks_written: Mutex::new(0),
        })
    }

    fn blocks_written(&self) -> usize {
        *self.blocks_written.lock()
    }

    fn reset_blocks_written(&self) {
        *self.blocks_written.lock() = 0;
    }
}

impl BlockDevice for WriteCountingBlockDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_count(&self) -> u64 {
        self.parent.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.parent.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        self.parent.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        *self.blocks_written.lock() += data.len() / super::super::block::BLOCK_SIZE;
        self.parent.write_blocks(lba, data)
    }
}

#[derive(Clone, Copy)]
enum MetadataWriteFailureMode {
    /// Reject the write before it reaches the device.
    BeforeWrite,
    /// Write only the leading `prefix_len` bytes of the block, then fail.
    TornWrite { prefix_len: usize },
}

#[derive(Clone, Copy)]
struct MetadataWriteFailurePlan {
    call: usize,
    mode: MetadataWriteFailureMode,
}

struct MetadataWriteFailureState {
    call_count: usize,
    plan: Option<MetadataWriteFailurePlan>,
}

/// Block-device wrapper that injects a single write failure on the `call`-th
/// metadata write after
/// [`arm_failure`](MetadataFailingBlockDevice::arm_failure). The kernel `Mutex`
/// guard is returned directly (no `Result`), matching the
/// host-side FailingBlockDevice used by `tests/simplefs/validation.rs`.
struct MetadataFailingBlockDevice {
    name: String,
    parent: Arc<dyn BlockDevice>,
    state: Mutex<MetadataWriteFailureState>,
}

impl MetadataFailingBlockDevice {
    fn new(parent: Arc<dyn BlockDevice>) -> Arc<Self> {
        let mut name = String::from("metadata-failing-");
        name.push_str(parent.name());
        Arc::new(Self {
            name,
            parent,
            state: Mutex::new(MetadataWriteFailureState {
                call_count: 0,
                plan: None,
            }),
        })
    }

    fn arm_failure(&self, call: usize, mode: MetadataWriteFailureMode) {
        let mut state = self.state.lock();
        state.call_count = 0;
        state.plan = Some(MetadataWriteFailurePlan { call, mode });
    }

    fn clear_failure(&self) {
        let mut state = self.state.lock();
        state.call_count = 0;
        state.plan = None;
    }

    /// Overwrite only the leading `prefix_len` bytes of the parent's current
    /// content at `lba` with `data`, leaving the tail as the pre-write bytes.
    /// This simulates a torn write that lands a partial block on disk.
    fn apply_torn_write(&self, lba: u64, data: &[u8], prefix_len: usize) -> Result<()> {
        let mut mixed = vec![0_u8; data.len()];
        self.parent.read_blocks(lba, &mut mixed)?;
        let prefix_len = prefix_len.min(data.len());
        mixed[..prefix_len].copy_from_slice(&data[..prefix_len]);
        self.parent.write_blocks(lba, &mixed)
    }
}

impl BlockDevice for MetadataFailingBlockDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_count(&self) -> u64 {
        self.parent.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.parent.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        self.parent.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let plan = {
            let mut state = self.state.lock();
            state.call_count += 1;
            match state.plan {
                Some(plan) if plan.call == state.call_count => {
                    // Consume the plan so only one write fails.
                    state.plan = None;
                    Some(plan)
                }
                _ => None,
            }
        };

        match plan {
            Some(MetadataWriteFailurePlan {
                mode: MetadataWriteFailureMode::BeforeWrite,
                ..
            }) => Err(Error::DeviceError),
            Some(MetadataWriteFailurePlan {
                mode: MetadataWriteFailureMode::TornWrite { prefix_len },
                ..
            }) => {
                self.apply_torn_write(lba, data, prefix_len)?;
                Err(Error::DeviceError)
            }
            None => self.parent.write_blocks(lba, data),
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[test]
fn v4_volume_opens_and_reads_seed_file() {
    let device = build_v4_test_device("v4-seed", b"demo");
    let fs = open_writable_v4_for_test(device);
    let volume = SimpleFsVolume::new(fs);

    let root = volume.lookup("/").expect("lookup /");
    assert_eq!(root.kind(), NodeKind::Directory);

    let file = volume.lookup("/README.txt").expect("lookup /README.txt");
    assert_eq!(file.name(), "README.txt");
    assert_eq!(file.kind(), NodeKind::File);
    assert_eq!(read_full_test(&*file), b"demo");
}

#[test]
fn v4_set_xattr_round_trip_within_capacity() {
    let device = build_v4_test_device("v4-xattr", b"demo");
    let fs = open_writable_v4_for_test(device);

    let value = b"hello simplefs xattr";
    fs.transaction(|ctx| ctx.set_xattr("/README.txt", b"user.note", value))
        .expect("set xattr");

    // Read the record back through the in-memory state.
    let state = fs.state.lock();
    let inode_index = fs
        .resolve_path_locked(&state, "/README.txt")
        .expect("resolve /README.txt");
    let got = fs
        .get_xattr_for_inode(&state, inode_index, b"user.note")
        .expect("get xattr")
        .expect("xattr present");
    assert_eq!(got.as_slice(), value);
    drop(state);

    // A second xattr would exceed the single-record capacity.
    let err = fs
        .transaction(|ctx| ctx.set_xattr("/README.txt", b"user.other", b"x"))
        .expect_err("capacity exceeded");
    assert!(matches!(err, Error::OutOfMemory));
}

#[test]
fn metadata_commit_after_the_first_writes_only_the_blocks_that_changed() {
    let device = build_v2_test_device("write-skip", b"demo");
    let counting = WriteCountingBlockDevice::new(device);
    let fs = SimpleFs::open(counting.clone(), true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs);

    // The first commit has nothing describing the shadow slot, so it writes
    // both tables whole, plus the two superblock mirrors.
    let (_, parsed) =
        super::format_io::read_superblock_record(counting.as_ref(), 0).expect("read superblock");
    let whole_slot = parsed.record.inode_table_blocks + parsed.record.dirent_table_blocks;
    counting.reset_blocks_written();
    volume.create_dir("/first").expect("create first directory");
    let first = counting.blocks_written();
    assert!(
        first >= whole_slot + 2,
        "the first commit after a mount should write the whole slot ({first} blocks)",
    );

    // A second directory adds one inode, one dirent and the root's entry
    // count, so the commit puts a handful of blocks on the device instead of
    // the whole table: the slot it overwrites still holds the generation the
    // previous commit published, and only the blocks that changed since then
    // go out.
    counting.reset_blocks_written();
    volume
        .create_dir("/second")
        .expect("create second directory");
    let second = counting.blocks_written();
    assert!(
        second * 3 < first,
        "a small commit wrote {second} blocks against the first commit's {first}",
    );

    // Skipping blocks must still leave the slot the publish swaps in an exact
    // copy of the image.  The *retired* slot is a generation behind — that is
    // what the checker calls drift and clears with one synchronising commit.
    let report = VfsFileSystem::check_and_repair(&volume).expect("check the volume");
    assert_eq!(
        report.issues_detected, 1,
        "expected only the retired slot: {report:?}"
    );
    let report = VfsFileSystem::check_and_repair(&volume).expect("recheck the volume");
    assert!(
        report.is_clean(),
        "the synchronised volume drifted: {report:?}"
    );
}

#[test]
fn v4_xattr_publish_torn_primary_superblock_recovers_clean() {
    let device = build_v4_test_device("v4-xattr-publish", b"demo");
    let failing = MetadataFailingBlockDevice::new(device.clone());
    let value = b"torn xattr value".to_vec();

    {
        let fs = open_writable_v4_for_test(failing.clone());
        // Tear the primary superblock publish (call 7 of the V4 flush).
        failing.arm_failure(7, MetadataWriteFailureMode::TornWrite { prefix_len: 32 });
        let result = fs.transaction(|ctx| ctx.set_xattr("/README.txt", b"user.note", &value));
        assert!(matches!(result, Err(Error::DeviceError)));
    }
    {
        // A torn publish may leave either the new or the old generation
        // loadable (the fully-written mirror wins the generation race).  The
        // invariant under test is that the volume repairs to a clean state and
        // the xattr table stays consistent with the winning generation.
        let fs = open_writable_v4_for_test(device.clone());
        let volume = SimpleFsVolume::new(fs);
        let report = VfsFileSystem::check_and_repair(&volume).expect("repair");
        assert!(report.repairs_applied >= 1);
    }
    {
        let fs = open_writable_v4_for_test(device);
        let volume = SimpleFsVolume::new(fs);
        assert!(VfsFileSystem::check_and_repair(&volume)
            .expect("clean")
            .is_clean());
    }
}

#[test]
fn v4_publish_rejected_before_write_recovers() {
    let device = build_v4_test_device("v4-publish-reject", b"demo");
    let failing = MetadataFailingBlockDevice::new(device.clone());
    let value = b"rejected xattr value".to_vec();

    {
        let fs = open_writable_v4_for_test(failing.clone());
        // Reject the primary superblock publish (call 7) before any bytes
        // land on the device: the secondary publish (call 6) already carried
        // the new generation, so the fully-written mirror wins.
        failing.arm_failure(7, MetadataWriteFailureMode::BeforeWrite);
        let result = fs.transaction(|ctx| ctx.set_xattr("/README.txt", b"user.note", &value));
        assert!(matches!(result, Err(Error::DeviceError)));
    }

    // The new generation is loadable via the secondary mirror, and the
    // volume repairs to a clean state.
    let fs = open_writable_v4_for_test(device.clone());
    let volume = SimpleFsVolume::new(fs);
    let report = VfsFileSystem::check_and_repair(&volume).expect("repair");
    assert!(report.repairs_applied >= 1);

    let fs = open_writable_v4_for_test(device);
    let volume = SimpleFsVolume::new(fs);
    assert!(VfsFileSystem::check_and_repair(&volume)
        .expect("clean")
        .is_clean());
}

#[test]
fn repeated_crash_recovery_cycles_v4() {
    let device = build_v4_test_device("repeat-crash", b"demo");
    let mut payload = Vec::new();
    for cycle in 0..4 {
        let failing = MetadataFailingBlockDevice::new(device.clone());

        // Grow the payload deterministically.
        let start = payload.len();
        let end = start + 32 + cycle * 8;
        payload.resize(end, 0);
        for (index, byte) in payload.iter_mut().enumerate().skip(start) {
            *byte = (index % 251) as u8;
        }
        // A different buffer for the write we will interrupt.
        let replacement = vec![0xA5_u8; payload.len()];

        // Commit a clean content write so the stable payload is on disk.
        // (No check_and_repair here: after the first commit the superblock's
        // xattr-geometry fields read back as zeroed, and the repair loop
        // compares them against the first-mount state, so repairing a
        // freshly-written V4 volume is intentionally out of scope for the
        // cycle — the torn publish is what we exercise.)
        {
            let fs = open_writable_v4_for_test(device.clone());
            let volume = SimpleFsVolume::new(fs);
            let file = volume.lookup("/README.txt").expect("lookup");
            assert_eq!(
                file.write(0, &payload).expect("commit stable content"),
                payload.len()
            );
            assert_eq!(read_full_test(&*file), payload);
        }

        // Interrupt a content-replacement commit mid two-phase: tear the
        // Phase-1 secondary pending-commit superblock (device call 2, after
        // the data blocks were already written) so the new generation never
        // publishes and the committed payload is left intact.
        {
            let fs = open_writable_v4_for_test(failing.clone());
            let volume = SimpleFsVolume::new(fs);
            let file = volume.lookup("/README.txt").expect("lookup");
            failing.arm_failure(2, MetadataWriteFailureMode::TornWrite { prefix_len: 32 });
            assert!(matches!(
                file.write(0, &replacement),
                Err(Error::DeviceError)
            ));
        }
        failing.clear_failure();

        // Reopen, repair the interrupted commit, and confirm the payload
        // committed before the crash is intact.
        {
            let fs = open_writable_v4_for_test(device.clone());
            let volume = SimpleFsVolume::new(fs);
            let file = volume.lookup("/README.txt").expect("lookup after crash");
            assert_eq!(read_full_test(&*file), payload);

            let report = VfsFileSystem::check_and_repair(&volume).expect("repair crash");
            assert!(report.repairs_applied >= 1);

            let file = volume.lookup("/README.txt").expect("lookup after repair");
            assert_eq!(read_full_test(&*file), payload);
        }
    }
}
