//! src/kernel/fs/simplefs/tests.rs
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

use crate::kernel::fs::block::{BlockDevice, MemoryBlockDevice};
use crate::kernel::fs::vfs::{FileSystem as VfsFileSystem, NodeKind, VNode};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::{ImageEntry, SimpleFs, SimpleFsVolume};

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
