//! tests/simplefs/support/mod.rs
//!
//! Shared helpers for the SimpleFs integration-test suites.

use std::sync::Arc;
use std::sync::Mutex;

use protofire::kernel::fs::block::BlockDevice;
use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::simplefs::ImageEntry;
use protofire::kernel::fs::simplefs::SimpleFs;
use protofire::kernel::fs::simplefs::SimpleFsVolume;
use protofire::kernel::fs::vfs::FileSystem as VfsFileSystem;
use protofire::kernel::fs::vfs::VNode;
use protofire::Error;
use protofire::Result;

pub fn read_all(node: &dyn VNode) -> Vec<u8> {
    let mut buffer = vec![0_u8; node.size()];
    let count = node.read(0, &mut buffer).expect("read node");
    buffer.truncate(count);
    buffer
}

// `read_u32_le` / `build_stable_anchor_device` are used by the recovery and
// fault-matrix suites but not by every consumer of this module; each test
// binary is a separate crate, so unused helpers trip dead_code in binaries
// that only need `build_seed_image`/`read_all`.  The same applies to
// `build_v4_seed_image`, which only the undo-log property suite uses.
#[allow(dead_code)]
pub fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 in bounds"))
}

pub fn build_seed_image(
    label: &str,
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_data_blocks: usize,
) -> Vec<u8> {
    SimpleFs::build_image_with_headroom(
        label,
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

/// V4 seed image (persistent xattr table) — needed by suites that exercise
/// xattr set/rollback, which V2 images cannot express.
#[allow(dead_code)]
pub fn build_v4_seed_image(
    label: &str,
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_xattrs: usize,
    extra_data_blocks: usize,
) -> Vec<u8> {
    SimpleFs::build_v4_image_with_headroom(
        label,
        &[ImageEntry {
            path: "/seed.txt",
            data: b"seed",
        }],
        extra_inodes,
        extra_dir_entries,
        extra_xattrs,
        extra_data_blocks,
    )
    .expect("build writable v4 simplefs image")
}

#[allow(dead_code)]
pub fn build_stable_anchor_device(
    device_name: &str,
    fs_label: &str,
    extra_inodes: usize,
    extra_dir_entries: usize,
    extra_data_blocks: usize,
) -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new(
        device_name,
        build_seed_image(fs_label, extra_inodes, extra_dir_entries, extra_data_blocks),
        false,
    );
    {
        let fs = SimpleFs::open(device.clone(), true).expect("open writable simplefs");
        let volume = SimpleFsVolume::new(fs);
        volume
            .create_dir("/stable")
            .expect("create stable directory");
        let anchor = volume
            .create_file("/stable/anchor.txt")
            .expect("create stable anchor");
        anchor
            .write(0, b"stable-state")
            .expect("write stable anchor");
    }
    device
}

/// How a [`FaultingBlockDevice`] fails the target device write.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum FaultMode {
    /// Fail the write without touching the device at all.
    BeforeWrite,
    /// Write only a prefix of the block, then fail — simulating a torn block
    /// landing on disk.
    TornWrite { prefix_len: usize },
}

/// A block device that fails exactly one device write (the `fault_write`-th
/// since construction), either before writing or after tearing it.  This is
/// the shared crash-injection primitive for the SimpleFs test suites,
/// mirroring the private devices in recovery.rs / fault_matrix.rs so the
/// undo-log property suite can drive the same crash points.
#[allow(dead_code)]
pub struct FaultingBlockDevice {
    inner: Arc<MemoryBlockDevice>,
    fault_write: usize,
    mode: FaultMode,
    writes_seen: Mutex<usize>,
}

impl FaultingBlockDevice {
    #[allow(dead_code)]
    pub fn new(inner: Arc<MemoryBlockDevice>, fault_write: usize, mode: FaultMode) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fault_write,
            mode,
            writes_seen: Mutex::new(0),
        })
    }
}

impl BlockDevice for FaultingBlockDevice {
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
        let mut writes_seen = self.writes_seen.lock().expect("writes_seen lock");
        *writes_seen += 1;

        if *writes_seen != self.fault_write {
            return self.inner.write_blocks(lba, data);
        }

        match self.mode {
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
