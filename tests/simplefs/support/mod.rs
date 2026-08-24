//! tests/simplefs/support/mod.rs
//!
use std::sync::Arc;

use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::simplefs::{ImageEntry, SimpleFs, SimpleFsVolume};
use protofire::kernel::fs::vfs::FileSystem as VfsFileSystem;
use protofire::kernel::fs::vfs::VNode;

pub fn read_all(node: &dyn VNode) -> Vec<u8> {
    let mut buffer = vec![0_u8; node.size()];
    let count = node.read(0, &mut buffer).expect("read node");
    buffer.truncate(count);
    buffer
}

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
