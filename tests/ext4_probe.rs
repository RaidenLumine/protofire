//! Ext4 against a volume `mkfs.ext4` wrote.
//!
//! Every other ext4 test in this tree feeds the driver bytes this tree made,
//! so none of them can see a disagreement with the format — and there was one:
//! the superblock's three feature words were read a word late, which made
//! every real volume look like it carried unknown incompat features.  The
//! driver answered `Unsupported` to a volume `mkfs.ext4` had just written, and
//! nothing noticed, because the only test that opened the driver handed it
//! random bytes and accepted any error.
//!
//! This needs `mkfs.ext4` and the image it is pointed at, so it runs where the
//! host tools are: `make check-ext4-image` builds the volume and runs it.

use protofire::fs::ext4::Ext4FsVolume;
use protofire::fs::vfs::FileSystem;
use protofire::fs::vfs::VNode;
use protofire::kernel::block::MemoryBlockDevice;
use std::sync::Arc;

fn open_probe_volume() -> Ext4FsVolume {
    let path = std::env::var("EXT4_PROBE_IMAGE")
        .expect("EXT4_PROBE_IMAGE names a volume `mkfs.ext4` wrote");
    let bytes = std::fs::read(&path).expect("read the image");
    let device = MemoryBlockDevice::new("ext4-probe", bytes, true);
    Ext4FsVolume::open(device).expect("ext4 must open a volume mkfs.ext4 wrote")
}

#[test]
fn ext4_opens_a_volume_mkfs_wrote() {
    let volume = open_probe_volume();
    assert!(
        volume.name().starts_with("ext4:"),
        "the volume names itself after the device it was opened on"
    );
}

#[test]
fn ext4_reads_a_file_the_host_wrote_into_the_image() {
    let volume = open_probe_volume();
    let node: Arc<dyn VNode> = volume.lookup("/probe.txt").expect("the root's probe file");

    let mut buffer = [0_u8; 64];
    let read = node.read(0, &mut buffer).expect("read the probe file");
    assert_eq!(
        &buffer[..read],
        b"hello-from-mkfs-ext4",
        "the bytes must be the ones the host wrote, not a zeroed buffer"
    );
    assert_eq!(node.size(), b"hello-from-mkfs-ext4".len());
}

#[test]
fn ext4_reads_a_directory_the_host_created() {
    let volume = open_probe_volume();
    let node = volume.lookup("/").expect("the volume root");
    assert_eq!(node.kind(), protofire::fs::NodeKind::Directory);
}
