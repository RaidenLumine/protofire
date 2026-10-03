//! fuzz/fuzz_targets/filesystem_images.rs
//!
//! Coverage-guided fuzzing for every filesystem image opener in the tree.
//!
//! A disk is the one input this kernel reads that it did not write, so every
//! format's opener is a boundary.  The in-tree harness feeds each of them
//! random bytes and single mutations; this drives the same set with the
//! coverage-guided mutator, which is what finds the shapes a seed did not.

#![no_main]

use libfuzzer_sys::fuzz_target;
use protofire::fs::block::MemoryBlockDevice;
use protofire::fs::btrfs::BtrfsVolume;
use protofire::fs::erofs::EroFsVolume;
use protofire::fs::exfat::ExfatVolume;
use protofire::fs::ext4::Ext4FsVolume;
use protofire::fs::f2fs::F2fsVolume;
use protofire::fs::fat32::FatVolume;
use protofire::fs::iso9660::Iso9660Volume;
use protofire::fs::ntfs::NtfsFs;
use protofire::fs::partition::read_mbr_partitions;
use protofire::fs::simplefs::SimpleFs;
use protofire::fs::squashfs::SquashfsVolume;
use protofire::fs::xfs::XfsVolume;

fuzz_target!(|data: &[u8]| {
    // A zero-block device is not an image parser boundary; skip it rather than
    // letting every empty input look like the same read failure.
    if data.is_empty() {
        return;
    }

    let device = MemoryBlockDevice::new("fuzz-fs", data.to_vec(), true);

    let _ = read_mbr_partitions(device.as_ref());
    let _ = BtrfsVolume::open(vec![device.clone()]);
    let _ = ExfatVolume::open(device.clone());
    let _ = Ext4FsVolume::open(device.clone());
    let _ = F2fsVolume::open(device.clone());
    let _ = FatVolume::open(device.clone());
    let _ = EroFsVolume::open(device.clone());
    let _ = NtfsFs::new(device.clone());
    let _ = SquashfsVolume::open(device.clone());
    let _ = Iso9660Volume::open(device.clone());
    let _ = SimpleFs::open(device.clone(), false);
    let _ = XfsVolume::open(device);
});
