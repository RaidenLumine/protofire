//! src/fs/system_image.rs
//!
//! The system volume's A/B pair: which of the two system slots a boot takes,
//! and the two operations that change it.
//!
//! `/system` is mounted read-only, so its content cannot be updated in place —
//! the unit that switches is the *volume*.  A boot disk carries two system
//! partitions, and a slot is **committed** when its volume carries a build
//! marker at [`SYSTEM_BUILD_MARKER_PATH`].  A boot takes the committed slot
//! whose generation is highest; a disk with no marker anywhere (every disk
//! before this existed) is taken from the first slot, and a slot whose volume
//! does not open — a torn write, a half-written image — is not a candidate at
//! all, which is the point of having two.
//!
//! The switch is therefore the marker, and it is written *last*: an image that
//! committed itself before its content was in place would take a machine over
//! with something unreadable behind it.  That also makes rollback cheap: the
//! slot that lost is still there, whole, so withdrawing the winner's marker
//! hands the machine back to it with no data copied.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::Error;
use crate::Result;

use super::block::BlockDevice;
use super::block::BlockSliceDevice;
use super::block::MemoryBlockDevice;
use super::block::BLOCK_SIZE;
use super::partition::read_mbr_partitions;
use super::simplefs::SimpleFs;
use super::simplefs::SimpleFsVolume;
use super::vfs::FileSystem as VfsFileSystem;

/// Where a build marker lives inside a system volume.
pub const SYSTEM_BUILD_MARKER_PATH: &str = "/etc/build";

/// The first marker's format word.
const SYSTEM_BUILD_FORMAT: &str = "protofire-system-build-1";

/// The MBR slots the two system volumes live in.
///
/// A is the slot `StorageZone::System` has always used, so a disk built before
/// the pair existed is a disk with only A.
pub const SYSTEM_SLOT_A: usize = 0;
pub const SYSTEM_SLOT_B: usize = 3;

/// The build a system volume holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemBuild {
    /// Which generation this volume is.  Higher wins.
    pub generation: u64,
}

/// One system slot, as a boot sees it.
pub struct SystemSlot {
    /// The MBR slot this volume is in (A or B).
    pub slot: usize,
    /// The volume's block device.
    pub device: Arc<dyn BlockDevice>,
    /// The build it is committed as, when it carries a marker.
    pub build: Option<SystemBuild>,
}

impl SystemSlot {
    /// Whether this slot is a candidate for a boot.
    pub const fn is_committed(&self) -> bool {
        self.build.is_some()
    }
}

/// The marker text for one build.
pub fn render_build_marker(build: SystemBuild) -> String {
    format!(
        "format = \"{SYSTEM_BUILD_FORMAT}\"\ngeneration = {}\n",
        build.generation
    )
}

/// Parse a build marker, or `None` when the text is not one.
pub fn parse_build_marker(text: &str) -> Option<SystemBuild> {
    let mut format_seen = false;
    let mut generation = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "format" if value == SYSTEM_BUILD_FORMAT => format_seen = true,
            "generation" => generation = value.parse::<u64>().ok(),
            // An unknown key is not a reason to refuse a marker — a later
            // format may add one — but a marker that is not this format is.
            _ => {}
        }
    }

    let generation = generation?;
    format_seen.then_some(SystemBuild { generation })
}

/// The system slots a partition table describes, in slot order.
///
/// `read_only` is the caller's: the boot mounts `/system` read-only, and the
/// update path has to be able to write the slot it is installing into.
pub fn system_slots(disk: &Arc<dyn BlockDevice>, read_only: bool) -> Result<Vec<SystemSlot>> {
    let Some(partitions) = read_mbr_partitions(disk.as_ref())? else {
        return Ok(Vec::new());
    };

    let mut slots = Vec::new();
    for slot in [SYSTEM_SLOT_A, SYSTEM_SLOT_B] {
        let Some(partition) = partitions[slot] else {
            continue;
        };

        let device = BlockSliceDevice::new(
            &format!(
                "system-slot-{}",
                if slot == SYSTEM_SLOT_A { "a" } else { "b" }
            ),
            disk.clone(),
            partition.start_block,
            partition.block_count,
            read_only,
        ) as Arc<dyn BlockDevice>;

        let build = read_build(&device);
        slots.push(SystemSlot {
            slot,
            device,
            build,
        });
    }

    Ok(slots)
}

/// Which slot a boot should take: the highest committed generation, and the
/// first slot when nothing is committed.
///
/// `None` means the disk has no system slot at all.
pub fn select_system_slot(slots: &[SystemSlot]) -> Option<&SystemSlot> {
    let best = slots
        .iter()
        .filter(|slot| slot.is_committed())
        .max_by_key(|slot| slot.build.map(|build| build.generation));

    best.or_else(|| slots.first())
}

/// Read one volume's build marker, or `None` when it is not a committed system
/// volume.
///
/// A volume that does not open — torn, truncated, not a volume at all — is not
/// a candidate: the boot has to be able to tell "this slot is bad" from "this
/// slot is older", and this is that distinction.
pub fn read_build(device: &Arc<dyn BlockDevice>) -> Option<SystemBuild> {
    let volume = SimpleFs::open(device.clone(), true).ok()?;
    let volume = SimpleFsVolume::new(volume);
    let node = volume.lookup(SYSTEM_BUILD_MARKER_PATH).ok()?;

    let mut buffer = alloc::vec![0_u8; 256];
    let read = node.read(0, &mut buffer).ok()?;
    buffer.truncate(read);
    let text = core::str::from_utf8(&buffer).ok()?;

    parse_build_marker(text)
}

/// Write a system volume image into the slot that is not active.
///
/// The image carries its own build marker, and that marker is the whole switch:
/// once it is on the disk, the next boot takes this slot.  An image that is not
/// a system volume, carries no marker, or is not newer than the active build is
/// refused — a half-written image cannot commit itself, and an update cannot
/// silently go backwards.
///
/// Returns the build that now wins.
pub fn install_system_build(disk: &Arc<dyn BlockDevice>, image: &[u8]) -> Result<SystemBuild> {
    let build = read_image_build(image)?;

    let slots = system_slots(disk, false)?;
    if slots.is_empty() {
        return Err(Error::NotFound);
    }

    let active = select_system_slot(&slots).ok_or(Error::NotFound)?;
    let active_generation = active.build.map(|build| build.generation).unwrap_or(0);
    if build.generation <= active_generation {
        return Err(Error::AlreadyExists);
    }

    // The slot that is not active is the one an update lands in, so the machine
    // keeps running the build it is running until the *next* boot takes the new
    // one.
    let target = slots
        .iter()
        .find(|slot| slot.slot != active.slot)
        .ok_or(Error::NotFound)?;

    // Where the marker lives inside the image is what the write order below
    // depends on: the file that commits the volume has to be the last thing
    // that lands.
    let marker = image_file_extent(image)?;
    write_volume_image(target.device.as_ref(), image, marker)?;

    Ok(build)
}

/// Withdraw the active build, so the next boot takes the other slot.
///
/// The payload of the withdrawn build stays where it is; only its commitment
/// goes, which is what makes this a rollback rather than a reinstall — and a
/// later install of the same bytes can commit them again.
pub fn withdraw_active_build(disk: &Arc<dyn BlockDevice>) -> Result<SystemBuild> {
    let slots = system_slots(disk, false)?;
    let active = select_system_slot(&slots).ok_or(Error::NotFound)?;
    let build = active.build.ok_or(Error::NotFound)?;

    let volume = SimpleFsVolume::new(SimpleFs::open(active.device.clone(), true)?);
    volume.remove_path(SYSTEM_BUILD_MARKER_PATH)?;

    Ok(build)
}

/// The build a system volume image carries.
fn read_image_build(image: &[u8]) -> Result<SystemBuild> {
    let device: Arc<dyn BlockDevice> = MemoryBlockDevice::new("system-image", image.to_vec(), true);
    read_build(&device).ok_or(Error::InvalidArgument)
}

/// The blocks `image` gives the build marker, as `(first_block, block_count)`.
fn image_file_extent(image: &[u8]) -> Result<(usize, usize)> {
    let device: Arc<dyn BlockDevice> = MemoryBlockDevice::new("system-image", image.to_vec(), true);
    let volume = SimpleFs::open(device, true)?;
    let (start, count) = volume.file_extent(SYSTEM_BUILD_MARKER_PATH)?;
    Ok((start as usize, count as usize))
}

/// Write `image` over `device`, committing it last.
///
/// A slot is a candidate for the next boot as soon as its build marker reads
/// back, so *where* the marker lands in the write is what decides whether a
/// machine that loses power mid-install boots a half-written volume.  The
/// marker's blocks are therefore written in three steps — zeroed first, left
/// out of the payload pass, written last — and the commit is the final write.
/// A crash before it leaves a slot whose marker does not parse, which is a
/// slot the boot skips.
///
/// The marker has to fit in a single block for that to hold: a marker written
/// across two block writes has a moment where the first block is on the disk
/// and the second is not, and a marker whose first block carries the whole
/// text would read back as a commit.
fn write_volume_image(
    device: &dyn BlockDevice,
    image: &[u8],
    marker: (usize, usize),
) -> Result<()> {
    if image.is_empty() || !image.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidArgument);
    }
    let blocks = image.len() / BLOCK_SIZE;
    if blocks > device.block_count() as usize {
        return Err(Error::NoSpace);
    }

    let (marker_start, marker_count) = marker;
    let marker_end = marker_start
        .checked_add(marker_count)
        .ok_or(Error::InvalidArgument)?;
    if marker_count != 1 || marker_end > blocks {
        return Err(Error::InvalidArgument);
    }

    let mut block = alloc::vec![0_u8; BLOCK_SIZE];

    // 1. Disown.  The slot is overwritten in place, so the first thing that has to
    //    go is the old marker: until it does, a machine that dies here would boot
    //    the slot's previous build from a volume that is already being replaced.
    block.fill(0);
    device.write_blocks(marker_start as u64, &block)?;

    // 2. The payload, everything but the file that commits it.
    for index in 0..blocks {
        if index == marker_start {
            continue;
        }
        let offset = index * BLOCK_SIZE;
        block.copy_from_slice(&image[offset..offset + BLOCK_SIZE]);
        device.write_blocks(index as u64, &block)?;
    }

    // 3. The commit.
    let offset = marker_start * BLOCK_SIZE;
    block.copy_from_slice(&image[offset..offset + BLOCK_SIZE]);
    device.write_blocks(marker_start as u64, &block)?;
    device.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::partition::write_mbr_partitions;
    use crate::fs::partition::MbrPartitionEntry;
    use crate::fs::partition::MbrPartitionTable;
    use crate::fs::simplefs::ImageEntry;
    use alloc::vec;

    const ZONE_BLOCKS: u64 = 256;
    const SLOT_A_START: u64 = 8;
    const SLOT_B_START: u64 = SLOT_A_START + ZONE_BLOCKS;
    const APPS_START: u64 = SLOT_B_START + ZONE_BLOCKS;
    const APPS_BLOCKS: u64 = 64;
    const DATA_START: u64 = APPS_START + APPS_BLOCKS;
    /// The data volume below is built with 64 blocks of headroom, so its
    /// partition has to be larger than the image — the same relationship the
    /// demo disk's own layout has to keep.
    const DATA_BLOCKS: u64 = 128;
    const TOTAL_BLOCKS: u64 = DATA_START + DATA_BLOCKS;

    /// A system volume image committed as `generation`.
    fn system_image(generation: Option<u64>) -> Vec<u8> {
        let marker = render_build_marker(SystemBuild {
            generation: generation.unwrap_or(1),
        });
        let mut entries = vec![ImageEntry {
            path: "/etc/hostname",
            data: b"slottest\n",
        }];
        if generation.is_some() {
            // The marker outlives the call: `build_image` copies what it is
            // handed into the image.
            entries.push(ImageEntry {
                path: SYSTEM_BUILD_MARKER_PATH,
                data: marker.as_bytes(),
            });
        }

        SimpleFs::build_image_with_headroom("simplefs:system", &entries, 16, 32, 64)
            .expect("build a system volume")
    }

    /// A disk with two system slots and the two other zones.
    fn two_slot_disk(slot_a: Vec<u8>, slot_b: Vec<u8>) -> Arc<dyn BlockDevice> {
        let mut bytes = alloc::vec![0_u8; TOTAL_BLOCKS as usize * BLOCK_SIZE];
        let mut partitions: MbrPartitionTable = [None; 4];
        partitions[SYSTEM_SLOT_A] = Some(MbrPartitionEntry::new(
            true,
            0xa1,
            SLOT_A_START,
            ZONE_BLOCKS,
        ));
        partitions[SYSTEM_SLOT_B] = Some(MbrPartitionEntry::new(
            false,
            0xa1,
            SLOT_B_START,
            ZONE_BLOCKS,
        ));
        partitions[1] = Some(MbrPartitionEntry::new(false, 0xa2, APPS_START, APPS_BLOCKS));
        partitions[2] = Some(MbrPartitionEntry::new(false, 0xa3, DATA_START, DATA_BLOCKS));
        write_mbr_partitions(&mut bytes[..BLOCK_SIZE], &partitions).expect("write the MBR");

        let data = SimpleFs::build_image_with_headroom(
            "simplefs:data",
            &[ImageEntry {
                path: "/users/guest/note.txt",
                data: b"runtime state lives here\n",
            }],
            16,
            32,
            64,
        )
        .expect("build the data volume");

        for (start, image) in [
            (SLOT_A_START, &slot_a),
            (SLOT_B_START, &slot_b),
            (DATA_START, &data),
        ] {
            let offset = start as usize * BLOCK_SIZE;
            bytes[offset..offset + image.len()].copy_from_slice(image);
        }

        MemoryBlockDevice::new("two-slot-disk", bytes, false)
    }

    /// The data zone of a test disk, as a volume.
    fn data_volume(disk: &Arc<dyn BlockDevice>) -> SimpleFsVolume {
        let partitions = read_mbr_partitions(disk.as_ref())
            .expect("read the MBR")
            .expect("an MBR");
        let data = partitions[2].expect("a data partition");
        let device: Arc<dyn BlockDevice> = BlockSliceDevice::new(
            "data",
            disk.clone(),
            data.start_block,
            data.block_count,
            false,
        );
        SimpleFsVolume::new(SimpleFs::open(device, true).expect("open the data zone"))
    }

    /// Read a whole file through a volume.
    fn read_file(volume: &SimpleFsVolume, path: &str) -> String {
        let node = volume.lookup(path).expect("lookup");
        let mut buffer = alloc::vec![0_u8; 256];
        let count = node.read(0, &mut buffer).expect("read");
        String::from_utf8(buffer[..count].to_vec()).expect("utf8")
    }

    #[test]
    fn the_newest_committed_build_wins() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));
        let slots = system_slots(&disk, true).expect("slots");

        assert_eq!(slots.len(), 2);
        let active = select_system_slot(&slots).expect("a slot");
        assert_eq!(active.slot, SYSTEM_SLOT_B);
        assert_eq!(active.build, Some(SystemBuild { generation: 2 }));
    }

    #[test]
    fn a_slot_that_is_not_committed_loses_to_one_that_is() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(None));
        let slots = system_slots(&disk, true).expect("slots");

        let active = select_system_slot(&slots).expect("a slot");
        assert_eq!(active.slot, SYSTEM_SLOT_A);
        assert_eq!(active.build, Some(SystemBuild { generation: 1 }));
    }

    #[test]
    fn a_disk_with_no_marker_anywhere_is_taken_from_the_first_slot() {
        // Every disk built before the pair existed looks like this, and it has
        // to keep booting from the slot it always did.
        let disk = two_slot_disk(system_image(None), system_image(None));
        let slots = system_slots(&disk, true).expect("slots");

        let active = select_system_slot(&slots).expect("a slot");
        assert_eq!(active.slot, SYSTEM_SLOT_A);
        assert_eq!(active.build, None);
    }

    #[test]
    fn a_slot_whose_volume_is_torn_is_not_a_candidate() {
        // A half-written image must not brick the machine: the other slot takes
        // the boot.
        let torn = alloc::vec![0x5a_u8; ZONE_BLOCKS as usize * BLOCK_SIZE];
        let disk = two_slot_disk(system_image(Some(1)), torn);
        let slots = system_slots(&disk, true).expect("slots");

        let active = select_system_slot(&slots).expect("a slot");
        assert_eq!(active.slot, SYSTEM_SLOT_A);
        assert_eq!(active.build, Some(SystemBuild { generation: 1 }));
    }

    /// A disk whose writes stop landing after a budget, which is what a
    /// machine that loses power mid-install looks like from the kernel's side:
    /// the writes that follow do not land either, and nobody is told.
    struct LosingDisk {
        inner: Arc<dyn BlockDevice>,
        budget: core::sync::atomic::AtomicUsize,
    }

    impl LosingDisk {
        fn new(inner: Arc<dyn BlockDevice>, budget: usize) -> Self {
            Self {
                inner,
                budget: core::sync::atomic::AtomicUsize::new(budget),
            }
        }
    }

    impl BlockDevice for LosingDisk {
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
            let spent = self
                .budget
                .try_update(
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                    |left: usize| left.checked_sub(1),
                )
                .is_err();
            if spent {
                return Ok(());
            }

            self.inner.write_blocks(lba, data)
        }
    }

    #[test]
    fn an_install_that_loses_power_at_any_write_never_commits_a_partial_build() {
        // The property the install path promises: a slot becomes a candidate
        // for the next boot only once every block of the image it carries is
        // on the disk.  The loop is the proof — it stops the writes at every
        // point an install can be interrupted, and each of those disks has to
        // boot the build it was already running.
        let image = system_image(Some(3));
        let (_, marker_blocks) = image_file_extent(&image).expect("marker extent");
        let blocks = image.len() / BLOCK_SIZE;
        // One tombstone write, the payload without the marker, and the commit.
        let writes = blocks + marker_blocks;

        for budget in 0..writes {
            let inner = two_slot_disk(system_image(Some(1)), system_image(Some(2)));
            let disk: Arc<dyn BlockDevice> = Arc::new(LosingDisk::new(inner, budget));
            let _ = install_system_build(&disk, &image);

            let slots = system_slots(&disk, true).expect("slots");
            let active = select_system_slot(&slots).expect("a slot");
            let generation = active.build.map(|build| build.generation).unwrap_or(0);
            assert!(
                generation <= 2,
                "with {budget} of {writes} writes landed, the boot took generation {generation}"
            );
        }
    }

    #[test]
    fn an_install_lands_in_the_inactive_slot_and_takes_the_next_boot() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));
        let newer = system_image(Some(3));

        let build = install_system_build(&disk, &newer).expect("install");
        assert_eq!(build, SystemBuild { generation: 3 });

        let slots = system_slots(&disk, true).expect("slots");
        let active = select_system_slot(&slots).expect("a slot");
        // Slot B was active, so the update went into A — and now A wins.
        assert_eq!(active.slot, SYSTEM_SLOT_A);
        assert_eq!(active.build, Some(SystemBuild { generation: 3 }));
    }

    #[test]
    fn an_image_that_is_not_newer_is_refused() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));

        assert_eq!(
            install_system_build(&disk, &system_image(Some(2))).map(|_| ()),
            Err(Error::AlreadyExists)
        );
        assert_eq!(
            install_system_build(&disk, &system_image(Some(1))).map(|_| ()),
            Err(Error::AlreadyExists)
        );

        // ...and the disk is untouched.
        let slots = system_slots(&disk, true).expect("slots");
        assert_eq!(
            select_system_slot(&slots).expect("a slot").build,
            Some(SystemBuild { generation: 2 })
        );
    }

    #[test]
    fn an_image_without_a_marker_cannot_commit_itself() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));

        assert_eq!(
            install_system_build(&disk, &system_image(None)).map(|_| ()),
            Err(Error::InvalidArgument)
        );

        let slots = system_slots(&disk, true).expect("slots");
        assert_eq!(
            select_system_slot(&slots).expect("a slot").build,
            Some(SystemBuild { generation: 2 })
        );
    }

    #[test]
    fn an_image_that_is_not_a_volume_is_refused() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));

        let garbage = alloc::vec![0x11_u8; BLOCK_SIZE * 4];
        assert_eq!(
            install_system_build(&disk, &garbage).map(|_| ()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn a_system_switch_leaves_the_data_zone_alone() {
        // What makes the pair useful: a system update replaces a *system
        // volume*, so everything a running machine wrote under `/data` — user
        // data, credentials, caches, logs — is exactly where it was, and the
        // same holds for a rollback.
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));

        let data = data_volume(&disk);
        data.create_file("/users/guest/session.log")
            .expect("create a runtime file");
        let node = data.lookup("/users/guest/session.log").expect("lookup");
        node.write(0, b"something the machine wrote\n")
            .expect("write a runtime file");

        install_system_build(&disk, &system_image(Some(3))).expect("install");
        withdraw_active_build(&disk).expect("withdraw");

        // Two system switches later, the data zone holds what it held.
        let data = data_volume(&disk);
        assert_eq!(
            read_file(&data, "/users/guest/note.txt"),
            "runtime state lives here\n"
        );
        assert_eq!(
            read_file(&data, "/users/guest/session.log"),
            "something the machine wrote\n"
        );
    }

    #[test]
    fn withdrawing_the_active_build_hands_the_machine_back() {
        let disk = two_slot_disk(system_image(Some(1)), system_image(Some(2)));

        let withdrawn = withdraw_active_build(&disk).expect("withdraw");
        assert_eq!(withdrawn, SystemBuild { generation: 2 });

        // The build that was active is still *there* — its content was not
        // touched — and the other one is what a boot now takes.
        let slots = system_slots(&disk, true).expect("slots");
        let active = select_system_slot(&slots).expect("a slot");
        assert_eq!(active.slot, SYSTEM_SLOT_A);
        assert_eq!(active.build, Some(SystemBuild { generation: 1 }));
        assert_eq!(
            slots
                .iter()
                .find(|slot| slot.slot == SYSTEM_SLOT_B)
                .unwrap()
                .build,
            None
        );
        assert_eq!(
            read_build(
                &slots
                    .iter()
                    .find(|slot| slot.slot == SYSTEM_SLOT_B)
                    .unwrap()
                    .device
            ),
            None
        );
    }

    #[test]
    fn a_marker_round_trips_and_unknown_text_is_not_one() {
        let marker = render_build_marker(SystemBuild { generation: 42 });
        assert_eq!(
            parse_build_marker(&marker),
            Some(SystemBuild { generation: 42 })
        );

        assert_eq!(parse_build_marker(""), None);
        assert_eq!(parse_build_marker("generation = 3\n"), None);
        assert_eq!(
            parse_build_marker("format = \"other\"\ngeneration = 3\n"),
            None
        );
        assert_eq!(
            parse_build_marker("format = \"protofire-system-build-1\"\n"),
            None
        );
    }
}
