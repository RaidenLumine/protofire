//! src/fs/install.rs
//!
//! The installation path: putting this kernel's zones onto a disk a machine
//! already has.
//!
//! The tool half of the tree builds *images* — `mkimage` writes the demo disk,
//! and `make iso` writes a bootable medium — and neither of those is an
//! install: a machine's disk carries a table its own partitioning tool wrote,
//! with partitions this kernel has no name for, and installing means adding
//! the three zones to that table without touching anything else.  That is what
//! this module does, over a disk image in memory, so the whole operation is a
//! host test and a gate boot rather than a privilege.
//!
//! ## What an install does
//!
//! 1. **Read the disk's own table.**  A disk with no verified GPT is refused;
//!    writing a table onto a disk someone else partitioned is a decision this
//!    module does not make ([`write_gpt_preserving`] holds the same line).
//! 2. **Place each zone.**  A zone the table already carries keeps its extent —
//!    a reinstall is idempotent — and a zone the table does not carry takes the
//!    first aligned gap between the entries that is big enough.  Zones do not
//!    overlap each other or anything already there.
//! 3. **Write the zone volumes into their extents**, zeroing the rest of each
//!    extent first so a grown or shrunken zone cannot leave a stale tail for a
//!    reader to believe.
//! 4. **Rewrite the table**, replacing the zones' entries and copying every
//!    other entry byte for byte
//!    ([`crate::fs::partition::write_gpt_preserving`]).
//!
//! What it deliberately does not do: create a table that is not there, resize
//! a machine's partitions, or write anything outside the extents the table
//! says are free.  An installer for a real machine would add a user interface
//! and a confirmation on top; the disk-side operation is this.

use alloc::vec::Vec;

use super::block::BLOCK_SIZE;
use super::demo::build_zone_image;
use super::layout::StorageZone;
use super::partition::read_gpt_layout_from_bytes;
use super::partition::write_gpt_preserving;
use super::partition::GptLayout;
use super::partition::GptPartitionEntry;
use crate::Error;
use crate::Result;

/// How each zone is placed when its extent must be chosen.
///
/// The counts are the demo disk's own zone sizes — the sizes the volumes in
/// `build_zone_image` are packed to fit — so an installed disk holds the same
/// content the demo image does, at extents the machine's table chose.
const PLACEMENT_ALIGN_BLOCKS: u64 = 2048;

/// The extent one zone got, and whether the table already carried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledZone {
    pub zone: StorageZone,
    /// The zone's first block on the disk, inclusive.
    pub first_block: u64,
    /// The zone's last block on the disk, inclusive.
    pub last_block: u64,
    /// Whether this install wrote to an extent the table already carried (a
    /// reinstall in place) rather than taking free space.
    pub reused: bool,
}

/// What one install did, in the order the zones were placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub zones: Vec<InstalledZone>,
    /// The table the disk carries after the install.
    pub entries: Vec<GptPartitionEntry>,
}

/// The block extent each zone occupies, for a disk it is being installed on.
///
/// `existing` is the table the disk carries: a zone whose type GUID is already
/// in it keeps that entry's extent, and every other entry is an obstacle the
/// free-space search steps around.  The search is first-fit over the table's
/// spans — not over every block — so its cost is the table's size, and its
/// bounds are the span the disk's own headers declare a partition may use.
fn place_zones(layout: &GptLayout, existing: &[GptPartitionEntry]) -> Result<Vec<InstalledZone>> {
    use super::layout::DEMO_DISK_APPS_BLOCKS;
    use super::layout::DEMO_DISK_DATA_BLOCKS;
    use super::layout::DEMO_DISK_SYSTEM_BLOCKS;

    let wanted: [(StorageZone, u64); 3] = [
        (StorageZone::System, DEMO_DISK_SYSTEM_BLOCKS),
        (StorageZone::Apps, DEMO_DISK_APPS_BLOCKS),
        (StorageZone::Data, DEMO_DISK_DATA_BLOCKS),
    ];

    // Begin with everything the table already carries, so the free-space
    // search never hands a zone an extent that is taken.
    let mut taken: Vec<(u64, u64)> = existing
        .iter()
        .filter(|entry| !entry.is_unused())
        .map(|entry| (entry.first_lba, entry.last_lba))
        .collect();

    let mut placed = Vec::with_capacity(wanted.len());
    for (zone, blocks) in wanted {
        // A zone the table already carries keeps its extent — the extent is
        // the disk's decision, not this module's to make twice.
        let existing_entry = existing
            .iter()
            .find(|entry| entry.type_guid == zone.gpt_type_guid());
        if let Some(entry) = existing_entry {
            if entry.block_count() < blocks {
                return Err(Error::NoSpace);
            }
            placed.push(InstalledZone {
                zone,
                first_block: entry.first_lba,
                // The zone's content fits the entry's extent; a bigger entry
                // keeps its size, because shrinking a partition the table
                // declared is not an install's to do.
                last_block: entry.last_lba,
                reused: true,
            });
            continue;
        }

        let first = find_gap(&taken, layout, blocks).ok_or(Error::NoSpace)?;
        let extent = (first, first + blocks - 1);
        taken.push(extent);
        placed.push(InstalledZone {
            zone,
            first_block: extent.0,
            last_block: extent.1,
            reused: false,
        });
    }

    Ok(placed)
}

/// The first aligned run of `blocks` whole blocks inside the span the disk's
/// headers declare usable, clear of every span in `taken`.
///
/// The spans need not be sorted; the walk is over them sorted by first block,
/// keeping a cursor at the end of everything passed — which is the first
/// address a gap may start at.
fn find_gap(taken: &[(u64, u64)], layout: &GptLayout, blocks: u64) -> Option<u64> {
    let mut spans = taken.to_vec();
    spans.sort_unstable();

    let mut cursor = layout.first_usable_lba;
    for (first, last) in spans {
        // A span entirely before the cursor is behind it; overlapping or
        // ahead, the cursor moves past it.
        if last < cursor {
            continue;
        }
        if first > cursor {
            let start = align_up(cursor, PLACEMENT_ALIGN_BLOCKS);
            if start + blocks - 1 < first && start + blocks - 1 <= layout.last_usable_lba {
                return Some(start);
            }
        }
        cursor = cursor.max(last + 1);
    }

    let start = align_up(cursor, PLACEMENT_ALIGN_BLOCKS);
    if start + blocks - 1 <= layout.last_usable_lba {
        Some(start)
    } else {
        None
    }
}

/// Round `value` up to the next multiple of `align`.
const fn align_up(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

/// Install this kernel's zones onto the GPT disk image in `disk`.
///
/// The disk's table must already carry a verified GPT: this adds zones to a
/// disk a machine already has, and inventing a table is not its job.  See the
/// module comment for the order of operations.
pub fn install_zones_into_disk_image(disk: &mut [u8]) -> Result<InstallReport> {
    let (layout, existing) = read_gpt_layout_from_bytes(disk)?.ok_or(Error::NotFound)?;

    let placed = place_zones(&layout, &existing)?;

    // 3. The zone volumes, each zeroing its whole extent before the image lands: a
    //    reinstall reuses the extent, and bytes the previous volume left past the
    //    new image's length are bytes a reader could believe.
    let mut zone_entries: Vec<([u8; 16], u64, u64)> = Vec::with_capacity(placed.len());
    for zone in &placed {
        let image = build_zone_image(zone.zone);
        let capacity = (zone.last_block - zone.first_block + 1) as usize * BLOCK_SIZE;
        if image.len() > capacity {
            return Err(Error::NoSpace);
        }
        let at = zone.first_block as usize * BLOCK_SIZE;
        disk[at..at + capacity].fill(0);
        disk[at..at + image.len()].copy_from_slice(&image);
        zone_entries.push((zone.zone.gpt_type_guid(), zone.first_block, zone.last_block));
    }

    // 4. The table, with everything the install did not claim copied back.
    let entries = write_gpt_preserving(disk, &zone_entries)?;

    Ok(InstallReport {
        zones: placed,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::install_zones_into_disk_image;
    use crate::fs::layout::StorageZone;
    #[allow(unused_imports)]
    use crate::fs::partition::read_gpt_from_bytes;
    use crate::fs::partition::read_gpt_layout_from_bytes;
    use crate::fs::partition::write_gpt_partitions;
    use crate::Error;

    const BLOCK: usize = 512;
    /// A machine-sized disk: 64 MiB, room for the zones and a stranger's
    /// partition.
    const DISK_BLOCKS: u64 = 64 * 1024;
    /// The stranger partition: 1 MiB at block 4096, the kind of thing a
    /// partitioning tool leaves behind.
    const STRANGER_FIRST: u64 = 4096;
    const STRANGER_BLOCKS: u64 = 2048;
    /// Not any of this kernel's type GUIDs — a Linux filesystem UUID stands
    /// in, byte for byte.
    const STRANGER_TYPE: [u8; 16] = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];

    /// A disk with a GPT and one partition a stranger's tool wrote, its
    /// extent filled with a pattern so a write through it shows.
    fn machine_disk() -> Vec<u8> {
        let mut disk = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        write_gpt_partitions(
            &mut disk,
            &[(0, STRANGER_TYPE, STRANGER_FIRST, STRANGER_BLOCKS)],
        )
        .expect("the table writes");
        let at = STRANGER_FIRST as usize * BLOCK;
        for (i, byte) in disk[at..at + STRANGER_BLOCKS as usize * BLOCK]
            .iter_mut()
            .enumerate()
        {
            *byte = (i % 251) as u8;
        }
        disk
    }

    /// One pass over the disk: the zones are in the table by type GUID, the
    /// stranger's entry is untouched — same GUID, same extent, same bytes in
    /// its partition — and every zone's extent holds its volume.
    #[test]
    fn an_install_adds_the_zones_and_leaves_a_stranger_alone() {
        let mut disk = machine_disk();
        let before = disk
            [STRANGER_FIRST as usize * BLOCK..(STRANGER_FIRST + STRANGER_BLOCKS) as usize * BLOCK]
            .to_vec();

        let report = install_zones_into_disk_image(&mut disk).expect("the install runs");
        assert_eq!(report.zones.len(), 3, "three zones are installed");

        // The stranger's partition: bytes and entry both untouched.
        let after = &disk
            [STRANGER_FIRST as usize * BLOCK..(STRANGER_FIRST + STRANGER_BLOCKS) as usize * BLOCK];
        assert_eq!(
            before, after,
            "the stranger's partition bytes are untouched"
        );
        let (_, entries) = read_gpt_layout_from_bytes(&disk).unwrap().unwrap();
        let stranger = entries
            .iter()
            .find(|entry| entry.type_guid == STRANGER_TYPE)
            .expect("the stranger's entry survives");
        assert_eq!(stranger.first_lba, STRANGER_FIRST);
        assert_eq!(stranger.last_lba, STRANGER_FIRST + STRANGER_BLOCKS - 1);

        // Each zone: an entry by type GUID at the extent the report names,
        // and its volume's own bytes at the start of that extent.
        for installed in &report.zones {
            let entry = entries
                .iter()
                .find(|entry| entry.type_guid == installed.zone.gpt_type_guid())
                .expect("the zone's entry is in the table");
            assert_eq!(entry.first_lba, installed.first_block);
            assert_eq!(entry.last_lba, installed.last_block);
            let image = crate::fs::demo::build_zone_image(installed.zone);
            let at = installed.first_block as usize * BLOCK;
            assert_eq!(
                &disk[at..at + image.len()],
                image.as_slice(),
                "the zone's volume is at the extent the table names"
            );
        }

        // No zone overlaps the stranger: the extents are disjoint.
        for installed in &report.zones {
            assert!(
                installed.last_block < STRANGER_FIRST
                    || installed.first_block > STRANGER_FIRST + STRANGER_BLOCKS - 1,
                "a zone overlaps the stranger's partition"
            );
        }
    }

    /// Installing twice is idempotent: the second install reuses every zone's
    /// extent rather than copying the disk's content somewhere new.
    #[test]
    fn a_second_install_reuses_every_extent() {
        let mut disk = machine_disk();
        let first = install_zones_into_disk_image(&mut disk).expect("the first install runs");
        let second = install_zones_into_disk_image(&mut disk).expect("the second install runs");

        for (a, b) in first.zones.iter().zip(&second.zones) {
            assert_eq!(a.first_block, b.first_block);
            assert_eq!(a.last_block, b.last_block);
            assert!(b.reused, "the second install writes the extents in place");
        }
    }

    /// A disk with no verified GPT is refused rather than given one.
    #[test]
    fn a_disk_without_a_gpt_is_refused() {
        let mut blank = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        assert_eq!(
            install_zones_into_disk_image(&mut blank),
            Err(Error::NotFound)
        );
    }

    /// A disk with a GPT but no room for the zones is refused, and the
    /// refusal happens before the table is rewritten — the stranger's entry
    /// is still exactly as it was.
    #[test]
    fn a_disk_with_no_room_is_refused_before_anything_is_written() {
        // 4 MiB: a GPT's ends plus the stranger leave nowhere near the three
        // zones' extents.
        let mut disk = vec![0_u8; 4 * 1024 * BLOCK];
        write_gpt_partitions(&mut disk, &[(0, STRANGER_TYPE, 512, 1024)])
            .expect("the table writes");
        let before = disk.clone();
        assert_eq!(
            install_zones_into_disk_image(&mut disk),
            Err(Error::NoSpace)
        );
        assert_eq!(disk, before, "a refused install writes nothing");
    }

    /// The zone's type GUIDs are the only thing the table gains: the count of
    /// entries whose type this kernel knows grows by exactly the zones it
    /// installed, and the stranger's type is still not one of them.
    #[test]
    fn the_table_gains_only_the_zones() {
        let mut disk = machine_disk();
        let report = install_zones_into_disk_image(&mut disk).expect("the install runs");
        let (_, entries) = read_gpt_layout_from_bytes(&disk).unwrap().unwrap();

        let protofire = entries
            .iter()
            .filter(|entry| {
                let guid = entry.type_guid;
                guid == StorageZone::System.gpt_type_guid()
                    || guid == StorageZone::Apps.gpt_type_guid()
                    || guid == StorageZone::Data.gpt_type_guid()
            })
            .count();
        assert_eq!(protofire, report.zones.len());
        assert_eq!(
            entries.iter().filter(|entry| !entry.is_unused()).count(),
            report.zones.len() + 1,
            "the stranger plus the zones, and nothing else"
        );
    }
}
