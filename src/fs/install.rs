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
//! 1. **Read the disk's own table.**  A disk with no verified GPT is refused by
//!    [`install_zones_into_disk_image`] — writing a table onto a disk someone
//!    else partitioned is a decision this module does not make on its own.  It
//!    makes it on the caller's, for a disk that carries no partition
//!    information at all: [`install_zones_into_blank_disk_image`] writes a
//!    fresh GPT over such a disk and then installs onto it.
//! 2. **Place each zone.**  A zone the table already carries keeps its extent —
//!    a reinstall is idempotent — and a zone the table does not carry takes the
//!    first aligned gap between the entries that is big enough.  Zones do not
//!    overlap each other or anything already there.
//! 3. **Write the zone volumes into their extents**, zeroing the rest of each
//!    extent first so a grown or shrunken zone cannot leave a stale tail for a
//!    reader to believe.
//! 4. **Rewrite the table** — replacing the zones' entries and copying every
//!    other entry byte for byte
//!    ([`crate::fs::partition::write_gpt_preserving`]), or writing the fresh
//!    one from the same placement when there was no table.
//!
//! What it deliberately does not do: overwrite a table that is there — a
//! damaged GPT included — resize a machine's partitions, or write anything
//! outside the extents the table (or, on a blank disk, the fresh layout) says
//! are free.
//!
//! The user interface is [`plan_zones_into_disk_image`]: the same read, the
//! same refusal and the same placement, stopped short of every write, so a
//! caller can show a person what an install *would* do before any of it
//! happens.  The host command (`src/main.rs`) prints the plan and takes a
//! typed confirmation; the plan itself is the disk-side half of that
//! contract, and the one the confirmation rests on.

use alloc::vec::Vec;

use super::block::BLOCK_SIZE;
use super::demo::build_zone_image;
use super::layout::StorageZone;
use super::partition::fresh_gpt_layout;
use super::partition::gpt_signature_present;
use super::partition::mbr_has_partitions;
use super::partition::read_gpt_from_bytes;
use super::partition::read_gpt_layout_from_bytes;
use super::partition::write_gpt_partitions;
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
    /// Whether this install **wrote** the table rather than adding to one:
    /// true only on the blank-disk route, where the disk carried no partition
    /// information and the fresh GPT is this install's.
    pub created_table: bool,
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

/// What an install **would** do, computed without writing anything.
///
/// This is the confirmation's material: the same reads, the same predicate
/// and the same placement the install itself runs, so what a caller shows a
/// person is what would happen rather than a second description that can
/// drift.  Nothing here touches the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// Each zone and the extent it would take, in the order it is placed.
    pub zones: Vec<InstalledZone>,
    /// Whether the table would be **written** rather than added to: true only
    /// where the disk carries no partition information (the blank-disk route).
    pub created_table: bool,
    /// The in-use entries that are not these zones and would be kept byte for
    /// byte.  Empty on the fresh-table route, which has no other entry.
    pub preserved: Vec<GptPartitionEntry>,
}

/// Plan an install without touching the disk: the reads, the refusal and the
/// placement of [`install_zones_into_disk_image`], stopped short of every
/// write.
///
/// `may_create` is which route's plan is asked for — `false` refuses a disk
/// with no table exactly as the flagless install does, `true` plans the fresh
/// table the flagged route would write.  A plan that answers `Ok` is the
/// promise the install keeps: the same call on the same bytes writes what the
/// plan names.
pub fn plan_zones_into_disk_image(disk: &[u8], may_create: bool) -> Result<InstallPlan> {
    let (layout, existing, created_table) = read_or_create(disk, may_create)?;
    let zones = place_zones(&layout, &existing)?;
    let preserved = existing
        .iter()
        .filter(|entry| {
            !entry.is_unused()
                && entry.type_guid != StorageZone::System.gpt_type_guid()
                && entry.type_guid != StorageZone::Apps.gpt_type_guid()
                && entry.type_guid != StorageZone::Data.gpt_type_guid()
        })
        .copied()
        .collect();
    Ok(InstallPlan {
        zones,
        created_table,
        preserved,
    })
}

/// The table a route would work against: the disk's own verified table, or —
/// where `may_create` says the caller asked for one — the fresh layout a
/// blank disk would get.  Everything else is `NotFound`.
fn read_or_create(
    disk: &[u8],
    may_create: bool,
) -> Result<(GptLayout, Vec<GptPartitionEntry>, bool)> {
    match read_gpt_layout_from_bytes(disk)? {
        Some((layout, entries)) => Ok((layout, entries, false)),
        None => {
            // A fresh table is for a disk that carries none.  What "carries
            // none" means is stated by the two partition-side questions:
            // MBR entries of any type (a protective one included) and a GPT
            // signature are both something already there, and something
            // there is the flagless route's refusal to make again — not this
            // function's to overrule.
            if !may_create || mbr_has_partitions(disk) || gpt_signature_present(disk) {
                return Err(Error::NotFound);
            }
            let total_blocks = (disk.len() / BLOCK_SIZE) as u64;
            Ok((fresh_gpt_layout(total_blocks)?, Vec::new(), true))
        }
    }
}

/// Install this kernel's zones onto the GPT disk image in `disk`.
///
/// The disk's table must already carry a verified GPT: this adds zones to a
/// disk a machine already has, and inventing a table is not its job.  See the
/// module comment for the order of operations.
pub fn install_zones_into_disk_image(disk: &mut [u8]) -> Result<InstallReport> {
    install_zones(disk, false)
}

/// Install this kernel's zones onto `disk`, writing a **fresh GPT** first
/// when the disk carries no partition information at all.
///
/// This is [`install_zones_into_disk_image`]'s refusal made a decision by the
/// caller, for the disk a machine has but has never partitioned: one whose
/// bytes are not a table — no verified GPT, no MBR entries, no GPT signature
/// — gets a fresh table whose layout, protective MBR and two header copies
/// are [`crate::fs::partition::write_gpt_partitions`]'s, and the zones are
/// placed inside it by the same planning the flagless route uses
/// ([`fresh_gpt_layout`] is the span the writer will state).
///
/// It is **not** a licence to repartition: a disk that already carries a
/// table — entries of any type, a GPT that failed its checksum, even a lone
/// protective MBR — is refused exactly as the flagless route refuses it.
/// Erasing a partitioned disk is a decision with no undo, and this module
/// only ever makes it about bytes that are not one.
pub fn install_zones_into_blank_disk_image(disk: &mut [u8]) -> Result<InstallReport> {
    install_zones(disk, true)
}

/// The one install path both entry points share: `may_create` is whether a
/// fresh table may be written when the disk carries none.
fn install_zones(disk: &mut [u8], may_create: bool) -> Result<InstallReport> {
    let (layout, existing, created_table) = read_or_create(disk, may_create)?;

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

    // 4. The table.  A disk that had one keeps everything the install did not
    //    claim, byte for byte; a blank disk gets the fresh writer, whose entries
    //    are the same placement in slots of its own — there is no other entry to
    //    preserve, and the reader below is what says the writer's bytes are a table
    //    this kernel verifies.  A fresh table the reader then refuses is this
    //    function's own contradiction, and it says so rather than reporting an
    //    install whose entries nobody can read.
    let entries = if created_table {
        let table: Vec<(usize, [u8; 16], u64, u64)> = placed
            .iter()
            .enumerate()
            .map(|(slot, zone)| {
                (
                    slot,
                    zone.zone.gpt_type_guid(),
                    zone.first_block,
                    zone.last_block - zone.first_block + 1,
                )
            })
            .collect();
        write_gpt_partitions(disk, &table)?;
        read_gpt_from_bytes(disk)?.ok_or(Error::InternalError)?
    } else {
        write_gpt_preserving(disk, &zone_entries)?
    };

    Ok(InstallReport {
        zones: placed,
        entries,
        created_table,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::install_zones_into_blank_disk_image;
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

    /// A disk with no verified GPT is refused rather than given one — the
    /// flagless route's decision, still, now that the flagged route exists.
    #[test]
    fn a_disk_without_a_gpt_is_refused() {
        let mut blank = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        assert_eq!(
            install_zones_into_disk_image(&mut blank),
            Err(Error::NotFound)
        );
    }

    /// The flagged route, on a disk that carries no partition information:
    /// a fresh GPT is written, the reader verifies it, and a second install
    /// goes through the ordinary route and reuses every extent — the fresh
    /// table became the disk's own.
    #[test]
    fn a_blank_disk_gets_a_fresh_table_and_then_installs() {
        let mut blank = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        let first = install_zones_into_blank_disk_image(&mut blank).expect("the fresh install");
        assert!(first.created_table, "and it says it wrote the table");
        assert_eq!(first.zones.len(), 3);

        // The table is one this kernel's reader verifies, and it carries
        // exactly the zones — a fresh disk has no stranger to preserve.
        let (layout, entries) = read_gpt_layout_from_bytes(&blank).unwrap().unwrap();
        assert_eq!(layout.first_usable_lba, 34);
        assert_eq!(layout.last_usable_lba, DISK_BLOCKS - 34);
        assert_eq!(entries.iter().filter(|e| !e.is_unused()).count(), 3);

        for installed in &first.zones {
            assert!(!installed.reused, "every zone was placed");
            let entry = entries
                .iter()
                .find(|entry| entry.type_guid == installed.zone.gpt_type_guid())
                .expect("the zone's entry");
            assert_eq!(entry.first_lba, installed.first_block);
            assert_eq!(entry.last_lba, installed.last_block);
            let image = crate::fs::demo::build_zone_image(installed.zone);
            let at = installed.first_block as usize * BLOCK;
            assert_eq!(&blank[at..at + image.len()], image.as_slice());
        }

        // The disk now carries a table, so the next install is the ordinary
        // route: the extents are kept, not chosen again.
        let second = install_zones_into_disk_image(&mut blank).expect("the second install");
        assert!(!second.created_table, "the table was already there");
        for (first, second) in first.zones.iter().zip(&second.zones) {
            assert_eq!(first.first_block, second.first_block);
            assert_eq!(first.last_block, second.last_block);
            assert!(second.reused);
        }
    }

    /// The plan the confirmation shows is the install it then runs: same
    /// refusals, same placements, same preserved set.  This is the contract
    /// the user interface rests on — what a person is shown is what would
    /// be written — and it is checked by planning and installing the same
    /// bytes and comparing the two.
    #[test]
    fn the_plan_is_what_the_install_does() {
        // The flagless route, on a machine's disk: refused or planned
        // together, and the plan names the stranger as preserved.
        let mut disk = machine_disk();
        let plan = super::plan_zones_into_disk_image(&disk, false).expect("the plan");
        assert!(!plan.created_table);
        assert_eq!(plan.preserved.len(), 1, "the stranger is preserved");
        assert_eq!(plan.preserved[0].first_lba, STRANGER_FIRST);
        let report = install_zones_into_disk_image(&mut disk).expect("the install");
        assert_eq!(plan.zones, report.zones, "the install did what was planned");

        // The flagged route, on a blank disk: the plan says the table would
        // be created, and the install does.
        let mut blank = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        let plan = super::plan_zones_into_disk_image(&blank, true).expect("the plan");
        assert!(plan.created_table);
        assert!(plan.preserved.is_empty(), "a fresh table preserves nothing");
        let report = install_zones_into_blank_disk_image(&mut blank).expect("the install");
        assert_eq!(plan.zones, report.zones);

        // And a refusal is a refusal in both: a blank disk without the flag,
        // and a disk that carries entries even *with* it.  The second is a
        // plain MBR disk — the flagged route plans a fresh table only for a
        // disk with no partition information at all.
        let blank = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        assert_eq!(
            super::plan_zones_into_disk_image(&blank, false),
            Err(Error::NotFound)
        );
        let mut mbr = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        let mut table: crate::fs::partition::MbrPartitionTable = [None; 4];
        table[0] = Some(crate::fs::partition::MbrPartitionEntry::new(
            false,
            STRANGER_TYPE[0],
            STRANGER_FIRST,
            STRANGER_BLOCKS,
        ));
        crate::fs::partition::write_mbr_partitions(&mut mbr[..BLOCK], &table)
            .expect("the MBR writes");
        assert_eq!(
            super::plan_zones_into_disk_image(&mbr, true),
            Err(Error::NotFound)
        );

        // The plan touches nothing: the bytes it was computed from are
        // exactly the bytes a caller read.
        let untouched = machine_disk();
        let _ = super::plan_zones_into_disk_image(&untouched, false).expect("the plan");
        assert_eq!(untouched, machine_disk(), "a plan wrote to the disk");
    }

    /// The flagged route is not a licence to repartition: a disk that
    /// carries MBR entries — a real table's, or a lone protective one, the
    /// shape a GPT's own first sector is — is refused rather than given a
    /// fresh table.
    #[test]
    fn the_flagged_route_refuses_a_disk_that_carries_entries() {
        // A plain MBR disk: somebody's partitioning tool put a table there,
        // and the zones are not this install's to place.
        let mut mbr = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        let mut table: crate::fs::partition::MbrPartitionTable = [None; 4];
        table[0] = Some(crate::fs::partition::MbrPartitionEntry::new(
            false,
            STRANGER_TYPE[0], // any type byte: presence is what refuses
            STRANGER_FIRST,
            STRANGER_BLOCKS,
        ));
        crate::fs::partition::write_mbr_partitions(&mut mbr[..BLOCK], &table)
            .expect("the MBR writes");
        let before = mbr.clone();
        assert_eq!(
            install_zones_into_blank_disk_image(&mut mbr),
            Err(Error::NotFound)
        );
        assert_eq!(mbr, before, "a refused install writes nothing");

        // A protective MBR alone: `write_gpt_partitions` writes one, and the
        // check keeps its first sector before the header makes it a GPT.
        let mut disk = vec![0_u8; DISK_BLOCKS as usize * BLOCK];
        write_gpt_partitions(&mut disk, &[]).expect("the table writes");
        let mut protective_only = disk.clone();
        // Keep the first sector, take the GPT away: this disk carries an MBR
        // entry and no verified GPT.
        protective_only[BLOCK..].fill(0);
        let before = protective_only.clone();
        assert_eq!(
            install_zones_into_blank_disk_image(&mut protective_only),
            Err(Error::NotFound)
        );
        assert_eq!(protective_only, before, "a refused install writes nothing");

        // A GPT whose primary header is damaged: the signature is there, the
        // disk declares a table, and neither route may write over it.
        let mut damaged = disk.clone();
        damaged[BLOCK + 16] ^= 0xFF; // the header's CRC field
        let before = damaged.clone();
        assert_eq!(
            install_zones_into_blank_disk_image(&mut damaged),
            Err(Error::NotFound)
        );
        assert_eq!(damaged, before);
        assert_eq!(
            install_zones_into_disk_image(&mut damaged),
            Err(Error::NotFound)
        );
        assert_eq!(damaged, before);

        // A GPT whose **primary end** is destroyed but whose backup is whole:
        // the MBR and the primary header are gone, and the last block still
        // spells the signature — which is the backup the format's own reader
        // would consult, so a fresh table here would overwrite the one copy
        // a repair could use.  The backup's place is checked for exactly this.
        let mut backup_only = disk;
        let first_usable = 34 * BLOCK;
        backup_only[..first_usable].fill(0);
        let before = backup_only.clone();
        assert_eq!(
            install_zones_into_blank_disk_image(&mut backup_only),
            Err(Error::NotFound)
        );
        assert_eq!(backup_only, before, "a refused install writes nothing");
    }

    /// A blank disk with room only for two of the three zones is refused
    /// **before anything is written**, including the table: the fresh table
    /// is this install's, and an install that cannot finish must leave the
    /// disk exactly as it was.
    #[test]
    fn a_blank_disk_with_no_room_is_refused_before_the_table() {
        // 1 MiB: past the format's minimum, nowhere near the zones.
        let mut disk = vec![0_u8; 2 * 1024 * BLOCK];
        let before = disk.clone();
        assert_eq!(
            install_zones_into_blank_disk_image(&mut disk),
            Err(Error::NoSpace)
        );
        assert_eq!(disk, before, "a refused install writes nothing");
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
