//! src/fs/demo/mod.rs
//!
//! The demo volume: what it holds, and how each zone is packaged.
//!
//! The packaging is the same everywhere — a zone is a `SimpleFs` image sized
//! for a fixed partition range, and a failure degrades to a readable
//! placeholder rather than to a disk the boot path cannot parse.  What differs
//! is *content*: which payloads a target ships and what its manifests say.
//! That half lives one file per architecture (`x86_64.rs`, `aarch64.rs`,
//! `riscv64.rs`), and the machine's own directory — `arch/<arch>/demo.rs` —
//! says which one this build gets, so this file names no architecture at all.
//!
//! ═══════════════════════════════════════════════════════════════════════════
//! LEGACY MODULE — prefer alternatives for new code:
//!   - `SimpleFs::build_image` / `SimpleFs::build_image_with_headroom` for
//!     constructing SimpleFs images directly.
//!
//! This module is kept for:
//!   1. `build_demo_memory_device()` → `fs.init()` boot path (path_helpers.rs)
//!   2. Kernel-side MBR boot disk tests in `filesystem/tests.rs`
//!   3. `build_demo_disk_image()` as the host `mkimage` subcommand in `main.rs`
//!
//! ═══════════════════════════════════════════════════════════════════════════

use alloc::vec;
use alloc::vec::Vec;

use super::block::BLOCK_SIZE;
use super::layout::StorageZone;
use super::layout::DEFAULT_ZONES;
use super::layout::DEMO_DISK_TOTAL_BLOCKS_WITH_SYSTEM_PAIR;
use super::layout::DEMO_MBR_SYSTEM_PARTITION_TYPE;
use super::layout::DEMO_SYSTEM_SLOT_A_GENERATION;
use super::layout::DEMO_SYSTEM_SLOT_B_GENERATION;
use super::layout::SYSTEM_SLOT_B_DISK_RANGE;
use super::partition::write_mbr_partitions;
use super::partition::MbrPartitionEntry;
use super::partition::MbrPartitionTable;
use super::simplefs::ImageEntry;
use super::simplefs::SimpleFs;
use crate::Result;

// ── Per-architecture contents ──────────────────────────────────────────
//
// Each module answers two questions: the apps zone for this target, and the
// system zone.  Everything else — the layout, the fallback, the disk — is
// here.

// The machine's own directory picks the file; from here down, nothing knows
// which one answered.
use crate::arch::machine_demo::content;

const DATA_ZONE_EXTRA_INODES: usize = 64;

const DATA_ZONE_EXTRA_DIRENTS: usize = 128;

const DATA_ZONE_EXTRA_DATA_BLOCKS: usize = 256;

/// Headroom the app zone keeps for what a running machine installs into it.
///
/// An install adds a version directory, the program and its manifest, the
/// catalog and current records, and the transaction log — so the image has to
/// arrive with room for them, or the first install on a fresh machine would be
/// the one that found out it had none.
pub(crate) const APPS_ZONE_EXTRA_INODES: usize = 32;

/// See [`APPS_ZONE_EXTRA_INODES`].
pub(crate) const APPS_ZONE_EXTRA_DIRENTS: usize = 64;

/// See [`APPS_ZONE_EXTRA_INODES`].  The program is the demo launcher, a few
/// kilobytes, and the log and records are small; the count matches the x86_64
/// zone's, which has carried an install for longest.
pub(crate) const APPS_ZONE_EXTRA_DATA_BLOCKS: usize = 128;

const SYSTEM_FILES: &[ImageEntry<'static>] = &[
    ImageEntry {
        path: "/boot/kernel.bin",
        data: b"bare-metal kernel image placeholder\n",
    },
    ImageEntry {
        path: "/etc/hostname",
        data: b"protofire\n",
    },
    ImageEntry {
        path: "/runtime/README.txt",
        data: b"System volume stored inside a block-backed demo image.\n",
    },
    ImageEntry {
        path: "/runtime/tools/shell.bin",
        data: b"demo-shell\n",
    },
    ImageEntry {
        path: "/usr/share/motd",
        data: b"Prototype kernel: block-backed system volume with stable handle-based I/O.\n",
    },
];

const DATA_FILES: &[ImageEntry<'static>] = &[
    ImageEntry {
        path: "/etc/.directory",
        data: b"",
    },
    ImageEntry {
        path: "/users/guest/documents/readme.txt",
        data: b"User data lives on a block-backed data image instead of a hard-coded directory tree.\n",
    },
    ImageEntry {
        path: "/users/guest/downloads/welcome.txt",
        data: b"Downloads are placeholders until real networking and writable storage exist.\n",
    },
    ImageEntry {
        path: "/public/shared/note.txt",
        data: b"Shared data volume used by the host-side regression tests.\n",
    },
];

pub fn build_zone_image(zone: StorageZone) -> Vec<u8> {
    // Build each logical zone independently so a failure in demo app packaging
    // can degrade to a readable placeholder image instead of breaking disk
    // discovery for the entire boot flow.
    #[cfg(target_os = "none")]
    let heap_before = crate::memory::heap::heap_model().remaining();

    let image = match zone {
        StorageZone::System => content::system_zone_image(DEMO_SYSTEM_SLOT_A_GENERATION),
        StorageZone::Apps => content::apps_zone_image(zone),
        StorageZone::Data => content::data_zone_image(zone),
    };

    #[cfg(target_os = "none")]
    {
        let heap_after = crate::memory::heap::heap_model().remaining();
        crate::println!(
            "[heap] {} zone: {} KiB -> {} KiB (delta: {} KiB)",
            zone.volume_label(),
            heap_before / 1024,
            heap_after / 1024,
            (heap_before as i64 - heap_after as i64) / 1024
        );
    }

    match image {
        Ok(image) => image,
        Err(error) => {
            crate::println!(
                "[fs    ] failed to build demo {} zone image: {}",
                zone.volume_label(),
                error.as_str()
            );
            build_fallback_zone_image(zone)
        }
    }
}

fn build_fallback_zone_image(zone: StorageZone) -> Vec<u8> {
    const FALLBACK_ZONE_FILES: &[ImageEntry<'static>] = &[ImageEntry {
        path: "/README.txt",
        data: b"Demo zone fallback image generated after build failure.\n",
    }];

    // Keep the fixed partition mountable even after packaging failures. Only
    // fall back to a raw zero block when the emergency image itself cannot be
    // built.
    match SimpleFs::build_image(zone.volume_label(), FALLBACK_ZONE_FILES) {
        Ok(image) => image,
        Err(error) => {
            crate::println!(
                "[fs    ] failed to build fallback {} zone image: {}",
                zone.volume_label(),
                error.as_str()
            );
            vec![0_u8; BLOCK_SIZE]
        }
    }
}

pub fn build_demo_disk_image() -> Vec<u8> {
    let mut disk = vec![0_u8; DEMO_DISK_TOTAL_BLOCKS_WITH_SYSTEM_PAIR as usize * BLOCK_SIZE];
    let mut partitions: MbrPartitionTable = [None; 4];

    // The demo disk uses a fixed partition layout so boot code and tests can
    // discover the same zones through MBR parsing without depending on a host
    // filesystem.
    // The second system slot: the same content, committed as a newer build, so
    // a demo boot exercises the pair — the boot takes the *newest committed*
    // slot, and this is what makes that a fact rather than a claim.
    let (system_b_start, system_b_blocks) = SYSTEM_SLOT_B_DISK_RANGE;
    let mut system_b =
        content::system_zone_image(DEMO_SYSTEM_SLOT_B_GENERATION).unwrap_or_default();
    let system_b_capacity = system_b_blocks as usize * BLOCK_SIZE;
    if system_b.len() > system_b_capacity {
        crate::println!(
            "[fs    ] demo second system slot exceeds its range ({} > {}); leaving it empty",
            system_b.len(),
            system_b_capacity
        );
        system_b.clear();
    }
    let system_b_offset = system_b_start as usize * BLOCK_SIZE;
    disk[system_b_offset..system_b_offset + system_b.len()].copy_from_slice(&system_b);
    partitions[crate::fs::system_image::SYSTEM_SLOT_B] = Some(MbrPartitionEntry::new(
        false,
        DEMO_MBR_SYSTEM_PARTITION_TYPE,
        system_b_start,
        system_b_blocks,
    ));

    for zone in DEFAULT_ZONES {
        let mut zone_image = build_zone_image(zone);
        let (start_block, block_count) = zone.disk_range();
        let start = start_block as usize * BLOCK_SIZE;
        let capacity = block_count as usize * BLOCK_SIZE;

        if zone_image.len() > capacity {
            crate::println!(
                "[fs    ] demo {} zone image exceeds fixed range ({} > {}); using fallback image",
                zone.volume_label(),
                zone_image.len(),
                capacity
            );
            zone_image = build_fallback_zone_image(zone);
        }

        if zone_image.len() > capacity {
            crate::println!(
                "[fs    ] fallback {} zone image still exceeds fixed range ({} > {}); leaving payload empty",
                zone.volume_label(),
                zone_image.len(),
                capacity
            );
            zone_image.clear();
        }

        disk[start..start + zone_image.len()].copy_from_slice(&zone_image);
        // Mark only the system zone bootable; the other zones are still normal
        // partitions but should not be treated as firmware entry points.
        partitions[zone.partition_slot()] = Some(MbrPartitionEntry::new(
            zone == StorageZone::System,
            zone.mbr_partition_type(),
            start_block,
            block_count,
        ));
    }

    if let Err(error) = write_mbr_partitions(&mut disk[..BLOCK_SIZE], &partitions) {
        crate::println!(
            "[fs    ] failed to write demo MBR partition table: {}",
            error.as_str()
        );
    }
    disk
}

/// Variant of [`build_demo_disk_image`] kept for callers that historically
/// passed a packaging/checksum key.  The current zone-image builders do not
/// consume a key, so the disk is built identically.
pub fn build_demo_disk_image_with_key(_key: &str) -> Vec<u8> {
    build_demo_disk_image()
}

/// Build the system zone from the shared files, one init ELF, and the
/// distribution's service declarations.
///
/// The caller passes the bytes rather than a name, because the two targets
/// that share this differ only in where their placeholder came from: what the
/// zone needs is the image, not the story behind it.
///
/// The ELF lands at `/init.elf` so the kernel finds it at `/system/init.elf`,
/// which is the default init path (`DEFAULT_INIT_PATH`).
///
/// `/rc.d/defaults.toml` is rendered from the same list the kernel falls back
/// to when a disk has no declarations, so a stock boot exercises the declared
/// path and a disk without one still runs the same system.
pub(crate) fn build_system_zone_from(init_elf: &[u8], generation: u64) -> Result<Vec<u8>> {
    let mut entries: alloc::vec::Vec<ImageEntry<'_>> = alloc::vec::Vec::new();
    for entry in SYSTEM_FILES {
        entries.push(*entry);
    }
    entries.push(ImageEntry {
        path: "/init.elf",
        data: init_elf,
    });
    // The build marker is what makes this volume a *committed* system slot: a
    // boot takes the committed slot with the highest generation, so the pair
    // can be switched and rolled back without copying a payload — see
    // `crate::fs::system_image`.
    let marker =
        crate::fs::system_image::render_build_marker(crate::fs::system_image::SystemBuild {
            generation,
        });
    entries.push(ImageEntry {
        path: crate::fs::system_image::SYSTEM_BUILD_MARKER_PATH,
        data: marker.as_bytes(),
    });
    // Written where the build has the demo at all: the declarations name the
    // prototype programs, and a build without them packages none to name.
    // The text outlives `entries`, which borrows it until the image is built.
    #[cfg(any(feature = "demo-disk", test))]
    let declarations =
        crate::kernel::service::render_config(&crate::kernel::service::default_definitions());
    #[cfg(any(feature = "demo-disk", test))]
    entries.push(ImageEntry {
        path: "/rc.d/defaults.toml",
        data: declarations.as_bytes(),
    });
    SimpleFs::build_image(StorageZone::System.volume_label(), &entries)
}

/// The data zone: the shared files, plus the package the boot installs.
///
/// The staged program is the target's own launcher, so what gets installed is
/// a program this machine can really run, and the digest in the manifest is
/// computed here — the kernel builds the package, so it can say what it is.
/// A boot that installs it exercises the whole path on the machine rather than
/// only in the host tests: read the package, verify what it claims, write the
/// app zone, and make the version active.
pub(crate) fn build_data_zone_from(zone: StorageZone, program: &[u8]) -> Result<Vec<u8>> {
    let digest = crate::kernel::crypto::sha256_hex(program);
    let manifest = alloc::format!(
        "name = \"demo-installed\"\nversion = \"1.0.0\"\nformat = \"{}\"\nentry = \"bin/demo.elf\"\nworking_dir = \".\"\nentry_sha256 = \"{}\"\n",
        crate::user::program::DEMO_PROGRAM_FORMAT,
        digest,
    );

    let mut entries: Vec<ImageEntry<'_>> = Vec::new();
    entries.extend_from_slice(DATA_FILES);
    entries.push(ImageEntry {
        path: "/downloads/demo-installed@1.0.0/manifest.toml",
        data: manifest.as_bytes(),
    });
    entries.push(ImageEntry {
        path: "/downloads/demo-installed@1.0.0/bin/demo.elf",
        data: program,
    });

    SimpleFs::build_image_with_headroom(
        zone.volume_label(),
        &entries,
        DATA_ZONE_EXTRA_INODES,
        DATA_ZONE_EXTRA_DIRENTS,
        DATA_ZONE_EXTRA_DATA_BLOCKS,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, any(feature = "demo-disk", test)))]
mod tests {
    use super::*;
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::simplefs::SimpleFsVolume;
    use crate::fs::vfs::FileSystem as VfsFileSystem;
    use crate::kernel::service;

    /// Read a whole file out of a freshly built zone image.
    fn read_from_zone(image: Vec<u8>, path: &str) -> Vec<u8> {
        let device = MemoryBlockDevice::new("system", image, true);
        let volume = SimpleFsVolume::new(SimpleFs::open(device, true).expect("open the zone"));
        let node = volume.lookup(path).expect("the entry");
        let mut buffer = alloc::vec![0u8; node.size()];
        let read = node.read(0, &mut buffer).expect("read the entry");
        buffer.truncate(read);
        buffer
    }

    #[test]
    fn the_demo_disk_carries_the_system_pair_with_the_newer_slot_committed() {
        // The demo boots through its own MBR layout, so this is the disk a
        // boot actually reads: both system slots present, and B committed as
        // the newer build, which is what makes the boot take it.
        let disk: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> =
            crate::fs::block::MemoryBlockDevice::new("demo-disk", build_demo_disk_image(), true);

        let slots = crate::fs::system_image::system_slots(&disk, true).expect("slots");
        assert_eq!(slots.len(), 2, "{:?}", slots.len());

        let active = crate::fs::system_image::select_system_slot(&slots).expect("active");
        assert_eq!(active.slot, crate::fs::system_image::SYSTEM_SLOT_B);
        assert_eq!(
            active.build,
            Some(crate::fs::system_image::SystemBuild {
                generation: DEMO_SYSTEM_SLOT_B_GENERATION
            })
        );

        // The other zones are the disk's business too: the data zone carries
        // the file every writable-zone test opens.
        let partitions = crate::fs::partition::read_mbr_partitions(disk.as_ref())
            .expect("read the MBR")
            .expect("an MBR");
        let data = partitions[StorageZone::Data.partition_slot()].expect("a data partition");
        let data_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> =
            crate::fs::block::BlockSliceDevice::new(
                "data",
                disk.clone(),
                data.start_block,
                data.block_count,
                false,
            );
        let volume = crate::fs::simplefs::SimpleFs::open(data_device, true).expect("open data");
        let volume = crate::fs::simplefs::SimpleFsVolume::new(volume);
        use crate::fs::vfs::FileSystem as _;
        assert!(
            volume.lookup("/etc/.directory").is_ok(),
            "the data zone lost its directories"
        );

        // ...and the image the builder makes for that zone, on its own.
        let image_device: alloc::sync::Arc<dyn crate::fs::block::BlockDevice> =
            crate::fs::block::MemoryBlockDevice::new(
                "data-image",
                build_zone_image(StorageZone::Data),
                false,
            );
        let image_volume = crate::fs::simplefs::SimpleFsVolume::new(
            crate::fs::simplefs::SimpleFs::open(image_device, true).expect("open image"),
        );
        assert!(
            image_volume.lookup("/etc/.directory").is_ok(),
            "the data zone image itself lost its directories"
        );
    }

    #[test]
    fn the_system_zone_ships_the_declarations_the_kernel_falls_back_to() {
        // The demo disk's `/system/rc.d` and the kernel's fallback are one
        // list in two forms.  If they were two lists, a boot would still work
        // — and would be running something the distribution never declared.
        let image = build_system_zone_from(b"init", DEMO_SYSTEM_SLOT_A_GENERATION)
            .expect("build the system zone");
        let text = read_from_zone(image, "/rc.d/defaults.toml");
        let text = core::str::from_utf8(&text).expect("the declarations are UTF-8");

        assert_eq!(
            service::parse_service_config(text).expect("parse the shipped declarations"),
            service::default_definitions()
        );
    }

    #[test]
    fn the_system_zone_still_carries_the_init_program_and_the_shared_files() {
        let image = build_system_zone_from(b"init", DEMO_SYSTEM_SLOT_A_GENERATION)
            .expect("build the system zone");
        assert_eq!(read_from_zone(image.clone(), "/init.elf"), b"init");
        assert!(!read_from_zone(image, "/runtime/README.txt").is_empty());
    }
}
