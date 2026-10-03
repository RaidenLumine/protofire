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
use super::layout::DEMO_DISK_TOTAL_BLOCKS;
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
        StorageZone::System => content::system_zone_image(),
        StorageZone::Apps => content::apps_zone_image(zone),
        StorageZone::Data => SimpleFs::build_image_with_headroom(
            zone.volume_label(),
            DATA_FILES,
            DATA_ZONE_EXTRA_INODES,
            DATA_ZONE_EXTRA_DIRENTS,
            DATA_ZONE_EXTRA_DATA_BLOCKS,
        ),
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
    let mut disk = vec![0_u8; DEMO_DISK_TOTAL_BLOCKS as usize * BLOCK_SIZE];
    let mut partitions: MbrPartitionTable = [None; 4];

    // The demo disk uses a fixed partition layout so boot code and tests can
    // discover the same zones through MBR parsing without depending on a host
    // filesystem.
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

/// Build the system zone from the shared files and one init ELF.
///
/// The caller passes the bytes rather than a name, because the two targets
/// that share this differ only in where their placeholder came from: what the
/// zone needs is the image, not the story behind it.
///
/// The ELF lands at `/init.elf` so the kernel finds it at `/system/init.elf`,
/// which is the default init path (`DEFAULT_INIT_PATH`).
pub(crate) fn build_system_zone_from(init_elf: &[u8]) -> Result<Vec<u8>> {
    let mut entries: alloc::vec::Vec<ImageEntry<'_>> = alloc::vec::Vec::new();
    for entry in SYSTEM_FILES {
        entries.push(*entry);
    }
    entries.push(ImageEntry {
        path: "/init.elf",
        data: init_elf,
    });
    SimpleFs::build_image(StorageZone::System.volume_label(), &entries)
}
