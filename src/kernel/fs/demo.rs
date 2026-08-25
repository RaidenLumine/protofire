//! src/kernel/fs/demo.rs
//!
//! Demo filesystem image and layout builders used for boot/runtime sample data.
//!
//! ═══════════════════════════════════════════════════════════════════════════
//! LEGACY MODULE — prefer alternatives for new code:
//!   - `test_support::build_test_zone_image` for tests that just need a valid
//!     SimpleFs image (avoids pulling in assembly payload sections).
//!   - `SimpleFs::build_image` / `SimpleFs::build_image_with_headroom` for
//!     constructing SimpleFs images directly.
//!
//! This module is kept for:
//!   1. `build_demo_memory_device()` → `fs.init()` boot path (path_helpers.rs)
//!   2. Kernel-side MBR boot disk tests in `filesystem/tests.rs`
//!   3. `build_demo_disk_image()` linker retention call in `main.rs`
//!
//! ═══════════════════════════════════════════════════════════════════════════

use alloc::vec;
use alloc::vec::Vec;

#[cfg(target_arch = "aarch64")]
use crate::user::demo::demo_program_aarch64_elf::build_demo_program_artifact;
#[cfg(target_arch = "aarch64")]
use crate::user::demo::demo_program_aarch64_elf::build_fault_demo_program_artifact;
#[cfg(target_arch = "aarch64")]
use crate::user::demo::demo_program_aarch64_elf::build_rust_demo_program_artifact;
#[cfg(target_arch = "aarch64")]
use crate::user::demo::demo_program_aarch64_elf::build_shell_program_artifact;
// riscv64 keeps the assembly shell fallback since ring3-shell isn't yet
// compiled for riscv64.
#[cfg(target_arch = "riscv64")]
use crate::user::demo::demo_program_riscv64_elf::build_demo_program_artifact;
#[cfg(target_arch = "riscv64")]
use crate::user::demo::demo_program_riscv64_elf::build_shell_program_artifact;
#[cfg(target_arch = "x86_64")]
use crate::user::demo::demo_program_x86_64_elf::build_demo_program_artifact;
#[cfg(target_arch = "x86_64")]
use crate::user::demo::demo_program_x86_64_elf::build_rust_demo_program_artifact;
#[cfg(target_arch = "x86_64")]
use crate::user::demo::demo_program_x86_64_elf::build_rust_io_demo_program_artifact;
#[cfg(target_arch = "x86_64")]
use crate::user::demo::demo_program_x86_64_elf::build_shell_program_artifact;

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

const DATA_ZONE_EXTRA_INODES: usize = 64;
const DATA_ZONE_EXTRA_DIRENTS: usize = 128;
const DATA_ZONE_EXTRA_DATA_BLOCKS: usize = 256;

#[cfg(target_arch = "x86_64")]
const APPS_ZONE_EXTRA_INODES: usize = 32;
#[cfg(target_arch = "x86_64")]
const APPS_ZONE_EXTRA_DIRENTS: usize = 64;
#[cfg(target_arch = "x86_64")]
const APPS_ZONE_EXTRA_DATA_BLOCKS: usize = 128;

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

// These manifests are the exact on-disk payloads consumed by the catalog and
// launcher parsers, so the demo disk exercises the same metadata path as a
// future real installer.
#[cfg(target_arch = "x86_64")]
const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "aarch64")]
const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-aarch64-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "aarch64")]
const DEMO_RUST_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-rust/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust\"\nargv = [\"demo-launcher-rust\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\", \"--runtime=rust\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust\", \"ASTRA_RUNTIME=ring3-aarch64-rust-payload\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust\"\n";
#[cfg(target_arch = "aarch64")]
const DEMO_EXEC_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-exec\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-exec/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-exec\"\nargv = [\"demo-launcher-exec\"]\nenv = [\"ASTRA_EXEC=1\", \"ASTRA_APP_ID=demo-launcher-exec\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "aarch64")]
const DEMO_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-fault\"\nargv = [\"demo-launcher-fault\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\", \"--trigger-fault=code-write\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-fault\", \"ASTRA_RUNTIME=ring3-aarch64-fault\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_RUST_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-rust/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust\"\nargv = [\"demo-launcher-rust\", \"--profile=demo\", \"--transport=serial\", \"--runtime=rust\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust\", \"ASTRA_RUNTIME=ring3-rust-payload\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_RUST_IO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust-io\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-rust-io/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust-io\"\nargv = [\"demo-launcher-rust-io\", \"--profile=demo\", \"--transport=serial\", \"--runtime=rust-io\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust-io\", \"ASTRA_RUNTIME=ring3-rust-io\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust-io\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-fault\"\nargv = [\"demo-launcher-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_INVALID_OPCODE_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-invalid-opcode\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-invalid-opcode/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-invalid-opcode\"\nargv = [\"demo-launcher-invalid-opcode\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=ud2\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-invalid-opcode\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_GENERAL_PROTECTION_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-general-protection\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-general-protection/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-general-protection\"\nargv = [\"demo-launcher-general-protection\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=gp\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-general-protection\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_ONE_SHOT_PAGE_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-one-shot-page-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-one-shot-page-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-one-shot-page-fault\"\nargv = [\"demo-launcher-one-shot-page-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page-one-shot\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-one-shot-page-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";
#[cfg(target_arch = "x86_64")]
const DEMO_NESTED_PAGE_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-nested-page-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-nested-page-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-nested-page-fault\"\nargv = [\"demo-launcher-nested-page-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page-nested\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-nested-page-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

/// Shell launch manifest.  The shell ELF is metadata-only (no PT_LOAD segments)
/// so the loader always falls back to the `host_proxy = "shell"` path, which
/// maps to `shell_user_main()` on all platforms.
#[cfg(target_arch = "x86_64")]
const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";
#[cfg(target_arch = "aarch64")]
const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

// ── RISC-V 64 manifests ─────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=riscv64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-riscv64-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

#[cfg(target_arch = "riscv64")]
const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

pub fn build_zone_image(zone: StorageZone) -> Vec<u8> {
    // Build each logical zone independently so a failure in demo app packaging
    // can degrade to a readable placeholder image instead of breaking disk
    // discovery for the entire boot flow.
    #[cfg(target_os = "none")]
    let heap_before = crate::kernel::memory::heap::heap_model().remaining();

    let image = match zone {
        StorageZone::System => build_system_zone_image(),
        StorageZone::Apps => build_apps_zone_image(zone),
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
        let heap_after = crate::kernel::memory::heap::heap_model().remaining();
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

#[cfg(target_arch = "x86_64")]
fn build_apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    #[cfg(target_os = "none")]
    let h = || crate::kernel::memory::heap::heap_model().remaining();

    let demo_program = build_demo_program_artifact();
    #[cfg(target_os = "none")]
    crate::println!(
        "[heap]   after demo_program artifact ({} KiB): {} KiB free",
        demo_program.bytes.len() / 1024,
        h() / 1024
    );

    let rust_demo_program = build_rust_demo_program_artifact();
    #[cfg(target_os = "none")]
    crate::println!(
        "[heap]   after rust_demo artifact ({} KiB): {} KiB free",
        rust_demo_program.bytes.len() / 1024,
        h() / 1024
    );

    let rust_io_demo_program = build_rust_io_demo_program_artifact();
    #[cfg(target_os = "none")]
    crate::println!(
        "[heap]   after rust_io_demo artifact ({} KiB): {} KiB free",
        rust_io_demo_program.bytes.len() / 1024,
        h() / 1024
    );

    // Assembly shell is kept for the apps zone (catalog entries expect it).
    // The placeholder ring3 ELF is used as /init.elf in the system zone instead.
    let shell_program = build_shell_program_artifact();
    #[cfg(target_os = "none")]
    crate::println!(
        "[heap]   after shell artifact ({} KiB): {} KiB free",
        shell_program.bytes.len() / 1024,
        h() / 1024
    );

    let entries = apps_entries(
        &demo_program.bytes,
        &rust_demo_program.bytes,
        &rust_io_demo_program.bytes,
        &shell_program.bytes,
    );
    #[cfg(target_os = "none")]
    crate::println!("[heap]   after entries array: {} KiB free", h() / 1024);

    let result = SimpleFs::build_image_with_headroom(
        zone.volume_label(),
        &entries,
        APPS_ZONE_EXTRA_INODES,
        APPS_ZONE_EXTRA_DIRENTS,
        APPS_ZONE_EXTRA_DATA_BLOCKS,
    );
    #[cfg(target_os = "none")]
    crate::println!(
        "[heap]   after build_image (result {}): {} KiB free",
        if result.is_ok() { "ok" } else { "err" },
        h() / 1024
    );
    result
}

#[cfg(target_arch = "aarch64")]
fn build_apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    let demo_program = build_demo_program_artifact();
    let rust_demo_program = build_rust_demo_program_artifact();
    let fault_program = build_fault_demo_program_artifact();
    let shell_program = build_shell_program_artifact();

    let entries = apps_entries_aarch64(
        &demo_program.bytes,
        &rust_demo_program.bytes,
        &fault_program.bytes,
        &shell_program.bytes,
    );
    SimpleFs::build_image(zone.volume_label(), &entries)
}

#[cfg(target_arch = "riscv64")]
fn build_apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    let demo_program = build_demo_program_artifact();
    let shell_program = build_shell_program_artifact();
    let entries = apps_entries_riscv64(&demo_program.bytes, &shell_program.bytes);
    SimpleFs::build_image(zone.volume_label(), &entries)
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn build_apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    const PLACEHOLDER_APPS_FILES: &[ImageEntry<'static>] = &[ImageEntry {
        path: "/README.txt",
        data: b"User demo payloads are currently unavailable on this target.\n",
    }];

    SimpleFs::build_image(zone.volume_label(), PLACEHOLDER_APPS_FILES)
}

/// Build the system zone image, including the placeholder ring3 ELF at
/// `/init.elf` so the kernel can find it at `/system/init.elf` — the default
/// init path (`DEFAULT_INIT_PATH`).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn build_system_zone_image() -> Result<Vec<u8>> {
    let mut entries: alloc::vec::Vec<ImageEntry<'_>> = alloc::vec::Vec::new();
    for entry in SYSTEM_FILES {
        entries.push(*entry);
    }
    // Place the placeholder ring3 ELF as /init.elf (mounted at /system/init.elf).
    let shell_init = demo_stub_elf_for_target();
    entries.push(ImageEntry {
        path: "/init.elf",
        data: shell_init,
    });
    SimpleFs::build_image(StorageZone::System.volume_label(), &entries)
}

/// Build the system zone image, using the assembly shell as the init ELF
/// (ring3-shell is not yet compiled for riscv64).
#[cfg(target_arch = "riscv64")]
fn build_system_zone_image() -> Result<Vec<u8>> {
    let mut entries: alloc::vec::Vec<ImageEntry<'_>> = alloc::vec::Vec::new();
    for entry in SYSTEM_FILES {
        entries.push(*entry);
    }
    let shell = build_shell_program_artifact();
    entries.push(ImageEntry {
        path: "/init.elf",
        data: &shell.bytes,
    });
    SimpleFs::build_image(StorageZone::System.volume_label(), &entries)
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn build_system_zone_image() -> Result<Vec<u8>> {
    SimpleFs::build_image(StorageZone::System.volume_label(), SYSTEM_FILES)
}

// ── Placeholder ring3 demo ELFs ────────────────────────────────────────
//
// The demo disk ships a few ring3 "apps" (shell, demo-launcher, …) and
// /system/init.elf.  Their real binaries (ring3-shell, …) are not built in
// this repository, so we embed minimal `exit(0)` ELF stubs in their place.
// These bytes were previously generated at build time (which silently fell
// back to stubs when the real ELFs were absent); they are now generated here
// so the placeholder is explicit and local.  Swap them for real ring3 binaries
// once those are built in-tree.

#[cfg(target_arch = "x86_64")]
const DEMO_STUB_ELF_X86_64: [u8; 130] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x31, 0xff, 0xcd,
    0x80, 0xf4,
];

#[cfg(target_arch = "aarch64")]
const DEMO_STUB_ELF_AARCH64: [u8; 136] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xb7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xd2, 0x60, 0x00, 0x80, 0xd2,
    0x01, 0x00, 0x00, 0xd4, 0x1f, 0x20, 0x03, 0xd5,
];

/// Return the placeholder ring3 demo ELF bytes for the current architecture.
#[cfg(target_arch = "x86_64")]
fn demo_stub_elf_for_target() -> &'static [u8] {
    &DEMO_STUB_ELF_X86_64
}

#[cfg(target_arch = "aarch64")]
fn demo_stub_elf_for_target() -> &'static [u8] {
    &DEMO_STUB_ELF_AARCH64
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

#[cfg(target_arch = "x86_64")]
fn apps_entries<'a>(
    demo_program_elf: &'a [u8],
    rust_demo_program_elf: &'a [u8],
    rust_io_demo_program_elf: &'a [u8],
    shell_program_elf: &'a [u8],
) -> [ImageEntry<'a>; 46] {
    // Mirror the installed-app layout used by the launch core:
    // - /catalog holds versioned and alias records
    // - /current holds active-entry aliases
    // - /packages holds manifests and payloads
    // Several fault demos reuse the same ELF and switch behavior through
    // manifest argv/env so the runtime path, not the binary bytes, is what gets
    // exercised.
    [
        ImageEntry {
            path: "/catalog/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust.toml",
            data: b"id = \"demo-launcher-rust\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-rust@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust-io.toml",
            data: b"id = \"demo-launcher-rust-io\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-rust-io@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-fault.toml",
            data: b"id = \"demo-launcher-fault\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-invalid-opcode.toml",
            data: b"id = \"demo-launcher-invalid-opcode\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-invalid-opcode@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-general-protection.toml",
            data: b"id = \"demo-launcher-general-protection\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-general-protection@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-one-shot-page-fault.toml",
            data: b"id = \"demo-launcher-one-shot-page-fault\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-one-shot-page-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-nested-page-fault.toml",
            data: b"id = \"demo-launcher-nested-page-fault\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-nested-page-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher@0.1.0.toml",
            data: b"id = \"demo-launcher\"\nmanifest = \"/apps/packages/demo-launcher/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust@0.1.0.toml",
            data: b"id = \"demo-launcher-rust\"\nmanifest = \"/apps/packages/demo-launcher-rust/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust-io@0.1.0.toml",
            data: b"id = \"demo-launcher-rust-io\"\nmanifest = \"/apps/packages/demo-launcher-rust-io/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-fault@0.1.0.toml",
            data: b"id = \"demo-launcher-fault\"\nmanifest = \"/apps/packages/demo-launcher-fault/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-invalid-opcode@0.1.0.toml",
            data: b"id = \"demo-launcher-invalid-opcode\"\nmanifest = \"/apps/packages/demo-launcher-invalid-opcode/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-general-protection@0.1.0.toml",
            data: b"id = \"demo-launcher-general-protection\"\nmanifest = \"/apps/packages/demo-launcher-general-protection/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-one-shot-page-fault@0.1.0.toml",
            data: b"id = \"demo-launcher-one-shot-page-fault\"\nmanifest = \"/apps/packages/demo-launcher-one-shot-page-fault/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-nested-page-fault@0.1.0.toml",
            data: b"id = \"demo-launcher-nested-page-fault\"\nmanifest = \"/apps/packages/demo-launcher-nested-page-fault/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-rust.toml",
            data: b"id = \"demo-launcher-rust\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-rust@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-rust-io.toml",
            data: b"id = \"demo-launcher-rust-io\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-rust-io@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-fault.toml",
            data: b"id = \"demo-launcher-fault\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-invalid-opcode.toml",
            data: b"id = \"demo-launcher-invalid-opcode\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-invalid-opcode@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-general-protection.toml",
            data: b"id = \"demo-launcher-general-protection\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-general-protection@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-one-shot-page-fault.toml",
            data: b"id = \"demo-launcher-one-shot-page-fault\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-one-shot-page-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-nested-page-fault.toml",
            data: b"id = \"demo-launcher-nested-page-fault\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-nested-page-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/demo-launcher/manifest.toml",
            data: DEMO_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust/manifest.toml",
            data: DEMO_RUST_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust-io/manifest.toml",
            data: DEMO_RUST_IO_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-fault/manifest.toml",
            data: DEMO_FAULT_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-invalid-opcode/manifest.toml",
            data: DEMO_INVALID_OPCODE_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-general-protection/manifest.toml",
            data: DEMO_GENERAL_PROTECTION_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-one-shot-page-fault/manifest.toml",
            data: DEMO_ONE_SHOT_PAGE_FAULT_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-nested-page-fault/manifest.toml",
            data: DEMO_NESTED_PAGE_FAULT_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust/bin/demo.elf",
            data: rust_demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust-io/bin/demo.elf",
            data: rust_io_demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-fault/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-invalid-opcode/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-general-protection/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-one-shot-page-fault/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-nested-page-fault/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/runtime/java/README.txt",
            data: b"JDK is still not bundled. A real JVM port requires stable user-space ABI, virtual memory, threads, networking, and graphics.\n",
        },
        ImageEntry {
            path: "/catalog/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"./shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/shell@0.1.0.toml",
            data: b"id = \"shell\"\nmanifest = \"/apps/packages/shell/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/shell/manifest.toml",
            data: SHELL_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/shell/bin/shell.elf",
            data: shell_program_elf,
        },
    ]
}

#[cfg(target_arch = "aarch64")]
fn apps_entries_aarch64<'a>(
    demo_program_elf: &'a [u8],
    rust_program_elf: &'a [u8],
    fault_program_elf: &'a [u8],
    shell_program_elf: &'a [u8],
) -> [ImageEntry<'a>; 27] {
    // The AArch64 payload set is smaller but preserves the same catalog/current/
    // package split so launch logic stays architecture-agnostic.
    [
        ImageEntry {
            path: "/README.txt",
            data: b"AArch64 apps volume: assembly launcher, a Rust wait/decode launcher, an exec target, and a fault-child demo for EL0 exec/wait/termination validation.\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust.toml",
            data: b"id = \"demo-launcher-rust\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-rust@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-exec.toml",
            data: b"id = \"demo-launcher-exec\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-exec@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-fault.toml",
            data: b"id = \"demo-launcher-fault\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher@0.1.0.toml",
            data: b"id = \"demo-launcher\"\nmanifest = \"/apps/packages/demo-launcher/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-rust@0.1.0.toml",
            data: b"id = \"demo-launcher-rust\"\nmanifest = \"/apps/packages/demo-launcher-rust/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-exec@0.1.0.toml",
            data: b"id = \"demo-launcher-exec\"\nmanifest = \"/apps/packages/demo-launcher-exec/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-fault@0.1.0.toml",
            data: b"id = \"demo-launcher-fault\"\nmanifest = \"/apps/packages/demo-launcher-fault/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/appctl.toml",
            data: b"id = \"appctl\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/appctl@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/app-center.toml",
            data: b"id = \"app-center\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/app-center@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-rust.toml",
            data: b"id = \"demo-launcher-rust\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-rust@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-exec.toml",
            data: b"id = \"demo-launcher-exec\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-exec@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-fault.toml",
            data: b"id = \"demo-launcher-fault\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-fault@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/appctl/manifest.toml",
            data: APPCTL_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/app-center/manifest.toml",
            data: APP_CENTER_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher/manifest.toml",
            data: DEMO_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust/manifest.toml",
            data: DEMO_RUST_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-exec/manifest.toml",
            data: DEMO_EXEC_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-fault/manifest.toml",
            data: DEMO_FAULT_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/appctl/bin/demo.elf",
            data: appctl_elf,
        },
        ImageEntry {
            path: "/packages/app-center/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-rust/bin/demo.elf",
            data: rust_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-exec/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/packages/demo-launcher-fault/bin/demo.elf",
            data: fault_program_elf,
        },
        ImageEntry {
            path: "/runtime/java/README.txt",
            data: b"JDK is still not bundled. A real JVM port requires stable user-space ABI, virtual memory, threads, networking, and graphics.\n",
        },
        ImageEntry {
            path: "/catalog/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"./shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/shell@0.1.0.toml",
            data: b"id = \"shell\"\nmanifest = \"/apps/packages/shell/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/shell/manifest.toml",
            data: SHELL_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/shell/bin/shell.elf",
            data: shell_program_elf,
        },
    ]
}

// ── RISC-V 64 apps entries ───────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
fn apps_entries_riscv64<'a>(
    demo_program_elf: &'a [u8],
    shell_program_elf: &'a [u8],
) -> [ImageEntry<'a>; 12] {
    // Minimal catalog for RISC-V bring-up: demo launcher + shell.
    [
        ImageEntry {
            path: "/README.txt",
            data: b"RISC-V 64 apps volume: demo launcher and shell.\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher@0.1.0.toml",
            data: b"id = \"demo-launcher\"\nmanifest = \"/apps/packages/demo-launcher/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher.toml",
            data: b"id = \"demo-launcher\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/demo-launcher/manifest.toml",
            data: DEMO_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher/bin/demo.elf",
            data: demo_program_elf,
        },
        ImageEntry {
            path: "/runtime/java/README.txt",
            data: b"JDK is still not bundled.\n",
        },
        ImageEntry {
            path: "/catalog/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"./shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/shell@0.1.0.toml",
            data: b"id = \"shell\"\nmanifest = \"/apps/packages/shell/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/shell.toml",
            data: b"id = \"shell\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/shell@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/shell/manifest.toml",
            data: SHELL_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/shell/bin/shell.elf",
            data: shell_program_elf,
        },
    ]
}
