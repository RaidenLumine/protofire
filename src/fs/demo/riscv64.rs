//! src/fs/demo/riscv64.rs
//!
//! The demo volume's riscv64 contents: which payloads it ships, the manifests
//! that describe them, and the init ELF the system zone carries.

use super::*;

use crate::user::demo::demo_program_riscv64_elf::build_demo_program_artifact;

use crate::user::demo::demo_program_riscv64_elf::build_shell_program_artifact;

const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=riscv64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-riscv64-prototype\", \"ASTRA_ZONE=/apps\"]\n";

const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\n";

pub(crate) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    let demo_program = build_demo_program_artifact();
    let shell_program = build_shell_program_artifact();
    let entries = apps_entries_riscv64(&demo_program.bytes, &shell_program.bytes);
    // Headroom for what a running machine installs here: the zone is the one an
    // install writes, and an image built with no room for one would fail the
    // first install a fresh machine ever attempted.
    SimpleFs::build_image_with_headroom(
        zone.volume_label(),
        &entries,
        APPS_ZONE_EXTRA_INODES,
        APPS_ZONE_EXTRA_DIRENTS,
        APPS_ZONE_EXTRA_DATA_BLOCKS,
    )
}

/// The data zone: the shared files plus the package the boot installs.
pub(crate) fn data_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    super::build_data_zone_from(zone, &build_demo_program_artifact().bytes)
}

/// The system zone: the shared files plus the init program at `/init.elf`.
///
/// Init used to be the shell artifact, back when that artifact was
/// metadata-only and the loader routed it to the in-kernel proxy: kernel code
/// wearing the shell's name, printing a prompt nobody typed at.  A ring-3 shell
/// is not that — it reads the console — and an init copy of it raced the
/// apps-zone copy for every keystroke, with only one of the two running on a
/// stack the loader had set up for it.  Init is not where a shell belongs, and
/// it is not a stub any more either: it is the demo's own program, emitted into
/// its section and wrapped by the shared ELF builder, which reads
/// `/system/rc.d` and asks for the services to be started.
pub(crate) fn system_zone_image(generation: u64) -> Result<Vec<u8>> {
    let payload = super::init_payload_riscv64::payload_bytes();
    let entry_offset = super::init_payload_riscv64::payload_entry_offset();
    let init = crate::user::demo::elf_builder::build_artifact_from_payload(
        payload,
        entry_offset,
        crate::user::program::DEMO_PROGRAM_ENTRY as u64,
        crate::user::program::DEMO_PROGRAM_MACHINE,
    );
    super::build_system_zone_from(&init.bytes, generation)
}

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
