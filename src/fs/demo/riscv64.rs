//! src/fs/demo/riscv64.rs
//!
//! The demo volume's riscv64 contents: which payloads it ships, the manifests
//! that describe them, and the init ELF the system zone carries.

use super::*;

use crate::user::demo::demo_program_riscv64_elf::build_demo_program_artifact;

use crate::user::demo::demo_program_riscv64_elf::build_shell_program_artifact;

/// The system zone's init program: `exit(0)`, and nothing else.
///
/// It used to be the shell artifact, back when that artifact was metadata-only:
/// the loader then ran the in-kernel proxy, which is kernel code wearing the
/// shell's name, so having it as init only printed a prompt nobody typed at.
/// A ring-3 shell is not that — it reads the console — and an init copy of it
/// raced the apps-zone copy for every keystroke, with only one of the two
/// running on a stack the loader had set up for it.  The other two targets ship
/// a stub here for the same reason: init is not where a shell belongs.
/// The exit is followed by a spin, which is what this target's assembly
/// payloads do too (`demo_program_riscv64`'s exit block ends in `j 3b`):
/// falling off the end of a slot program is an illegal instruction, and the
/// point of a stub is to say nothing at all.
const DEMO_STUB_PAYLOAD_RISCV64: [u8; 16] = [
    0x93, 0x08, 0x30, 0x00, // addi a7, zero, 3 — exit
    0x13, 0x05, 0x00, 0x00, // addi a0, zero, 0 — with status 0
    0x73, 0x00, 0x00, 0x00, // ecall
    0x6f, 0x00, 0x00, 0x00, // j . — spin if it returns
];

const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=riscv64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-riscv64-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

pub(super) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    let demo_program = build_demo_program_artifact();
    let shell_program = build_shell_program_artifact();
    let entries = apps_entries_riscv64(&demo_program.bytes, &shell_program.bytes);
    SimpleFs::build_image(zone.volume_label(), &entries)
}

/// The system zone: the shared files plus the stub init program.
pub(super) fn system_zone_image() -> Result<Vec<u8>> {
    let init = crate::user::demo::elf_builder::build_artifact_from_payload(
        &DEMO_STUB_PAYLOAD_RISCV64,
        0,
        crate::user::program::DEMO_PROGRAM_ENTRY as u64,
        crate::user::program::DEMO_PROGRAM_MACHINE,
    );
    super::build_system_zone_from(&init.bytes)
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
