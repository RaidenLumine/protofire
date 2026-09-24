//! src/kernel/fs/demo/riscv64.rs
//!
//! The demo volume's riscv64 contents: which payloads it ships, the manifests
//! that describe them, and the init ELF the system zone carries — the assembly
//! shell, since the ring3 shell is not built for this target.

use super::*;

// riscv64 keeps the assembly shell fallback since ring3-shell isn't yet
// compiled for riscv64.
use crate::user::demo::demo_program_riscv64_elf::build_demo_program_artifact;

use crate::user::demo::demo_program_riscv64_elf::build_shell_program_artifact;

const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=riscv64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-riscv64-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-riscv64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

pub(super) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    let demo_program = build_demo_program_artifact();
    let shell_program = build_shell_program_artifact();
    let entries = apps_entries_riscv64(&demo_program.bytes, &shell_program.bytes);
    SimpleFs::build_image(zone.volume_label(), &entries)
}

/// The system zone: the shared files plus the assembly shell as the init ELF
/// (ring3-shell is not yet compiled for riscv64).
pub(super) fn system_zone_image() -> Result<Vec<u8>> {
    let shell = build_shell_program_artifact();
    super::build_system_zone_from(&shell.bytes)
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
