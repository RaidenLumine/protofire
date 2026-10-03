//! src/fs/demo/aarch64.rs
//!
//! The demo volume's aarch64 contents: which payloads it ships, the manifests
//! that describe them, and the placeholder ELFs the system zone carries.
//!
//! The builder that assembles a zone is in `super`; this is what it asks this
//! architecture for.

use super::*;

use crate::user::demo::demo_program_aarch64_elf::build_demo_program_artifact;

use crate::user::demo::demo_program_aarch64_elf::build_fault_demo_program_artifact;

use crate::user::demo::demo_program_aarch64_elf::build_rust_demo_program_artifact;

use crate::user::demo::demo_program_aarch64_elf::build_shell_program_artifact;

const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-aarch64-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_RUST_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-rust/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust\"\nargv = [\"demo-launcher-rust\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\", \"--runtime=rust\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust\", \"ASTRA_RUNTIME=ring3-aarch64-rust-payload\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust\"\n";

const DEMO_EXEC_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-exec\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-exec/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-exec\"\nargv = [\"demo-launcher-exec\"]\nenv = [\"ASTRA_EXEC=1\", \"ASTRA_APP_ID=demo-launcher-exec\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/demo-launcher-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-fault\"\nargv = [\"demo-launcher-fault\", \"--profile=demo\", \"--transport=serial\", \"--arch=aarch64\", \"--trigger-fault=code-write\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-fault\", \"ASTRA_RUNTIME=ring3-aarch64-fault\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

/// Shell launch manifest.  On this architecture the entry beside it really is
/// the shell: `crate::user::demo::shell_payload_aarch64` is a loadable ring-3
/// program, so the loader runs it and never reaches `host_proxy = "shell"`.
/// The entry stays because RISC-V has no ring-3 shell yet and its manifest does
/// route through `shell_user_main()`.
const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-aarch64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

pub(crate) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
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

// Code tail (file offset 0x78..0x97, matching the PT_LOAD below) is a minimal
// `exit(0)` under the AArch64 syscall ABI (number in x8, args in x0-x5):
//   mov x8, #3    ; SyscallNumber::Exit
//   mov x0, #0    ; exit status 0
//   mov x1..x5, #0 ; trailing args must be zero or `exit` rejects (see below)
//   svc #0        ; terminate (kernel does not return to the stub)
// The EL0 startup context loads x1 = argv pointer and x2 = envp pointer (both
// nonzero stack addresses); the `exit` handler validates that every arg past
// x0 is zero, so an uncleaned x1/x2 makes it return InvalidArgument and the
// stub falls into zero-fill and dies with an undefined-instruction (ec=0x00)
// abort at the end of the image.  The PT_LOAD p_filesz/p_memsz must cover the
// `svc`, otherwise the same truncation happens.
/// The system zone's init program: `exit(0)`, and nothing else.
///
/// Shipped only where the build cannot carry an ELF payload section (see the
/// x86_64 copy): machine code, wrapped into an ELF by `elf_builder` rather than
/// by a header written out by hand here.
#[cfg(not(any(target_os = "linux", target_os = "none")))]
const DEMO_STUB_PAYLOAD_AARCH64: [u8; 32] = [
    0x68, 0x00, 0x80, 0xd2, // movz x8, #3 — exit
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0 — with status 0
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0
    0x02, 0x00, 0x80, 0xd2, // movz x2, #0
    0x03, 0x00, 0x80, 0xd2, // movz x3, #0
    0x04, 0x00, 0x80, 0xd2, // movz x4, #0
    0x05, 0x00, 0x80, 0xd2, // movz x5, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
];

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

/// The system zone: the shared files plus the init program at `/init.elf`.
///
/// The init program is the demo's own code, emitted into its section and
/// wrapped by the shared ELF builder: it reads `/system/rc.d` and asks for the
/// services to be started.  A host that cannot carry an ELF payload section
/// gets the exit-only stub below instead (see the x86_64 copy).
pub(crate) fn system_zone_image() -> Result<Vec<u8>> {
    let payload = super::init_payload_aarch64::payload_bytes();
    let entry_offset = super::init_payload_aarch64::payload_entry_offset();
    #[cfg(any(target_os = "linux", target_os = "none"))]
    let init = crate::user::demo::elf_builder::build_artifact_from_payload(
        payload,
        entry_offset,
        crate::user::program::DEMO_PROGRAM_ENTRY as u64,
        crate::user::program::DEMO_PROGRAM_MACHINE,
    );
    #[cfg(not(any(target_os = "linux", target_os = "none")))]
    let init = {
        let _ = (payload, entry_offset);
        crate::user::demo::elf_builder::build_artifact_from_payload(
            &DEMO_STUB_PAYLOAD_AARCH64,
            0,
            crate::user::program::DEMO_PROGRAM_ENTRY as u64,
            crate::user::program::DEMO_PROGRAM_MACHINE,
        )
    };
    super::build_system_zone_from(&init.bytes)
}
