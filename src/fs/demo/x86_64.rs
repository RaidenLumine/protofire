//! src/fs/demo/x86_64.rs
//!
//! The demo volume's x86_64 contents: which payloads it ships, the manifests
//! that describe them, and the placeholder ELFs the system zone carries.
//!
//! The builder that assembles a zone is in `super`; this is what it asks this
//! architecture for.

use super::*;

use crate::user::demo::demo_program_x86_64_elf::build_demo_program_artifact;

use crate::user::demo::demo_program_x86_64_elf::build_rust_demo_program_artifact;

use crate::user::demo::demo_program_x86_64_elf::build_rust_io_demo_program_artifact;

use crate::user::demo::demo_program_x86_64_elf::build_shell_program_artifact;

const APPS_ZONE_EXTRA_INODES: usize = 32;

const APPS_ZONE_EXTRA_DIRENTS: usize = 64;

const APPS_ZONE_EXTRA_DATA_BLOCKS: usize = 128;

// These manifests are the exact on-disk payloads consumed by the catalog and
// launcher parsers, so the demo disk exercises the same metadata path as a
// future real installer.
const DEMO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher\"\nargv = [\"demo-launcher\", \"--profile=demo\", \"--transport=serial\"]\nenv = [\"ASTRA_APP_ID=demo-launcher\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_RUST_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-rust/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust\"\nargv = [\"demo-launcher-rust\", \"--profile=demo\", \"--transport=serial\", \"--runtime=rust\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust\", \"ASTRA_RUNTIME=ring3-rust-payload\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust\"\n";

const DEMO_RUST_IO_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-rust-io\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-rust-io/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-rust-io\"\nargv = [\"demo-launcher-rust-io\", \"--profile=demo\", \"--transport=serial\", \"--runtime=rust-io\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-rust-io\", \"ASTRA_RUNTIME=ring3-rust-io\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-rust-io\"\n";

const DEMO_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-fault\"\nargv = [\"demo-launcher-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_INVALID_OPCODE_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-invalid-opcode\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-invalid-opcode/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-invalid-opcode\"\nargv = [\"demo-launcher-invalid-opcode\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=ud2\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-invalid-opcode\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_GENERAL_PROTECTION_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-general-protection\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-general-protection/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-general-protection\"\nargv = [\"demo-launcher-general-protection\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=gp\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-general-protection\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_ONE_SHOT_PAGE_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-one-shot-page-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-one-shot-page-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-one-shot-page-fault\"\nargv = [\"demo-launcher-one-shot-page-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page-one-shot\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-one-shot-page-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_NESTED_PAGE_FAULT_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-nested-page-fault\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-nested-page-fault/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-nested-page-fault\"\nargv = [\"demo-launcher-nested-page-fault\", \"--profile=demo\", \"--transport=serial\", \"--trigger-fault=page-nested\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-nested-page-fault\", \"ASTRA_RUNTIME=ring3-prototype\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher\"\n";

const DEMO_VIRGL_PROGRAM_MANIFEST: &[u8] = b"name = \"demo-launcher-virgl\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/demo-launcher-virgl/bin/demo.elf\"\nworking_dir = \"/apps/packages/demo-launcher-virgl\"\nargv = [\"demo-launcher-virgl\", \"--profile=demo\", \"--transport=serial\", \"--runtime=virgl\"]\nenv = [\"ASTRA_APP_ID=demo-launcher-virgl\", \"ASTRA_RUNTIME=ring3-virgl-proxy\", \"ASTRA_ZONE=/apps\"]\nhost_proxy = \"demo-launcher-virgl\"\n";

/// Shell launch manifest.  On this architecture the entry beside it really is
/// the shell: the payload in `crate::user::demo::shell_payload_x86_64` is a
/// loadable ring-3 program, so the loader runs it and never reaches
/// `host_proxy = "shell"`.  The entry stays because AArch64 and RISC-V have no
/// ring-3 shell yet, and their manifests do route through `shell_user_main()`.
const SHELL_PROGRAM_MANIFEST: &[u8] = b"name = \"shell\"\nversion = \"0.1.0\"\nformat = \"elf64-x86_64-user\"\nentry = \"/apps/packages/shell/bin/shell.elf\"\nworking_dir = \"/apps/packages/shell\"\nargv = [\"shell\"]\nenv = [\"ASTRA_APP_ID=shell\", \"ASTRA_RUNTIME=ring3-prototype\"]\nhost_proxy = \"shell\"\n";

pub(super) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    #[cfg(target_os = "none")]
    let h = || crate::memory::heap::heap_model().remaining();

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

    // The shell is a ring-3 program here, so this is the payload package that
    // `SHELL_PROGRAM_MANIFEST` launches — not a header the loader has to route
    // to the in-kernel Rust shell.  The bare stub ELF is used as /init.elf in
    // the system zone instead.
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

/// The system zone's init program: `exit(0)`, and nothing else.
///
/// A demo disk wants a program at `/system/init.elf` that does nothing — the
/// services the demo cares about are started by the kernel's own init — and
/// this is that program's machine code rather than a hand-written ELF around
/// it: `elf_builder` wraps the bytes the way it wraps every other demo
/// payload, so the header, the segment and the entry point come from one place
/// instead of two.
const DEMO_STUB_PAYLOAD_X86_64: [u8; 10] = [
    0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3 — exit
    0x31, 0xff, // xor edi, edi — with status 0
    0xcd, 0x80, // int 0x80
    0xf4, // hlt — reached only if the exit returned
];

fn apps_entries<'a>(
    demo_program_elf: &'a [u8],
    rust_demo_program_elf: &'a [u8],
    rust_io_demo_program_elf: &'a [u8],
    shell_program_elf: &'a [u8],
) -> [ImageEntry<'a>; 51] {
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
            path: "/catalog/demo-launcher-virgl.toml",
            data: b"id = \"demo-launcher-virgl\"\nversion = \"0.1.0\"\ncatalog = \"./demo-launcher-virgl@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/catalog/demo-launcher-virgl@0.1.0.toml",
            data: b"id = \"demo-launcher-virgl\"\nmanifest = \"/apps/packages/demo-launcher-virgl/manifest.toml\"\n",
        },
        ImageEntry {
            path: "/current/demo-launcher-virgl.toml",
            data: b"id = \"demo-launcher-virgl\"\nversion = \"0.1.0\"\ncatalog = \"../catalog/demo-launcher-virgl@0.1.0.toml\"\n",
        },
        ImageEntry {
            path: "/packages/demo-launcher-virgl/manifest.toml",
            data: DEMO_VIRGL_PROGRAM_MANIFEST,
        },
        ImageEntry {
            path: "/packages/demo-launcher-virgl/bin/demo.elf",
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

/// The system zone: the shared files plus the stub init program at
/// `/init.elf`.
pub(super) fn system_zone_image() -> Result<Vec<u8>> {
    let init = crate::user::demo::elf_builder::build_artifact_from_payload(
        &DEMO_STUB_PAYLOAD_X86_64,
        0,
        crate::user::program::DEMO_PROGRAM_ENTRY as u64,
        crate::user::program::DEMO_PROGRAM_MACHINE,
    );
    super::build_system_zone_from(&init.bytes)
}
