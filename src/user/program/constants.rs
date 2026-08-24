//! src/user/program/constants.rs
//!
//! Path constants, page-size constants, and small utility functions shared across
//! the user-program loader, catalog resolution, and ELF-image planning layers.

// ── catalog / app paths ───────────────────────────────────────────────

// Shell paths are kept ungated because the kernel-resident shell module
// needs them for re-spawn and argv0 matching.
pub const SHELL_CATALOG_PATH: &str = "/apps/catalog/shell.toml";
pub const SHELL_CURRENT_PATH: &str = "/apps/current/shell.toml";
pub const SHELL_PROGRAM_PATH: &str = "/apps/packages/shell/bin/shell.elf";

// Demo-program paths are distribution-specific; they are gated behind the
// `demo-disk` feature so the kernel can be built without them.
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_CATALOG_PATH: &str = "/apps/catalog/demo-launcher.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_CURRENT_PATH: &str = "/apps/current/demo-launcher.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_PROGRAM_PATH: &str = "/apps/packages/demo-launcher/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_CATALOG_PATH: &str = "/apps/catalog/demo-launcher-rust.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_VERSIONED_CATALOG_PATH: &str = "/apps/catalog/demo-launcher-rust@0.1.0.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_CURRENT_PATH: &str = "/apps/current/demo-launcher-rust.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_PROGRAM_PATH: &str = "/apps/packages/demo-launcher-rust/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_CATALOG_PATH: &str = "/apps/catalog/demo-launcher-rust-io.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_CURRENT_PATH: &str = "/apps/current/demo-launcher-rust-io.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_PROGRAM_PATH: &str = "/apps/packages/demo-launcher-rust-io/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_FAULT_CATALOG_PATH: &str = "/apps/catalog/demo-launcher-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_FAULT_CURRENT_PATH: &str = "/apps/current/demo-launcher-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_FAULT_PROGRAM_PATH: &str = "/apps/packages/demo-launcher-fault/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_INVALID_OPCODE_CATALOG_PATH: &str =
    "/apps/catalog/demo-launcher-invalid-opcode.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_INVALID_OPCODE_CURRENT_PATH: &str =
    "/apps/current/demo-launcher-invalid-opcode.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_INVALID_OPCODE_PROGRAM_PATH: &str =
    "/apps/packages/demo-launcher-invalid-opcode/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_GENERAL_PROTECTION_CATALOG_PATH: &str =
    "/apps/catalog/demo-launcher-general-protection.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_GENERAL_PROTECTION_CURRENT_PATH: &str =
    "/apps/current/demo-launcher-general-protection.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_GENERAL_PROTECTION_PROGRAM_PATH: &str =
    "/apps/packages/demo-launcher-general-protection/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_ONE_SHOT_PAGE_FAULT_CATALOG_PATH: &str =
    "/apps/catalog/demo-launcher-one-shot-page-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_ONE_SHOT_PAGE_FAULT_CURRENT_PATH: &str =
    "/apps/current/demo-launcher-one-shot-page-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_ONE_SHOT_PAGE_FAULT_PROGRAM_PATH: &str =
    "/apps/packages/demo-launcher-one-shot-page-fault/bin/demo.elf";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_NESTED_PAGE_FAULT_CATALOG_PATH: &str =
    "/apps/catalog/demo-launcher-nested-page-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_NESTED_PAGE_FAULT_CURRENT_PATH: &str =
    "/apps/current/demo-launcher-nested-page-fault.toml";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_NESTED_PAGE_FAULT_PROGRAM_PATH: &str =
    "/apps/packages/demo-launcher-nested-page-fault/bin/demo.elf";

// ── demo data paths ───────────────────────────────────────────────────

#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_DATA_PATH: &str = "/data/users/guest/documents/readme.txt";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_SESSION_DIR: &str = "/data/users/guest/downloads/demo-state";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_SESSION_LOG_PATH: &str = "/data/users/guest/downloads/demo-state/demo-session.log";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_TEMP_PATH: &str = "/data/users/guest/downloads/demo-state/demo-temp.bin";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_DATA_PATH: &str = "/data/users/guest/downloads/ring3-rust-io.txt";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_STATE_DIR: &str = "/data/users/guest/downloads/rust-io-state";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_SESSION_PATH: &str = "/data/users/guest/downloads/rust-io-state/session.log";
#[cfg(any(feature = "demo-disk", test))]
pub const DEMO_RUST_IO_TEMP_PATH: &str = "/data/users/guest/downloads/rust-io-state/temp.bin";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_DATA_PAYLOAD: &[u8] = b"rust io data path roundtrip";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_SESSION_PAYLOAD: &[u8] = b"rust io session persisted";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_SESSION_TRUNCATED: &[u8] = b"rust io session";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_TEMP_PAYLOAD: &[u8] = b"temporary rust io state";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_CHILD_ARGV0: &str = "demo-launcher-rust-child";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_CHILD_ARGV1: &str = "--spawned-by=rust-io";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_CHILD_ENV0: &str = "ASTRA_APP_ID=demo-launcher-rust-child";
#[cfg(any(feature = "demo-disk", test))]
pub(crate) const DEMO_RUST_IO_CHILD_ENV1: &str = "ASTRA_PARENT=demo-launcher-rust-io";

// ── installed-app roots ───────────────────────────────────────────────

// Installed applications live under `/apps` with versioned catalogs in
// `/apps/catalog`, active redirects in `/apps/current`, and package payloads
// in `/apps/packages`.
pub(crate) const INSTALLED_CATALOG_ROOT: &str = "/apps/catalog";
pub(crate) const INSTALLED_CURRENT_ROOT: &str = "/apps/current";
pub(crate) const INSTALLED_PACKAGE_ROOT: &str = "/apps/packages";
pub(crate) const MAX_CATALOG_REDIRECT_DEPTH: usize = 8;

// ── ELF / page-size constants ─────────────────────────────────────────

// Keep the demo ELF well above the low kernel image/heap window so the
// bare-metal combined process root can map it without colliding with the
// runtime kernel address space.
pub const DEMO_PROGRAM_ENTRY: usize = 0x0000_0001_0000_1000;
pub const DEMO_PROGRAM_FORMAT: &str = current_program_format();
pub const DEMO_PROGRAM_MACHINE: u16 = current_machine();
pub const USER_PAGE_SIZE: usize = 4096;
pub const USER_STACK_GUARD_SIZE: usize = USER_PAGE_SIZE;
pub const USER_STACK_SIZE: usize = 256 * 1024;
pub const USER_EXCEPTION_STACK_GUARD_SIZE: usize = USER_PAGE_SIZE;
pub const USER_EXCEPTION_STACK_SIZE: usize = 64 * 1024;
pub const USER_IMAGE_STACK_GAP: usize = 64 * 1024;
pub const X86_64_USER_STACK_TOP: usize = 0x0000_7FFF_FFFF_F000;

// ── ASLR constants ──────────────────────────────────────────────────────────
// Random slides applied at ELF load time to randomize the process address
// space.  Only active on bare metal (`target_os = "none"`); host tests get
// zero slide for deterministic behaviour.

/// Maximum random slide for the ELF base address (page-aligned bytes).
/// 1 MiB = 256 pages of entropy.
pub const ASLR_ELF_SLIDE_MAX: usize = 256 * USER_PAGE_SIZE; // 1 MiB

/// Maximum random slide for the user stack (page-aligned bytes).
/// 256 KiB = 64 pages of entropy.
pub const ASLR_STACK_SLIDE_MAX: usize = 64 * USER_PAGE_SIZE; // 256 KiB

// ── auxiliary vector constants ────────────────────────────────────────

pub(crate) const AUXV_AT_NULL: u64 = 0;
pub(crate) const AUXV_AT_PAGESZ: u64 = 6;
pub(crate) const AUXV_AT_ENTRY: u64 = 9;
#[cfg(target_arch = "x86_64")]
pub(crate) const X86_64_AUXV_AT_PAGESZ: u64 = AUXV_AT_PAGESZ;
#[cfg(target_arch = "x86_64")]
pub(crate) const X86_64_AUXV_AT_ENTRY: u64 = AUXV_AT_ENTRY;

// ── const fns ─────────────────────────────────────────────────────────

pub(crate) const fn current_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        0x3E
    }

    #[cfg(target_arch = "aarch64")]
    {
        0xB7
    }

    #[cfg(target_arch = "riscv64")]
    {
        0xF3 // EM_RISCV
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        0
    }
}

pub(crate) const fn current_program_format() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "elf64-x86_64-user"
    }

    #[cfg(target_arch = "aarch64")]
    {
        "elf64-aarch64-user"
    }

    #[cfg(target_arch = "riscv64")]
    {
        "elf64-riscv64-user"
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        "elf64-user"
    }
}

pub(crate) const fn default_user_stack_top() -> usize {
    X86_64_USER_STACK_TOP
}

// ── alignment / range utilities ───────────────────────────────────────

pub(crate) const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

pub(crate) const fn is_page_aligned(value: usize) -> bool {
    value & (USER_PAGE_SIZE - 1) == 0
}

pub(crate) fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|aligned| align_down(aligned, align))
}

pub(crate) const fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}
