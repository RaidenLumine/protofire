//! src/arch/x86_64/kaslr.rs
//!
//! Kernel Address Space Layout Randomisation for x86_64.
//!
//! This module is where kernel self-relocation at boot time would live; it is
//! a stub today (see Current status).
//!
//! ## Current status
//!
//! KASLR is **disabled**: [`try_relocate`] and [`is_relocated`] answer "not
//! relocated" and nothing calls them, and the relocation loop is not
//! restored.  What enabling it needs:
//!
//! 1. A large image.  A debug build's `.bss` is 67.5 MiB (measured), so
//!    relocating the full image makes the destination range overlap the source
//!    and BSS has to be skipped and re-zeroed at the new base.
//!
//! 2. The relocation table is proven but not applied anywhere.  The generator
//!    keeps a record only when the bytes at its site are the symbol's
//!    `st_value` plus the record's addend, reports what it drops by reason, and
//!    `make check-kaslr-relocs` fails when an address the kernel stores — the
//!    frame pool's two ends, the image's end — is missing from the table.  What
//!    no gate covers is the runtime half: copying an image, applying the table,
//!    and booting the result.
//!
//! 3. A delta the entry path can know.  The kernel's own ranges come from
//!    link-time symbols, and the compiler folds their addresses into immediates
//!    — `runtime_kernel_page_plan` contains `mov $0x2489c000,%rax`, an
//!    immediate the table itself lists as `__bss_end + 0x1000` (both measured).
//!    The relocation table rewrites such values, but no symbol can tell the
//!    boot what to rewrite them *by*: every symbol moves with the image.  The
//!    relocator has to pass the base it chose, and the bootstrap identity map
//!    has to cover both the link-time and the relocated address until the
//!    switch.
//!
//! When those are resolved, enable KASLR by restoring the body of
//! `try_relocate` and the relocation loop.
//!
//! ## Architecture
//!
//! On boot the kernel is loaded at `KERNEL_LOAD_ADDRESS` (0x200000) by
//! GRUB / QEMU `-kernel`.  This module would copy text+rodata+data to a
//! random 2 MiB-aligned physical address, zero BSS there, adjust absolute
//! addresses via a pre-computed relocation table, and jump to the relocated
//! `kernel_entry`.  The identity map (active during early boot) must cover
//! both the original and new locations.
//!
//! The relocation table is proven at generation time rather than filtered by
//! guess: `tools/gen-kaslr-relocs` keeps a record only when the bytes at its
//! site are the named symbol's `st_value` plus the record's addend — a record
//! the linker did not apply cannot pass that equality, whatever its bytes
//! look like — and `make check-kaslr-relocs` holds the table to that proof
//! and to the addresses the kernel stores.

// ── Public API ──────────────────────────────────────────────────────────

/// Try to relocate the kernel to a random base address.
///
/// Currently disabled in debug builds.  See module-level docs.
pub fn try_relocate(_magic: u32, _info: u32) -> usize {
    0
}

/// Whether this invocation is running from a KASLR-relocated image.
pub fn is_relocated() -> bool {
    false
}
