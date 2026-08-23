//! src/arch/x86_64/kaslr.rs
//! Kernel Address Space Layout Randomisation for x86_64.
//!
//! This module provides kernel self-relocation at boot time.
//!
//! ## Current status
//!
//! KASLR is **disabled** in debug builds because:
//!
//! 1. The kernel's BSS is ~52 MiB in debug builds (contains large embedded
//!    payloads).  Relocating the full image causes the destination range to
//!    overlap with the source, requiring BSS to be skipped and re-zeroed.
//!
//! 2. The relocation table generated from `--emit-relocs` contains entries
//!    for non-address values (instruction immediates, constants) that happen
//!    to fall in the kernel physical address range.  Applying these corrupts
//!    the relocated image.  A build-time filter (checking each entry's site
//!    value against the kernel extent) removes most, but some false
//!    positives remain.
//!
//! 3. After relocation the kernel's page-table setup must map the *new*
//!    physical base, not the link-time base.  The current page-table code
//!    reads the kernel base from the link-time symbol `__kernel_start`
//!    which the compiler constant-folds to 0x200000, defeating runtime
//!    detection of the relocation.
//!
//! When these issues are resolved, enable KASLR by restoring the body of
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
//! The relocation table is pre-validated at build time: every entry's site
//! value was checked to be a plausible kernel-absolute address within
//! [KERNEL_LOAD_ADDRESS, kernel_end).  The gen-kaslr-relocs tool also
//! filters overlapping entries (e.g. R_X86_64_64 at both the instruction
//! prefix and the immediate operand of the same `movabs`).

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
