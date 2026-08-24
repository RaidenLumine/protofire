//! src/kernel/smp/mod.rs
//!
//! SMP subsystem — AP discovery, bring-up, and TLB shootdown.
//!
//! ## Boot flow
//!
//! 1. BSP discovers AP LAPIC IDs via ACPI MADT parsing.
//! 2. Trampoline code is copied to a low physical address (0x8000).
//! 3. For each AP: allocate a kernel stack, write entry data to the
//!    trampoline page, then send INIT-SIPI-SIPI via the LAPIC ICR.
//! 4. The AP starts in 16-bit real mode, transitions to 64-bit long mode,
//!    and calls [`ap_entry`].
//! 5. [`ap_entry`] initialises per-CPU data, sets GS base, configures the
//!    local APIC, and enters the idle loop.
//!
//! ## Memory layout
//!
//! The trampoline sits at physical address `TRAMPOLINE_BASE` (0x8000),
//! identity-mapped in the boot page tables.  A data page follows at
//! `TRAMPOLINE_DATA_BASE` (0x9000) for passing parameters to APs.

pub(crate) mod bringup;
pub(crate) mod discovery;
pub(crate) mod tlb;

pub(crate) use bringup::*;
#[cfg_attr(
    not(all(target_arch = "x86_64", target_os = "none")),
    allow(unused_imports)
)]
pub(crate) use discovery::*;
pub(crate) use tlb::*;
