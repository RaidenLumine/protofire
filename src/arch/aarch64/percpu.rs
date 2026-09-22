//! src/arch/aarch64/percpu.rs
//!
//! Where this CPU's `PerCpuData` lives: `TPIDR_EL1`.
//!
//! `TPIDR_EL1` is a plain per-CPU register with no user-mode counterpart to
//! swap against, so the base is simply read and written here.

use crate::kernel::percpu::PERCPU_OFFSET_SCHEDULER;
use crate::kernel::process::Scheduler;

/// Whether a zero base means "too early" rather than "a bug".
///
/// aarch64 points `TPIDR_EL1` at the BSP's per-CPU block during kernel init,
/// and the trap path is entered before that on early faults, so a zero base is
/// a state the kernel legitimately passes through.
pub fn expects_base_installed() -> bool {
    false
}

/// The current CPU's `PerCpuData` base, or 0 before it is installed.
pub fn base() -> u64 {
    let base: u64;
    // SAFETY: reading `TPIDR_EL1` has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
    }
    base
}

/// Point this CPU at its `PerCpuData`.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives this CPU's use of it.
pub unsafe fn set_base(base: u64) {
    // SAFETY: writing `TPIDR_EL1` has no side effects beyond this CPU's view of
    // its own per-CPU data.
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) base, options(nostack));
    }
}

/// The scheduler pointer, read through the base register.
#[inline]
pub fn scheduler_ptr() -> *mut Scheduler {
    let base = base();
    if base == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: a non-zero base is this CPU's PerCpuData, and the field sits at
    // `PERCPU_OFFSET_SCHEDULER` (checked at compile time).
    unsafe { *((base + PERCPU_OFFSET_SCHEDULER as u64) as *const *mut Scheduler) }
}
