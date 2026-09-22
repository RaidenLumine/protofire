//! src/arch/riscv64/percpu.rs
//!
//! Where this CPU's `PerCpuData` lives: the `tp` register (x4).
//!
//! `tp` is also the register a user thread owns, so this module keeps the
//! kernel's pointer in a global as well.  The trap vector in `trap.S` loads
//! `tp` from that global on every kernel entry, because a trap that arrives
//! from U-mode finds `tp` holding the user's value rather than ours.

use crate::kernel::percpu::PERCPU_OFFSET_SCHEDULER;
use crate::kernel::process::Scheduler;

/// The hart's `PerCpuData`, for the trap vector to reload `tp` from.
///
/// The name is referenced from `trap.S`, so it must not be mangled.
#[cfg(target_os = "none")]
#[no_mangle]
pub static mut RISCV64_PERCPU_PTR: u64 = 0;

/// Whether a zero base means "too early" rather than "a bug".
///
/// The BSP sets `tp` during kernel init, and the trap vector is live before
/// that, so a zero `tp` is a state the kernel legitimately passes through.
pub fn expects_base_installed() -> bool {
    false
}

/// The current hart's `PerCpuData` base, or 0 before it is installed.
pub fn base() -> u64 {
    let base: u64;
    // SAFETY: reading `tp` has no side effects.
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) base, options(nostack));
    }
    base
}

/// Point this hart at its `PerCpuData`, and remember it for the trap vector.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives this hart's use of it.
pub unsafe fn set_base(base: u64) {
    // SAFETY: writing `tp` affects only this hart's own view, and the global
    // is what the trap vector reads; both are updated together so a trap
    // cannot observe one without the other on this hart.
    unsafe {
        core::arch::asm!("mv tp, {}", in(reg) base, options(nostack));
        RISCV64_PERCPU_PTR = base;
    }
}

/// The scheduler pointer, read through the base register.
#[inline]
pub fn scheduler_ptr() -> *mut Scheduler {
    let base = base();
    if base == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: a non-zero base is this hart's PerCpuData, and the field sits at
    // `PERCPU_OFFSET_SCHEDULER` (checked at compile time).
    unsafe { *((base + PERCPU_OFFSET_SCHEDULER as u64) as *const *mut Scheduler) }
}
