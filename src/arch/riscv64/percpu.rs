//! src/arch/riscv64/percpu.rs
//!
//! Where this hart's `PerCpuData` lives: the `tp` register (x4), and the slot
//! that hart's trap entry reloads it from.
//!
//! `tp` is also the register a user thread owns, so a trap from U-mode finds it
//! holding the user's value rather than ours.  `stvec` is per-hart, so each
//! hart enters through its own stub in `trap.S` and each stub loads its own
//! slot below.  One global holding "the" pointer instead is the boot hart's
//! block on every hart — which is what the second hart to take a timer
//! interrupt would have run its handler against.

use crate::kernel::percpu::PERCPU_OFFSET_SCHEDULER;
use crate::kernel::process::Scheduler;

/// Harts this architecture keeps a per-CPU base for: one slot each, indexed by
/// the hart's own ID.
///
/// The index is the hart ID, not a dense CPU number, because the hart ID is
/// what this machine's hardware names a CPU by: it is what SBI HSM starts, what
/// a trap stub is chosen by, and — through `plic_context_for_cpu` — what the
/// PLIC addresses a context with.  A hart whose ID is past this table is a hart
/// the kernel cannot keep state for, and `smp.rs` declines to start it.
pub(crate) const MAX_HARTS: usize = crate::kernel::smp::MAX_CPUS;

/// Per-hart `PerCpuData` pointers, for the trap stubs to reload `tp` from.
///
/// The name is referenced from `trap.S`, so it must not be mangled.
#[cfg(target_os = "none")]
#[no_mangle]
pub static mut RISCV64_PERCPU_PTRS: [u64; MAX_HARTS] = [0; MAX_HARTS];

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

/// Publish the block a hart that is about to start will run on.
///
/// This is what a hart starting from a reset reads — its trampoline takes `tp`
/// from the slot, and its trap stubs reload it — so the slot is filled before
/// `hart_start`, by whichever hart is doing the starting.  `tp` itself is not
/// touched: the caller is running on its own block.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives `hart_id`'s use of it,
/// and `hart_id` must be a hart that is not running yet.
pub unsafe fn publish_base(hart_id: usize, base: u64) {
    if hart_id < MAX_HARTS {
        // SAFETY: the index is in range, and the caller owns the slot until the
        // hart it names starts.
        unsafe { (*core::ptr::addr_of_mut!(RISCV64_PERCPU_PTRS))[hart_id] = base };
    }
}

/// Point a hart at its `PerCpuData`, and remember it for that hart's trap
/// entry.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives `hart_id`'s use of it,
/// and `hart_id` must be the hart that will run on it.
pub unsafe fn set_base_for_hart(hart_id: usize, base: u64) {
    if hart_id >= MAX_HARTS {
        return;
    }
    // SAFETY: the index is in range, the table is a plain static array of
    // pointers, and each slot belongs to one hart — the caller owns the one it
    // names.  The slot is written before `tp` below, because a hart started
    // through SBI runs its trap stub before anything else of ours and the stub
    // reads the slot.
    unsafe { (*core::ptr::addr_of_mut!(RISCV64_PERCPU_PTRS))[hart_id] = base };
    // SAFETY: writing `tp` affects only this hart's own view, and the slot is
    // already visible, so a trap on this hart cannot observe the new `tp`
    // without the slot that reloads it.
    unsafe {
        core::arch::asm!("mv tp, {}", in(reg) base, options(nostack));
    }
}

/// Point *this* hart at its `PerCpuData`.
///
/// The boot hart is the hart this runs on: it is the one the boot protocol
/// named in `a0` before the Rust entry, and the only hart that runs kernel
/// init. A hart started later installs its own base through
/// [`set_base_for_hart`], with the ID SBI handed it.
///
/// # Safety
///
/// As [`set_base_for_hart`], for the boot hart.
pub unsafe fn set_base(base: u64) {
    // A missing hand-off means the boot could not tell which hart it is on,
    // and the same missing hand-off is what leaves hart discovery with nothing
    // to discover; 0 is where such a boot is already single-CPU by accident.
    let hart_id = super::smp::boot_hart_id().unwrap_or(0) as usize;
    // SAFETY: `base` is the BSP's live block, as the caller's contract says,
    // and `hart_id` is the hart this runs on — the one the boot protocol named.
    unsafe { set_base_for_hart(hart_id, base) };
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
