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
//!
//! ## Two numbers, not one
//!
//! A scheduler slot is dense — the BSP is 0 and the APs are 1, 2, … — because
//! it indexes the kernel's per-CPU arrays.  A hart id is whatever the machine
//! says it is, and it is allowed to be large and sparse: OpenSBI hands the
//! reset to whichever hart it likes, and a boot has landed on hart 39 of 40.
//! Treating the two as one number meant such a boot could not keep state for
//! the CPU it was running on at all.  So the tables below are keyed by slot,
//! and [`RISCV64_HART_SLOTS`] is the one translation from a hart id to its
//! slot — read by the trampoline, which runs before any Rust code on a hart.

use crate::kernel::percpu::PERCPU_OFFSET_SCHEDULER;

/// Logical CPU slots: one per CPU the scheduler can hold.
pub(crate) const MAX_HARTS: usize = crate::kernel::smp::MAX_CPUS;

/// Hart ids the translation table covers.
///
/// Hart ids are the machine's numbering, and today's machines keep them small
/// — but "small" is a property of the machines, not of the format.  A hart
/// outside this range is one the trampoline has no translation for, so
/// bring-up declines it with a message instead of starting a hart that would
/// run with another CPU's state.
pub(crate) const MAX_HART_IDS: usize = 256;

/// Value of [`SLOT_HARTS`] for a slot that has not been published.
pub(crate) const NO_HART: u64 = u64::MAX;

/// Value of [`RISCV64_HART_SLOTS`] for a hart that has not been given a slot.
pub(crate) const NO_SLOT: u8 = 0xFF;

/// Per-slot `PerCpuData` pointers, for the trap stubs to reload `tp` from.
///
/// Indexed by logical slot, which is what a trap stub's own index is.  The
/// name is referenced from `trap.S`, so it must not be mangled.
#[cfg(target_os = "none")]
#[no_mangle]
pub static mut RISCV64_PERCPU_PTRS: [u64; MAX_HARTS] = [0; MAX_HARTS];

/// Hart id each logical slot runs on.
///
/// Written once per slot by the BSP before the hart it names starts.  The
/// scheduler, the PLIC context and the IMSIC file are addressed by different
/// numbers, and this is the table that connects them.
static SLOT_HARTS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[u64; MAX_HARTS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([NO_HART; MAX_HARTS]);

/// Slot of each hart id the trampoline can be handed.
///
/// A hart started through SBI runs its trampoline before any Rust code, with
/// only the hart id SBI put in `a0`; this is the one lookup that turns it into
/// the slot whose block it must adopt.  Referenced from `boot.S`, so it must
/// not be mangled.
#[cfg(target_os = "none")]
#[no_mangle]
pub static mut RISCV64_HART_SLOTS: [u8; MAX_HART_IDS] = [NO_SLOT; MAX_HART_IDS];

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

/// The hart id logical slot `slot` runs on, if it is known.
///
/// Slot 0 is the boot CPU by construction, and the boot protocol named it
/// before any Rust ran — so the answer exists before `install_bsp` publishes
/// the tables.  That matters because the console and the interrupt controller
/// come up before it, and a controller that could not name the CPU it was
/// initialising for would open no threshold and take no wire interrupt.
pub(crate) fn hart_of_slot(slot: u32) -> Option<u64> {
    let index = slot as usize;
    if index >= MAX_HARTS {
        return None;
    }
    // SAFETY: the index is in range; each slot is written once, before the hart
    // it names starts, and never cleared.
    let hart = unsafe { (*SLOT_HARTS.get())[index] };
    if hart != NO_HART {
        return Some(hart);
    }
    if slot == 0 {
        return super::smp::boot_hart_id();
    }
    None
}

/// The logical slot hart `hart_id` runs on, if it was published.
pub(crate) fn slot_of_hart(hart_id: u64) -> Option<u32> {
    if hart_id >= MAX_HART_IDS as u64 {
        return None;
    }
    // SAFETY: the index is bounded; the table is written by the BSP before the
    // hart it names can run.
    let slot = unsafe { (*core::ptr::addr_of!(RISCV64_HART_SLOTS))[hart_id as usize] };
    (slot != NO_SLOT).then_some(slot as u32)
}

/// The hart id of the CPU running this code.
///
/// The kernel's logical id is in the per-CPU block; this is the machine's name
/// for the same CPU, which is what the PLIC context, the IMSIC file and an SBI
/// IPI mask are addressed by.
pub(crate) fn current_hart_id() -> Option<u64> {
    hart_of_slot(crate::kernel::percpu::get().cpu_id)
}

/// The position of `hart_id` among the machine's harts.
///
/// The machine's device tree lists its CPUs in the machine's order, and the
/// controllers that take an *index* rather than an id — the IMSIC's file
/// stride and the APLIC's per-hart register block — count in that order.  The
/// hart id itself is not that position.
pub(crate) fn hart_index(hart_id: u64) -> Option<usize> {
    let count = crate::arch::fdt::cpu_count();
    if count == 0 {
        // No tree: the machine's numbering is the dense one the fallback
        // constants describe.
        return (hart_id <= u32::MAX as u64).then_some(hart_id as usize);
    }
    (0..count)
        .find(|index| crate::arch::fdt::cpu_hardware_id(*index) == Some(hart_id))
        .map(|index| index as usize)
}

/// The position of logical CPU `slot`'s hart among the machine's harts.
pub(crate) fn hart_index_of_slot(slot: u32) -> Option<usize> {
    hart_of_slot(slot).and_then(hart_index)
}

/// Publish the block and the identity a hart that is about to start will run
/// with.
///
/// This is what a hart starting from a reset reads — its trampoline takes `tp`
/// from the slot, and its trap stubs reload it — so the slot is filled before
/// `hart_start`, by whichever hart is doing the starting.  `tp` itself is not
/// touched: the caller is running on its own block.
///
/// Answers `false` for a slot or hart id the tables cannot hold; the caller
/// must then not start the hart, because a hart with no translation would run
/// on another CPU's state.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives the hart's use of it,
/// `slot` must be a slot no running hart owns yet, and the hart must not be
/// running.
pub unsafe fn publish_base(slot: u32, hart_id: u64, base: u64) -> bool {
    let slot_index = slot as usize;
    if slot_index >= MAX_HARTS || hart_id >= MAX_HART_IDS as u64 {
        return false;
    }
    // SAFETY: both indices are in range, and the caller owns the slot until the
    // hart it names starts.  Each table is written before the hart can read it.
    unsafe {
        (*core::ptr::addr_of_mut!(RISCV64_HART_SLOTS))[hart_id as usize] = slot as u8;
        (*core::ptr::addr_of_mut!(RISCV64_PERCPU_PTRS))[slot_index] = base;
        (*SLOT_HARTS.get())[slot_index] = hart_id;
    }
    true
}

/// Point a hart at its `PerCpuData`, and remember it for that hart's trap
/// entry.
///
/// # Safety
///
/// `base` must be the address of a live, 64-byte-aligned
/// [`crate::kernel::percpu::PerCpuData`] that outlives the slot's use of it,
/// `slot` must belong to the running hart, and `hart_id` must be the hart that
/// will run on it.
pub unsafe fn set_base_for_slot(slot: u32, hart_id: u64, base: u64) {
    let slot_index = slot as usize;
    if slot_index >= MAX_HARTS {
        return;
    }
    if hart_id < MAX_HART_IDS as u64 {
        // SAFETY: the index is in range; the caller owns the slot.
        unsafe {
            (*core::ptr::addr_of_mut!(RISCV64_HART_SLOTS))[hart_id as usize] = slot as u8;
        }
    }
    // SAFETY: as `publish_base` — the caller owns the slot, and the slot is
    // written before `tp` below, because a trap on this hart reloads `tp` from
    // it.
    unsafe {
        (*core::ptr::addr_of_mut!(RISCV64_PERCPU_PTRS))[slot_index] = base;
        (*SLOT_HARTS.get())[slot_index] = hart_id;
    }
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
/// [`set_base_for_slot`], with the slot the BSP published for it.
///
/// # Safety
///
/// As [`set_base_for_slot`], for the boot hart.
pub unsafe fn set_base(base: u64) {
    // A missing hand-off means the boot could not tell which hart it is on,
    // and the same missing hand-off is what leaves hart discovery with nothing
    // to discover; 0 is where such a boot is already single-CPU by accident.
    let hart_id = super::smp::boot_hart_id().unwrap_or(0);
    // SAFETY: `base` is the BSP's live block, as the caller's contract says,
    // and the BSP is logical slot 0 by construction.
    unsafe { set_base_for_slot(0, hart_id, base) };
}

/// The scheduler pointer, read through the base register.
#[inline]
pub fn scheduler_ptr() -> *mut () {
    let base = base();
    if base == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: a non-zero base is this hart's PerCpuData, and the field sits at
    // `PERCPU_OFFSET_SCHEDULER` (checked at compile time).
    unsafe { *((base + PERCPU_OFFSET_SCHEDULER as u64) as *const *mut ()) }
}
