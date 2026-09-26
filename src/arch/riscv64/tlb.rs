//! src/arch/riscv64/tlb.rs
//!
//! What this architecture owes the other harts after a page-table edit.
//!
//! `sfence.vma` is hart-local: the edit path issues it where the edit happens
//! (`MMU::flush_tlb_page`), and that fence says nothing to any other hart.
//! Once more than one hart schedules, an edit made on one of them can leave a
//! stale translation on another — pointing at a frame the kernel has since
//! handed to someone else — so the answer below is `true`: the edit is posted
//! to the log in `kernel/smp/tlb.rs` and every other hart drops it on its next
//! kernel entry.
//!
//! The two `drop_local_*` functions are that side of the same message: the
//! *receiver* runs them, and it is the only place in this architecture where
//! dropping a translation is a standalone operation rather than part of an
//! edit.  Nothing here posts by itself — an edit path calls
//! `post_range_invalidation` — which is also why the stack window's retirement
//! grace is real now: an address is handed out again only once every hart has
//! said it dropped it.

use core::arch::asm;

use crate::memory::paging::PAGE_SIZE;

/// Drop `[start, end)` from this hart's TLB, one page at a time.
///
/// Called on the hart that was *told* about an edit, not on the one that made
/// it, so the range is whatever the log carried: a run of pages somebody else
/// changed.  The fence goes per page because `sfence.vma` takes one address at
/// a time; a range from the log is small by construction (a longer one is
/// promoted to a full flush), so this is a handful of fences at most.
pub fn drop_local_range(start: usize, end: usize) {
    let mut page = start & !(PAGE_SIZE - 1);
    while page < end {
        // SAFETY: `sfence.vma` with a virtual address is a TLB maintenance
        // instruction; it has no memory side effects and cannot fault.  rs2 =
        // x0 means "every ASID", which is what a kernel edit needs — the
        // translation being dropped may be tagged with any process's ASID.
        unsafe {
            asm!("sfence.vma {va}, zero", va = in(reg) page, options(nostack, preserves_flags));
        }
        page = page.saturating_add(PAGE_SIZE);
    }
}

/// Drop every translation on this hart.
///
/// The receiver's half of a promoted request: the log ran out, so the request
/// lost its range and every hart drops everything instead.
pub fn drop_local_all() {
    // SAFETY: as `drop_local_range`: TLB maintenance, no memory side effects.
    // Both operands being x0 means "every address, every ASID".
    unsafe {
        asm!("sfence.vma zero, zero", options(nostack, preserves_flags));
    }
}

/// Do the other CPUs have to be told about an edit?
///
/// Yes.  A hart's fence is local to that hart, and more than one hart runs
/// threads here, so an edit made by any of them can leave a stale translation
/// on another.  The one case that used to make this answer `false` — a machine
/// where only the boot hart schedules — is no longer this one.
pub const fn other_cpus_need_telling() -> bool {
    true
}
