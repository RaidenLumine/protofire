//! src/arch/x86_64/tlb.rs
//!
//! Dropping this CPU's translations, the x86_64 way.
//!
//! `invlpg` names one page and is this CPU's alone; a reload of CR3 drops
//! everything and is also this CPU's alone.  Neither reaches another CPU, so
//! an edit has to be posted to the kernel's invalidation log for the rest of
//! the machine to walk, which is what [`other_cpus_need_telling`] says.

use crate::memory::paging::PAGE_SIZE;

/// Drop this CPU's translations for the pages in `[start, end)`.
///
/// The range is rounded outwards: a caller that edited half a page has to
/// lose the whole page's translation, and dropping a page nobody touched
/// costs one instruction and cannot be wrong.
pub fn drop_local_range(start: usize, end: usize) {
    let mut page = start & !(PAGE_SIZE - 1);
    let end = end.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    while page < end {
        // SAFETY: invalidating a translation is safe for any address — the
        // next access to it walks the page tables again.
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) page, options(nostack)) };
        page += PAGE_SIZE;
    }
}

/// Drop every translation this CPU holds.
///
/// What the machine needs when a PCID is handed out again: entries tagged
/// with it may still be in this CPU's TLB, and `invlpg` cannot name which
/// address space's entry to drop.
pub fn drop_local_all() {
    super::paging::pcid::flush_all_tlb();
}

/// Do the other CPUs see an edit without being told about it?
///
/// No.  `invlpg` and a CR3 reload are local operations, so whoever edits a
/// page table here also has to drop its own translation and post the range
/// for everyone else.
pub const fn other_cpus_need_telling() -> bool {
    true
}
