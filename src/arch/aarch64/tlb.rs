//! src/arch/aarch64/tlb.rs
//!
//! Whether this architecture owes anything to a page-table edit.
//!
//! Nothing, on both counts.  This kernel invalidates to the inner-shareable
//! domain where the page table is edited — the MMU's own map and unmap paths
//! issue the full `DSB; TLBI ...IS; DSB; ISB` sequence — so by the time an
//! edit returns, every core that could hold the translation has dropped it.
//! The leading `DSB` is part of why that holds: without it the invalidation
//! can be broadcast before the descriptor that prompted it is visible, and a
//! core that walks the table then re-loads the stale entry.  The drop the
//! kernel asks for here has already happened, and telling the other CPUs later
//! would ask them to walk a request they have honoured.
//!
//! What that costs is named where it is paid: not here, and not on any path
//! that passes through this module.

/// Nothing to drop: the edit that changed the range dropped it everywhere.
pub fn drop_local_range(start: usize, end: usize) {
    let _ = (start, end);
}

/// Nothing to drop, for the same reason.
pub fn drop_local_all() {}

/// Do the other CPUs have to be told about an edit?
///
/// No — see the module note.  An invalidation issued with the inner-shareable
/// suffix reaches every core in the domain, not just the one that issued it.
pub const fn other_cpus_need_telling() -> bool {
    false
}
