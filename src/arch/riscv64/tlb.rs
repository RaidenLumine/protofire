//! src/arch/riscv64/tlb.rs
//!
//! Whether this architecture owes anything to a page-table edit.
//!
//! `sfence.vma` is hart-local, and the kernel's page-table edits issue it
//! where the edit happens.  So the answer below is the one the machine's
//! *scheduler* needs rather than the one the architecture can offer: the
//! boot hart is the only hart that runs threads, so it is the only hart that
//! edits a table, and the flush it issues is complete for every CPU the
//! kernel dispatches on.  The secondary harts idle in `wfi` with their own
//! copies of whatever they touched on the way up.  They will have to be told
//! the day they start scheduling: the invalidation log in `kernel/smp/tlb.rs`
//! is where a request for them would be posted, and this answer is what has
//! to change with it.
//!
//! The *instruction* to drop a translation is not in this module for that
//! reason: the edit path owns it (`MMU::flush_tlb_page`), and duplicating it
//! here would be a second fence per edit with nothing to show for it.

/// Nothing to drop: the edit path fenced the range for the CPU that will run
/// on it.
pub fn drop_local_range(start: usize, end: usize) {
    let _ = (start, end);
}

/// Nothing to drop, for the same reason.
pub fn drop_local_all() {}

/// Do the other CPUs have to be told about an edit?
///
/// Not the ones this kernel runs threads on.  A hart's fence says nothing to
/// another hart, so the honest answer for the architecture is "yes, unless
/// there is only one hart that edits tables" — and that is the state this
/// kernel is in.  See the module note for what changes it.
pub const fn other_cpus_need_telling() -> bool {
    false
}
