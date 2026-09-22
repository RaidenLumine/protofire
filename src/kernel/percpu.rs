//! src/kernel/percpu.rs
//!
//! Per-CPU data infrastructure for SMP.
//!
//! Each CPU gets its own [`PerCpuData`] block, and each architecture keeps the
//! pointer to it somewhere the CPU can reach cheaply: `gs` on x86_64,
//! `TPIDR_EL1` on aarch64, `tp` on riscv64.  *Which register* is the
//! architecture's business and lives in [`crate::arch::percpu`]; this module
//! owns the block itself and the accessors built on it, and names no
//! architecture at all.
//!
//! A target with no such register — the host, and any future target that has
//! not declared its own — reports a base of zero, and the accessors fall back
//! to a single static block, which is what single-CPU mode means.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;

// ── PerCpuData struct ────────────────────────────────────────────────────

/// Per-CPU data block, aligned to a cache line (64 bytes).
///
/// # Layout stability
///
/// The `scheduler` field is at offset 8.  The GS-based fast-path
/// (`current_scheduler_ptr`) loads it with `mov reg, gs:[8]`.
/// Do not reorder or insert fields before `scheduler` without updating
/// [`PERCPU_OFFSET_SCHEDULER`].
///
/// # Safety
///
/// `Sync` is implemented because each CPU accesses only its own instance.
/// Raw pointers in this struct are never dereferenced concurrently by
/// multiple CPUs.
#[repr(C, align(64))]
pub struct PerCpuData {
    /// Offset 0: Logical CPU ID (0 = BSP, 1, 2, … = APs).
    pub cpu_id: u32,
    /// Offset 4: Local APIC ID (for IPI targeting on x86_64).
    pub lapic_id: u8,
    /// Offset 8: Pointer to this CPU's scheduler instance.
    pub scheduler: *mut crate::kernel::process::Scheduler,
    /// Offset 16: Pointer to this CPU's private TSS (Task State Segment).
    /// Each CPU must have its own TSS so that privilege_stack_table[0]
    /// (kernel stack on ring transition) is not corrupted by cross-CPU races.
    /// Stored as `*mut u8` so the struct compiles on all architectures;
    /// x86_64 code casts to `*mut crate::arch::x86_64::gdt::TaskStateSegment`.
    pub tss: *mut u8,
    /// Offset 24: Last-observed TLB generation.  Compared against the
    /// global [`super::smp::TLB_GENERATION`] counter on each kernel entry;
    /// a mismatch triggers a full CR3 reload (TLB flush).
    pub tlb_generation_seen: u64,
    /// Offset 32: Per-CPU context switch counter (saturating).
    pub context_switches: u64,
    /// Offset 40: Per-CPU kernel entry/exit counter.
    pub kernel_entries: u64,
    /// Offset 48: NUMA node ID (NUMA_NODE_NONE = 0xFF = none).
    pub numa_node_id: crate::kernel::topology::NodeId,
    /// Offset 49..64: Reserved for future expansion.
    _reserved: [u8; 15],
}

// SAFETY: each CPU accesses only its own PerCpuData instance, so there is
// no concurrent access to the raw pointers within.
unsafe impl Sync for PerCpuData {}

// Compile-time size and field-offset checks.  Every architecture reads the
// scheduler field by offset rather than through a Rust field access (that is
// what makes the lookup one or two instructions), so the layout is part of the
// contract, not an implementation detail.
const _: () = {
    if core::mem::size_of::<PerCpuData>() != 64 {
        panic!("PerCpuData must be exactly 64 bytes");
    }
    if core::mem::offset_of!(PerCpuData, cpu_id) != 0 {
        panic!("PerCpuData.cpu_id must be at offset 0");
    }
    if core::mem::offset_of!(PerCpuData, lapic_id) != 4 {
        panic!("PerCpuData.lapic_id must be at offset 4");
    }
    if core::mem::offset_of!(PerCpuData, scheduler) != 8 {
        panic!("PerCpuData.scheduler must be at offset 8");
    }
};

/// Byte offset of `scheduler` within [`PerCpuData`], used by the GS-based
/// fast-path (`mov reg, gs:[PERCPU_OFFSET_SCHEDULER]`).
pub const PERCPU_OFFSET_SCHEDULER: usize = 8;

impl PerCpuData {
    pub const fn zeroed() -> Self {
        Self {
            cpu_id: 0,
            lapic_id: 0,
            scheduler: core::ptr::null_mut(),
            tss: core::ptr::null_mut(),
            tlb_generation_seen: 0,
            context_switches: 0,
            kernel_entries: 0,
            numa_node_id: crate::kernel::topology::NUMA_NODE_NONE,
            _reserved: [0; 15],
        }
    }
}

// ── Public accessors ────────────────────────────────────────────────────

/// Return a reference to the current CPU's [`PerCpuData`].
///
/// The architecture supplies the base; a base of zero means per-CPU data is
/// not installed yet (or this target has none), and the caller gets the static
/// fallback, which reads as an idle CPU with no scheduler.
///
/// This is the slow-but-safe path; use [`current_scheduler_ptr`] for the
/// hot path.
pub fn get() -> &'static PerCpuData {
    let base = crate::arch::percpu::base();
    if base == 0 {
        // SAFETY: the fallback is a static, and every CPU that reaches it sees
        // the same zeroed block; nothing mutates it through this reference.
        return unsafe { &*EARLY_FALLBACK.get() };
    }
    // SAFETY: a non-zero base is this CPU's live PerCpuData; each CPU sees only
    // its own, so the shared reference is not shared in practice.
    unsafe { &*(base as *const PerCpuData) }
}

/// Return a mutable reference to the current CPU's [`PerCpuData`].
///
/// # Safety
///
/// The caller must ensure no other thread on the **same** CPU is
/// concurrently accessing the per-CPU data.  Access from a different
/// CPU is always safe because each CPU has its own instance.
pub fn get_mut() -> &'static mut PerCpuData {
    let base = crate::arch::percpu::base();
    if base == 0 {
        // Two architectures install the base before anything can reach
        // per-CPU data and one does not; the difference is theirs to state.
        assert!(
            !crate::arch::percpu::expects_base_installed(),
            "PerCpuData base not initialised"
        );
        // SAFETY: as `get`, plus the caller's own guarantee that nothing else
        // on this CPU is touching the block.
        return unsafe { &mut *EARLY_FALLBACK.get() };
    }
    // SAFETY: each CPU accesses only its own PerCpuData, so the exclusive
    // reference is not shared with another CPU.
    unsafe { &mut *(base as *mut PerCpuData) }
}

/// The block handed out before this CPU's own is installed.
///
/// Zeroed, so `cpu_id` reads 0 and `scheduler` reads null: early callers see an
/// idle CPU rather than a fault, which is what boot-time code before per-CPU
/// setup needs.
static EARLY_FALLBACK: SyncUnsafeCell<PerCpuData> = SyncUnsafeCell::new(PerCpuData::zeroed());

/// Fast-path: return the current CPU's scheduler pointer.
///
/// One architecture-specific instruction sequence — `gs:`-relative on x86_64,
/// base register plus a load elsewhere — and null on a target with no per-CPU
/// register, where callers fall back to the global `AtomicPtr`.
///
/// # Safety
///
/// The returned pointer is only valid if the scheduler is still alive.
/// Callers must use `as_ref()` with appropriate lifetime management.
#[inline]
pub fn current_scheduler_ptr() -> *mut crate::kernel::process::Scheduler {
    crate::arch::percpu::scheduler_ptr()
}

/// Update the per-CPU scheduler pointer for the current CPU.
///
/// It resolves the current CPU's [`PerCpuData`] through the architecture's base
/// register, so it works for the BSP and for APs alike.  A base of zero means
/// this CPU has no per-CPU block — a target without the register — and the call
/// is a no-op, matching the global `AtomicPtr` path callers use there.
pub fn set_current_scheduler(scheduler: *mut crate::kernel::process::Scheduler) {
    let base = crate::arch::percpu::base();
    if base != 0 {
        // SAFETY: a non-zero base is this CPU's own block, which the caller of
        // `set_current_scheduler` owns; the field write is the only access.
        let percpu = unsafe { &mut *(base as *mut PerCpuData) };
        percpu.scheduler = scheduler;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percpu_zeroed_is_all_zeros() {
        let p = PerCpuData::zeroed();
        assert_eq!(p.cpu_id, 0);
        assert_eq!(p.lapic_id, 0);
        assert!(p.scheduler.is_null());
    }

    #[test]
    fn percpu_size_is_cache_line() {
        assert_eq!(core::mem::size_of::<PerCpuData>(), 64);
    }

    #[test]
    fn percpu_get_returns_static_on_host() {
        let a = get();
        let b = get();
        assert_eq!(a.cpu_id, b.cpu_id);
        // Both point to the same static.
        assert!(core::ptr::eq(a, b));
    }
}
