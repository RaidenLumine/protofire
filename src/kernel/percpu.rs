//! src/kernel/percpu.rs
//!
//! Per-CPU data infrastructure for SMP.
//!
//! On x86_64 bare-metal, each CPU's [`PerCpuData`] is accessed via the GS
//! segment base register (IA32_GS_BASE MSR, 0xC0000101).  The BSP instance
//! is a static; AP instances are heap-allocated during CPU bring-up (Phase 5).
//!
//! On other architectures and test builds, a single static [`PerCpuData`] is
//! returned by [`get()`].

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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

// Compile-time size and field-offset checks (x86_64 only — the layout must
// match what the assembly inlines expect).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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

// ── BSP static (x86_64 bare-metal) ──────────────────────────────────────

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static BSP_PERCPU: SyncUnsafeCell<PerCpuData> = SyncUnsafeCell::new(PerCpuData::zeroed());

/// Set up the GS segment base to point to the BSP [`PerCpuData`].
///
/// Writes `IA32_GS_BASE` MSR (`0xC0000101`).  Must be called once during
/// early boot, after GDT load but before any `get()` or
/// `current_scheduler_ptr()` call.
///
/// # Safety
///
/// The caller must ensure this runs exactly once on the BSP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn early_init_gs_base() {
    let base = BSP_PERCPU.get() as u64;
    unsafe {
        core::arch::asm!(
            "mov ecx, 0xC0000101",  // IA32_GS_BASE
            "wrmsr",
            in("eax") base as u32,
            in("edx") (base >> 32) as u32,
            out("ecx") _,
        );
    }
}

/// Set up the kernel GS base MSR for `swapgs` support.
///
/// Writes `IA32_KERNEL_GS_BASE` MSR (`0xC0000102`) to point to the BSP
/// [`PerCpuData`].  When user mode sets GS to its own selector (overwriting
/// `IA32_GS_BASE`), the interrupt entry path uses `swapgs` to exchange
/// GS_BASE ↔ KERNEL_GS_BASE, restoring the kernel's per-CPU view.
///
/// Must be called once during early boot, after [`early_init_gs_base`].
///
/// # Safety
///
/// The caller must ensure this runs exactly once on the BSP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn early_init_kernel_gs_base() {
    let base = BSP_PERCPU.get() as u64;
    unsafe {
        core::arch::asm!(
            "mov ecx, 0xC0000102",  // IA32_KERNEL_GS_BASE
            "wrmsr",
            in("eax") base as u32,
            in("edx") (base >> 32) as u32,
            out("ecx") _,
        );
    }
}

/// Set the kernel GS base MSR for an AP.
///
/// Writes `IA32_KERNEL_GS_BASE` (`0xC0000102`) so that `swapgs` on this CPU
/// correctly swaps to the per-CPU data.  Call during AP boot, after the
/// per-CPU data pointer is written to `IA32_GS_BASE`.
///
/// # Safety
///
/// Must be called once per AP, after the AP's [`PerCpuData`] is allocated
/// and GS base is pointed to it.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn init_ap_kernel_gs_base(percpu: *const PerCpuData) {
    let base = percpu as u64;
    unsafe {
        core::arch::asm!(
            "mov ecx, 0xC0000102",  // IA32_KERNEL_GS_BASE
            "wrmsr",
            in("eax") base as u32,
            in("edx") (base >> 32) as u32,
            out("ecx") _,
        );
    }
}

/// Fill in the BSP's per-CPU data fields after the scheduler and LAPIC are
/// available.
///
/// Called during [`Kernel::init`] after the LAPIC is up.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn init_bsp(scheduler: *mut crate::kernel::process::Scheduler, lapic_id: u8, tss: *mut u8) {
    let percpu = unsafe { &mut *BSP_PERCPU.get() };
    percpu.cpu_id = 0;
    percpu.lapic_id = lapic_id;
    percpu.scheduler = scheduler;
    percpu.tss = tss;
}

// ── Public accessors ────────────────────────────────────────────────────

/// Return a reference to the current CPU's [`PerCpuData`].
///
/// On x86_64 bare-metal, reads the GS base via `rdmsr` and dereferences it.
/// On other targets / test builds, returns a static default (single-CPU mode).
///
/// This is the slow-but-safe path; use [`current_scheduler_ptr`] for the
/// hot path (single `gs:` load).
pub fn get() -> &'static PerCpuData {
    get_impl()
}

/// Return a mutable reference to the current CPU's [`PerCpuData`].
///
/// # Safety
///
/// The caller must ensure no other thread on the **same** CPU is
/// concurrently accessing the per-CPU data.  Access from a different
/// CPU is always safe because each CPU has its own instance.
pub fn get_mut() -> &'static mut PerCpuData {
    // Resolve the base pointer and reconstruct a mutable reference.
    // Each CPU accesses only its own PerCpuData, so this is safe.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!(
                "mov ecx, 0xC0000101",
                "rdmsr",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") base,
                out("rdx") _,
                out("rcx") _,
            );
        }
        assert!(base != 0, "PerCpuData GS base not initialised");
        unsafe { &mut *(base as *mut PerCpuData) }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
        }
        if base == 0 {
            static EARLY_FALLBACK: crate::util::sync_unsafe_cell::SyncUnsafeCell<PerCpuData> =
                crate::util::sync_unsafe_cell::SyncUnsafeCell::new(PerCpuData::zeroed());
            unsafe { &mut *EARLY_FALLBACK.get() }
        } else {
            unsafe { &mut *(base as *mut PerCpuData) }
        }
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) base, options(nostack));
        }
        if base == 0 {
            static EARLY_FALLBACK: crate::util::sync_unsafe_cell::SyncUnsafeCell<PerCpuData> =
                crate::util::sync_unsafe_cell::SyncUnsafeCell::new(PerCpuData::zeroed());
            unsafe { &mut *EARLY_FALLBACK.get() }
        } else {
            unsafe { &mut *(base as *mut PerCpuData) }
        }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none"),
    )))]
    {
        static GLOBAL_PERCPU: crate::util::sync_unsafe_cell::SyncUnsafeCell<PerCpuData> =
            crate::util::sync_unsafe_cell::SyncUnsafeCell::new(PerCpuData::zeroed());
        unsafe { &mut *GLOBAL_PERCPU.get() }
    }
}

fn get_impl() -> &'static PerCpuData {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!(
                "mov ecx, 0xC0000101",
                "rdmsr",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") base,
                out("rdx") _,
                out("rcx") _,
            );
        }
        if base == 0 {
            // GS base not yet initialised (extremely early boot).
            // Return a zeroed fallback so callers see null scheduler.
            static EARLY_FALLBACK: PerCpuData = PerCpuData::zeroed();
            &EARLY_FALLBACK
        } else {
            unsafe { &*(base as *const PerCpuData) }
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
        }
        if base == 0 {
            static EARLY_FALLBACK: PerCpuData = PerCpuData::zeroed();
            &EARLY_FALLBACK
        } else {
            unsafe { &*(base as *const PerCpuData) }
        }
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) base, options(nostack));
        }
        if base == 0 {
            static EARLY_FALLBACK: PerCpuData = PerCpuData::zeroed();
            &EARLY_FALLBACK
        } else {
            unsafe { &*(base as *const PerCpuData) }
        }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none"),
    )))]
    {
        static GLOBAL_PERCPU: PerCpuData = PerCpuData::zeroed();
        &GLOBAL_PERCPU
    }
}

/// Fast-path: return the current CPU's scheduler pointer.
///
/// - x86_64 bare-metal: single `mov reg, gs:[PERCPU_OFFSET_SCHEDULER]` (1 insn).
/// - AArch64 bare-metal: `mrs reg, tpidr_el1` followed by load from offset 8
///   (the `scheduler` field in [`PerCpuData`]).
/// - Other targets: returns null (callers fall back to the global `AtomicPtr`).
///
/// # Safety
///
/// The returned pointer is only valid if the scheduler is still alive.
/// Callers must use `as_ref()` with appropriate lifetime management.
#[inline]
pub fn current_scheduler_ptr() -> *mut crate::kernel::process::Scheduler {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let ptr: *mut crate::kernel::process::Scheduler;
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[{}]",
                out(reg) ptr,
                const PERCPU_OFFSET_SCHEDULER,
                options(nostack, readonly),
            );
        }
        ptr
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
        }
        if base == 0 {
            core::ptr::null_mut()
        } else {
            // The scheduler field is at offset 8 in PerCpuData (same layout).
            unsafe { *((base + 8) as *const *mut crate::kernel::process::Scheduler) }
        }
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let base: u64;
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) base, options(nostack));
        }
        if base == 0 {
            core::ptr::null_mut()
        } else {
            unsafe { *((base + 8) as *const *mut crate::kernel::process::Scheduler) }
        }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none"),
    )))]
    {
        core::ptr::null_mut()
    }
}

/// Update the per-CPU scheduler pointer for the current CPU.
///
/// On x86_64 bare-metal this resolves the current CPU's [`PerCpuData`] via
/// the GS segment base, so it works for both BSP and APs.  On AArch64 the
/// same is done via TPIDR_EL1.  On other targets this is a no-op (the global
/// `AtomicPtr` path is used instead).
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
))]
pub fn set_current_scheduler(scheduler: *mut crate::kernel::process::Scheduler) {
    let base: u64;
    unsafe {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        core::arch::asm!(
            "mov ecx, 0xC0000101",
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") base,
            out("rdx") _,
            out("rcx") _,
        );
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        core::arch::asm!("mv {}, tp", out(reg) base, options(nostack));
    }
    if base != 0 {
        let percpu = unsafe { &mut *(base as *mut PerCpuData) };
        percpu.scheduler = scheduler;
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none"),
)))]
pub fn set_current_scheduler(_scheduler: *mut crate::kernel::process::Scheduler) {
    // no-op on non-bare-metal: the global AtomicPtr path is used instead
}

/// Set the AArch64 per-CPU data pointer via TPIDR_EL1.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn aarch64_set_tpidr_el1(val: u64) {
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) val, options(nostack));
    }
}

/// Host stub for aarch64_set_tpidr_el1.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn aarch64_set_tpidr_el1(_val: u64) {
    // no-op on non-AArch64
}

/// Set the RISC-V per-CPU data pointer via the tp (x4) register.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub fn riscv64_set_tp(val: u64) {
    unsafe {
        core::arch::asm!("mv tp, {}", in(reg) val, options(nostack));
    }
}

/// Host stub for riscv64_set_tp.
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub fn riscv64_set_tp(_val: u64) {
    // no-op on non-RISC-V
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
