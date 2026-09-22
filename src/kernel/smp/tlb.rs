//! src/kernel/smp/tlb.rs
//!
//! TLB shootdown, cross-CPU invalidation, and boot CR3 management.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::apic;

// ── TLB shootdown ─────────────────────────────────────────────────────

/// Virtual address for the pending TLB shootdown (0 = none).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static SHOOTDOWN_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Number of CPUs that have acknowledged the current shootdown.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static SHOOTDOWN_ACK_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Serialises TLB shootdown protocol entry so that only one CPU at a time
/// publishes a VA and collects acknowledgements.  Uses the same
/// exponential-backoff pattern as [`MEMORY_MANAGER_LOCK`] — interrupts
/// are NOT disabled, so other CPUs can handle our IPI while spinning here.
///
/// Currently unused while cross-CPU IPI delivery is being debugged;
/// see [`tlb_shootdown`] for the generation-counter workaround.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
static SHOOTDOWN_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Acquire the shootdown serialisation lock with exponential backoff.
/// Interrupts remain enabled so the caller (and other CPUs) can still
/// receive IPIs while contending for this lock.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn acquire_shootdown_lock() {
    let mut backoff: u32 = 1;
    while SHOOTDOWN_LOCK
        .compare_exchange_weak(
            false,
            true,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        while SHOOTDOWN_LOCK.load(core::sync::atomic::Ordering::Relaxed) {
            for _ in 0..backoff.min(64) {
                core::hint::spin_loop();
            }
            backoff = backoff.saturating_mul(2).min(1024);
        }
        backoff = 1;
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn release_shootdown_lock() {
    SHOOTDOWN_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

/// Global TLB generation counter.  Incremented by [`tlb_shootdown`]
/// whenever a page-table entry is modified.  Each CPU checks this value
/// against its own `tlb_generation_seen` and reloads CR3 (full TLB flush)
/// when they differ.
#[cfg(target_os = "none")]
static TLB_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What each CPU has finished invalidating, published for the other CPUs to
/// read.
///
/// `CPU_FLUSHED_GENERATION[cpu] = generation` means: *CPU `cpu` has completed
/// a full TLB flush, and the generation counter read `generation` when that
/// flush was requested.*  It is written after the flush, never before, because
/// another CPU may reuse an address on the strength of it — see
/// [`all_cpus_flushed`].
///
/// This is deliberately separate from the per-CPU `tlb_generation_seen` latch,
/// which each CPU keeps for itself and which nothing else may read.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static CPU_FLUSHED_GENERATION: [core::sync::atomic::AtomicU64; super::bringup::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; super::bringup::MAX_CPUS];

/// Diagnostic: total number of shootdown IPI handler invocations per CPU.
/// Incremented unconditionally so we can tell whether the IPI ever arrived.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub static SHOOTDOWN_HANDLER_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Request a TLB shootdown for the given virtual address on all CPUs.
///
/// Invalidates the local TLB entry immediately via `invlpg` and increments
/// a global TLB generation counter.  Remote CPUs detect the generation
/// change on kernel entry (timer tick, syscall, exception) and reload CR3
/// to flush their entire TLB.
///
/// This generation-counter approach avoids IPI delivery, which has known
/// reliability issues on some QEMU configurations (fixed-mode IPIs are
/// accepted by the local ICR but never arrive at the destination LAPIC).
/// The trade-off is a full TLB flush on remote CPUs instead of a targeted
/// `invlpg`.  Once IPI delivery is debugged,
/// [`send_ipi_to_all_other_cpus`](super::bringup::send_ipi_to_all_other_cpus)
/// can be re-enabled for a single-page shootdown.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn tlb_shootdown(va: usize) {
    // Always invalidate locally — this is correct regardless of CPU count.
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack));
    }

    // Bump the global generation so remote CPUs flush on their next
    // kernel entry.  Wrapping is fine — the per-CPU check only cares
    // about inequality.
    TLB_GENERATION.fetch_add(1, Ordering::Release);
}

/// Record that this CPU has finished invalidating, as of `generation`.
///
/// Must be called *after* the flush, with the generation the flush was
/// performed for.  Publishing first would let another CPU reuse an address
/// whose translation this one still holds.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn publish_flushed_generation(cpu_id: u32, generation: u64) {
    // An id outside the array is not a CPU this kernel counts, and writing it
    // into some other CPU's slot would let a slice be reused on a flush that
    // never happened.  Not publishing is the safe answer: the grace stays
    // unsatisfied and the window keeps taking new addresses.
    if let Some(slot) = CPU_FLUSHED_GENERATION.get(cpu_id as usize) {
        slot.store(generation, Ordering::Release);
    }
}

/// Has every online CPU dropped the translations a flush request at
/// `generation` asked for?
///
/// This is the grace period an address must wait out before it can be handed
/// out again: an address that was mapped once and is about to be mapped again
/// must not still be cached anywhere, or the new mapping would be shadowed by
/// a stale translation to the old frame.
///
/// How much has to be waited for is an architecture property:
///
/// - x86_64 invalidates the local TLB only, so the answer is whatever the CPUS
///   themselves published after they flushed.  A CPU that has not published a
///   request cannot be assumed to have dropped it, and the caller then simply
///   keeps the address retired a little longer — the check never blocks.
/// - aarch64's page invalidation is inner-shareable (`tlbi ...is`) and its `dsb
///   ish` completes it, so the hardware has already done to every CPU what
///   x86_64 asks the others to do on their next kernel entry.  There is nothing
///   left to wait for.
/// - riscv64 has no stack window to hand out, and host builds have no TLB.
///
/// A CPU that is stuck with interrupts disabled can hold the answer back
/// indefinitely; that costs window addresses, never correctness, which is why
/// the caller treats "not yet" as "use the next address instead".
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn all_cpus_flushed(generation: u64) -> bool {
    let online = online_cpu_count() as usize;
    (0..online.min(super::bringup::MAX_CPUS))
        .all(|cpu| CPU_FLUSHED_GENERATION[cpu].load(Ordering::Acquire) >= generation)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn all_cpus_flushed(_generation: u64) -> bool {
    true
}

/// Apply any pending TLB invalidations that were requested by another CPU
/// since the last time this CPU checked.
///
/// Must be called on every kernel entry (timer tick, syscall, exception)
/// *after* the interrupt context has been saved.  Reloading CR3 is a full
/// TLB flush; it is cheap enough for the current SMP scale (2–4 CPUs).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn apply_remote_tlb_invalidations() {
    let current_gen = TLB_GENERATION.load(Ordering::Acquire);
    let percpu = crate::kernel::percpu::get_mut();
    if current_gen != percpu.tlb_generation_seen {
        // With CR4.PCIDE set, a same-PCID CR3 reload does NOT flush the TLB,
        // so the flush must go through the PCID-aware path: INVPCID when
        // active, a plain CR3 reload otherwise.
        crate::arch::x86_64::paging::pcid::flush_all_tlb();
        // The latch and the published record both say "flushed through
        // `current_gen`", and both are written only once the flush is done.
        percpu.tlb_generation_seen = current_gen;
        publish_flushed_generation(percpu.cpu_id, current_gen);
    }
}

/// Ask every CPU to flush its TLB on its next kernel entry.
///
/// Bumps the global TLB generation counter, which each CPU compares against
/// its own `tlb_generation_seen` in [`apply_remote_tlb_invalidations`].
/// Used by the PCID allocator when a wrap-around reuses PCIDs that may still
/// be tagged in remote TLBs.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn request_remote_tlb_flush() {
    TLB_GENERATION.fetch_add(1, Ordering::Release);
}

/// Ask every CPU to flush, and answer with the generation that request
/// belongs to.
///
/// The caller keeps the returned value and later asks [`all_cpus_flushed`]
/// whether every CPU has caught up with it.  Taking the value *after* the
/// page-table edit is what ties the two together: a CPU that publishes this
/// generation or later has taken its slow path after the edit was published.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn request_remote_tlb_flush_generation() -> u64 {
    TLB_GENERATION.fetch_add(1, Ordering::Release) + 1
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn request_remote_tlb_flush_generation() -> u64 {
    // Nothing to wait out where the architecture broadcasts its invalidations,
    // and nothing to record where there is no hardware TLB.  The value still
    // orders retirements first-in-first-out.
    #[cfg(target_os = "none")]
    {
        TLB_GENERATION.fetch_add(1, core::sync::atomic::Ordering::Release) + 1
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Handle a TLB shootdown IPI on any CPU (BSP or AP).
///
/// Called from the IDT handler for `IPI_SHOOTDOWN_VECTOR`.
/// Invalidates the local TLB entry for the address in [`SHOOTDOWN_VA`]
/// and increments the acknowledgment counter.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn handle_tlb_shootdown() {
    SHOOTDOWN_HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
    let va = SHOOTDOWN_VA.load(Ordering::Acquire);
    if va != 0 {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack));
        }
    }
    SHOOTDOWN_ACK_COUNT.fetch_add(1, Ordering::Release);
}

// ── Reschedule IPI ─────────────────────────────────────────────────────

/// Send a reschedule IPI to a specific CPU.
///
/// cpu_id=0 is the BSP (self-IPI not needed — the BSP checks need_resched on
/// every kernel exit).  For APs (cpu_id >= 1), sends `IPI_RESCHEDULE_VECTOR`
/// so the target CPU invokes its scheduler.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn send_reschedule_ipi(cpu_id: u32) {
    if cpu_id == 0 {
        return; // BSP: no self-IPI needed
    }
    let idx = (cpu_id - 1) as usize;
    let count = super::bringup::ONLINE_AP_COUNT.load(Ordering::Acquire) as usize;
    if idx >= count {
        return;
    }
    let ids = unsafe { &*super::bringup::AP_LAPIC_IDS.get() };
    super::bringup::send_ipi(
        ids[idx],
        super::bringup::IPI_RESCHEDULE_VECTOR as u32 | apic::ICR_DELIVERY_FIXED,
    );
}

/// Stub for non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn send_reschedule_ipi(_cpu_id: u32) {}

// ── Online CPU count ───────────────────────────────────────────────────

/// Return the total number of online CPUs (BSP + APs).
///
/// Before AP bring-up completes, returns 1 (BSP only).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn online_cpu_count() -> u32 {
    1 + super::bringup::ONLINE_AP_COUNT.load(Ordering::Acquire)
}

/// Stub for non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn online_cpu_count() -> u32 {
    // On non-x86_64, report 1 for BSP; updated by `bringup::set_online_ap_count`.
    1
}

/// Return the current TLB shootdown generation counter.
///
/// This is cross-arch — used by AArch64/RISC-V SMP to check whether a TLB
/// flush is needed (x86_64 reads the counter internally).
#[cfg(target_os = "none")]
#[cfg_attr(all(target_arch = "x86_64", target_os = "none"), allow(dead_code))]
pub fn tlb_generation() -> u64 {
    TLB_GENERATION.load(core::sync::atomic::Ordering::Acquire)
}

/// Return the current TLB shootdown generation counter.
///
/// Host builds never perform remote TLB invalidations, so the counter the
/// per-arch SMP helpers compare against stays at zero.
#[cfg(all(
    not(target_os = "none"),
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
pub fn tlb_generation() -> u64 {
    0
}

// ── Boot CR3 ───────────────────────────────────────────────────────────

/// Boot Page Table root (PML4) physical address.  Saved before
/// [`crate::arch::mmu::activate_prepared_runtime_kernel_page_tables`]
/// switches away from the bootstrap identity map.  The boot page tables
/// identity-map the first 1 GiB with 2 MiB pages, which covers all AP
/// trampoline code/data (0x8000–0xA000) and any ACPI table below 1 GiB.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static BOOT_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Save the current CR3 value (the boot page-table root) for AP startup.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn save_boot_cr3() {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    BOOT_CR3.store(cr3, core::sync::atomic::Ordering::Release);
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn save_boot_cr3() {}

// ── Stubs for non-bare-metal targets ───────────────────────────────────

/// Stub for non-bare-metal targets (tests, other architectures).
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn tlb_shootdown(_va: usize) {
    // no-op: single-CPU or test environment
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn handle_tlb_shootdown() {}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[allow(dead_code)]
pub fn apply_remote_tlb_invalidations() {}
