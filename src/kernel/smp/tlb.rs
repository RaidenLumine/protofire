//! src/kernel/smp/tlb.rs
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
        percpu.tlb_generation_seen = current_gen;
        // Reload CR3 to flush the entire TLB.
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
            core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
        }
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
/// flush is needed.
#[cfg(target_os = "none")]
pub fn tlb_generation() -> u64 {
    TLB_GENERATION.load(core::sync::atomic::Ordering::Acquire)
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
