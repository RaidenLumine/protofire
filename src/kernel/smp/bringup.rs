//! src/kernel/smp/bringup.rs
//!
//! AP trampoline, bring-up, per-CPU scheduler management, and IPI delivery.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::apic;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::boxed::Box;

// ── Constants ───────────────────────────────────────────────────────────

/// Physical base address for the AP trampoline.
/// Must be page-aligned, identity-mapped, and below 1 MiB (real-mode
/// addressability).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const TRAMPOLINE_BASE: u32 = 0x8000;

/// Physical address of the trampoline data page (parameters passed to APs).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const TRAMPOLINE_DATA_BASE: u32 = 0x9000;

/// Stack size for each AP's initial kernel stack.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const AP_STACK_SIZE: usize = 65536; // 64 KiB

/// Maximum number of application processors this kernel will store a
/// scheduler for.
///
/// One number for every architecture: the registry below is indexed by logical
/// CPU id, and a CPU the kernel cannot store a scheduler for is a CPU it
/// cannot dispatch a thread on.  An architecture that stops bringing cores up
/// earlier says so where it does that.
pub const MAX_APS: usize = 16;

/// Maximum total CPUs (BSP + APs).
pub const MAX_CPUS: usize = MAX_APS + 1;

/// The online-CPU mask is a `u32`, so every CPU has to fit in it.
const _: () = assert!(MAX_CPUS <= 32);

/// Statically-allocated AP stacks in kernel BSS to guarantee the stack pages
/// are mapped by the runtime page tables.  The heap-allocated stacks may fall
/// on pages that the kernel page-table setup does not cover.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[repr(C, align(4096))]
struct ApStack([u8; AP_STACK_SIZE]);

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static AP_STACKS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[ApStack; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
        ApStack([0; AP_STACK_SIZE]),
    ]);

// ── Per-CPU scheduler registry ─────────────────────────────────────────

/// Per-CPU scheduler pointers, indexed by logical CPU id.
///
/// `cpu_id` 0 is the BSP; an AP sits at the index it reports as its own id.
/// Each CPU registers its scheduler during boot — the BSP from `Kernel::init`,
/// an AP either from the core that starts it or from its own entry point — and
/// the pointer lives until shutdown.
static PERCPU_SCHEDULERS: crate::util::sync_unsafe_cell::SyncUnsafeCell<
    [*mut crate::kernel::process::Scheduler; MAX_CPUS],
> = crate::util::sync_unsafe_cell::SyncUnsafeCell::new([core::ptr::null_mut(); MAX_CPUS]);

/// Bit `N` is set once logical CPU `N` has a scheduler, which is the moment it
/// can run a thread.
///
/// This is the kernel's one answer to "how many CPUs are online", and
/// [`register_percpu_scheduler`] is the only thing that writes it.  It is
/// derived from the registry rather than kept beside it so that the two cannot
/// disagree, and it is a mask rather than a number because a count only works
/// as an index bound when the ids are contiguous — which nothing makes them.
///
/// Before this existed, each architecture answered the question its own way:
/// x86_64 counted the APs whose start it had confirmed, and aarch64 and riscv64
/// reached a setter that wrote a function-local static nobody read, behind a
/// count that was the constant 1.  A four-core machine then scheduled on one
/// core, and the number said everything was fine.
static ONLINE_CPUS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Register a CPU's scheduler, and with it the CPU.
///
/// # Safety
///
/// `scheduler` must stay alive for as long as the kernel runs: every other CPU
/// reaches it through this registry to place work.  Each `cpu_id` is
/// registered once, with one pointer.
#[cfg_attr(not(target_os = "none"), allow(dead_code))] // no CPU registers on a host build
pub unsafe fn register_percpu_scheduler(
    cpu_id: u32,
    scheduler: *mut crate::kernel::process::Scheduler,
) {
    let idx = cpu_id as usize;
    if idx >= MAX_CPUS {
        return;
    }
    // SAFETY: the index is in range, and this is the register-once call for
    // this CPU, so it owns the slot.
    unsafe { (*PERCPU_SCHEDULERS.get())[idx] = scheduler };
    // Whoever sees the bit has to see the pointer, so the pointer is stored
    // first and the bit is published with a release.
    ONLINE_CPUS.fetch_or(1 << idx, Ordering::Release);
}

/// Look up the scheduler for a CPU.
///
/// `None` means that CPU is not online — an id outside [`MAX_CPUS`] included.
/// Callers use this to decide whether a thread can be placed on a CPU, so the
/// answer has to be the same question [`cpu_is_online`] answers.
pub fn get_percpu_scheduler(cpu_id: u32) -> Option<&'static crate::kernel::process::Scheduler> {
    let idx = cpu_id as usize;
    if !cpu_is_online(cpu_id) {
        return None;
    }
    // SAFETY: the acquire in `cpu_is_online` is on the bit that the
    // registering CPU set after storing the pointer, and a registered
    // scheduler outlives the kernel.
    unsafe { (*PERCPU_SCHEDULERS.get())[idx].as_ref() }
}

/// Is this CPU running kernel code — that is, can it be given a thread?
pub fn cpu_is_online(cpu_id: u32) -> bool {
    let idx = cpu_id as usize;
    idx < MAX_CPUS && ONLINE_CPUS.load(Ordering::Acquire) & (1 << idx) != 0
}

/// Iterate over the online CPUs' schedulers, lowest id first.
///
/// Calls `f` with `(cpu_id, &Scheduler)` for each of them.
pub fn for_each_percpu_scheduler(mut f: impl FnMut(u32, &crate::kernel::process::Scheduler)) {
    let mask = ONLINE_CPUS.load(Ordering::Acquire);
    for idx in 0..MAX_CPUS as u32 {
        if mask & (1 << idx) == 0 {
            continue;
        }
        if let Some(sched) = get_percpu_scheduler(idx) {
            f(idx, sched);
        }
    }
}

/// Number of CPUs that can run a thread.
///
/// The CPU asking is one of them by definition — this code is running on it —
/// so the answer is at least 1 even before the BSP registers during init, and
/// on a host build that never registers at all.  Callers size loops and pick a
/// CPU for new work with this, and both want a bound rather than the zero an
/// empty registry would otherwise answer with.
pub fn online_cpu_count() -> u32 {
    ONLINE_CPUS.load(Ordering::Acquire).count_ones().max(1)
}

// ── Trampoline data layout at TRAMPOLINE_DATA_BASE ──────────────────────

/// Data passed from BSP to AP through the trampoline data page.
/// Each field sits at a known offset from `TRAMPOLINE_DATA_BASE`.
///
/// Offset layout (each field is 8 bytes for simplicity):
///   0x00: cr3 (page table root physical address)
///   0x08: entry_point (virtual address of ap_entry)
///   0x10: stack_top (virtual address of initial stack top)
///   0x18: cpu_id (logical CPU ID)
///   0x20: lapic_id (local APIC ID)
///   0x28: percpu_base (virtual address of PerCpuData for this CPU)
///   0x30: ap_started_flag (pointer to AtomicBool — AP sets to true when up)
///   0x38: runtime_cr3 (kernel runtime page-table root — used before calling
/// ap_entry)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[repr(C)]
struct TrampolineData {
    cr3: u64,             // 0x00 — boot page-table root (identity-maps first 1 GiB)
    stack_top: u64,       // 0x08 — read by trampoline via `mov rsp, [0x9008]`
    entry_point: u64,     // 0x10 — read by trampoline via `mov rax, [0x9010]`
    cpu_id: u64,          // 0x18 — read by trampoline via `mov edi, [0x9018]`
    lapic_id: u64,        // 0x20 — read by trampoline via `mov esi, [0x9020]`
    percpu_base: u64,     // 0x28
    ap_started_flag: u64, // 0x30 — read by trampoline via `mov rax, [0x9030]`
    runtime_cr3: u64,     // 0x38 — loaded before calling ap_entry
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl TrampolineData {
    unsafe fn write_to(self) {
        let dst = TRAMPOLINE_DATA_BASE as *mut TrampolineData;
        unsafe { core::ptr::write_volatile(dst, self) };
    }
}

// ── IPI delivery ───────────────────────────────────────────────────────

/// Send an IPI to a specific APIC ID.
///
/// The caller is responsible for assembling the ICR low value, including
/// any level/trigger-mode bits.  Only the destination (ICR high) is set here.
///
/// After writing ICR_LOW we spin for a short time so the LAPIC has a chance
/// to deliver the IPI.  We intentionally do NOT poll or clear the Delivery
/// Status bit because level-triggered IPIs (INIT) may keep the status bit set
/// indefinitely on some hardware / under QEMU emulation.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn send_ipi(apic_id: u8, icr_low: u32) {
    // Wait for the ICR to be ready (Delivery Status clear).  The LAPIC can
    // only buffer one outgoing IPI at a time, but a level-triggered IPI
    // (e.g. INIT) may keep Delivery Status set indefinitely, so bound this
    // poll rather than spinning forever.
    const ICR_DELIVERY_STATUS: u32 = 1 << 12;
    let mut spins: u64 = 0;
    while unsafe { apic::lapic_read(apic::LAPIC_ICR_LOW as u32) } & ICR_DELIVERY_STATUS != 0 {
        core::hint::spin_loop();
        spins += 1;
        if spins >= 1_000_000 {
            let icr_val = unsafe { apic::lapic_read(apic::LAPIC_ICR_LOW as u32) };
            crate::println!(
                "[WARN ] send_ipi(cpu{}): ICR Delivery Status stuck after {} spins (level-triggered IPI may keep it set), proceeding anyway, ICR_LOW={:#x}",
                crate::kernel::percpu::get().cpu_id,
                spins,
                icr_val,
            );
            break;
        }
    }
    if spins > 0 {
        crate::println!(
            "[diag ] send_ipi(cpu{}): Delivery Status cleared after {} spins",
            crate::kernel::percpu::get().cpu_id,
            spins,
        );
    }

    // Write ICR high (destination) first, then ICR low (triggers send).
    let icr_high = (apic_id as u32) << 24;
    unsafe {
        apic::lapic_write(apic::LAPIC_ICR_HIGH as u32, icr_high);
        apic::lapic_write(apic::LAPIC_ICR_LOW as u32, icr_low);
    }

    // Poll Delivery Status until the IPI has been accepted by the
    // destination LAPIC, then verify it cleared.
    spins = 0;
    while unsafe { apic::lapic_read(apic::LAPIC_ICR_LOW as u32) } & ICR_DELIVERY_STATUS != 0 {
        core::hint::spin_loop();
        spins += 1;
        if spins >= 1_000_000 {
            let icr_val = unsafe { apic::lapic_read(apic::LAPIC_ICR_LOW as u32) };
            crate::println!(
                "[WARN ] send_ipi(cpu{}): Delivery Status NOT clearing after send, ICR_LOW={:#x}, dst={}, vector={:#x}",
                crate::kernel::percpu::get().cpu_id,
                icr_val,
                apic_id,
                icr_low & 0xFF,
            );
            break;
        }
    }
}

/// Poll the ICR Delivery Status bit until it is clear.
///
/// Called before sending a non-level IPI (e.g. SIPI) to ensure the previous
/// IPI has been fully delivered.  Must NOT be called after a level-triggered
/// IPI (INIT), which may keep Delivery Status set indefinitely.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn wait_icr_ready() {
    for _ in 0..100_000 {
        let icr_low = unsafe { apic::lapic_read(apic::LAPIC_ICR_LOW as u32) };
        if icr_low & apic::ICR_STATUS_PENDING == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

// ── AP trampoline ──────────────────────────────────────────────────────

// Symbols from the trampoline assembly (ap_trampoline.asm).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
extern "C" {
    fn ap_trampoline_start();
    fn ap_trampoline_end();
}

/// Copy the trampoline code to its low-memory location.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn install_trampoline() {
    let start = ap_trampoline_start as *const u8;
    let end = ap_trampoline_end as *const u8;
    let len = (end as usize) - (start as usize);

    assert!(len <= 4096, "AP trampoline must fit in one page");

    let dst = TRAMPOLINE_BASE as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(start, dst, len);
    }

    // Verify the copy by reading back the first instruction bytes.
    let first_byte = unsafe { core::ptr::read_volatile(dst) };
    let expected_first_byte = unsafe { core::ptr::read_volatile(start) };
    crate::println!(
        "[smp   ] trampoline installed at {:#010x} len={} first_byte={:#x} expected={:#x}",
        TRAMPOLINE_BASE,
        len,
        first_byte,
        expected_first_byte
    );
    if first_byte != expected_first_byte {
        crate::println!(
            "[smp   ] WARNING: trampoline copy verification FAILED — physical memory may not be identity-mapped"
        );
    }
}

// ── AP entry point ─────────────────────────────────────────────────────

/// Entry point called from the AP trampoline once the AP reaches 64-bit
/// long mode.
///
/// # Safety
///
/// Called on the AP with interrupts disabled, running on a temporary stack
/// provided by the BSP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[no_mangle]
unsafe extern "C" fn ap_entry(cpu_id: u32, lapic_id: u8) -> ! {
    // Signal the BSP that we've reached 64-bit long mode.  The started_flag
    // pointer (a kernel virtual address) is stored at offset 0x30 in the
    // identity-mapped trampoline data page.  We must do this HERE under the
    // runtime page tables — the trampoline's 16-bit / 32-bit phases cannot
    // dereference a kernel virtual address.
    let started_ptr = unsafe { core::ptr::read_volatile(0x9030 as *const u64) } as *mut AtomicBool;
    if !started_ptr.is_null() {
        unsafe {
            (*started_ptr).store(true, Ordering::Release);
        }
    }

    // Reuse the PerCpuData already allocated by bring_up_single_ap (its
    // virtual address is in the trampoline data page at offset 0x28).
    let percpu_ptr = unsafe { core::ptr::read_volatile(0x9028 as *const u64) }
        as *mut crate::kernel::percpu::PerCpuData;

    // Load the shared kernel IDT so IPIs and other interrupts are delivered.
    crate::arch::x86_64::idt::init_ap();

    // Load the shared kernel GDT with this CPU's private TSS.
    let ap_tss = unsafe { (*percpu_ptr).tss as *mut crate::arch::x86_64::gdt::TaskStateSegment };
    crate::arch::x86_64::gdt::init_ap(ap_tss);

    // Point both GS bases at this CPU's PerCpuData, so `gs:`-relative
    // per-CPU access and `swapgs` on the interrupt path both see it.
    //
    // SAFETY: `percpu_ptr` is this AP's live PerCpuData, and this runs once
    // on this AP, after its GDT is loaded.
    unsafe {
        crate::arch::x86_64::percpu::init_ap_gs_bases(percpu_ptr);
    }

    // Initialize the local APIC on this CPU.
    apic::init_lapic_ap();

    // Scheduler and idle process were pre-created by the BSP before sending
    // INIT-SIPI-SIPI (see bring_up_single_ap).  Read the scheduler pointer
    // from PerCpuData and enter the dispatch loop directly — no heap
    // allocations needed here, avoiding lock contention with the BSP.
    let scheduler_ptr = unsafe { (*percpu_ptr).scheduler };

    crate::println!("[smp   ] AP cpu_id={} lapic_id={} online", cpu_id, lapic_id);

    // Enable interrupts now that the LAPIC is configured.  The trampoline
    // starts with IF=0 (cli); without sti the AP would never receive IPIs
    // (TLB shootdown, reschedule), leading to a deadlock when the BSP waits
    // for cross-CPU acknowledgements.
    crate::arch::interrupts::enable();
    loop {
        // Drop any thread that terminated in the previous scheduling epoch.
        // This happens with interrupts enabled so that KernelStack::drop
        // can safely acquire the memory-manager spinlock without deadlocking
        // with a cross-CPU TLB shootdown that requires our IPI ack.
        unsafe {
            (*scheduler_ptr).process_deferred_dying();
        }

        crate::arch::interrupts::disable();
        unsafe {
            (*scheduler_ptr).schedule();
        }
        // Enable interrupts and halt in one atomic window so that a pending
        // IPI (TLB shootdown, reschedule) is serviced immediately rather than
        // just waking the CPU from HLT with IF still clear.
        crate::arch::interrupts::enable_and_halt();
    }
}

// ── SMP bring-up orchestration ─────────────────────────────────────────

/// Bring up all discovered APs.
///
/// Called from [`Kernel::init`] on the BSP after per-CPU data and the
/// LAPIC are initialised.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn bring_up_aps(aps: &[(u32, u8)]) {
    if aps.is_empty() {
        crate::println!("[smp   ] no APs to bring up — running single-CPU");
        return;
    }

    unsafe { install_trampoline() };

    for &(cpu_id, lapic_id) in aps {
        if cpu_id > MAX_APS as u32 {
            crate::println!(
                "[smp   ] skipping cpu_id={} (exceeds MAX_APS={})",
                cpu_id,
                MAX_APS
            );
            continue;
        }

        // The AP joins the scheduler registry from inside this call, once its
        // start is confirmed — so there is no second bookkeeping pass that
        // could disagree with the first.
        bring_up_single_ap(cpu_id, lapic_id);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn bring_up_single_ap(cpu_id: u32, lapic_id: u8) {
    crate::println!(
        "[smp   ] bring_up_single_ap: cpu={} lapic={}",
        cpu_id,
        lapic_id
    );

    // Use a statically-allocated AP stack from kernel BSS (guaranteed mapped by
    // the runtime page tables, unlike heap-allocated pages which may not be).
    let idx = cpu_id as usize;
    if idx >= MAX_APS {
        crate::println!("[smp   ] cpu_id={} exceeds MAX_APS={}", cpu_id, MAX_APS);
        return;
    }
    // Use a statically-allocated AP stack from kernel BSS.  These are
    // guaranteed to be mapped by the runtime page tables.  The AP trampoline
    // now enables EFER.NXE (bit 11) so that the NX bit (bit 63) in BSS/data
    // PTEs is not treated as a reserved bit.
    let stack = unsafe { &raw mut (*AP_STACKS.get())[idx].0[0] };
    let stack_top = unsafe { stack.add(AP_STACK_SIZE) };

    // Allocate per-CPU data and a private TSS for this AP.
    //
    // Each step is announced before it runs.  This window has stalled on real
    // hardware-replacement runs with the log ending on the line above, and the
    // steps here are exactly the ones that touch shared state (the heap, the
    // scheduler registries) while earlier APs are already running — so when it
    // stalls again, the last marker names the step rather than leaving the
    // question open.  Three lines per boot for a path that has produced a
    // silent hang is a good trade.  See `docs` note on SMP bring-up.
    crate::println!("[smp   ]   prepare: per-cpu data");
    let percpu = Box::new(crate::kernel::percpu::PerCpuData::zeroed());
    let percpu_ptr = Box::into_raw(percpu);
    crate::println!("[smp   ]   prepare: ap task state segment");
    let ap_tss = Box::new(crate::arch::x86_64::gdt::TaskStateSegment::new());
    let ap_tss_ptr = Box::into_raw(ap_tss);
    unsafe {
        (*percpu_ptr).cpu_id = cpu_id;
        (*percpu_ptr).lapic_id = lapic_id;
        (*percpu_ptr).tss = ap_tss_ptr as *mut u8;
    }

    // ── Pre-create the AP's scheduler and idle process from the BSP ───
    // The AP would otherwise need the heap lock and MEMORY_MANAGER_LOCK
    // during ap_entry, racing with the BSP's spawn_demo_threads.  By
    // creating everything here (single-threaded, BSP only) the AP can
    // enter its dispatch loop without any heap allocations.
    let ap_scheduler = Box::new(crate::kernel::process::Scheduler::new());
    // Say which CPU this scheduler belongs to before anything is spawned on
    // it: its idle thread is pinned to that CPU, and the round-robin that
    // places other threads starts from it.
    ap_scheduler.bind_to_cpu(cpu_id);
    let ap_scheduler_ptr = Box::into_raw(ap_scheduler);
    unsafe {
        (*percpu_ptr).scheduler = ap_scheduler_ptr;
    }
    crate::println!("[smp   ]   prepare: ap scheduler registered");
    unsafe {
        (*ap_scheduler_ptr).start_idle_process();
    }
    crate::println!("[smp   ]   prepare: ap idle process started");

    // AP started flag.
    crate::println!("[smp   ]   prepare: started flag");
    let started = Box::new(AtomicBool::new(false));
    let started_ptr = Box::into_raw(started);

    // Use the saved boot CR3 (identity-maps first 1 GiB) rather than the
    // runtime kernel page-table root, which may not identity-map low memory.
    let cr3 = super::tlb::BOOT_CR3.load(core::sync::atomic::Ordering::Acquire);

    // Read the runtime CR3 (the active kernel page-table root) so the AP
    // can switch to it before calling ap_entry.  ap_entry accesses LAPIC
    // MMIO (0xFEE0_0000), which is only mapped in the runtime page tables.
    let runtime_cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) runtime_cr3, options(nostack, preserves_flags));
    }

    // Fill trampoline data.  Field order must match TrampolineData layout
    // (stack_top at 0x08, entry_point at 0x10 in the 8-byte grid).
    let tdata = TrampolineData {
        cr3,
        stack_top: stack_top as u64,
        entry_point: ap_entry as *const () as u64,
        cpu_id: cpu_id as u64,
        lapic_id: lapic_id as u64,
        percpu_base: percpu_ptr as u64,
        ap_started_flag: started_ptr as u64,
        runtime_cr3,
    };
    unsafe { tdata.write_to() };
    crate::println!("[smp   ] trampoline data written, sending INIT assert...");

    // ── INIT-SIPI-SIPI sequence (Intel SDM Vol 3 § 10.6) ────────────────
    // Step 1: Assert INIT.  Trigger Mode must be Level (bit 15) for INIT;
    // Level=Assert (bit 14) combined with Trigger Mode=Level is the
    // canonical INIT assert per Intel SDM § 10.6.1 Table 10-19.
    send_ipi(
        lapic_id,
        apic::ICR_DELIVERY_INIT | apic::ICR_LEVEL_ASSERT | apic::ICR_TRIGGER_LEVEL,
    );
    crate::println!("[smp   ] INIT assert sent, waiting 10 ms...");

    // Step 2: Wait at least 10 ms for the AP to process the INIT.
    for _ in 0..5000 {
        core::hint::spin_loop();
    }

    // Step 3: De-assert INIT.  Without this step the AP remains in the INIT
    // state and will never respond to the SIPI.
    send_ipi(lapic_id, apic::ICR_DELIVERY_INIT | apic::ICR_TRIGGER_LEVEL);
    crate::println!("[smp   ] INIT de-assert sent, waiting 200 µs...");

    // Step 4: Wait at least 200 µs between INIT de-assert and the first SIPI
    // (Intel SDM § 10.6, Table 10-21).  The LAPIC timer is not calibrated
    // here; a conservative spin-loop covers typical hardware.
    for _ in 0..2000 {
        core::hint::spin_loop();
    }

    // Step 5: Send the first SIPI.  Vector 0x08 → real-mode address 0x8000.
    // The INIT de-assert is level-triggered and may keep the ICR Delivery
    // Status bit set indefinitely — we must NOT poll it here.  The 200 µs
    // delay (step 4) is sufficient to satisfy the hardware requirement.
    // If the SIPI is lost because the ICR was still busy, the second SIPI
    // acts as a safety net.
    crate::println!("[smp   ] sending first SIPI...");
    send_ipi(lapic_id, 0x08 | apic::ICR_DELIVERY_STARTUP);

    // Step 6: Wait at least 200 µs between SIPIs (Intel SDM § 10.6).
    for _ in 0..2000 {
        core::hint::spin_loop();
    }

    crate::println!("[smp   ] sending second SIPI...");
    send_ipi(lapic_id, 0x08 | apic::ICR_DELIVERY_STARTUP);

    // Wait for the AP to signal that it has started.
    let mut started_ok = false;
    for _ in 0..50000 {
        if unsafe { (*started_ptr).load(Ordering::Acquire) } {
            started_ok = true;
            break;
        }
        core::hint::spin_loop();
    }

    if started_ok {
        crate::println!(
            "[smp   ] cpu_id={} lapic_id={} started successfully",
            cpu_id,
            lapic_id
        );
        // Record CPU → LAPIC ID for the IRQ load balancer.
        crate::arch::x86_64::irq_balance::register_cpu(cpu_id, lapic_id);
        // The AP is running and can be dispatched to, so it joins the
        // registry here — after its start was confirmed, not before: a CPU
        // that never came up must not look schedulable to any other CPU.
        // SAFETY: `ap_scheduler_ptr` was allocated for this AP and is never
        // freed, and this is the one registration of that id.
        unsafe {
            (*AP_LAPIC_IDS.get())[cpu_id as usize] = lapic_id;
            register_percpu_scheduler(cpu_id, ap_scheduler_ptr);
        }
        // Leak the started flag — the AP is running and we may need it later.
        core::mem::forget(unsafe { Box::from_raw(started_ptr) });
    } else {
        crate::println!(
            "[smp   ] timeout waiting for cpu_id={} lapic_id={} to start",
            cpu_id,
            lapic_id
        );
        // Clean up the started flag.
        drop(unsafe { Box::from_raw(started_ptr) });
        // The AP's scheduler was created but is never registered, so this CPU
        // is not schedulable and no other CPU will place work on it.
    }
}

// ── Calibrated busy-wait helpers (unused with short inline delays above) ──
// Keep for future use with configurable delay durations.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn spin_delay_ms(ms: u64) {
    let iterations = ms.saturating_mul(10_000);
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[allow(dead_code)]
fn spin_delay_us(us: u64) {
    let iterations = us.saturating_mul(10);
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

// ── IPI delivery ───────────────────────────────────────────────────────

/// BSP LAPIC ID, set during early SMP init.  Needed so APs can send
/// TLB-shootdown IPIs back to the BSP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static BSP_LAPIC_ID: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// LAPIC id of each CPU that is online, indexed by logical CPU id.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static AP_LAPIC_IDS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[u8; MAX_CPUS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([0; MAX_CPUS]);

/// Save the BSP LAPIC ID so APs can send IPIs back to the BSP.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn save_bsp_lapic_id(id: u8) {
    BSP_LAPIC_ID.store(id, Ordering::Release);
    // Record CPU 0 → LAPIC ID for the IRQ load balancer.
    crate::arch::x86_64::irq_balance::register_cpu(0, id);
}

/// Ask a CPU to look at its run queue again.
///
/// The kernel sends this when it has just made a thread runnable on another
/// CPU: without it the thread waits for that CPU's next timer tick, and a CPU
/// with nothing to run is halted rather than ticking — so a wake-up on an idle
/// core costs a full tick of latency, or arrives never.
///
/// A CPU that is not online cannot be asked, and the CPU sending the request
/// has no reason to ask itself: the BSP checks for pending work on every
/// kernel exit, and an AP checks before it halts.  How a CPU is reached is the
/// architecture's business, and each says so in its own
/// [`send_reschedule_ipi_to`].
pub fn send_reschedule_ipi(cpu_id: u32) {
    if !cpu_is_online(cpu_id) || cpu_id == crate::kernel::percpu::get().cpu_id {
        return;
    }
    send_reschedule_ipi_to(cpu_id);
}

/// Send the request to an online CPU that is not this one.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn send_reschedule_ipi_to(cpu_id: u32) {
    // CPU 0 is the BSP, which is never one of the APs whose LAPIC ids the
    // bring-up loop writes; its own id is what reaches it.
    let hardware_id = if cpu_id == 0 {
        BSP_LAPIC_ID.load(Ordering::Acquire)
    } else {
        // SAFETY: the CPU is online, so its LAPIC id was written before the
        // registry published that fact, and the acquire in `cpu_is_online` is
        // what makes the write visible here.
        unsafe { (*AP_LAPIC_IDS.get())[cpu_id as usize] }
    };
    send_ipi(
        hardware_id,
        IPI_RESCHEDULE_VECTOR as u32 | apic::ICR_DELIVERY_FIXED,
    );
}

/// Send the request as a software-generated interrupt.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn send_reschedule_ipi_to(cpu_id: u32) {
    crate::arch::aarch64::smp::send_reschedule_sgi(cpu_id);
}

/// RISC-V has no sender here yet: its secondary harts park in `wfi` without
/// entering the scheduler, so there is no run queue for a request to wake and
/// nothing that would read the flag it sets.  Sending the IPI is the second
/// half of putting those harts to work; this is the honest first half.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn send_reschedule_ipi_to(_cpu_id: u32) {}

/// A host build has no other CPU to reach.
#[cfg(not(all(
    target_os = "none",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
)))]
fn send_reschedule_ipi_to(_cpu_id: u32) {}

// ── Constants re-export ────────────────────────────────────────────────

/// IPI vector for reschedule requests.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub const IPI_RESCHEDULE_VECTOR: u8 = crate::arch::x86_64::idt::IPI_RESCHEDULE_VECTOR;
