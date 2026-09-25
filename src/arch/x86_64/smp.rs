//! src/arch/x86_64/smp.rs
//!
//! Starting the application processors: the trampoline, the SIPI sequence,
//! the per-CPU data each core needs before it can be dispatched to, and the
//! LAPIC plumbing that reaches one CPU from another.
//!
//! The kernel keeps what is the same everywhere — the registry of online
//! CPUs and the decision about who may be asked to reschedule — and this
//! module is what the x86_64 answer to the rest looks like.  It compares
//! with `arch/aarch64/smp.rs` (PSCI and an SGI) and `arch/riscv64/smp.rs`
//! (SBI HSM and a parked hart).

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use alloc::boxed::Box;

use crate::arch::x86_64::apic;
use crate::kernel::process::scheduler::registry::register;
use crate::kernel::smp::MAX_APS;
use crate::kernel::smp::MAX_CPUS;

// ── Constants ───────────────────────────────────────────────────────────

/// Physical base address for the AP trampoline.
/// Must be page-aligned, identity-mapped, and below 1 MiB (real-mode
/// addressability).
const TRAMPOLINE_BASE: u32 = 0x8000;

/// Physical address of the trampoline data page (parameters passed to APs).
const TRAMPOLINE_DATA_BASE: u32 = 0x9000;

/// Stack size for each AP's initial kernel stack.
const AP_STACK_SIZE: usize = 65536; // 64 KiB

/// Statically-allocated AP stacks in kernel BSS to guarantee the stack pages
/// are mapped by the runtime page tables.  The heap-allocated stacks may fall
/// on pages that the kernel page-table setup does not cover.
#[derive(Copy, Clone)]
#[repr(C, align(4096))]
struct ApStack([u8; AP_STACK_SIZE]);

static AP_STACKS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[ApStack; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([ApStack([0; AP_STACK_SIZE]); MAX_APS]);

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

impl TrampolineData {
    unsafe fn write_to(self) {
        let dst = TRAMPOLINE_DATA_BASE as *mut TrampolineData;
        unsafe { core::ptr::write_volatile(dst, self) };
    }
}

// ── Boot page-table root ───────────────────────────────────────────────

/// Boot Page Table root (PML4) physical address.  Saved before
/// [`crate::arch::mmu::activate_prepared_runtime_kernel_page_tables`]
/// switches away from the bootstrap identity map, and read back when an AP
/// starts: the trampoline runs on the boot tables, which identity-map the
/// first 1 GiB with 2 MiB pages and so cover all of its code and data
/// (0x8000–0xA000) and any ACPI table below 1 GiB.
pub(crate) static BOOT_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Save the current CR3 value (the boot page-table root) for AP startup.
pub fn save_boot_cr3() {
    let cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    BOOT_CR3.store(cr3, Ordering::Release);
}

// ── IPI delivery ───────────────────────────────────────────────────────

/// BSP LAPIC ID, set during early SMP init.  Needed so APs can send
/// TLB-shootdown IPIs back to the BSP.
static BSP_LAPIC_ID: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// LAPIC id of each CPU that is online, indexed by logical CPU id.
pub(crate) static AP_LAPIC_IDS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[u8; MAX_CPUS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([0; MAX_CPUS]);

/// Save the BSP LAPIC ID so APs can send IPIs back to the BSP.
pub fn save_bsp_lapic_id(id: u8) {
    BSP_LAPIC_ID.store(id, Ordering::Release);
    // Record CPU 0 → LAPIC ID for the IRQ load balancer.
    crate::arch::x86_64::irq_balance::register_cpu(0, id);
}

/// Ask one CPU to look at its run queue again, by LAPIC IPI.
///
/// The caller has already established that the CPU is online and is not the
/// one sending the request; this is the x86_64 half of that, and the kernel's
/// [`crate::kernel::smp::send_reschedule_ipi`] is the neutral one.
pub fn send_reschedule_ipi(cpu_id: u32) {
    // CPU 0 is the BSP, which is never one of the APs whose LAPIC ids the
    // bring-up loop writes; its own id is what reaches it.
    let hardware_id = if cpu_id == 0 {
        BSP_LAPIC_ID.load(Ordering::Acquire)
    } else {
        // SAFETY: the CPU is online, so its LAPIC id was written before the
        // registry published that fact, and the acquire in the registry is
        // what makes the write visible here.
        unsafe { (*AP_LAPIC_IDS.get())[cpu_id as usize] }
    };
    send_ipi(
        hardware_id,
        IPI_RESCHEDULE_VECTOR as u32 | apic::ICR_DELIVERY_FIXED,
    );
}

/// IPI vector for reschedule requests.
pub const IPI_RESCHEDULE_VECTOR: u8 = crate::arch::x86_64::idt::IPI_RESCHEDULE_VECTOR;

/// Send an IPI to a specific APIC ID.
///
/// The caller is responsible for assembling the ICR low value, including
/// any level/trigger-mode bits.  Only the destination (ICR high) is set here.
///
/// After writing ICR_LOW we spin for a short time so the LAPIC has a chance
/// to deliver the IPI.  We intentionally do NOT poll or clear the Delivery
/// Status bit because level-triggered IPIs (INIT) may keep the status bit set
/// indefinitely on some hardware / under QEMU emulation.
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

// Symbols from the trampoline assembly (ap_trampoline.asm, included by
// `main.rs` — the binary crate owns the assembly, so this only links in the
// kernel binary).
extern "C" {
    fn ap_trampoline_start();
    fn ap_trampoline_end();
}

/// Copy the trampoline code to its low-memory location.
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
    // (reschedule requests), leading to a deadlock when the BSP waits for
    // cross-CPU work to be picked up.
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
        // IPI (reschedule) is serviced immediately rather than just waking
        // the CPU from HLT with IF still clear.
        crate::arch::interrupts::enable_and_halt();
    }
}

// ── SMP bring-up orchestration ─────────────────────────────────────────

/// Bring up all discovered APs.
///
/// Called from `Kernel::init` on the BSP after per-CPU data and the LAPIC
/// are initialised.
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
    // silent hang is a good trade.
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
    let cr3 = BOOT_CR3.load(Ordering::Acquire);

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
            register(cpu_id, ap_scheduler_ptr);
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

#[allow(dead_code)]
fn spin_delay_ms(ms: u64) {
    let iterations = ms.saturating_mul(10_000);
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

#[allow(dead_code)]
fn spin_delay_us(us: u64) {
    let iterations = us.saturating_mul(10);
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}
