//! src/arch/aarch64/smp.rs
//!
//! AArch64 SMP arch support: spin-table AP wakeup, MMU-config save/restore,
//! GIC SGI (IPI) delivery, and AP entry-point logic.

use crate::kernel::percpu::PerCpuData;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

// ── Constants ───────────────────────────────────────────────────────────

pub(crate) const MAX_APS: usize = 16;
#[allow(dead_code)]
pub(crate) const MAX_CPUS: usize = MAX_APS + 1;
pub(crate) const AP_STACK_SIZE: usize = 65536;

pub(crate) const SGI_RESCHEDULE: u8 = 0;
pub(crate) const SGI_TLB_SHOOTDOWN: u8 = 1;

// ── Spin table (shared with boot.S) ────────────────────────────────────

/// Per-CPU spin-table entry (matched in boot.S):
///   +0: entry_addr (u64) — 0 = spin; non-zero = entry point
///   +8: stack_top  (u64)
#[repr(C)]
#[derive(Copy, Clone)]
struct SpinTableEntry {
    entry_addr: u64,
    stack_top: u64,
}

/// Referenced from boot.S by `aarch64_spin_table` symbol.
/// Each entry is 16 bytes: [entry_addr(u64), stack_top(u64)].
#[no_mangle]
static aarch64_spin_table: crate::util::sync_unsafe_cell::SyncUnsafeCell<
    [SpinTableEntry; MAX_APS],
> = crate::util::sync_unsafe_cell::SyncUnsafeCell::new(
    [SpinTableEntry {
        entry_addr: 0,
        stack_top: 0,
    }; MAX_APS],
);

// ── Per-CPU AP stacks ──────────────────────────────────────────────────

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
struct ApStack([u8; AP_STACK_SIZE]);

static AP_STACKS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[ApStack; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([ApStack([0; AP_STACK_SIZE]); MAX_APS]);

// ── Boot MMU config (saved by BSP, read by AP assembly with MMU off) ───

#[no_mangle]
pub(crate) static AARCH64_BOOT_TTBR0: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub(crate) static AARCH64_BOOT_TTBR1: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub(crate) static AARCH64_BOOT_TCR: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub(crate) static AARCH64_BOOT_MAIR: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub(crate) static AARCH64_BOOT_SCTLR: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub(crate) static AARCH64_VBAR_ADDR: AtomicU64 = AtomicU64::new(0);

// ── AP startup assembly ─────────────────────────────────────────────────

core::arch::global_asm!(
    r#"
.section .text
.global aarch64_ap_startup
aarch64_ap_startup:
    // Called from boot.S spin table: x0 = cpu_id, MMU off.
    // All data addresses are physical (identity-mapped).

    // 1. Restore MMU configuration from saved BSP values.
    adrp    x1, AARCH64_BOOT_TTBR0
    add     x1, x1, :lo12:AARCH64_BOOT_TTBR0
    ldr     x1, [x1]
    msr     ttbr0_el1, x1

    adrp    x1, AARCH64_BOOT_TTBR1
    add     x1, x1, :lo12:AARCH64_BOOT_TTBR1
    ldr     x1, [x1]
    msr     ttbr1_el1, x1
    isb

    adrp    x1, AARCH64_BOOT_TCR
    add     x1, x1, :lo12:AARCH64_BOOT_TCR
    ldr     x1, [x1]
    msr     tcr_el1, x1
    isb

    adrp    x1, AARCH64_BOOT_MAIR
    add     x1, x1, :lo12:AARCH64_BOOT_MAIR
    ldr     x1, [x1]
    msr     mair_el1, x1
    isb

    adrp    x1, AARCH64_BOOT_SCTLR
    add     x1, x1, :lo12:AARCH64_BOOT_SCTLR
    ldr     x1, [x1]
    msr     sctlr_el1, x1
    isb

    // MMU is now ON — VA == PA identity map, execution continues at the
    // same PC.

    // 2. Load exception vector table.
    adrp    x1, AARCH64_VBAR_ADDR
    add     x1, x1, :lo12:AARCH64_VBAR_ADDR
    ldr     x1, [x1]
    msr     vbar_el1, x1
    isb

    // 3. Enable FP/SIMD.
    mov     x1, #(0b11 << 20)
    msr     cpacr_el1, x1
    isb

    // 4. Jump to Rust entry.
    b       aarch64_ap_entry_rust
"#
);

// ── Assembly symbol declarations ───────────────────────────────────────

unsafe extern "C" {
    fn aarch64_ap_startup();
}

// ── Rust AP entry point ────────────────────────────────────────────────

#[no_mangle]
unsafe extern "C" fn aarch64_ap_entry_rust(cpu_id: u64) -> ! {
    let cpu_id32 = cpu_id as u32;

    // Point TPIDR_EL1 → this AP's PerCpuData.
    let percpu = ap_percpu_data(cpu_id32);
    if percpu.is_null() {
        crate::println!("[smp   ] FATAL: AP cpu_id={} has no PerCpuData", cpu_id);
        loop {
            crate::arch::halt();
        }
    }
    crate::kernel::percpu::aarch64_set_tpidr_el1(percpu as u64);

    // Initialise GIC CPU interface and timer (per-CPU).
    crate::arch::aarch64::interrupt_controller::init_gicc();
    crate::arch::aarch64::timer::init_ap();

    // Fetch pre-created scheduler.
    let sched_ptr = unsafe { (*percpu).scheduler };
    if sched_ptr.is_null() {
        crate::println!("[smp   ] FATAL: AP cpu_id={} has no scheduler", cpu_id);
        loop {
            crate::arch::halt();
        }
    }

    // Register in kernel-level per-CPU scheduler table.
    crate::kernel::smp::bringup::register_percpu_scheduler(cpu_id32, sched_ptr);

    crate::println!("[smp   ] AP cpu_id={} online", cpu_id);

    // ── Enter scheduler dispatch loop ──
    crate::arch::interrupts::enable();
    loop {
        unsafe {
            (*sched_ptr).process_deferred_dying();
        }
        crate::arch::interrupts::disable();
        unsafe {
            (*sched_ptr).schedule();
        }
        crate::arch::interrupts::enable_and_halt();
    }
}

// ── AP bring-up ────────────────────────────────────────────────────────

pub(crate) fn bring_up_aps() {
    let aps = discover_aps();
    if aps.is_empty() {
        crate::println!("[smp   ] no APs to bring up — running single-CPU");
        return;
    }

    crate::println!("[smp   ] bringing up {} AP(s)...", aps.len());
    for &(cpu_id, _mpidr) in &aps {
        let idx = (cpu_id as usize).wrapping_sub(1);
        if idx >= MAX_APS {
            crate::println!("[smp   ] skipping cpu_id={} > MAX_APS", cpu_id);
            continue;
        }
        bring_up_one(cpu_id, idx);
    }

    crate::kernel::smp::bringup::set_online_ap_count(aps.len() as u32);
    crate::println!("[smp   ] {} AP(s) online", aps.len());
}

fn bring_up_one(cpu_id: u32, idx: usize) {
    crate::println!("[smp   ] bring_up_one: cpu={}", cpu_id);

    let stack = unsafe { &raw mut (*AP_STACKS.get())[idx].0[0] };
    let stack_top = unsafe { stack.add(AP_STACK_SIZE) };

    // Pre-create scheduler + idle process.
    use alloc::boxed::Box;
    let sched = Box::new(crate::kernel::process::Scheduler::new());
    sched.init_next_cpu(cpu_id);
    let sched_ptr = Box::into_raw(sched);

    allocate_ap_percpu(cpu_id, sched_ptr);

    // Register early so idle thread affinitises to this CPU.
    crate::kernel::smp::bringup::set_online_ap_count(cpu_id);

    unsafe {
        (*sched_ptr).start_idle_process();
    }

    // Fill spin table: stack_top first, then entry_addr with release ordering.
    let entry = aarch64_ap_startup as *const () as u64;
    unsafe {
        (*aarch64_spin_table.get())[idx].stack_top = stack_top as u64;
        core::sync::atomic::fence(Ordering::Release);
        (*aarch64_spin_table.get())[idx].entry_addr = entry;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    unsafe {
        core::arch::asm!("dsb ish", "sev", options(nostack));
    }

    crate::println!("  [smp   ] cpu={} started", cpu_id);
}

// ── AP discovery ───────────────────────────────────────────────────────

fn discover_aps() -> Vec<(u32, u64)> {
    let total = crate::arch::fdt::cpu_count();
    if total <= 1 {
        return Vec::new();
    }
    let mut aps = Vec::new();
    for id in 1..total {
        aps.push((id as u32, id as u64));
    }
    crate::println!("[smp   ] FDT: {} CPUs total, {} AP(s)", total, aps.len());
    aps
}

// ── GIC SGI (IPI) delivery ─────────────────────────────────────────────

// The SGI-send primitives below are not yet wired into AP reschedule /
// shootdown signalling (the aarch64 SMP bring-up currently uses memory-based
// flags), so they are intentionally unused (dead-code allowed).
#[allow(dead_code)]
const GICD_SGIR: usize = 0xF00;

#[allow(dead_code)]
fn gicd_base() -> usize {
    crate::arch::fdt::platform_info()
        .gicd_base
        .unwrap_or(0x0800_0000)
}

#[allow(dead_code)]
fn send_sgi(sgi_id: u8, cpu_mask: u8) {
    if sgi_id >= 16 {
        return;
    }
    let reg = (gicd_base() + GICD_SGIR) as *mut u32;
    // Target List Filter = 0 (use CPU target list bits)
    unsafe {
        core::ptr::write_volatile(reg, ((cpu_mask as u32) << 16) | sgi_id as u32);
    }
}

#[allow(dead_code)]
pub(crate) fn send_reschedule_sgi(cpu_id: u32) {
    if cpu_id == 0 || cpu_id as usize >= MAX_CPUS {
        return;
    }
    send_sgi(SGI_RESCHEDULE, 1u8 << (cpu_id as u8));
}

#[allow(dead_code)]
pub(crate) fn send_tlb_shootdown_all() {
    let reg = (gicd_base() + GICD_SGIR) as *mut u32;
    // Filter = 1 (All Except Self)
    unsafe {
        core::ptr::write_volatile(reg, (1u32 << 24) | SGI_TLB_SHOOTDOWN as u32);
    }
}

pub(crate) fn handle_reschedule_sgi() {
    if let Some(s) = crate::kernel::process::Scheduler::global() {
        s.set_need_resched();
    }
}

pub(crate) fn handle_tlb_shootdown_sgi() {
    let generation = crate::kernel::smp::tlb::tlb_generation();
    let p = crate::kernel::percpu::get_mut();
    if generation != p.tlb_generation_seen {
        p.tlb_generation_seen = generation;
        unsafe {
            core::arch::asm!(
                "dsb ish",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack)
            );
        }
    }
}

// ── AP PerCpuData allocation ───────────────────────────────────────────

/// Raw pointers so we avoid non-Copy-array issues with `Option<Box<..>>`.
static AP_PERCPU: crate::util::sync_unsafe_cell::SyncUnsafeCell<[*mut PerCpuData; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([core::ptr::null_mut(); MAX_APS]);

fn allocate_ap_percpu(cpu_id: u32, sched_ptr: *mut crate::kernel::process::Scheduler) {
    let idx = (cpu_id as usize).wrapping_sub(1);
    if idx >= MAX_APS {
        return;
    }
    let mut b = alloc::boxed::Box::new(PerCpuData::zeroed());
    b.cpu_id = cpu_id;
    b.scheduler = sched_ptr;
    unsafe {
        (*AP_PERCPU.get())[idx] = alloc::boxed::Box::into_raw(b);
    }
}

fn ap_percpu_data(cpu_id: u32) -> *mut PerCpuData {
    let idx = (cpu_id as usize).wrapping_sub(1);
    if idx >= MAX_APS {
        return core::ptr::null_mut();
    }
    unsafe { (*AP_PERCPU.get())[idx] }
}

// ── Boot MMU config save ───────────────────────────────────────────────

pub(crate) fn save_boot_mmu_config() {
    let (ttbr0, ttbr1, tcr, mair, sctlr): (u64, u64, u64, u64, u64);
    unsafe {
        core::arch::asm!(
            "mrs {0}, ttbr0_el1", "mrs {1}, ttbr1_el1",
            "mrs {2}, tcr_el1",   "mrs {3}, mair_el1",
            "mrs {4}, sctlr_el1",
            out(reg) ttbr0, out(reg) ttbr1, out(reg) tcr,
            out(reg) mair, out(reg) sctlr,
            options(nostack, preserves_flags)
        );
    }
    AARCH64_BOOT_TTBR0.store(ttbr0, Ordering::Relaxed);
    AARCH64_BOOT_TTBR1.store(ttbr1, Ordering::Relaxed);
    AARCH64_BOOT_TCR.store(tcr, Ordering::Relaxed);
    AARCH64_BOOT_MAIR.store(mair, Ordering::Relaxed);
    AARCH64_BOOT_SCTLR.store(sctlr, Ordering::Relaxed);
}

pub(crate) fn save_vbar_addr() {
    let vbar: u64;
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar, options(nostack, preserves_flags));
    }
    AARCH64_VBAR_ADDR.store(vbar, Ordering::Relaxed);
}
