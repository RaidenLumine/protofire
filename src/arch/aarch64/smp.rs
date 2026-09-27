//! src/arch/aarch64/smp.rs
//!
//! AArch64 SMP arch support: spin-table AP wakeup, MMU-config save/restore,
//! GIC SGI (IPI) delivery, and AP entry-point logic.

// AP bring-up and SGI delivery only run on bare metal.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use crate::kernel::percpu::PerCpuData;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
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

    // `x0` is this AP's stack top, and setting the stack pointer here is the
    // entry's own job: PSCI drops a core straight at this label with whatever
    // stack the firmware left behind, so a path that assumed someone else had
    // set SP would start a core that pushes into memory it does not own.
    mov     sp, x0

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
unsafe extern "C" fn aarch64_ap_entry_rust() -> ! {
    // Which core this is comes from the hardware, not from an argument: the
    // entry point's register carries the stack top now, and `MPIDR_EL1` is the
    // authority on identity either way.
    let mpidr: u64;
    // SAFETY: MPIDR_EL1 is the core's own identity register and is readable
    // from EL1 at any time; the instruction touches no memory.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr) };
    let cpu_id32 = (mpidr & 0xff) as u32;
    let cpu_id = cpu_id32 as u64;

    // Point TPIDR_EL1 → this AP's PerCpuData.
    let percpu = ap_percpu_data(cpu_id32);
    if percpu.is_null() {
        crate::println!("[smp   ] FATAL: AP cpu_id={} has no PerCpuData", cpu_id);
        loop {
            crate::arch::halt();
        }
    }
    // SAFETY: `percpu` is this AP's live PerCpuData, allocated before the AP
    // was started, and this runs once per AP on that AP.
    unsafe {
        crate::arch::percpu::set_base(percpu as u64);
    }

    // Initialise GIC CPU interface and timer (per-CPU).
    crate::arch::aarch64::interrupt_controller::init_gicc();
    crate::arch::aarch64::timer::init_ap();

    // Fetch pre-created scheduler.
    // SAFETY: `percpu` is this AP's own block, published by `bring_up_one`
    // before PSCI started the core, so nothing else touches it yet.
    let sched_ptr = unsafe { (*percpu).scheduler };
    if sched_ptr.is_null() {
        crate::println!("[smp   ] FATAL: AP cpu_id={} has no scheduler", cpu_id);
        loop {
            crate::arch::halt();
        }
    }

    // Join the scheduler registry — the moment this core becomes a CPU the
    // kernel can dispatch on, and the moment `online_cpu_count` counts it.
    // It is done here, on the core itself, rather than by the core that called
    // `CPU_ON`: a core that never reaches this line never claimed to be up.
    //
    // SAFETY: `sched_ptr` was allocated for this CPU by the BSP before the
    // core was started, and it is never freed.
    unsafe {
        crate::kernel::process::scheduler::registry::register(cpu_id32, sched_ptr);
    }

    crate::println!("[smp   ] AP cpu_id={} online", cpu_id);

    // ── Enter scheduler dispatch loop ──
    crate::arch::interrupts::enable();
    loop {
        // SAFETY: `sched_ptr` is this core's own scheduler, handed to it by the
        // core that started it and never shared with another core.
        unsafe {
            (*sched_ptr).process_deferred_dying();
        }
        crate::arch::interrupts::disable();
        // SAFETY: as above — the same per-core scheduler, entered with
        // interrupts masked so this core's own accounting stays consistent.
        unsafe {
            (*sched_ptr).schedule();
        }
        crate::arch::interrupts::enable_and_halt();
    }
}

// ── AP bring-up ────────────────────────────────────────────────────────

pub(crate) fn bring_up_aps() {
    // The conduit has to be chosen before it is used: an `smc` or `hvc` this
    // platform cannot reach is an undefined instruction, not an error return.
    if !crate::arch::aarch64::psci::init_conduit_from_platform() {
        crate::println!("[smp   ] no PSCI conduit here — running single-CPU");
        return;
    }
    match crate::arch::aarch64::psci::version() {
        Some(version) => {
            crate::println!("[smp   ] PSCI version {:#x}", version);
        }
        None => {
            crate::println!("[smp   ] PSCI unavailable — running single-CPU");
            return;
        }
    }

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

    // "Started", not "online": PSCI returns as soon as the request is accepted,
    // and each core reports for itself from its own entry point — that is the
    // line the online count is built from, and it is not this one.
    crate::println!("[smp   ] {} AP(s) started", aps.len());
}

fn bring_up_one(cpu_id: u32, idx: usize) {
    crate::println!("[smp   ] bring_up_one: cpu={}", cpu_id);

    // SAFETY: `idx` is below `MAX_APS` (the caller's bound) and the stack pool
    // is a kernel static this function is the only writer of.
    let stack = unsafe { &raw mut (*AP_STACKS.get())[idx].0[0] };
    // Same margin the thread entry leaves: an AP that takes an exception
    // before it has pushed anything needs a trap frame below the mapped end
    // of its stack, and `stack_top` is exclusive.
    let stack_top =
        // SAFETY: as above — the top is inside the same pool page, one
        // exception frame below its end.
        unsafe { stack.add(AP_STACK_SIZE - crate::arch::aarch64::trap::EXCEPTION_FRAME_BYTES) };

    // Pre-create scheduler + idle process.
    use alloc::boxed::Box;
    let sched = Box::new(crate::kernel::process::Scheduler::new());
    // Bound to this CPU before anything is spawned on it: its idle thread is
    // pinned there, and the round-robin that places other threads starts there.
    sched.bind_to_cpu(cpu_id);
    let sched_ptr = Box::into_raw(sched);

    allocate_ap_percpu(cpu_id, sched_ptr);

    // SAFETY: the scheduler was just allocated for this core and has not been
    // handed to it yet, so this is the only reference to it.
    unsafe {
        (*sched_ptr).start_idle_process();
    }

    // Fill spin table: stack_top first, then entry_addr with release ordering.
    let entry = aarch64_ap_startup as *const () as u64;
    // Start it through PSCI, with the stack top as the context the entry reads
    // from `x0`.  The status comes back here instead of being waited for.
    // SAFETY: `cpu_id` names a core the platform's count says exists, `entry`
    // is this module's own AP entry, and `stack_top` is the top of the stack
    // just published for that core.
    match unsafe { crate::arch::aarch64::psci::cpu_on(cpu_id as u64, entry, stack_top as u64) } {
        Ok(()) => {
            crate::println!("  [smp   ] cpu={} started", cpu_id);
        }
        Err(status) => {
            crate::println!("  [smp   ] cpu={} CPU_ON rejected: {:#x}", cpu_id, status);
        }
    }
}

// ── AP discovery ───────────────────────────────────────────────────────

/// How many cores a GICv2 distributor can be told to target.
///
/// An SGI names its destinations as bits in an eight-bit list on the
/// distributor, so the controller simply cannot address more than eight of
/// them.  See [`discover_aps`] for why that is the ceiling on which cores this
/// kernel brings up.
const GICV2_CPU_INTERFACES: u32 = 8;

fn discover_aps() -> Vec<(u32, u64)> {
    // Two authorities with two different answers: the device tree says which
    // cores exist, the distributor says which of them this kernel can address.
    // A core beyond the second is a core that can be started and then never
    // woken — work would be placed on it with no IPI able to reach it — so the
    // smaller of the two is the number worth bringing up.
    let from_fdt = crate::arch::fdt::cpu_count();
    let addressable = gicd_cpu_count().unwrap_or(GICV2_CPU_INTERFACES);
    let total = from_fdt.min(addressable);
    if total <= 1 {
        return Vec::new();
    }
    if from_fdt > total {
        crate::println!(
            "[smp   ] {} CPUs present, {} addressable by this interrupt controller",
            from_fdt,
            total
        );
    }
    let mut aps = Vec::new();
    for id in 1..total {
        aps.push((id, id as u64));
    }
    crate::println!("[smp   ] {} CPUs total, {} AP(s)", total, aps.len());
    aps
}

/// Cores the distributor reports, `GICD_TYPER.CPUNumber` (bits [7:5]).
///
/// `None` when the register reads as all ones, which is what an absent or
/// unmapped distributor looks like; a count taken from that would invent
/// cores.
fn gicd_cpu_count() -> Option<u32> {
    // SAFETY: the `GICD_TYPER` register of the distributor the platform
    // described, inside the low device window the runtime tables map.
    let typer = unsafe { core::ptr::read_volatile((gicd_base() + 0x004) as *const u32) };
    if typer == u32::MAX {
        return None;
    }
    Some(((typer >> 5) & 0x7) + 1)
}

// ── GIC SGI (IPI) delivery ─────────────────────────────────────────────

const GICD_SGIR: usize = 0xF00;

fn gicd_base() -> usize {
    crate::arch::fdt::platform_info()
        .gicd_base
        .unwrap_or(0x0800_0000)
}

fn send_sgi(sgi_id: u8, cpu_mask: u8) {
    if sgi_id >= 16 {
        return;
    }
    let reg = (gicd_base() + GICD_SGIR) as *mut u32;
    // Target List Filter = 0 (use CPU target list bits)
    // SAFETY: the distributor's software-generated-interrupt register, in the
    // mapped device window; the bad-id check above keeps the id in range.
    unsafe {
        core::ptr::write_volatile(reg, ((cpu_mask as u32) << 16) | sgi_id as u32);
    }
}

/// Ask one core to look at its run queue again, as a software-generated
/// interrupt.
///
/// The distributor addresses cores by [[GICV2_CPU_INTERFACES]|bit position] in
/// the target list, and this kernel calls a core by that same number: the
/// core's own id, from `MPIDR_EL1`.  A core the list cannot name — id 0 is the
/// caller, and anything past the list's width — is not one this can reach.
pub fn send_reschedule_ipi(cpu_id: u32) {
    if cpu_id == 0 || cpu_id >= GICV2_CPU_INTERFACES {
        return;
    }
    send_sgi(SGI_RESCHEDULE, 1u8 << (cpu_id as u8));
}

/// Broadcast a "drop your translations" request to the other cores.
///
/// Nothing sends this, and that is the design rather than an omission: this
/// kernel's page-table edits broadcast their invalidation to the
/// inner-shareable domain themselves, so no remote translation is left for an
/// IPI to drop.  The receive side stays wired because it is the other half of
/// the same message; the send side is here so that the pair is visible
/// together.
#[allow(dead_code)]
pub(crate) fn send_tlb_shootdown_all() {
    let reg = (gicd_base() + GICD_SGIR) as *mut u32;
    // Filter = 1 (All Except Self)
    // SAFETY: as `send_sgi` — the same register, with the "all except self"
    // filter the broadcast wants.
    unsafe {
        core::ptr::write_volatile(reg, (1u32 << 24) | SGI_TLB_SHOOTDOWN as u32);
    }
}

/// CPUs that have already said they were woken by a reschedule IPI.
static RESCHEDULE_IPI_ANNOUNCED: AtomicU32 = AtomicU32::new(0);

pub(crate) fn handle_reschedule_sgi() {
    // A request that arrived and a request that was never sent look the same
    // from the scheduler's side: both end in "the queue was looked at and had
    // nothing newer".  The first one per CPU is announced so the two can be
    // told apart from outside, and the announcement is bounded by the CPU
    // count rather than by the traffic.
    let cpu_id = crate::kernel::percpu::get().cpu_id;
    if cpu_id < crate::kernel::smp::MAX_CPUS as u32 {
        let bit = 1u32 << cpu_id;
        if RESCHEDULE_IPI_ANNOUNCED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            crate::println!("[smp   ] cpu={} woke on a reschedule IPI", cpu_id);
        }
    }
    if let Some(s) = crate::kernel::process::Scheduler::global() {
        s.set_need_resched();
    }
}

/// Apply whatever another core has asked this one to drop.
///
/// The request arrives as an SGI, and what it means is "walk the kernel's
/// invalidation log": the CPU that edited a page table posted the range it
/// changed, and this is the other half of that.  Today nothing on this
/// architecture posts — its edits invalidate to the inner-shareable domain
/// where they happen — so the walk finds an empty log; it is here because it
/// is the receiving half of the message, and because a walk is what a
/// shootdown request means wherever one is sent.
pub(crate) fn handle_tlb_shootdown_sgi() {
    crate::kernel::smp::apply_remote_tlb_invalidations();
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
    // SAFETY: `idx` is below `MAX_APS` (checked at entry) and this core's slot
    // is written before the core itself is started, so no other writer is in
    // flight against the table.
    unsafe {
        (*AP_PERCPU.get())[idx] = alloc::boxed::Box::into_raw(b);
    }
}

fn ap_percpu_data(cpu_id: u32) -> *mut PerCpuData {
    let idx = (cpu_id as usize).wrapping_sub(1);
    if idx >= MAX_APS {
        return core::ptr::null_mut();
    }
    // SAFETY: as `allocate_ap_percpu` — the index is bounded, and a slot that
    // has not been filled yet reads as the null pointer the caller checks.
    unsafe { (*AP_PERCPU.get())[idx] }
}

// ── Boot MMU config save ───────────────────────────────────────────────

pub(crate) fn save_boot_mmu_config() {
    let (ttbr0, ttbr1, tcr, mair, sctlr): (u64, u64, u64, u64, u64);
    // SAFETY: five EL1 system-register reads performed once during bring-up;
    // none of them touches memory, and each register is one this kernel set.
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
    // SAFETY: as `save_boot_mmu_config` — a read of the vector-base register
    // this kernel installed.
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar, options(nostack, preserves_flags));
    }
    AARCH64_VBAR_ADDR.store(vbar, Ordering::Relaxed);
}
