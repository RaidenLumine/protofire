//! src/arch/riscv64/smp.rs
//!
//! RISC-V 64 SMP bring-up via SBI Hart State Management (HSM).
//!
//! ## Boot flow
//!
//! 1. BSP discovers secondary hart IDs from the FDT `/cpus` node.
//! 2. For each secondary hart the BSP allocates a 64 KiB boot stack, a
//!    [`PerCpuData`] block, and a scheduler with an idle thread, and publishes
//!    the block in that hart's per-CPU slot.
//! 3. [`sbi_hart_start`] is called with the target hart ID and the address of
//!    `_secondary_start` (in `.text.boot`), passing the stack pointer as the
//!    opaque context value.
//! 4. The secondary hart executes the trampoline in [boot.S], which sets its
//!    stack and its `tp` from the slot the BSP filled, then calls [`ap_entry`].
//! 5. [`ap_entry`] installs that hart's exception vectors, turns its MMU on,
//!    joins the scheduler registry, arms its timer, and enters the scheduler
//!    dispatch loop — from there it is a CPU the kernel runs threads on.
//!
//! Two things are deliberately *not* assumed about a hart started this way.
//! It comes up with paging off, so `satp` is set from the BSP's root table
//! before anything virtual is touched; and it comes up with `mhartid`
//! unreadable, so its identity is the hart ID SBI hands it in `a0`, which is
//! also the index its per-CPU slot and its trap stub are chosen by.
//!
//! ## SBI HSM extension
//!
//! Extension ID `0x48534D` ("HSM"), functions:
//! - `hart_start(hartid, start_addr, opaque)` — FID 0
//! - `hart_stop()` — FID 1
//! - `hart_get_status(hartid)` — FID 2
//!
//! Returns 0 on success, negative error code on failure.

use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::kernel::percpu::PerCpuData;

/// Maximum number of secondary CPUs we attempt to boot.
const MAX_APS: usize = 8;

/// Stack size for each secondary CPU (64 KiB).
const AP_STACK_SIZE: usize = 65536;

/// Statically-allocated stacks in kernel BSS so the runtime page tables
/// always cover them.
#[repr(C, align(4096))]
struct ApStack([u8; AP_STACK_SIZE]);

static AP_STACKS: crate::util::sync_unsafe_cell::SyncUnsafeCell<[ApStack; MAX_APS]> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new([
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
        ApStack([0u8; AP_STACK_SIZE]),
    ]);

// External assembly trampoline for secondary CPUs (defined in boot.S).
extern "C" {
    fn _secondary_start();
}

// ---------------------------------------------------------------------------
// SBI HSM extension
// ---------------------------------------------------------------------------

/// SBI Extension ID for Hart State Management.
const SBI_EXT_HSM: u64 = 0x48534D;

/// SBI HSM function: start a hart.
const SBI_HSM_HART_START: u64 = 0;

/// SBI Extension ID for inter-processor interrupts.
const SBI_EXT_IPI: u64 = 0x735049;

/// SBI IPI function: send an IPI to a set of harts.
const SBI_IPI_SEND: u64 = 0;

/// Raise a software interrupt on the harts named by `hart_mask`.
///
/// `hart_mask` is a bit vector whose bit `i` names hart `i + hart_mask_base`.
///
/// # Safety
///
/// The extension is present on every SBI implementation this target boots
/// under; a firmware that does not implement it returns an error rather than
/// trapping.
unsafe fn sbi_send_ipi(hart_mask: u64, hart_mask_base: u64) -> i64 {
    let ret: u64;
    // SAFETY: SBI ecall with the IPI extension.  `a0` carries the mask in and
    // the error code out; SBI preserves every other register, so `a1` — which
    // firmware clobbers — is declared in-out rather than as a plain input.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") hart_mask => ret,
            inlateout("a1") hart_mask_base => _,
            in("a6") SBI_IPI_SEND,
            in("a7") SBI_EXT_IPI,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret as i64
}

/// Start a hart via SBI HSM.
///
/// `hartid` — the target hart to start.
/// `start_addr` — physical address of the entry point.
/// `opaque` — value passed to the hart in `a1` (used as stack pointer here).
///
/// Returns 0 on success, or a negative SBI error code.
///
/// # Safety
///
/// The caller must ensure `start_addr` is a valid entry point in
/// executable memory.  The target hart must not already be running.
unsafe fn sbi_hart_start(hartid: u64, start_addr: usize, opaque: u64) -> i64 {
    let ret: u64;
    // SAFETY: SBI ecall with HSM extension — the HSM extension is present
    // on OpenSBI ≥ 0.9 (QEMU virt ships with ≥ 1.0).
    // On success a0=0; on error a0 contains a negative error code cast to u64.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") hartid => ret,
            // `a1` carries `start_addr` in and is clobbered by firmware out:
            // SBI preserves every register *except* `a0` and `a1`, so this is
            // an in-out rather than a plain input.
            inlateout("a1") start_addr => _,
            in("a2") opaque,
            in("a6") SBI_HSM_HART_START,
            in("a7") SBI_EXT_HSM,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret as i64
}

// ---------------------------------------------------------------------------
// FDT CPU discovery
// ---------------------------------------------------------------------------

/// Hart the kernel is running on, as the boot protocol reported it.
///
/// `u64::MAX` until `store_boot_hart` has been called.
static BOOT_HART: AtomicU64 = AtomicU64::new(u64::MAX);

/// Record the hart ID the boot protocol handed us in `a0`.
///
/// Called from `boot.S` before the Rust entry, from the same registers the
/// platform hands over in: `a0` is the boot hart's ID and `a1` is the flattened
/// device tree.  `mhartid` is not readable from S-mode, so this is the only
/// authoritative answer about which hart is running the kernel.
pub fn store_boot_hart(hartid: u64) {
    BOOT_HART.store(hartid, Ordering::Release);
}

/// The hart the kernel booted on.
///
/// It is *not* always hart 0.  QEMU `virt` with several harts hands the reset
/// to whichever hart it likes, and OpenSBI then reports that hart as the boot
/// hart — boots have landed on 0 and on 1 here.  Assuming 0 meant that on the
/// harts-1 boot the bring-up loop asked SBI to start the hart it was already
/// running on, got `SBI_ERR_ALREADY_STARTED`, and left the machine one hart
/// short with nothing but a log line to say why.
pub(crate) fn boot_hart_id() -> Option<u64> {
    let hartid = BOOT_HART.load(Ordering::Acquire);
    (hartid != u64::MAX).then_some(hartid)
}

/// Discover secondary hart IDs from the Flattened Device Tree.
///
/// The shared FDT module exposes the total CPU count parsed from the `/cpus`
/// node.  On QEMU `virt` and other OpenSBI platforms hart IDs are contiguous
/// starting at 0, so the harts are `0..cpu_count` and the only one to skip is
/// the one the kernel is running on.  When the FDT has not been parsed the
/// count is 0 and no secondary harts are reported.
fn discover_secondary_hartids() -> Vec<u64> {
    let mut hartids = Vec::new();

    let total = crate::arch::fdt::cpu_count() as u64;
    let Some(boot_hart) = boot_hart_id() else {
        // Without the boot hart's ID there is no way to tell a secondary hart
        // from the one already running, and starting the running hart is an
        // error rather than a start.  Report and start nothing.
        crate::println!("[smp] riscv64: boot hart ID unknown; not starting any hart");
        return hartids;
    };
    for hartid in 0..total {
        if hartid == boot_hart {
            continue;
        }
        // A hart past the per-CPU table has nowhere for the kernel to keep its
        // block or its trap stub, and a hart it cannot keep state for is one it
        // cannot run threads on.  Starting it anyway would give it another
        // hart's state — the failure this whole pass exists to remove.
        if hartid as usize >= super::percpu::MAX_HARTS {
            crate::println!(
                "[smp] riscv64: hart {} is past the per-CPU table ({} harts); not starting it",
                hartid,
                super::percpu::MAX_HARTS
            );
            continue;
        }
        if hartids.len() >= MAX_APS {
            crate::println!(
                "[smp] riscv64: more secondary harts than MAX_APS ({}); not starting the rest",
                MAX_APS
            );
            break;
        }
        hartids.push(hartid);
    }

    hartids
}

// ---------------------------------------------------------------------------
// AP bring-up
// ---------------------------------------------------------------------------

/// The page table the BSP runs on, saved before any hart is started.
///
/// SBI starts a hart with paging off, and gives it no way to ask what the
/// kernel's root table is; the hart that had it is the only one that can say.
static BOOT_SATP: AtomicU64 = AtomicU64::new(0);

/// Bring up all secondary harts discovered via FDT.
///
/// Each hart gets its boot stack, its per-CPU block, and its scheduler *before*
/// `hart_start`: the first instruction the hart runs after the reset reads the
/// per-CPU slot for its `tp`, so the block has to be there before the hart is.
pub fn bring_up_aps() {
    let hartids = discover_secondary_hartids();
    if hartids.is_empty() {
        crate::println!("[smp] riscv64: no secondary harts found in FDT");
        return;
    }

    crate::println!(
        "[smp] riscv64: bringing up {} secondary hart(s)...",
        hartids.len()
    );

    // Read the BSP's root table while the BSP is the only hart that could have
    // one.  A hart brought up with paging off would be running on the firmware's
    // identity map with the kernel's mappings absent — which is why the bring-up
    // below refuses to start anything when this is zero.
    let satp: u64;
    // SAFETY: reading `satp` has no side effects.
    unsafe {
        core::arch::asm!("csrr {satp}, satp", satp = out(reg) satp, options(nomem, nostack, preserves_flags));
    }
    BOOT_SATP.store(satp, Ordering::Release);
    if satp >> 60 == 0 {
        crate::println!("[smp] riscv64: BSP has paging off; not starting any hart");
        return;
    }

    let mut started: Vec<u32> = Vec::with_capacity(hartids.len());
    for (index, &hartid) in hartids.iter().enumerate() {
        if bring_up_one(hartid, index) {
            started.push(hartid as u32);
        }
    }

    // The firmware accepts a start request before the hart has run a line, so
    // "accepted" is not "online".  Wait for the harts that were accepted to
    // report in, because what follows a bring-up reasons about the online set
    // — the message-signalled placement above all, which names a hart that
    // must already be able to take the interrupt.
    let missing = crate::kernel::smp::wait_until_online(&started);
    for hartid in &missing {
        crate::println!(
            "[smp] riscv64: hart {} did not come online; continuing",
            hartid
        );
    }
}

/// Start one hart, and answer whether the firmware accepted the request.
///
/// A rejected hart is not "slow": SBI will never start it, so the caller must
/// not wait for it to report in.
fn bring_up_one(hartid: u64, index: usize) -> bool {
    use alloc::boxed::Box;

    // The block, the scheduler, and the idle thread are built here, on the BSP,
    // because a hart that has just been reset has no allocator and no state.
    let mut percpu = Box::new(PerCpuData::zeroed());
    percpu.cpu_id = hartid as u32;
    let sched = Box::new(crate::kernel::process::Scheduler::new());
    // Bound before anything is placed on it: this hart's first choice of thread
    // is its own idle thread, and the round-robin that places other work starts
    // from the CPU the scheduler is bound to.
    sched.bind_to_cpu(hartid as u32);
    let sched_ptr = Box::into_raw(sched);
    percpu.scheduler = sched_ptr;
    let percpu_ptr = Box::into_raw(percpu);
    // SAFETY: `sched_ptr` is a live scheduler allocated just above and never
    // freed; `start_idle_process` is what gives it something to switch to when
    // it finds no runnable thread.
    unsafe {
        (*sched_ptr).start_idle_process();
    }

    // Publish the block in this hart's slot.  The slot is the only channel: the
    // hart reads it from its trampoline, and its trap stubs read it on every
    // kernel entry.  `tp` is left alone — the BSP is running on its own block.
    // SAFETY: the hart is not running yet, and the block outlives the kernel.
    unsafe {
        super::percpu::publish_base(hartid as usize, percpu_ptr as u64);
    }

    // SAFETY: `AP_STACKS` is a static array of kernel BSS stacks, `index` is a
    // position in it (the caller iterates at most `MAX_APS` harts), and this
    // runs before any hart is started, so nothing else is reading the array.
    let stack_top = unsafe {
        let stacks = &mut *AP_STACKS.get();
        // Leave room below the top for the first trap this hart takes: the
        // frame is built downward from `sp` before anything is pushed, exactly
        // as on a thread stack, and `stack_top` is exclusive.
        let base = stacks[index].0.as_mut_ptr();
        base.add(AP_STACK_SIZE - core::mem::size_of::<super::trap::TrapFrame>()) as u64
    };

    let entry = _secondary_start as *const () as usize;
    crate::println!(
        "[smp] riscv64: SBI hart_start hartid={} entry=0x{:x} stack=0x{:x}",
        hartid,
        entry,
        stack_top
    );

    // SAFETY: `_secondary_start` points to the trampoline in `.text.boot`
    // (executable kernel memory).  The target hart is currently stopped
    // (managed by OpenSBI).  `stack_top` is inside a statically allocated
    // 64 KiB BSS stack, and every block the hart will touch is published above.
    let ret = unsafe { sbi_hart_start(hartid, entry, stack_top) };
    if ret != 0 {
        crate::println!(
            "[smp] riscv64: SBI hart_start failed for hartid={} (err={})",
            hartid,
            ret
        );
        return false;
    }

    // What comes back is "SBI accepted the request", not "the hart is up":
    // the hart reports that for itself from `ap_entry`, and the caller waits
    // for those reports before it returns.
    true
}

// ---------------------------------------------------------------------------
// Reaching another hart
// ---------------------------------------------------------------------------

/// Ask a hart to look at its run queue again, as a machine software interrupt.
///
/// The request goes through the firmware rather than through the CLINT.  The
/// CLINT's `msip` registers are the machine level's: writing one from S-mode
/// here is an access fault, and the hart that gets the trap is the one trying
/// to send work, not the one that should have received it.  The SBI IPI
/// extension exists to be the interface for exactly this.
///
/// Whether the request reaches the target as an S-mode software interrupt is
/// the firmware's answer, not this kernel's, and it is not a correctness
/// dependency either way: the receiving side is `handle_reschedule_ipi`, which
/// only sets a "look again" flag, and a hart that never sees it still finds the
/// work on its own next timer tick.  What is given up when no IPI arrives is
/// latency — up to one tick — not the wake-up.  The kernel's SMP layer does not
/// send this to the calling hart or to a hart that never came up.
pub fn send_reschedule_ipi(cpu_id: u32) {
    // SAFETY: an SBI call.  A firmware without the extension returns an error
    // instead of trapping, which is why the answer is dropped rather than
    // asserted on; the call has no memory side effects the caller can observe.
    let _ = unsafe { sbi_send_ipi(1u64 << cpu_id, 0) };
}

/// Harts that have already said they were woken by a reschedule IPI.
static RESCHEDULE_IPI_ANNOUNCED: AtomicU32 = AtomicU32::new(0);

/// Take the reschedule request this hart is servicing, and clear it.
pub(crate) fn handle_reschedule_ipi() {
    // A request that arrived and a request that was never sent look the same
    // from the scheduler's side: both end in "the queue was looked at and had
    // nothing newer".  The first one per hart is announced so the two can be
    // told apart from outside, and the announcement is bounded by the hart
    // count rather than by the traffic.
    let cpu_id = crate::kernel::percpu::get().cpu_id;
    if cpu_id < crate::kernel::smp::MAX_CPUS as u32 {
        let bit = 1u32 << cpu_id;
        if RESCHEDULE_IPI_ANNOUNCED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            crate::println!("[smp] riscv64: cpu={} woke on a reschedule IPI", cpu_id);
        }
    }
    // `global()` reads this hart's own per-CPU slot, so the flag lands on the
    // scheduler the request was for.
    if let Some(sched) = crate::kernel::process::Scheduler::global() {
        sched.set_need_resched();
    }
    // Clear SIP.SSIP: the request is a pending bit, and a hart that returned
    // from the handler without clearing it would take the same interrupt again
    // for ever, never reaching the thread the request was about.
    //
    // SAFETY: `csrci` on this hart's own `sip`.
    unsafe {
        core::arch::asm!("csrci sip, 2", options(nomem, nostack, preserves_flags));
    }
}

/// Entry point for secondary harts, called from the assembly trampoline in
/// boot.S with the hart ID SBI handed this hart in `a0`.
///
/// The trampoline has already set the stack from the opaque context and `tp`
/// from this hart's per-CPU slot.  What is left is what makes the hart a CPU
/// the kernel can dispatch on: its own exception vector, the page table, the
/// per-hart interrupt controller state, its timer, and its place in the
/// scheduler registry — in that order, because a tick that arrives before there
/// is a scheduler to receive it is a fault rather than a tick.
///
/// # Safety
///
/// Called only from the trampoline of a hart whose per-CPU block the BSP
/// published before starting it, with a valid kernel stack in `sp`.
#[no_mangle]
unsafe extern "C" fn ap_entry(hart_id: u64) -> ! {
    let cpu_id = hart_id as u32;
    crate::println!("[smp] riscv64 AP: hart {} running", hart_id);

    // 1. This hart's exception vector.  `stvec` is per-hart and a hart started by
    //    SBI has whatever the firmware left there, so this is not optional and not
    //    inherited.
    // SAFETY: the hart ID is this hart's own, handed over by SBI in `a0`, and
    // the BSP declined to start a hart outside the stub table.
    unsafe {
        super::trap::install_for_hart(hart_id as usize);
    }

    // 2. Turn the MMU on with the BSP's root table.  A hart started through HSM
    //    comes up with paging off; without this it would run on the firmware's
    //    identity map, where none of the kernel's mappings exist.
    let satp = BOOT_SATP.load(Ordering::Acquire);
    let current: u64;
    // SAFETY: reading `satp` has no side effects.
    unsafe {
        core::arch::asm!("csrr {current}, satp", current = out(reg) current, options(nomem, nostack, preserves_flags));
    }
    if current >> 60 == 0 {
        if satp >> 60 == 0 {
            crate::println!("[smp] riscv64 AP: FATAL — no page table to adopt");
            loop {
                crate::arch::halt();
            }
        }
        // SAFETY: `satp` is the root table the BSP runs on and mapped the kernel
        // in; writing it switches this hart onto the same translations, and
        // `sfence.vma` drops the TLB entries of the mapping we are leaving.
        unsafe {
            core::arch::asm!(
                "csrw satp, {satp}",
                "sfence.vma",
                satp = in(reg) satp,
                options(nomem, nostack, preserves_flags)
            );
        }
        crate::println!("[smp] riscv64 AP: hart {} paging on", hart_id);
    }

    // 3. FPU: FS = 0b11 (dirty/clean state is ours to use).
    // SAFETY: enabling the FPU state in `sstatus` affects only this hart.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {fs_mask}",
            fs_mask = in(reg) 0x0000_6000u64,
            options(nomem, nostack, preserves_flags)
        );
    }

    // 4. The scheduler the BSP built for this hart, already installed in the
    //    per-CPU block `tp` points at.
    let sched_ptr = crate::kernel::percpu::get().scheduler;
    if sched_ptr.is_null() {
        crate::println!(
            "[smp] riscv64 AP: FATAL — hart {} has no scheduler",
            hart_id
        );
        loop {
            crate::arch::halt();
        }
    }

    // 5. Join the scheduler registry — the moment this hart becomes a CPU the
    //    kernel can dispatch on, and the moment `online_cpu_count` counts it. It is
    //    done here, on the hart itself, rather than by the hart that called
    //    `hart_start`: a hart that never reaches this line never claimed to be up.
    //
    // SAFETY: `sched_ptr` was allocated for this CPU by the BSP before this hart
    // was started, and it is never freed.
    unsafe {
        crate::kernel::process::scheduler::registry::register(cpu_id, sched_ptr);
    }

    // 6. Per-hart interrupt controller state (this hart's PLIC context threshold)
    //    and this hart's timer.  Both are per-hart registers: the PLIC claims and
    //    completes through the context belonging to the hart, and the tick is armed
    //    in `stimecmp`/SBI for this hart alone.
    crate::arch::interrupt_controller::init();
    super::timer::init();

    crate::println!(
        "[smp] riscv64 AP: hart {} online, cpu_id={}, entering dispatch loop",
        hart_id,
        cpu_id
    );

    // ── Enter the scheduler dispatch loop ──
    crate::arch::interrupts::enable();
    loop {
        // SAFETY: `sched_ptr` is this CPU's live scheduler, registered above and
        // never freed; the loop is the same one the BSP runs.
        unsafe {
            (*sched_ptr).process_deferred_dying();
        }
        crate::arch::interrupts::disable();
        // SAFETY: `sched_ptr` is this CPU's live scheduler, registered above and
        // never freed.
        unsafe {
            (*sched_ptr).schedule();
        }
        crate::arch::interrupts::enable_and_halt();
    }
}
