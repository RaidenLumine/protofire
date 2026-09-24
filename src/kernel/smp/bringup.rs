//! src/kernel/smp/bringup.rs
//!
//! Which CPUs are online, and which scheduler belongs to each.
//!
//! Starting the application processors is the architecture's job —
//! `arch/x86_64/smp.rs`, `arch/aarch64/smp.rs`, `arch/riscv64/smp.rs` — and
//! so is reaching one of them afterwards (`arch::ipi`).  What is the same
//! everywhere stays here: the registry a CPU joins when it can be dispatched
//! on, and the answers built from it.

use core::sync::atomic::Ordering;

// ── Constants ───────────────────────────────────────────────────────────

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

/// Ask a CPU to look at its run queue again.
///
/// The kernel sends this when it has just made a thread runnable on another
/// CPU: without it the thread waits for that CPU's next timer tick, and a CPU
/// with nothing to run is halted rather than ticking — so a wake-up on an idle
/// core costs a full tick of latency, or arrives never.
///
/// A CPU that is not online cannot be asked, and the CPU sending the request
/// has no reason to ask itself: the BSP checks for pending work on every
/// kernel exit, and an AP checks before it halts.  How the CPU is reached is
/// the architecture's — see [`crate::arch::ipi`].
pub fn send_reschedule_ipi(cpu_id: u32) {
    if !cpu_is_online(cpu_id) || cpu_id == crate::kernel::percpu::get().cpu_id {
        return;
    }
    crate::arch::ipi::send_reschedule_ipi(cpu_id);
}
