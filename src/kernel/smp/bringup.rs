//! src/kernel/smp/bringup.rs
//!
//! Which CPUs are online, and how to reach one.
//!
//! This layer knows about CPUs and nothing about threads: which of them are
//! up (a mask, set as each one joins), how many that is, and how to ask one to
//! look at its run queue.  *What* a CPU runs belongs to the scheduler, which
//! keeps its own per-CPU registry beside the queues it describes — see
//! `crate::kernel::process::scheduler::registry`.
//!
//! Starting the application processors is the architecture's job —
//! `arch/x86_64/smp.rs`, `arch/aarch64/smp.rs`, `arch/riscv64/smp.rs` — and so
//! is reaching one of them afterwards (`arch::ipi`).

use core::sync::atomic::Ordering;

// ── Constants ───────────────────────────────────────────────────────────

/// Maximum number of application processors this kernel will track.
///
/// One number for every architecture: the online mask and the schedulers'
/// registry are both indexed by logical CPU id, and a CPU the kernel cannot
/// store a scheduler for is a CPU it cannot dispatch a thread on.  An
/// architecture that stops bringing cores up earlier says so where it does
/// that.
pub const MAX_APS: usize = 16;

/// Maximum total CPUs (BSP + APs).
pub const MAX_CPUS: usize = MAX_APS + 1;

/// The online-CPU mask is a `u32`, so every CPU has to fit in it.
const _: () = assert!(MAX_CPUS <= 32);

// ── The CPU registry ───────────────────────────────────────────────────

/// Bit `N` is set once logical CPU `N` is running kernel code.
///
/// This is the kernel's one answer to "how many CPUs are online".  It is a
/// mask rather than a number because a count only works as an index bound when
/// the ids are contiguous — which nothing makes them.
///
/// Before this existed, each architecture answered the question its own way:
/// x86_64 counted the APs whose start it had confirmed, and aarch64 and riscv64
/// reached a setter that wrote a function-local static nobody read, behind a
/// count that was the constant 1.  A four-core machine then scheduled on one
/// core, and the number said everything was fine.
static ONLINE_CPUS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Record that a CPU is up.
///
/// Called by the scheduler's registry, from the one place a CPU registers — so
/// "this CPU can be given a thread" and "a scheduler exists for it" are the
/// same event rather than two that have to be kept in step.
pub(crate) fn mark_cpu_online(cpu_id: u32) {
    let idx = cpu_id as usize;
    if idx < MAX_CPUS {
        ONLINE_CPUS.fetch_or(1 << idx, Ordering::Release);
    }
}

/// Is this CPU running kernel code — that is, can it be given a thread?
pub fn cpu_is_online(cpu_id: u32) -> bool {
    let idx = cpu_id as usize;
    idx < MAX_CPUS && ONLINE_CPUS.load(Ordering::Acquire) & (1 << idx) != 0
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

/// Which CPU this core is, for the console's per-CPU prefix — but only when
/// the machine runs more than one.
///
/// `None` on a single-CPU machine, because a `[cpu0]` in front of every line
/// says nothing a reader wants to know and makes the log harder to scan.  The
/// answer comes from the CPU's own per-CPU block, which every architecture
/// installs during bring-up; the question is asked of it only once another CPU
/// is online, so the block is always there to answer.
pub fn log_cpu_index() -> Option<usize> {
    if online_cpu_count() <= 1 {
        return None;
    }
    Some(crate::kernel::percpu::get().cpu_id as usize)
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
