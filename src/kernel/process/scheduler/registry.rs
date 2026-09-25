//! src/kernel/process/scheduler/registry.rs
//!
//! The machine's CPUs, and the scheduler each one runs.
//!
//! One scheduler per CPU is this module's own arrangement, so the table that
//! maps a CPU to its instance lives here rather than in the SMP layer.  That
//! layer knows about CPUs — which of them are up, how to reach one — and
//! nothing about threads; the scheduler is the part that needs to find another
//! CPU's run queues, so the scheduler is the part that keeps them.
//!
//! A CPU joins by registering: that single call is what publishes its
//! scheduler to the rest of the machine *and* what tells the SMP layer the CPU
//! is online, so the two cannot disagree about which CPUs can run work.

use crate::kernel::smp::mark_cpu_online;
use crate::kernel::smp::MAX_CPUS;

use super::Scheduler;

/// Per-CPU scheduler pointers, indexed by logical CPU id.
///
/// `cpu_id` 0 is the BSP; an AP sits at the index it reports as its own id.
/// Each CPU registers its scheduler during boot — the BSP from `Kernel::init`,
/// an AP either from the core that starts it or from its own entry point — and
/// the pointer lives until shutdown.
static PERCPU_SCHEDULERS: crate::util::sync_unsafe_cell::SyncUnsafeCell<
    [*mut Scheduler; MAX_CPUS],
> = crate::util::sync_unsafe_cell::SyncUnsafeCell::new([core::ptr::null_mut(); MAX_CPUS]);

/// Register a CPU's scheduler, and with it the CPU.
///
/// # Safety
///
/// `scheduler` must stay alive for as long as the kernel runs: every other CPU
/// reaches it through this registry to place work.  Each `cpu_id` is
/// registered once, with one pointer.
#[cfg_attr(not(target_os = "none"), allow(dead_code))] // no CPU registers on a host build
pub(crate) unsafe fn register(cpu_id: u32, scheduler: *mut Scheduler) {
    let idx = cpu_id as usize;
    if idx >= MAX_CPUS {
        return;
    }
    // SAFETY: the index is in range, and this is the register-once call for
    // this CPU, so it owns the slot.
    unsafe { (*PERCPU_SCHEDULERS.get())[idx] = scheduler };
    // Publish the CPU to the SMP layer, which is where "online" is answered
    // from.  The pointer is stored first and the bit is set with a release, so
    // whoever sees the bit sees the pointer.
    mark_cpu_online(cpu_id);
}

/// The scheduler a CPU runs, or `None` if that CPU is not online.
pub(crate) fn for_cpu(cpu_id: u32) -> Option<&'static Scheduler> {
    let idx = cpu_id as usize;
    if !crate::kernel::smp::cpu_is_online(cpu_id) {
        return None;
    }
    // SAFETY: the acquire inside `cpu_is_online` is on the bit that the
    // registering CPU set after storing the pointer, and a registered
    // scheduler outlives the kernel.
    unsafe { (*PERCPU_SCHEDULERS.get())[idx].as_ref() }
}

/// Iterate over the online CPUs' schedulers, lowest id first.
pub(crate) fn for_each(mut f: impl FnMut(u32, &'static Scheduler)) {
    for idx in 0..MAX_CPUS as u32 {
        if let Some(sched) = for_cpu(idx) {
            f(idx, sched);
        }
    }
}
