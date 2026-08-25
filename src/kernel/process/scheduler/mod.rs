//! src/kernel/process/scheduler/mod.rs
//!
//! Core scheduler with ready/wait queues, dispatch rules, and timer preemption.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::AtomicU32;
#[cfg(not(test))]
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::sync::atomic::AtomicBool;

use crate::kernel::sync::Mutex;

use super::{ContextCell, Process, ProcessId, Thread, ThreadPriority, THREAD_PRIORITY_COUNT};

// ── Submodule declarations ──
pub(crate) mod address;
pub(crate) mod api;
pub(crate) mod dispatch;
pub(crate) mod global;
pub(crate) mod lifecycle;
pub(crate) mod process;
pub(crate) mod queue;
pub(crate) mod spawn;
pub(crate) mod terminate;
#[cfg(test)]
mod tests;
pub(crate) mod timer;
pub(crate) mod types;
pub(crate) mod waker;

// ── Re-exports ──
#[cfg(all(
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ),
    target_os = "none"
))]
pub use api::thread_trampoline;
pub use api::{
    on_timer_tick, on_timer_tick_with_preemption, sleep_current, terminate_current,
    terminate_current_with_reason, yield_current,
};
pub(crate) use types::SchedulerHotspotStats;
pub(crate) use types::SchedulerStats;
pub(crate) use types::TimedWaiter;

// ── Constants ──
pub const TIME_SLICE_TICKS: u64 = 2;

pub(crate) const BOOST_THRESHOLD_TICKS: u64 = 50;
pub(crate) const BOOST_DURATION_TICKS: u64 = 8;

// ── Global scheduler pointer ──
#[cfg(not(test))]
static CURRENT_SCHEDULER: AtomicPtr<Scheduler> = AtomicPtr::new(ptr::null_mut());
#[cfg(test)]
std::thread_local! {
    static CURRENT_SCHEDULER: Cell<*mut Scheduler> = const { Cell::new(ptr::null_mut()) };
}

// ── Pointer helpers ──
#[cfg(not(test))]
pub(crate) fn store_current_scheduler_ptr(scheduler: *mut Scheduler) {
    CURRENT_SCHEDULER.store(scheduler, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn store_current_scheduler_ptr(scheduler: *mut Scheduler) {
    CURRENT_SCHEDULER.with(|slot| slot.set(scheduler));
}

#[cfg(not(test))]
pub(crate) fn load_current_scheduler_ptr() -> *mut Scheduler {
    CURRENT_SCHEDULER.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn load_current_scheduler_ptr() -> *mut Scheduler {
    CURRENT_SCHEDULER.with(Cell::get)
}

#[cfg(not(test))]
pub(crate) fn clear_current_scheduler_ptr_if_matches(scheduler: *mut Scheduler) {
    let _ = CURRENT_SCHEDULER.compare_exchange(
        scheduler,
        ptr::null_mut(),
        Ordering::Acquire,
        Ordering::Relaxed,
    );
}

#[cfg(test)]
pub(crate) fn clear_current_scheduler_ptr_if_matches(scheduler: *mut Scheduler) {
    CURRENT_SCHEDULER.with(|slot| {
        if slot.get() == scheduler {
            slot.set(ptr::null_mut());
        }
    });
}

#[cfg(test)]
pub(crate) fn clear_thread_local_scheduler_slot() {
    CURRENT_SCHEDULER.with(|slot| slot.set(ptr::null_mut()));
}

// ── Scheduler struct ──
pub struct Scheduler {
    ready_queues: Mutex<[VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT]>,
    waiting_queue: Mutex<Vec<TimedWaiter>>,
    current: Mutex<Option<Arc<Thread>>>,
    pub(crate) processes: Mutex<Vec<Arc<Process>>>,
    next_pid: Mutex<u32>,
    freed_pids: Mutex<Vec<u32>>,
    pub(crate) need_resched: AtomicBool,
    next_cpu: AtomicU32,
    dispatch_context: ContextCell,
    /// Drop-slot for the previously-running [`Arc<Thread>`] that must be freed
    /// *after* a context-switch, so the scheduler can release its last
    /// reference without corrupting the thread's own kernel stack.
    pub(crate) dying_thread: Mutex<Option<Arc<Thread>>>,
    /// Deferred-drop slot for `dying_thread` content, processed when interrupts
    /// are enabled.  This avoids a spinlock deadlock with the TLB shootdown IPI
    /// that would occur if we dropped inside `schedule_bare_metal` while
    /// holding `ipi_target_lock`.
    pub(crate) deferred_dying: Mutex<Option<Arc<Thread>>>,
    simulated_ticks: Mutex<u64>,
    hotspot_stats: Mutex<SchedulerHotspotStats>,
    pub(crate) stats: Mutex<SchedulerStats>,
}
