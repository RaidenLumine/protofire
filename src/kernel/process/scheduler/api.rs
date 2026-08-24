//! src/kernel/process/scheduler/api.rs
//!
//! Top-level public scheduler API functions and thread trampoline.
use super::Scheduler;

/// Voluntarily yield the current thread's remaining time slice.
///
/// If the scheduler is not initialised this is a no-op.
pub fn yield_current() {
    if let Some(scheduler) = Scheduler::global() {
        scheduler.yield_current_thread();
    }
}

/// Terminate the current thread immediately (no exit status).
///
/// # Panics
///
/// Panics if the scheduler is not initialised.
pub fn terminate_current() -> ! {
    Scheduler::global()
        .expect("Scheduler not initialized")
        .terminate_current_thread()
}

/// Terminate the current thread with a specific [`TerminationReason`].
///
/// # Panics
///
/// Panics if the scheduler is not initialised.
pub fn terminate_current_with_reason(reason: TerminationReason) -> ! {
    Scheduler::global()
        .expect("Scheduler not initialized")
        .terminate_current_thread_with_reason(Some(reason))
}

/// Advance the scheduler by one timer tick.
///
/// Delegates to [`Scheduler::handle_timer_tick`].  Returns `true` if
/// the current thread was preempted, or `false` if no scheduler is
/// installed.
pub fn on_timer_tick(ticks: u64) -> bool {
    if let Some(scheduler) = Scheduler::global() {
        scheduler.handle_timer_tick(ticks)
    } else {
        false
    }
}

/// Advance the scheduler by one timer tick with configurable preemption.
///
/// Delegates to [`Scheduler::handle_timer_tick_with_preemption`].
/// Returns `true` if the current thread was preempted, or `false` if
/// no scheduler is installed.
pub fn on_timer_tick_with_preemption(ticks: u64, allow_preemption: bool) -> bool {
    if let Some(scheduler) = Scheduler::global() {
        scheduler.handle_timer_tick_with_preemption(ticks, allow_preemption)
    } else {
        false
    }
}

/// Block the current thread for at least `ticks` timer ticks.
///
/// If the scheduler is not initialised this is a no-op.
pub fn sleep_current(ticks: u64) {
    if let Some(scheduler) = Scheduler::global() {
        scheduler.sleep_current_thread(ticks);
    }
}

use super::super::TerminationReason;

pub(crate) fn idle_entry() {}

#[cfg(all(
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ),
    target_os = "none"
))]
pub extern "C" fn thread_trampoline() -> ! {
    let thread = Scheduler::global().and_then(|scheduler| scheduler.current_thread());

    if let Some(thread) = thread {
        thread.run_entry();
    }

    terminate_current()
}
