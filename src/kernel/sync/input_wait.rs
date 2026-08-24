//! src/kernel/sync/input_wait.rs
//!
//! Shared helpers for input-style wait loops, timeout bookkeeping, and waiter statistics.

use alloc::sync::Arc;

use crate::kernel::process::{Scheduler, ThreadWaitOutcome};

use super::{
    wait::{
        plan_timed_wait, TimedWaitPlan, WaitTimeoutCleanup, WaitTimeoutCleanupRef, WaiterIdentity,
    },
    Mutex,
};

pub(crate) trait WaitStatsBookkeeping<K>: Send {
    fn observe_waiter_peak(&mut self, kind: K, predicted_waiters: usize);
    fn observe_wake(&mut self, kind: K, woke: usize);
    fn observe_timeout(&mut self, kind: K);
}

struct StatsTimeoutObserver<S, K> {
    stats: Arc<Mutex<S>>,
    kind: K,
}

impl<S, K> WaitTimeoutCleanup for StatsTimeoutObserver<S, K>
where
    S: WaitStatsBookkeeping<K> + 'static,
    K: Copy + Send + Sync + 'static,
{
    fn remove_waiter(&self, _identity: WaiterIdentity) {}

    fn on_timeout(&self, _identity: WaiterIdentity) {
        self.stats.lock().observe_timeout(self.kind);
    }
}

pub(crate) fn timeout_observer<S, K>(stats: Arc<Mutex<S>>, kind: K) -> WaitTimeoutCleanupRef
where
    S: WaitStatsBookkeeping<K> + 'static,
    K: Copy + Send + Sync + 'static,
{
    Arc::new(StatsTimeoutObserver { stats, kind })
}

pub(crate) fn record_wait_registration<S, K>(stats: &Mutex<S>, waiter_count: usize, kind: K)
where
    S: WaitStatsBookkeeping<K>,
    K: Copy,
{
    let predicted_waiters = waiter_count.saturating_add(1);
    stats.lock().observe_waiter_peak(kind, predicted_waiters);
}

pub(crate) fn record_wake_count<S, K>(stats: &Mutex<S>, kind: K, woke: usize)
where
    S: WaitStatsBookkeeping<K>,
    K: Copy,
{
    if woke == 0 {
        return;
    }

    stats.lock().observe_wake(kind, woke);
}

pub(crate) fn set_current_wait_outcome(outcome: ThreadWaitOutcome) {
    if let Some(thread) = Scheduler::global().and_then(|scheduler| scheduler.current_thread()) {
        thread.set_wait_outcome(outcome);
    }
}

pub(crate) fn mark_current_wait_completed() {
    set_current_wait_outcome(ThreadWaitOutcome::Completed);
}

fn runtime_timed_wait_plan(timeout_ticks: u64) -> TimedWaitPlan {
    if Scheduler::global().is_none() {
        return TimedWaitPlan::Unavailable;
    }

    plan_timed_wait(timeout_ticks)
}

fn finish_ready_probe<T>(value: Option<T>) -> Option<T> {
    if value.is_some() {
        mark_current_wait_completed();
    }

    value
}

pub(crate) fn finish_unobserved_timeout<S, K, T>(stats: &Mutex<S>, kind: K, value: T) -> T
where
    S: WaitStatsBookkeeping<K>,
    K: Copy,
{
    set_current_wait_outcome(ThreadWaitOutcome::TimedOut);
    stats.lock().observe_timeout(kind);
    value
}

pub(crate) fn wait_until_ready(
    mut is_ready: impl FnMut() -> bool,
    mut wait_once: impl FnMut() -> bool,
) -> bool {
    if is_ready() {
        mark_current_wait_completed();
        return false;
    }

    wait_once()
}

pub(crate) fn wait_until_ready_timeout(
    timeout_ticks: u64,
    mut is_ready: impl FnMut() -> bool,
    mut wait_once: impl FnMut(u64) -> bool,
    mut on_unobserved_timeout: impl FnMut(),
) -> bool {
    let wait_plan = runtime_timed_wait_plan(timeout_ticks);
    if wait_plan == TimedWaitPlan::Unavailable {
        return false;
    }

    if is_ready() {
        mark_current_wait_completed();
        return false;
    }

    match wait_plan {
        TimedWaitPlan::ZeroTimeout => {
            on_unobserved_timeout();
            false
        }
        TimedWaitPlan::Deadline(_) => wait_once(timeout_ticks),
        TimedWaitPlan::Unavailable => false,
    }
}

pub(crate) fn probe_then_wait_then_probe<T>(
    mut probe: impl FnMut() -> Option<T>,
    mut wait_once: impl FnMut(),
) -> Option<T> {
    if let Some(value) = finish_ready_probe(probe()) {
        return Some(value);
    }

    wait_once();

    finish_ready_probe(probe())
}

pub(crate) fn probe_then_timed_wait_loop<T>(
    timeout_ticks: u64,
    mut probe: impl FnMut() -> Option<T>,
    mut wait_once: impl FnMut(u64) -> bool,
    mut on_unobserved_timeout: impl FnMut(),
) -> Option<T> {
    if let Some(value) = finish_ready_probe(probe()) {
        return Some(value);
    }

    let deadline = match runtime_timed_wait_plan(timeout_ticks) {
        TimedWaitPlan::Unavailable => return finish_ready_probe(probe()),
        TimedWaitPlan::ZeroTimeout => {
            on_unobserved_timeout();
            return None;
        }
        TimedWaitPlan::Deadline(deadline) => deadline,
    };
    let scheduler =
        Scheduler::global().expect("timed wait deadline planning requires an installed scheduler");

    loop {
        if let Some(value) = finish_ready_probe(probe()) {
            return Some(value);
        }

        let now = scheduler.current_tick();
        if now >= deadline {
            on_unobserved_timeout();
            return None;
        }

        let timed_out = wait_once(deadline - now);

        if let Some(value) = finish_ready_probe(probe()) {
            return Some(value);
        }

        if timed_out {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{probe_then_timed_wait_loop, wait_until_ready_timeout};
    use crate::kernel::process::Scheduler;
    use std::cell::Cell;

    #[test]
    fn wait_until_ready_timeout_without_scheduler_short_circuits_before_ready_probe() {
        let ready_probes = Cell::new(0);
        let timeout_callbacks = Cell::new(0);

        assert!(!wait_until_ready_timeout(
            0,
            || {
                ready_probes.set(ready_probes.get() + 1);
                true
            },
            |_| panic!("wait_once should not run without scheduler"),
            || timeout_callbacks.set(timeout_callbacks.get() + 1),
        ));
        assert_eq!(ready_probes.get(), 0);
        assert_eq!(timeout_callbacks.get(), 0);
    }

    #[test]
    fn wait_until_ready_timeout_zero_timeout_runs_timeout_handler_with_scheduler() {
        let scheduler = Scheduler::new();
        let ready_probes = Cell::new(0);
        let timeout_callbacks = Cell::new(0);

        unsafe {
            scheduler.install_global_unchecked();
        }

        assert!(!wait_until_ready_timeout(
            0,
            || {
                ready_probes.set(ready_probes.get() + 1);
                false
            },
            |_| panic!("wait_once should not run for zero-timeout probes"),
            || timeout_callbacks.set(timeout_callbacks.get() + 1),
        ));
        assert_eq!(ready_probes.get(), 1);
        assert_eq!(timeout_callbacks.get(), 1);
    }

    #[test]
    fn probe_then_timed_wait_loop_without_scheduler_rechecks_probe_before_returning() {
        let probes = Cell::new(0);

        let value = probe_then_timed_wait_loop(
            5,
            || {
                probes.set(probes.get() + 1);
                (probes.get() == 2).then_some(7_u8)
            },
            |_| panic!("wait_once should not run without scheduler"),
            || panic!("timeout callback should not run without scheduler"),
        );

        assert_eq!(value, Some(7));
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn probe_then_timed_wait_loop_zero_timeout_runs_timeout_handler_with_scheduler() {
        let scheduler = Scheduler::new();
        let timeout_callbacks = Cell::new(0);

        unsafe {
            scheduler.install_global_unchecked();
        }

        let value = probe_then_timed_wait_loop(
            0,
            || None::<u8>,
            |_| panic!("wait_once should not run for zero-timeout probes"),
            || timeout_callbacks.set(timeout_callbacks.get() + 1),
        );

        assert_eq!(value, None);
        assert_eq!(timeout_callbacks.get(), 1);
    }
}
