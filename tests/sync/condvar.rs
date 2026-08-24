//! tests/sync/condvar.rs
//!
//! Host-side integration tests for condition-variable wait, wake, and timeout behavior.

use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};

use protofire::kernel::process::Scheduler;
use protofire::kernel::sync::{Condvar, Mutex};

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn condvar_wait_releases_mutex_for_notifier() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Arc::new(Mutex::new(1usize));
    let first = scheduler.spawn_named("waiter", 0x1000);
    let second = scheduler.spawn_named("notifier", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    let guard = shared.lock();
    let wait = condvar.wait(guard);
    assert!(wait.blocked());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(condvar.waiter_count(), 1);

    {
        let mut guard = shared.lock();
        *guard = 7;
        assert!(condvar.notify_one());
    }

    assert_eq!(condvar.waiter_count(), 0);
    assert!(!wait.timed_out());

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    let guard = wait.relock();
    assert_eq!(*guard, 7);
}

#[test]
fn condvar_notify_all_wakes_multiple_waiters() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Arc::new(Mutex::new(0usize));
    let first = scheduler.spawn_named("waiter-a", 0x1000);
    let second = scheduler.spawn_named("waiter-b", 0x2000);
    let third = scheduler.spawn_named("notifier", 0x3000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    let wait_a = condvar.wait(shared.lock());
    assert!(wait_a.blocked());

    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    let wait_b = condvar.wait(shared.lock());
    assert!(wait_b.blocked());
    assert_eq!(condvar.waiter_count(), 2);

    assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
    {
        let mut guard = shared.lock();
        *guard = 42;
        assert_eq!(condvar.notify_all(), 2);
    }

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    let guard = wait_a.relock();
    assert_eq!(*guard, 42);
    drop(guard);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    let guard = wait_b.relock();
    assert_eq!(*guard, 42);
}

#[test]
fn condvar_timeout_relocks_mutex_after_wake() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Arc::new(Mutex::new(5usize));
    let first = scheduler.spawn_named("waiter", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    let wait = condvar.wait_timeout(shared.lock(), 3);
    assert!(wait.blocked());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(condvar.waiter_count(), 1);

    {
        let mut guard = shared.lock();
        *guard = 9;
    }

    scheduler.handle_timer_tick(3);
    assert_eq!(condvar.waiter_count(), 0);
    assert!(wait.timed_out());

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    let guard = wait.relock();
    assert_eq!(*guard, 9);
}

#[test]
fn condvar_notify_before_deadline_prevents_timeout_outcome() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Arc::new(Mutex::new(5usize));
    let first = scheduler.spawn_named("waiter", 0x1000);
    let second = scheduler.spawn_named("notifier", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    let wait = condvar.wait_timeout(shared.lock(), 3);
    assert!(wait.blocked());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(condvar.waiter_count(), 1);
    assert_eq!(scheduler.waiting_count(), 1);

    {
        let mut guard = shared.lock();
        *guard = 13;
        assert!(condvar.notify_one());
    }

    assert_eq!(condvar.waiter_count(), 0);
    assert_eq!(scheduler.waiting_count(), 0);

    scheduler.handle_timer_tick(3);
    assert!(!wait.timed_out());

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    let guard = wait.relock();
    assert_eq!(*guard, 13);
}

#[test]
fn condvar_zero_timeout_with_scheduler_is_non_blocking_and_timed_out() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Mutex::new(31usize);
    let first = scheduler.spawn_named("waiter", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    let wait = condvar.wait_timeout(shared.lock(), 0);
    assert!(!wait.blocked());
    assert!(wait.timed_out());
    assert_eq!(condvar.waiter_count(), 0);
    assert_eq!(scheduler.waiting_count(), 0);

    let guard = wait.relock();
    assert_eq!(*guard, 31);
}

#[test]
fn condvar_wait_without_scheduler_keeps_guard_held_and_does_not_block() {
    let _guard = test_lock();
    let condvar = Condvar::new();
    let shared = Mutex::new(11usize);

    let wait = condvar.wait(shared.lock());

    assert!(!wait.blocked());
    assert!(!wait.timed_out());
    assert_eq!(condvar.waiter_count(), 0);

    let guard = wait.relock();
    assert_eq!(*guard, 11);
}

#[test]
fn condvar_wait_timeout_without_scheduler_keeps_guard_held_and_does_not_block() {
    let _guard = test_lock();
    let condvar = Condvar::new();
    let shared = Mutex::new(23usize);

    let wait = condvar.wait_timeout(shared.lock(), 5);

    assert!(!wait.blocked());
    assert!(!wait.timed_out());
    assert_eq!(condvar.waiter_count(), 0);

    let guard = wait.relock();
    assert_eq!(*guard, 23);
}

#[test]
fn condvar_notify_one_after_timeout_does_not_wake_stale_waiter() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let condvar = Condvar::new();
    let shared = Arc::new(Mutex::new(41usize));
    let waiter = scheduler.spawn_named("waiter", 0x1000);
    let worker = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));

    let wait = condvar.wait_timeout(shared.lock(), 3);
    assert!(wait.blocked());
    assert_eq!(scheduler.current_thread_id(), Some(worker.tid()));
    assert_eq!(condvar.waiter_count(), 1);

    scheduler.handle_timer_tick(3);
    assert!(wait.timed_out());
    assert_eq!(condvar.waiter_count(), 0);

    {
        let mut guard = shared.lock();
        *guard = 99;
        assert!(!condvar.notify_one());
        assert_eq!(condvar.notify_all(), 0);
    }

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));
    let guard = wait.relock();
    assert_eq!(*guard, 99);
}
