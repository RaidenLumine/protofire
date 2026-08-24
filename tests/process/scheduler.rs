//! tests/process/scheduler.rs
//!
//! Host-side integration tests for scheduling, waits, and synchronization primitives.

use std::sync::{Mutex, OnceLock};

use protofire::arch::x86_64::gdt;
use protofire::kernel::process::{
    sleep_current, ProcessState, Scheduler, ThreadWaitOutcome, UserThreadStart,
};
use protofire::kernel::sync::{Event, Semaphore};

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn spawned_threads_receive_kernel_stacks() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("worker", 0x200000);
    let context = thread.context();
    let (stack_bottom, stack_top) = thread.stack_bounds();

    assert_ne!(context.stack_pointer, 0);
    assert!(context.stack_pointer <= stack_top);
    assert!(context.stack_pointer >= stack_bottom);
    assert_eq!(context.instruction_pointer, 0x200000);
}

#[test]
fn spawned_user_threads_keep_initial_x86_64_context() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let start = UserThreadStart {
        instruction_pointer: 0x401000,
        stack_pointer: 0x7fff_ffff_f000,
        exception_stack_pointer: None,
    };
    let thread = scheduler.spawn_user_named("user", start);
    let context = thread
        .x86_64_user_context()
        .expect("x86_64 user context should exist");

    assert_eq!(
        context.instruction_pointer,
        start.instruction_pointer as u64
    );
    assert_eq!(context.stack_pointer, start.stack_pointer as u64);
    assert_eq!(context.code_segment, gdt::user_code_selector() as u64);
    assert_eq!(context.stack_segment, gdt::user_data_selector() as u64);
    assert_eq!(context.rflags, 0x202);
}

#[test]
fn schedule_rotates_ready_threads() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    assert_eq!(scheduler.process_count(), 2);
    assert_eq!(scheduler.ready_count(), 2);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(first.switch_count(), 1);
}

#[test]
fn sleeping_threads_block_and_wake_on_timer_tick() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    sleep_current(3);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);

    scheduler.handle_timer_tick(1);
    assert_eq!(scheduler.waiting_count(), 1);

    scheduler.handle_timer_tick(3);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(scheduler.ready_count(), 1);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
}

#[test]
fn timer_tick_preempts_current_thread_on_host() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!scheduler.handle_timer_tick(1));
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(scheduler.handle_timer_tick(2));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(first.switch_count(), 1);
}

#[test]
fn scheduler_hotspot_stats_track_sleep_timeout_and_preemption_flow() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert_eq!(scheduler.hotspot_stats().dispatch_count, 1);

    sleep_current(3);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));

    let stats = scheduler.hotspot_stats();
    assert_eq!(stats.dispatch_count, 2);
    assert_eq!(stats.block_count, 1);
    assert_eq!(stats.timed_wait_registration_count, 1);
    assert_eq!(stats.timeout_wake_count, 0);
    assert_eq!(stats.preempt_count, 0);

    scheduler.handle_timer_tick(3);

    let stats = scheduler.hotspot_stats();
    assert_eq!(stats.timeout_wake_count, 1);
    assert_eq!(scheduler.ready_count(), 1);

    scheduler.schedule();

    let stats = scheduler.hotspot_stats();
    assert_eq!(stats.preempt_count, 1);
    assert_eq!(stats.dispatch_count, 3);
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
}

#[test]
fn manual_reset_event_wakes_all_waiters() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::manual_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);
    let third = scheduler.spawn_named("third", 0x3000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert!(event.wait());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(event.waiter_count(), 1);

    assert!(event.wait());
    assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
    assert_eq!(event.waiter_count(), 2);

    assert_eq!(event.signal(), 2);
    assert!(event.is_signaled());
    assert_eq!(event.waiter_count(), 0);
    assert_eq!(scheduler.ready_count(), 2);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
}

#[test]
fn manual_reset_event_reset_clears_sticky_signal_for_zero_timeout_probe() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::manual_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert_eq!(event.signal(), 0);
    assert!(event.is_signaled());
    assert!(!event.wait_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert!(event.is_signaled());

    event.reset();
    assert!(!event.is_signaled());
    assert!(!event.wait_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(event.waiter_count(), 0);
}

#[test]
fn auto_reset_event_keeps_sticky_signal_until_wait() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert_eq!(event.signal(), 0);
    assert!(event.is_signaled());
    assert_eq!(event.waiter_count(), 0);

    assert!(!event.wait());
    assert!(!event.is_signaled());
    assert_eq!(event.waiter_count(), 0);
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
}

#[test]
fn scheduler_hotspot_stats_track_signal_wakes_and_reset() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    scheduler.reset_hotspot_stats();
    assert!(event.wait());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));

    let stats = scheduler.hotspot_stats();
    assert_eq!(stats.dispatch_count, 1);
    assert_eq!(stats.block_count, 1);
    assert_eq!(stats.timed_wait_registration_count, 0);
    assert_eq!(stats.signal_wake_count, 0);

    assert_eq!(event.signal(), 1);

    let stats = scheduler.hotspot_stats();
    assert_eq!(stats.signal_wake_count, 1);
    assert_eq!(stats.timeout_wake_count, 0);
    assert_eq!(stats.block_count, 1);
}

#[test]
fn auto_reset_event_wakes_one_waiter_per_signal() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);
    let third = scheduler.spawn_named("third", 0x3000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert!(event.wait());
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));

    assert!(event.wait());
    assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
    assert_eq!(event.waiter_count(), 2);

    assert_eq!(event.signal(), 1);
    assert_eq!(event.waiter_count(), 1);
    assert!(!event.is_signaled());
    assert_eq!(scheduler.ready_count(), 1);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert_eq!(event.signal(), 1);
    assert_eq!(event.waiter_count(), 0);
    assert_eq!(scheduler.ready_count(), 2);
}

#[test]
fn event_timeout_marks_thread_and_removes_waiter() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(event.wait_timeout(3));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(event.waiter_count(), 1);

    scheduler.handle_timer_tick(2);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(scheduler.waiting_count(), 1);

    scheduler.handle_timer_tick(3);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(event.waiter_count(), 0);
}

#[test]
fn event_signal_before_deadline_prevents_timeout_outcome() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(event.wait_timeout(3));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(event.waiter_count(), 1);

    assert_eq!(event.signal(), 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(event.waiter_count(), 0);

    scheduler.handle_timer_tick(3);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
}

#[test]
fn auto_reset_event_skips_waiters_from_terminated_processes() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let stale = scheduler.spawn_named("stale", 0x1000);
    let live = scheduler.spawn_named("live", 0x2000);
    let notifier = scheduler.spawn_named("notifier", 0x3000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(stale.tid()));
    assert!(event.wait());

    assert_eq!(scheduler.current_thread_id(), Some(live.tid()));
    assert!(event.wait());

    assert_eq!(scheduler.current_thread_id(), Some(notifier.tid()));
    stale.process().set_state(ProcessState::Terminated);

    assert_eq!(event.signal(), 1);
    assert_eq!(live.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(scheduler.ready_count(), 1);
    assert_eq!(event.waiter_count(), 0);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(live.tid()));
}

#[test]
fn event_zero_timeout_behaves_as_non_blocking_probe() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event = Event::auto_reset(false);
    let first = scheduler.spawn_named("first", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!event.wait_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(event.waiter_count(), 0);

    assert_eq!(event.signal(), 0);
    assert!(event.is_signaled());
    assert!(!event.wait_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert!(!event.is_signaled());
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(event.waiter_count(), 0);
}

#[test]
fn semaphore_release_wakes_waiter_and_keeps_extra_permits() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(semaphore.acquire_timeout(5));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);

    assert_eq!(semaphore.release(2), 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(semaphore.permits(), 1);
    assert!(semaphore.try_acquire());
    assert_eq!(semaphore.permits(), 0);
}

#[test]
fn semaphore_timeout_marks_thread_as_timed_out() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(semaphore.acquire_timeout(2));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);

    scheduler.handle_timer_tick(2);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(semaphore.permits(), 0);
}

#[test]
fn semaphore_release_after_timeout_restores_permit_without_waking_stale_waiter() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(semaphore.acquire_timeout(2));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(scheduler.waiting_count(), 1);

    scheduler.handle_timer_tick(2);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);

    assert_eq!(semaphore.release(1), 0);
    assert_eq!(semaphore.permits(), 1);
    assert!(semaphore.try_acquire());
    assert_eq!(semaphore.permits(), 0);
}

#[test]
fn semaphore_zero_timeout_behaves_as_non_blocking_probe() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let first = scheduler.spawn_named("first", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!semaphore.acquire_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(semaphore.permits(), 0);

    assert_eq!(semaphore.release(1), 0);
    assert_eq!(semaphore.permits(), 1);
    assert!(!semaphore.acquire_timeout(0));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(semaphore.permits(), 0);
}
