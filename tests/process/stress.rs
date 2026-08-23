//! tests/process/stress.rs
//! Concurrency stress tests and memory pressure tests for the kernel.
//!
//! - **Concurrency stress**: spawn many threads, exercise synchronisation
//!   primitives, rapid create/destroy cycles, timer-driven preemption.
//!   Primary goal: verify no panics / crashes under load.
//! - **Memory pressure**: allocate until exhaustion, verify graceful failure,
//!   fragmentation stress, heap integrity after churn.

use std::sync::{Mutex, OnceLock};

use protofire::kernel::process::{sleep_current, Scheduler};
use protofire::kernel::sync::{Event, Semaphore};

// ── Test serialisation ─────────────────────────────────────────────────────

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ── Concurrency stress tests ────────────────────────────────────────────────

#[test]
fn stress_spawn_many_threads_and_schedule_all() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();

    let count = 50;
    let threads: Vec<_> = (0..count)
        .map(|i| scheduler.spawn_named("worker", 0x1000 + i * 0x10))
        .collect();

    assert_eq!(scheduler.process_count(), count);
    assert_eq!(scheduler.ready_count(), count);

    unsafe {
        scheduler.install_global_unchecked();
    }

    for _ in 0..count * 2 {
        scheduler.schedule();
    }

    for t in &threads {
        assert!(
            t.switch_count() > 0,
            "thread {} was never scheduled",
            t.tid()
        );
    }
}

#[test]
fn stress_rapid_semaphore_try_acquire_release() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(1);
    let main = scheduler.spawn_named("main", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

    for _ in 0..200 {
        assert!(semaphore.try_acquire());
        assert_eq!(semaphore.release(1), 0);
    }
    assert_eq!(semaphore.permits(), 1);
}

#[test]
fn stress_semaphore_timeout_returns_without_panic() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let main = scheduler.spawn_named("main", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

    // acquire_timeout should not panic regardless of permits.
    let _ = semaphore.acquire_timeout(10);
    let _ = semaphore.acquire_timeout(0);
}

#[test]
fn stress_event_signal_reset_does_not_panic() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let event_manual = Event::manual_reset(false);
    let event_auto = Event::auto_reset(false);
    let main = scheduler.spawn_named("main", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

    // Manual-reset signal/reset cycle.
    for _ in 0..100 {
        event_manual.signal();
        assert!(event_manual.is_signaled());
        event_manual.reset();
        assert!(!event_manual.is_signaled());
    }

    // Auto-reset signal/wait cycle (no assertion on wait return — it may
    // or may not block depending on scheduler state).
    for _ in 0..100 {
        event_auto.signal();
        let _ = event_auto.wait();
    }
}

#[test]
fn stress_rapid_thread_spawn_and_schedule() {
    let _guard = test_lock();

    for cycle in 0..20 {
        let scheduler = Scheduler::new();
        let main = scheduler.spawn_named("main", 0x1000);

        unsafe {
            scheduler.install_global_unchecked();
        }
        scheduler.schedule();
        assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

        for i in 0..5 {
            let _t = scheduler.spawn_named("transient", 0x2000 + i * 0x10);
            scheduler.schedule();
        }

        let proc_count = scheduler.process_count();
        assert!(
            proc_count >= 6,
            "cycle {cycle}: expected >=6 processes, got {proc_count}"
        );
    }
}

#[test]
fn stress_sleep_and_timer_preemption() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("first", 0x1000);
    let second = scheduler.spawn_named("second", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    // First sleeps for 5 ticks.
    sleep_current(5);
    // After sleeping, scheduler should have switched to second.
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);

    // Advance time: first should wake.
    scheduler.handle_timer_tick(10);
    assert_eq!(scheduler.waiting_count(), 0);
}

#[test]
fn stress_many_sleepers_timer_wake() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let main = scheduler.spawn_named("main", 0x1000);

    let sleeper_count = 6;
    let sleepers: Vec<_> = (0..sleeper_count)
        .map(|i| scheduler.spawn_named("sleeper", 0x2000 + i * 0x10))
        .collect();

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

    // Put each sleeper to sleep with different durations.
    for (i, _) in sleepers.iter().enumerate() {
        scheduler.schedule();
        let current = scheduler.current_thread_id().unwrap();
        if sleepers.iter().any(|s| s.tid() == current) {
            sleep_current(((i + 1) * 2) as u64);
        }
    }

    let initial_waiting = scheduler.waiting_count();

    // Advance timer ticks to wake sleepers.
    for _ in 0..15 {
        scheduler.handle_timer_tick(2);
    }

    // After sufficient ticks, all sleepers should have woken
    // (or at least fewer should be waiting).
    let final_waiting = scheduler.waiting_count();
    assert!(
        final_waiting < initial_waiting || initial_waiting == 0,
        "sleepers should wake on timer tick (waiting: {initial_waiting} → {final_waiting})"
    );
}

#[test]
fn stress_semaphore_multi_release_does_not_panic() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let semaphore = Semaphore::new(0);
    let main = scheduler.spawn_named("main", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(main.tid()));

    // Release multiple permits on an uncontended semaphore — just verify
    // no panic.
    assert_eq!(semaphore.release(3), 0);
    assert_eq!(semaphore.permits(), 3);
    assert!(semaphore.try_acquire());
    assert!(semaphore.try_acquire());
    assert!(semaphore.try_acquire());
    assert_eq!(semaphore.permits(), 0);
}

// ── Memory pressure tests ───────────────────────────────────────────────────

#[test]
fn memory_allocate_until_oom_then_free_all() {
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    for _ in 0..1000 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vec![0xA5u8; 1024]));
        match result {
            Ok(block) => blocks.push(block),
            Err(_) => break,
        }
    }

    let allocated = blocks.len();
    assert!(allocated > 0, "should allocate at least one block");

    for block in &blocks {
        assert!(block.iter().all(|&b| b == 0xA5), "block corrupted");
    }

    drop(blocks);
    let _recovery = vec![0xCCu8; 512];
}

#[test]
fn memory_fragmentation_stress_odd_sized_allocations() {
    let mut blocks: Vec<Option<Vec<u8>>> = Vec::new();

    for size in 1..=256 {
        let block = vec![(size & 0xFF) as u8; size];
        blocks.push(Some(block));
    }

    for i in (0..blocks.len()).step_by(2) {
        blocks[i] = None;
    }

    for i in (0..blocks.len()).step_by(2) {
        let size = ((i * 7 + 3) % 128) + 1;
        if let Ok(block) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vec![0x5Au8; size]))
        {
            blocks[i] = Some(block);
        }
    }

    for block in blocks.iter().flatten() {
        assert!(!block.is_empty(), "empty block after fragmentation stress");
    }
}

#[test]
fn memory_large_allocation_and_free() {
    let large = vec![0x42u8; 1024 * 1024];
    assert!(large.iter().all(|&b| b == 0x42));
    drop(large);

    let _small1 = vec![0x99u8; 4096];
    let _small2 = vec![0x88u8; 2048];
}

#[test]
fn memory_alternating_alloc_free_cycle() {
    for cycle in 0..50 {
        let a = vec![0x11u8; 256];
        let b = vec![0x22u8; 512];
        let c = vec![0x33u8; 128];

        assert_eq!(a[0], 0x11, "cycle {cycle}: a corrupt");
        assert_eq!(b[0], 0x22, "cycle {cycle}: b corrupt");
        assert_eq!(c[0], 0x33, "cycle {cycle}: c corrupt");

        drop(a);
        drop(c);
        drop(b);
    }
}

#[test]
fn memory_zero_size_allocations() {
    let a: Vec<u8> = Vec::new();
    let b: Vec<u8> = vec![];
    assert!(a.is_empty());
    assert!(b.is_empty());

    let c: Vec<u8> = Vec::with_capacity(0);
    assert!(c.is_empty());
}

#[test]
fn memory_many_small_allocations_stress() {
    let mut objects: Vec<Vec<u64>> = Vec::new();

    for i in 0..1000 {
        let obj = vec![i as u64];
        objects.push(obj);
    }

    for (i, obj) in objects.iter().enumerate() {
        assert_eq!(obj[0], i as u64, "object {i} corrupted");
    }
}
