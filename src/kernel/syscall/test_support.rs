//! src/kernel/syscall/test_support.rs
//! Shared syscall test helpers for modules that need a live current process/thread context.
//!
//! We use a simple `AtomicBool` spinlock instead of `std::sync::Mutex` because
//! `Mutex::lock()` returns `PoisonError` when a prior holder panicked.  In a
//! test binary that runs many tests in one process, a single panicking syscall
//! test would poison the lock and cascade into 8+ spurious failures across
//! unrelated test modules.  An `AtomicBool` spinlock cannot be poisoned — if a
//! holder panics, the guard's `Drop` releases the lock and the next test
//! proceeds normally.

use alloc::{boxed::Box, sync::Arc, vec};

use crate::kernel::process::{LaunchContext, Process, Scheduler};

use core::sync::atomic::{AtomicBool, Ordering};

static TEST_LOCK: AtomicBool = AtomicBool::new(false);

pub(super) struct TestLockGuard;

impl Drop for TestLockGuard {
    fn drop(&mut self) {
        TEST_LOCK.store(false, Ordering::Release);
    }
}

/// Acquire the global syscall-test serialisation lock.
///
/// Spins until the lock is available.  On return the caller owns the lock
/// exclusively; it is released when the returned guard is dropped.
/// Unlike `std::sync::Mutex`, this lock cannot be poisoned, so a panicking
/// test does not cascade failures into subsequent tests.
pub(super) fn test_lock() -> TestLockGuard {
    while TEST_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // If the previous holder panicked, the thread-local CURRENT_SCHEDULER
    // slot may still hold a dangling pointer to the now-dropped Box<Scheduler>.
    // Clear it eagerly so the next test starts from a clean slate.
    Scheduler::clear_thread_local_scheduler();
    TestLockGuard
}

pub(super) fn scheduled_current_process(name: &str) -> (Box<Scheduler>, Arc<Process>) {
    // Keep the scheduler at a stable heap address before publishing it through
    // the global raw-pointer slot used by syscall runtime helpers.
    let scheduler = Box::new(Scheduler::new());
    let thread = scheduler.spawn_named(name, 0x1000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));

    (scheduler, thread.process().clone())
}

pub(super) fn locked_scheduled_current_process(
    name: &str,
) -> (TestLockGuard, Box<Scheduler>, Arc<Process>) {
    let guard = test_lock();
    let (scheduler, process) = scheduled_current_process(name);
    (guard, scheduler, process)
}

pub(super) fn sample_launch_context() -> LaunchContext {
    LaunchContext {
        catalog_id: "demo-app".into(),
        manifest_path: "/apps/packages/demo-app/manifest.toml".into(),
        image_path: "/apps/packages/demo-app/bin/demo.elf".into(),
        version: "0.1.0".into(),
        working_dir: "/data/users/guest/workspace".into(),
        arguments: vec!["demo-app".into(), "--verbose".into()],
        environment: vec!["ASTRA_APP_ID=demo-app".into()],
    }
}
