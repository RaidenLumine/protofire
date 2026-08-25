//! tests/io/console.rs
//!
//! Host-side integration tests for console line buffering and timeout
//! semantics.

use std::sync::{Mutex, OnceLock};

use protofire::kernel::console;
use protofire::kernel::drivers::{keyboard, serial};
use protofire::kernel::process::{Scheduler, ThreadWaitOutcome};

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn console_cooks_input_only_after_newline() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x30);

    assert_eq!(console.pending_byte_count(), 0);
    assert_eq!(console.try_read_byte(), None);
    assert_eq!(console.try_read_line(), None);

    keyboard::inject_scancode(0x1C);

    assert_eq!(console.pending_byte_count(), 3);
    assert_eq!(console.try_read_line(), Some("ab\n".to_string()));
    assert_eq!(console.pending_byte_count(), 0);
}

#[test]
fn console_backspace_edits_the_pending_line() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x30);
    keyboard::inject_scancode(0x0E);
    keyboard::inject_scancode(0x2E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.try_read_line(), Some("ac\n".to_string()));
}

#[test]
fn console_echoes_typed_input_backspace_and_newline_to_serial() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    let serial = serial::init_device();
    keyboard.clear();
    console.clear();
    serial.clear();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x30);
    keyboard::inject_scancode(0x0E);
    keyboard::inject_scancode(0x2E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.try_read_line(), Some("ac\n".to_string()));
    assert_eq!(serial.captured_tx_bytes(), b"ab\x08 \x08c\r\n");
}

#[test]
fn console_backspace_erases_full_tab_echo_width() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    let serial = serial::init_device();
    keyboard.clear();
    console.clear();
    serial.clear();

    keyboard::inject_scancode(0x0F);
    keyboard::inject_scancode(0x0E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.try_read_line(), Some("\n".to_string()));
    assert_eq!(
        serial.captured_tx_bytes(),
        b"    \x08 \x08\x08 \x08\x08 \x08\x08 \x08\r\n"
    );
}

#[test]
fn console_waiter_wakes_only_when_a_line_is_committed() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(console.wait_for_input_timeout(5));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(console.waiter_count(), 1);

    keyboard::inject_scancode(0x1E);
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(console.waiter_count(), 1);
    assert_eq!(console.pending_byte_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);

    keyboard::inject_scancode(0x1C);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(console.waiter_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(console.try_read_line(), Some("a\n".to_string()));
}

#[test]
fn console_waiter_times_out_without_newline() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(console.wait_for_input_timeout(3));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(console.waiter_count(), 1);

    keyboard::inject_scancode(0x1E);
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(console.waiter_count(), 1);

    scheduler.handle_timer_tick(3);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(console.waiter_count(), 0);
    assert_eq!(console.pending_byte_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
}

#[test]
fn console_zero_timeout_is_non_blocking_probe() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);
    let _second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!console.wait_for_input_timeout(0));
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(console.waiter_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
}

#[test]
fn console_immediate_timeout_reads_mark_completion_when_input_is_already_buffered() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.read_byte_timeout(5), Some(b'a'));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);

    keyboard.clear();
    console.clear();
    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.read_line_timeout(5), Some("a\n".to_string()));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
}

#[test]
fn console_immediate_read_marks_completion_when_input_is_already_buffered() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);

    assert_eq!(console.read_byte(), Some(b'a'));
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
}

#[test]
fn console_wait_stats_track_waiter_peak_and_wake_count() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();
    console.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader-a", 0x1000);
    let second = scheduler.spawn_named("tty-reader-b", 0x2000);
    let third = scheduler.spawn_named("producer", 0x3000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert!(console.wait_for_input_timeout(5));

    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert!(console.wait_for_input_timeout(5));
    assert_eq!(console.wait_stats().waiter_peak, 2);

    assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);

    let stats = console.wait_stats();
    assert_eq!(stats.waiter_peak, 2);
    assert_eq!(stats.wake_count, 2);
    assert_eq!(stats.timeout_count, 0);
}

#[test]
fn console_wait_stats_track_timeout_count() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();
    console.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);
    let _second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!console.wait_for_input_timeout(0));
    assert_eq!(console.wait_stats().timeout_count, 1);

    assert!(console.wait_for_input_timeout(3));
    assert_eq!(
        console.wait_stats().timeout_count,
        1,
        "async timeout should be counted only when the timer path actually fires"
    );
    scheduler.handle_timer_tick(3);

    let stats = console.wait_stats();
    assert_eq!(stats.waiter_peak, 1);
    assert_eq!(stats.timeout_count, 2);
}

#[test]
fn console_read_timeout_probes_count_once_without_registering_waiters() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();
    console.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("tty-reader", 0x1000);
    let _second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert_eq!(console.read_byte_timeout(0), None);
    assert_eq!(console.wait_stats().timeout_count, 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
    assert_eq!(console.waiter_count(), 0);

    assert_eq!(console.read_line_timeout(0), None);

    let stats = console.wait_stats();
    assert_eq!(stats.waiter_peak, 0);
    assert_eq!(stats.timeout_count, 2);
    assert_eq!(console.waiter_count(), 0);
}
