//! tests/io/keyboard.rs
//!
//! Host-side integration tests for keyboard decode, buffering, and wait
//! semantics.

use std::sync::{Mutex, OnceLock};

use protofire::kernel::drivers::keyboard::{self, KeyCode, KeyEvent, KeyModifiers};
use protofire::kernel::process::{Scheduler, ThreadWaitOutcome};

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn injected_scancodes_are_buffered_and_readable() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x30);

    assert_eq!(device.pending_count(), 2);
    assert_eq!(keyboard::try_read_scancode(), Some(0x1E));
    assert_eq!(keyboard::try_read_scancode(), Some(0x30));
    assert_eq!(device.pending_count(), 0);
}

#[test]
fn raw_scancode_burst_drops_oldest_entries() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    for scancode in 0_u8..=64 {
        keyboard::inject_scancode(scancode);
    }

    assert_eq!(device.pending_count(), 64);
    for expected in 1_u8..=64 {
        assert_eq!(keyboard::try_read_scancode(), Some(expected));
    }
    assert_eq!(keyboard::try_read_scancode(), None);
    assert_eq!(device.pending_count(), 0);
}

#[test]
fn decoded_key_events_preserve_press_release_and_characters() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x9E);

    assert_eq!(device.pending_count(), 2);
    assert_eq!(device.pending_event_count(), 2);
    assert_eq!(device.pending_char_count(), 1);

    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: true,
            character: Some('a'),
            modifiers: KeyModifiers::default(),
        })
    );
    assert_eq!(keyboard::try_read_char(), Some('a'));
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: false,
            character: None,
            modifiers: KeyModifiers::default(),
        })
    );
    assert_eq!(keyboard::try_read_char(), None);
}

#[test]
fn modifiers_change_generated_characters() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    keyboard::inject_scancode(0x2A);
    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x9E);
    keyboard::inject_scancode(0xAA);
    keyboard::inject_scancode(0x3A);
    keyboard::inject_scancode(0xBA);
    keyboard::inject_scancode(0x1E);

    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::LeftShift,
            pressed: true,
            character: None,
            modifiers: KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: true,
            character: Some('A'),
            modifiers: KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(keyboard::try_read_char(), Some('A'));
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: false,
            character: None,
            modifiers: KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::LeftShift,
            pressed: false,
            character: None,
            modifiers: KeyModifiers::default(),
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::CapsLock,
            pressed: true,
            character: None,
            modifiers: KeyModifiers {
                caps_lock: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::CapsLock,
            pressed: false,
            character: None,
            modifiers: KeyModifiers {
                caps_lock: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: true,
            character: Some('A'),
            modifiers: KeyModifiers {
                caps_lock: true,
                ..KeyModifiers::default()
            },
        })
    );
    assert_eq!(keyboard::try_read_char(), Some('A'));
    assert_eq!(keyboard::try_read_event(), None);
}

#[test]
fn extended_scancodes_decode_to_key_events() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    keyboard::inject_scancode(0xE0);
    keyboard::inject_scancode(0x48);
    keyboard::inject_scancode(0xE0);
    keyboard::inject_scancode(0xC8);

    assert_eq!(device.pending_count(), 4);
    assert_eq!(device.pending_event_count(), 2);
    assert_eq!(device.pending_char_count(), 0);

    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::ArrowUp,
            pressed: true,
            character: None,
            modifiers: KeyModifiers::default(),
        })
    );
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::ArrowUp,
            pressed: false,
            character: None,
            modifiers: KeyModifiers::default(),
        })
    );
    assert_eq!(keyboard::try_read_char(), None);
}

#[test]
fn waiting_reader_wakes_when_scancode_arrives() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(device.wait_for_scancode_timeout(5));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(device.waiter_count(), 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Pending);

    keyboard::inject_scancode(0x20);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(device.waiter_count(), 0);
    assert_eq!(device.pending_count(), 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(keyboard::try_read_scancode(), Some(0x20));
}

#[test]
fn waiting_event_reader_wakes_when_key_arrives() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("event-reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(device.wait_for_event_timeout(5));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(device.event_waiter_count(), 1);

    keyboard::inject_scancode(0x1E);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(device.event_waiter_count(), 0);
    assert_eq!(device.pending_event_count(), 1);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(
        keyboard::try_read_event(),
        Some(KeyEvent {
            code: KeyCode::A,
            pressed: true,
            character: Some('a'),
            modifiers: KeyModifiers::default(),
        })
    );
}

#[test]
fn waiting_reader_times_out_without_input() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(device.wait_for_scancode_timeout(3));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(device.waiter_count(), 1);

    scheduler.handle_timer_tick(3);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(device.waiter_count(), 0);
    assert_eq!(device.pending_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
}

#[test]
fn waiting_char_reader_times_out_without_input() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("char-reader", 0x1000);
    let second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(device.wait_for_char_timeout(3));
    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert_eq!(scheduler.waiting_count(), 1);
    assert_eq!(device.char_waiter_count(), 1);

    scheduler.handle_timer_tick(3);
    assert_eq!(scheduler.waiting_count(), 0);
    assert_eq!(device.char_waiter_count(), 0);
    assert_eq!(device.pending_char_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
}

#[test]
fn keyboard_wait_stats_track_peaks_and_wakes_per_queue() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();
    device.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("scancode-reader", 0x1000);
    let second = scheduler.spawn_named("event-reader", 0x2000);
    let third = scheduler.spawn_named("char-reader", 0x3000);
    let fourth = scheduler.spawn_named("producer", 0x4000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));
    assert!(device.wait_for_scancode_timeout(5));

    assert_eq!(scheduler.current_thread_id(), Some(second.tid()));
    assert!(device.wait_for_event_timeout(5));

    assert_eq!(scheduler.current_thread_id(), Some(third.tid()));
    assert!(device.wait_for_char_timeout(5));

    assert_eq!(scheduler.current_thread_id(), Some(fourth.tid()));
    keyboard::inject_scancode(0x1E);

    let stats = device.wait_stats();
    assert_eq!(stats.scancode_waiter_peak, 1);
    assert_eq!(stats.event_waiter_peak, 1);
    assert_eq!(stats.char_waiter_peak, 1);
    assert_eq!(stats.scancode_wake_count, 1);
    assert_eq!(stats.event_wake_count, 1);
    assert_eq!(stats.char_wake_count, 1);
    assert_eq!(stats.scancode_timeout_count, 0);
    assert_eq!(stats.event_timeout_count, 0);
    assert_eq!(stats.char_timeout_count, 0);
}

#[test]
fn keyboard_wait_stats_track_timeout_counts() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();
    device.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("reader", 0x1000);
    let _second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert!(!device.wait_for_scancode_timeout(0));
    assert!(!device.wait_for_event_timeout(0));
    assert!(!device.wait_for_char_timeout(0));

    assert!(device.wait_for_scancode_timeout(3));
    assert_eq!(
        device.wait_stats().scancode_timeout_count,
        1,
        "observed timeouts should be recorded when the timer callback fires, not when the wait is armed"
    );
    scheduler.handle_timer_tick(3);

    let stats = device.wait_stats();
    assert_eq!(stats.scancode_waiter_peak, 1);
    assert_eq!(stats.scancode_timeout_count, 2);
    assert_eq!(stats.event_timeout_count, 1);
    assert_eq!(stats.char_timeout_count, 1);
}

#[test]
fn keyboard_read_timeout_probes_count_once_per_queue() {
    let _guard = test_lock();
    let device = keyboard::init_device();
    device.clear();
    device.reset_wait_stats();

    let scheduler = Scheduler::new();
    let first = scheduler.spawn_named("reader", 0x1000);
    let _second = scheduler.spawn_named("worker", 0x2000);

    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(first.tid()));

    assert_eq!(device.read_scancode_timeout(0), None);
    assert_eq!(device.read_event_timeout(0), None);
    assert_eq!(device.read_char_timeout(0), None);

    let stats = device.wait_stats();
    assert_eq!(stats.scancode_waiter_peak, 0);
    assert_eq!(stats.event_waiter_peak, 0);
    assert_eq!(stats.char_waiter_peak, 0);
    assert_eq!(stats.scancode_timeout_count, 1);
    assert_eq!(stats.event_timeout_count, 1);
    assert_eq!(stats.char_timeout_count, 1);
    assert_eq!(device.waiter_count(), 0);
    assert_eq!(device.event_waiter_count(), 0);
    assert_eq!(device.char_waiter_count(), 0);
    assert_eq!(first.wait_outcome(), ThreadWaitOutcome::TimedOut);
}
