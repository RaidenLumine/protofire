//! src/user/shared/signal.rs
//! High-level signal API for ring3 user-space programs.
//!
//! This module provides convenience wrappers around the raw signal syscalls
//! (`sys_send_signal`, `sys_wait_signal`, `sys_set_signal_mask`) so that
//! ring3 programs can work with typed [`ProcessSignalRecord`] values instead
//! of raw byte buffers.
//!
//! # Cooperative signal model
//!
//! The kernel delivers signals cooperatively: a process must explicitly call
//! [`wait_signal`] (or the blocking [`wait_signal_forever`]) to receive the
//! next pending signal.  There is no asynchronous preemption — the signal
//! sits in the per-process queue until the program asks for it.
//!
//! # Signal mask
//!
//! Programs can block specific signals with [`block_signal`] /
//! [`set_signal_mask`].  Blocked signals remain queued but are not delivered
//! until unblocked.  SIGKILL and SIGSTOP ignore the mask.
//!
//! # Typical usage
//!
//! ```ignore
//! use crate::user::shared::signal;
//! use crate::user::shared::syscall::{SIGTERM, SIGINT, SIGCHLD};
//!
//! // Simple blocking wait in an event loop
//! loop {
//!     let sig = signal::wait_signal_forever();
//!     match sig.signal {
//!         SIGTERM | SIGINT => break,
//!         SIGCHLD => { /* reap children */ }
//!         _ => {}
//!     }
//! }
//! ```

use crate::user::shared::abi::process::ProcessSignalRecord;
use crate::user::shared::syscall;

// Re-export POSIX signal constants so callers can `use signal::SIGTERM` etc.
pub use crate::user::shared::syscall::{
    SIGCHLD, SIGCONT, SIGHUP, SIGINT, SIGKILL, SIGQUIT, SIGSTOP, SIGTERM, SIGTSTP,
};

/// Sentinel value for "block indefinitely" passed to `wait_signal`.
pub const WAIT_FOREVER: u64 = u64::MAX;

/// Signal handler function pointer type (ring3 side).
///
/// Compatible with the kernel's `SignalHandler = fn(i32)` — the signal
/// number is passed as the sole argument.
pub type SignalHandler = fn(i32);

// ── Core wait API ──────────────────────────────────────────────────────────

/// Wait for a signal with an optional timeout.
///
/// * `timeout_ticks` — maximum ticks to wait, or [`WAIT_FOREVER`] to block
///   indefinitely.  Pass `0` for a non-blocking poll.
///
/// Returns `Some(record)` if a signal was dequeued, or `None` if the timeout
/// expired with no signal pending.
pub fn wait_signal(timeout_ticks: u64) -> Option<ProcessSignalRecord> {
    let mut buf = [0u8; core::mem::size_of::<ProcessSignalRecord>()];
    match syscall::sys_wait_signal(timeout_ticks, &mut buf) {
        Ok(()) => {
            // Safety: the kernel writes a valid ProcessSignalRecord into buf.
            // The layout is repr(C) and binary-stable.
            let record: ProcessSignalRecord = unsafe { core::ptr::read(buf.as_ptr().cast()) };
            Some(record)
        }
        Err(_) => None,
    }
}

/// Block the calling thread until a signal is delivered to this process.
///
/// Convenience wrapper around [`wait_signal`]`(WAIT_FOREVER)`.  Panics if
/// the syscall fails (which only happens on invalid arguments, so this
/// should never panic in correct code).
pub fn wait_signal_forever() -> ProcessSignalRecord {
    wait_signal(WAIT_FOREVER).expect("wait_signal(WAIT_FOREVER) failed")
}

/// Non-blocking poll: return the next pending signal, or `None` if the
/// queue is empty.
pub fn poll_signal() -> Option<ProcessSignalRecord> {
    wait_signal(0)
}

// ── Signal mask ────────────────────────────────────────────────────────────

/// Block delivery of `signal` by adding it to the current signal mask.
///
/// Blocked signals are still enqueued but their default actions are
/// deferred until the signal is unblocked.  Has no effect on SIGKILL or
/// SIGSTOP.
pub fn block_signal(signal: usize) {
    let current = syscall::sys_set_signal_mask(0).unwrap_or(0) as u32;
    let _ = syscall::sys_set_signal_mask((current | (1u32 << signal)).into());
}

/// Unblock `signal` by removing it from the current signal mask.
pub fn unblock_signal(signal: usize) {
    let current = syscall::sys_set_signal_mask(0).unwrap_or(0) as u32;
    let _ = syscall::sys_set_signal_mask((current & !(1u32 << signal)).into());
}

/// Atomically get and set the signal mask.
///
/// Returns the previous mask value.
pub fn set_signal_mask(mask: u32) -> u32 {
    syscall::sys_set_signal_mask(mask.into()).unwrap_or(0) as u32
}

/// Return the current signal mask.
pub fn signal_mask() -> u32 {
    syscall::sys_set_signal_mask(0).unwrap_or(0) as u32
}

// ── Send ───────────────────────────────────────────────────────────────────

/// Send a signal to a process.
///
/// `sender_pid` is the PID of the sending process.  `payload` is an
/// optional user-defined value delivered alongside the signal.
pub fn send_signal(pid: usize, signal: usize, payload: usize) -> Result<(), isize> {
    syscall::sys_send_signal(pid, signal, payload)
}

// ── Cooperative dispatch loop ──────────────────────────────────────────────

/// Run a cooperative signal-wait loop that dispatches to registered
/// handlers.
///
/// This function never returns — it blocks on [`wait_signal_forever`] and
/// calls the matching handler for each received signal.  Use this when a
/// ring3 program wants to dedicate a thread to signal handling.
///
/// # Example
///
/// ```ignore
/// signal::signal_dispatch_loop(&[
///     (SIGTERM, |_| arch::exit(0)),
///     (SIGINT,  |_| arch::exit(0)),
///     (SIGCHLD, |_| { /* reap children */ }),
/// ]);
/// ```
pub fn signal_dispatch_loop(handlers: &[(usize, SignalHandler)]) -> ! {
    loop {
        let record = wait_signal_forever();
        let mut handled = false;
        for &(signal, handler) in handlers {
            if record.signal == signal {
                handler(record.signal as i32);
                handled = true;
                break;
            }
        }
        // Unhandled signals are silently ignored (default POSIX behaviour
        // for signals with no handler).
        let _ = handled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::shared::abi::process::ProcessSignalRecord;
    use alloc::vec;

    #[test]
    fn wait_signal_timeout_zero_returns_none_without_scheduler() {
        // When no scheduler is running (host-side unit test), a zero-timeout
        // wait should return None rather than panic.
        assert_eq!(wait_signal(0), None);
    }

    #[test]
    fn poll_signal_returns_none_without_scheduler() {
        assert_eq!(poll_signal(), None);
    }

    #[test]
    fn signal_constants_are_stable() {
        assert_eq!(SIGHUP, 1);
        assert_eq!(SIGINT, 2);
        assert_eq!(SIGQUIT, 3);
        assert_eq!(SIGKILL, 9);
        assert_eq!(SIGTERM, 15);
        assert_eq!(SIGCHLD, 17);
        assert_eq!(SIGCONT, 18);
        assert_eq!(SIGSTOP, 19);
        assert_eq!(SIGTSTP, 20);
    }

    #[test]
    fn wait_forever_is_max_u64() {
        assert_eq!(WAIT_FOREVER, u64::MAX);
    }

    #[test]
    fn signal_record_roundtrip_via_ptr_read() {
        // Verify that the ptr::read pattern used in wait_signal works
        // correctly by simulating what the kernel writes.
        let original = ProcessSignalRecord::new(SIGTERM, 42, 0xdead);
        let size = core::mem::size_of::<ProcessSignalRecord>();
        let mut buf = vec![0u8; size];

        // Write the record into the buffer as the kernel would.
        unsafe {
            core::ptr::write(buf.as_mut_ptr().cast(), original);
        }

        // Read it back as wait_signal does.
        let restored: ProcessSignalRecord = unsafe { core::ptr::read(buf.as_ptr().cast()) };
        assert_eq!(restored, original);
    }

    #[test]
    fn signal_mask_set_and_get_returns_zero_without_scheduler() {
        // Without a running process, set_signal_mask returns the default (0).
        let old = set_signal_mask(0);
        assert_eq!(old, 0);
    }

    #[test]
    fn block_unblock_signal_does_not_panic() {
        // These should not panic even without a running process.
        block_signal(SIGINT);
        unblock_signal(SIGINT);
    }

    #[test]
    fn send_signal_without_scheduler_returns_err() {
        // Without a running scheduler, send_signal should return an error,
        // not panic.
        let result = send_signal(1, SIGTERM, 0);
        assert!(result.is_err());
    }
}
