//! src/kernel/audit/mod.rs
//!
//! Kernel audit subsystem: event emission and ring buffer.
//! Audit subsystem — event logging ring buffer and per-process enable mask.
//!
//! The audit subsystem provides a fixed-size lock-free ring buffer into which
//! kernel components (primarily the syscall dispatcher) emit structured event
//! records.  Each process has an `audit_enable_mask` that gates which event
//! types are logged, keeping overhead at zero when auditing is disabled.

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;

pub mod buffer;
pub mod types;

use buffer::AuditBuffer;

// ── Global audit buffer ───────────────────────────────────────────────────

static GLOBAL_AUDIT_BUFFER: AtomicPtr<AuditBuffer> = AtomicPtr::new(ptr::null_mut());

/// Install the global audit buffer.  Called once during kernel init.
///
/// # Safety
///
/// The caller must guarantee that `buffer` outlives every future access.
pub unsafe fn install_global(buffer: &'static AuditBuffer) {
    GLOBAL_AUDIT_BUFFER.store(buffer as *const _ as *mut _, Ordering::SeqCst);
}

/// Install a heap-allocated buffer as the global audit ring buffer.
/// Returns `true` if the buffer was installed, `false` if one was already set.
pub fn try_install(buffer: Box<AuditBuffer>) -> bool {
    let raw = Box::into_raw(buffer);
    match GLOBAL_AUDIT_BUFFER.compare_exchange(
        ptr::null_mut(),
        raw,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => true,
        Err(existing) => {
            // Another thread installed a buffer already — drop ours.
            drop(unsafe { Box::from_raw(raw) });
            // Only race if called concurrently; use the existing pointer.
            let _ = existing;
            false
        }
    }
}

/// Return a reference to the global audit buffer, or `None` if not installed.
pub fn global() -> Option<&'static AuditBuffer> {
    let ptr = GLOBAL_AUDIT_BUFFER.load(Ordering::SeqCst);
    unsafe { ptr.as_ref() }
}

/// Initialize the global audit subsystem.  Allocates the ring buffer and
/// stores it as the global singleton.  Safe to call multiple times — the
/// second and subsequent calls are no-ops.
pub fn init() {
    if global().is_some() {
        return;
    }
    let buf = Box::new(AuditBuffer::new());
    try_install(buf);
}

/// Emit an audit record into the global buffer.
/// Returns `false` if the buffer is full or not yet initialised.
pub fn emit_record(record: types::AuditRecord) -> bool {
    global().map(|buffer| buffer.emit(record)).unwrap_or(false)
}

/// Read up to `max` audit records from the global buffer into `records`.
/// Returns the number of records actually copied, or 0 if not initialised.
pub fn read_records(records: &mut [types::AuditRecord]) -> usize {
    global()
        .map(|buffer| buffer.read_events(records))
        .unwrap_or(0)
}
