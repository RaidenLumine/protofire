//! src/kernel/softirq.rs
//! Software-interrupt ("softirq") mechanism used to defer high-frequency
//! work (timer ticks, IRQ tail processing) out of the hard-interrupt path
//! and into the scheduler loop, where context switching is safe.
//!
//! The design is a small fixed vector table: drivers register a handler per
//! vector during boot, raise the vector from IRQ context via
//! [`raise_softirq`], and the scheduler drains it with [`process_softirqs`]
//! before resuming user code.

use core::sync::atomic::{AtomicU32, Ordering};

/// Number of softirq vectors.
pub const SOFTIRQ_MAX: usize = 8;

/// Bitmask of currently-pending softirq vectors.
static SOFTIRQ_PENDING: AtomicU32 = AtomicU32::new(0);

/// Per-vector softirq handlers.  Mutated only during boot via
/// [`register_softirq`]; read-only once the scheduler starts.
static mut SOFTIRQ_HANDLERS: [Option<fn(u32)>; SOFTIRQ_MAX] = [None; SOFTIRQ_MAX];

/// Register the handler for softirq vector `nr`.
///
/// Called during boot before the scheduler is started.  Out-of-range vectors
/// are silently ignored.
pub fn register_softirq(nr: usize, handler: fn(u32)) {
    if nr < SOFTIRQ_MAX {
        // SAFETY: registration only happens during boot, single-threaded,
        // before any processor can drain softirqs.
        unsafe { SOFTIRQ_HANDLERS[nr] = Some(handler) };
    }
}

/// Raise softirq vector `nr` (idempotent).
///
/// Safe to call from interrupt context; the vector is only processed by
/// [`process_softirqs`] once the scheduler loop gets to it.
pub fn raise_softirq(nr: usize) {
    if nr < SOFTIRQ_MAX {
        SOFTIRQ_PENDING.fetch_or(1u32 << nr, Ordering::Release);
    }
}

/// Whether any softirq is currently pending.
pub fn softirq_pending() -> bool {
    SOFTIRQ_PENDING.load(Ordering::Acquire) != 0
}

/// Drain and dispatch all pending softirq vectors.
///
/// Each handler is called with its vector number and runs with interrupts
/// enabled (the caller must have re-enabled them) so it will not re-enter
/// while it's running (non-reentrant per vector).
pub fn process_softirqs() {
    let pending = SOFTIRQ_PENDING.swap(0, Ordering::Acquire);
    if pending == 0 {
        return;
    }

    // SAFETY: SOFTIRQ_HANDLERS is only mutated during boot (via
    // register_softirq); by the time process_softirqs is called, all
    // handlers are registered and will only be read from this point.
    #[allow(clippy::needless_range_loop)]
    for nr in 0..SOFTIRQ_MAX {
        if pending & (1u32 << nr) != 0 {
            let handler = unsafe { SOFTIRQ_HANDLERS[nr] };
            if let Some(h) = handler {
                h(nr as u32);
            }
        }
    }
}
