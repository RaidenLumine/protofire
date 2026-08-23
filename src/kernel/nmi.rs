//! src/kernel/nmi.rs
//! Architecture-neutral non-maskable interrupt handling.
//!
//! A small registry of NMI handlers runs on every NMI-class entry point:
//! - x86_64 vector 2 (NMI)
//! - AArch64 SError and FIQ vectors
//! - RISC-V machine traps (once the kernel is extended to M-mode, or via a
//!   future `smnmi` supervisor-NMI extension; S-mode itself has no
//!   architectural NMI source)
//!
//! A handler returns `true` when it fully serviced the NMI; if none claims
//! it, the architecture layer logs the condition so it is not silently lost.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kernel::irq_stats;
use crate::kernel::sync::Mutex;

/// A handler invoked on every NMI.  Returns `true` if it consumed the NMI.
pub type NmiHandler = fn() -> bool;

/// Maximum number of registered NMI handlers.
pub const MAX_NMI_HANDLERS: usize = 8;

static HANDLERS: Mutex<Vec<NmiHandler>> = Mutex::new(Vec::new());

/// Total NMI-class entries system-wide (mirrors [`irq_stats`] per-CPU cells).
static NMI_COUNT: AtomicU64 = AtomicU64::new(0);

/// Register an NMI handler.
///
/// Fails with [`crate::Error::OutOfMemory`] when the handler table is full.
pub fn register_handler(handler: NmiHandler) -> crate::Result<()> {
    let mut handlers = HANDLERS.lock();
    if handlers.len() >= MAX_NMI_HANDLERS {
        return Err(crate::Error::OutOfMemory);
    }
    handlers.push(handler);
    Ok(())
}

/// Run all registered NMI handlers for the current CPU.
///
/// Records the NMI in [`irq_stats`] *before* running handlers so the
/// profiler sees every NMI even when a handler claims it.  Returns `true`
/// if any handler reported that it serviced the NMI.
pub fn dispatch() -> bool {
    NMI_COUNT.fetch_add(1, Ordering::Relaxed);
    irq_stats::record_nmi();

    // Clone the handler list so a handler can (re)register without
    // deadlocking on the registry lock.
    let handlers = HANDLERS.lock().clone();
    let mut claimed = false;
    for handler in handlers {
        if handler() {
            claimed = true;
        }
    }
    claimed
}

/// Total number of NMI-class entries system-wide.
pub fn count() -> u64 {
    NMI_COUNT.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;

    static CLAIMED: AtomicBool = AtomicBool::new(false);

    fn claiming_handler() -> bool {
        CLAIMED.store(true, Ordering::Relaxed);
        true
    }

    fn ignoring_handler() -> bool {
        false
    }

    #[test]
    fn dispatch_runs_all_handlers_and_records_nmi() {
        let _guard = irq_stats::test_lock();
        irq_stats::reset_for_test();
        NMI_COUNT.store(0, Ordering::Relaxed);
        HANDLERS.lock().clear();
        CLAIMED.store(false, Ordering::Relaxed);

        register_handler(ignoring_handler).unwrap();
        register_handler(claiming_handler).unwrap();

        assert!(dispatch(), "a claiming handler should report handled");
        assert!(CLAIMED.load(Ordering::Relaxed));
        assert_eq!(irq_stats::total_nmis(), 1);
        assert_eq!(count(), 1);

        HANDLERS.lock().clear();
    }

    #[test]
    fn unclaimed_nmi_returns_false() {
        let _guard = irq_stats::test_lock();
        irq_stats::reset_for_test();
        NMI_COUNT.store(0, Ordering::Relaxed);
        HANDLERS.lock().clear();

        register_handler(ignoring_handler).unwrap();
        assert!(!dispatch());
        assert_eq!(count(), 1);

        HANDLERS.lock().clear();
    }

    #[test]
    fn handler_registry_is_bounded() {
        let _guard = irq_stats::test_lock();
        HANDLERS.lock().clear();

        for _ in 0..MAX_NMI_HANDLERS {
            register_handler(ignoring_handler).unwrap();
        }
        assert_eq!(
            register_handler(ignoring_handler),
            Err(crate::Error::OutOfMemory)
        );

        HANDLERS.lock().clear();
    }
}
