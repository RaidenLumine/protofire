//! src/kernel/maintenance.rs
//!
//! Deferred kernel maintenance.
//!
//! Two periodic jobs used to run straight from the timer tick: block-cache
//! write-back and audit persistence.  Both do filesystem work — they take the
//! global filesystem lock, walk the mount table, and write to a block device —
//! so the kernel was issuing disk I/O from inside an interrupt handler, with
//! interrupts masked for its whole duration.  The clock stopped on that CPU,
//! preemption stopped with it, and any other CPU that wanted the filesystem
//! lock spun for the length of a flush with its own interrupts masked too.
//!
//! The tick now does nothing but set a flag.  This module owns those flags and
//! the sleeping thread that drains them, so the work happens in ordinary
//! thread context where blocking, preemption and interrupts all still work.
//!
//! The flags are deliberately latches rather than counters: if the thread is
//! busy, several due periods collapse into one flush, which is what you want
//! from a job whose only purpose is to stop dirty data accumulating.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// Name of the kernel thread that performs deferred maintenance.
pub const MAINTENANCE_THREAD_NAME: &str = "kernel-maintenance";

/// How often the maintenance thread wakes to look for work, in scheduler
/// ticks.  This bounds the delay between a job becoming due and running; the
/// jobs themselves are periodic at coarser intervals, so a short poll costs
/// nothing beyond a parked thread waking up.
pub const MAINTENANCE_POLL_TICKS: u64 = 25;

/// Set by the timer tick when aged dirty blocks are due for write-back.
static BLOCK_CACHE_WRITE_BACK_DUE: AtomicBool = AtomicBool::new(false);

/// Set by the timer tick when the audit ring buffer is due for persistence.
static AUDIT_PERSIST_DUE: AtomicBool = AtomicBool::new(false);

/// Ask for aged dirty blocks to be written back.
///
/// Called from the timer interrupt, so this stays a single atomic store: no
/// lock, no allocation, no device access.
pub(crate) fn request_block_cache_write_back() {
    BLOCK_CACHE_WRITE_BACK_DUE.store(true, Ordering::Release);
}

/// Ask for the audit ring buffer to be persisted.
///
/// Same interrupt-safety contract as
/// [`request_block_cache_write_back`].
pub(crate) fn request_audit_persist() {
    AUDIT_PERSIST_DUE.store(true, Ordering::Release);
}

/// Take the pending write-back request, clearing it.
///
/// Only [`maintenance_entry`] drains a latch on a real boot, and that thread
/// does not exist on the host, so this is unused there.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn take_block_cache_write_back() -> bool {
    BLOCK_CACHE_WRITE_BACK_DUE.swap(false, Ordering::AcqRel)
}

/// Take the pending audit-persist request, clearing it.
///
/// Same host-side reasoning as [`take_block_cache_write_back`].
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn take_audit_persist() -> bool {
    AUDIT_PERSIST_DUE.swap(false, Ordering::AcqRel)
}

/// Forget every pending request.
///
/// The latches are process-global, so a host test that sets one and does not
/// drain it would otherwise change what the next test observes.
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    BLOCK_CACHE_WRITE_BACK_DUE.store(false, Ordering::Release);
    AUDIT_PERSIST_DUE.store(false, Ordering::Release);
}

/// The deferred-maintenance thread.
///
/// Runs as a sleeping kernel thread rather than from the idle loop, for the
/// same reason the service supervisor does: the idle thread is only chosen
/// when nothing else is runnable, so a busy system can keep maintenance from
/// running at all.  Sleeping on the scheduler's own wait queue guarantees it a
/// turn without costing anything between passes.
#[cfg(target_os = "none")]
pub(crate) fn maintenance_entry() {
    let mut passes: u64 = 0;
    /// Cycles observed at the first pass, kept until the rate can be derived.
    #[cfg(feature = "fs_lock_timing")]
    let mut calibration_start: Option<u64> = None;

    loop {
        crate::kernel::process::sleep_current(MAINTENANCE_POLL_TICKS);
        passes += 1;

        // Liveness: this thread is one of two independent heartbeats, so a
        // stalled log can be read as "the machine stopped" or "this thread
        // stopped" rather than both looking the same.
        let now_tick = crate::kernel::process::Scheduler::global()
            .map(|scheduler| scheduler.current_tick())
            .unwrap_or(0);
        crate::kernel::heartbeat::beat("maintenance", passes, now_tick);

        // Both jobs fail softly: a flush that cannot complete is retried on the
        // next due period, and the latch has already been cleared, so a
        // persistently failing device cannot spin this thread.
        if take_block_cache_write_back() {
            let _ = crate::kernel::fs::sync_global_caches_aged(
                crate::kernel::fs::block_cache::WRITE_BACK_AGE_TICKS,
            );
        }

        if take_audit_persist() {
            crate::kernel::audit::persist::persist_to_file();
        }

        // Opt-in, like the other profilers in this tree: the counters are
        // always maintained (they are plain atomics, and the measurement only
        // means something if it is taken on an unmodified boot), but printing
        // is behind `fs_lock_timing` so a default boot stays quiet.
        #[cfg(feature = "fs_lock_timing")]
        {
            // Derive the counter rate from this thread's own poll cadence
            // rather than sleeping for it.  An extra sleep here would be a
            // scheduling perturbation added purely for bookkeeping, and the
            // interval between two passes is already a known number of ticks.
            let now = crate::arch::timer::monotonic_cycles();
            match calibration_start {
                None => calibration_start = Some(now),
                Some(start) if passes == CALIBRATION_PASSES => {
                    if crate::arch::timer::cycles_per_second().is_none() {
                        crate::arch::timer::record_cycles_per_tick(
                            now.wrapping_sub(start),
                            passes * MAINTENANCE_POLL_TICKS,
                        );
                    }
                }
                Some(_) => {}
            }

            if passes.is_multiple_of(LOCK_TIMING_REPORT_PASSES) {
                crate::kernel::fs::lock_timing::report();
            }
        }
    }
}

/// Passes to sample the cycle counter across before deriving its rate.  Four
/// passes of [`MAINTENANCE_POLL_TICKS`] is one second at the programmed 100 Hz
/// tick: long enough for the ratio to be accurate, and it costs nothing beyond
/// the polling the thread already does.
#[cfg(all(target_os = "none", feature = "fs_lock_timing"))]
const CALIBRATION_PASSES: u64 = 4;

/// Passes between lock-timing reports.  Four passes a second, so this is
/// roughly every ten seconds.
#[cfg(all(target_os = "none", feature = "fs_lock_timing"))]
const LOCK_TIMING_REPORT_PASSES: u64 = 40;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_observed_once_and_then_cleared() {
        reset_for_tests();
        assert!(!take_block_cache_write_back());

        request_block_cache_write_back();
        assert!(take_block_cache_write_back());
        // The latch is one-shot: draining it must leave nothing behind, or the
        // thread would flush again on every pass forever.
        assert!(!take_block_cache_write_back());
    }

    #[test]
    fn repeated_requests_coalesce_into_one() {
        reset_for_tests();
        for _ in 0..8 {
            request_block_cache_write_back();
        }

        assert!(take_block_cache_write_back());
        assert!(!take_block_cache_write_back());
    }

    #[test]
    fn each_job_has_its_own_latch() {
        reset_for_tests();

        request_audit_persist();
        assert!(!take_block_cache_write_back());
        assert!(take_audit_persist());
        assert!(!take_audit_persist());

        request_block_cache_write_back();
        assert!(!take_audit_persist());
        assert!(take_block_cache_write_back());
    }

    #[test]
    fn reset_clears_both_latches() {
        reset_for_tests();
        request_block_cache_write_back();
        request_audit_persist();

        reset_for_tests();

        assert!(!take_block_cache_write_back());
        assert!(!take_audit_persist());
    }
}
