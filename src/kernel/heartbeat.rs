//! src/kernel/heartbeat.rs
//!
//! Liveness heartbeat for diagnosing a stalled machine.
//!
//! When a kernel stops making progress, the log simply ends, and the end of a
//! log cannot say *why*: a machine wedged with interrupts masked, a runnable
//! thread that never gets scheduled, and a single blocked thread all look the
//! same.  They call for completely different investigations.
//!
//! A heartbeat separates them.  Several independent kernel threads call
//! [`beat`] on their own cadence; each line reports the scheduler tick, so:
//!
//! - **Every heartbeat stops.**  The scheduler stopped running threads, which
//!   points at interrupts being masked somewhere or the timer not being
//!   serviced.
//! - **One heartbeat stops, the others continue.**  The scheduler is fine and
//!   one thread is blocked — and the surviving heartbeats name the threads that
//!   are still alive.
//!
//! Off by default: a heartbeat is a diagnostic, and a shipped kernel should
//! not narrate its own liveness.  Enable it with the `liveness_heartbeat`
//! feature, which the SMP runtime check does.

// The counters only exist when the heartbeat is compiled in; with the feature
// off, `beat` is a no-op and has nothing to keep.
#[cfg(feature = "liveness_heartbeat")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "liveness_heartbeat")]
use core::sync::atomic::Ordering;

/// Passes between heartbeats, counted in the polling threads' own loop
/// iterations.  At the 25-tick poll the maintenance and supervisor threads
/// use, sixteen passes is roughly four seconds.
#[cfg(feature = "liveness_heartbeat")]
pub(crate) const HEARTBEAT_PERIOD_PASSES: u64 = 16;

/// Total heartbeats emitted, across every source.  Reported in each line so
/// that a run's liveness can be judged from the last line alone.
#[cfg(feature = "liveness_heartbeat")]
static HEARTBEATS: AtomicU64 = AtomicU64::new(0);

/// Record one pass of a polling thread, and print a heartbeat when due.
///
/// `source` names the calling thread; `passes` is that thread's own counter;
/// `now_tick` is the scheduler tick, which is what makes the line useful — a
/// heartbeat whose ticks are advancing proves the timer is still being
/// serviced, whatever else has stopped.
#[inline]
pub(crate) fn beat(source: &str, passes: u64, now_tick: u64) {
    #[cfg(feature = "liveness_heartbeat")]
    {
        if passes == 0 || !passes.is_multiple_of(HEARTBEAT_PERIOD_PASSES) {
            return;
        }

        let beat_number = HEARTBEATS.fetch_add(1, Ordering::Relaxed) + 1;
        let processes = crate::kernel::process::Scheduler::global()
            .map(|scheduler| scheduler.process_count())
            .unwrap_or(0);

        crate::println!(
            "[hb    ] {} beat={} tick={} passes={} processes={}",
            source,
            beat_number,
            now_tick,
            passes,
            processes
        );
    }

    #[cfg(not(feature = "liveness_heartbeat"))]
    {
        let _ = (source, passes, now_tick);
    }
}
