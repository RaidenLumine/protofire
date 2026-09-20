//! src/kernel/fs/lock_timing.rs
//!
//! Hold-time measurement for the global filesystem lock.
//!
//! ## Why this exists
//!
//! The global lock over `FileSystem` covers the namespace, not the data path:
//! an open `FileHandle` moves bytes without touching it.  The question this
//! module answers is whether the *remaining* holds — syscall-side namespace
//! operations, and the volume repair that scans a whole volume under the lock
//! — are long enough to justify redesigning how mount lifetime is tracked.
//! That is a large change, so it should be driven by a measurement rather than
//! by the shape of the code.
//!
//! ## Design constraints
//!
//! - **It must not perturb what it measures.**  Durations are recorded into
//!   plain atomics; there is no allocation, no nested lock, and no formatting
//!   on the measured path.  A measurement that itself takes the filesystem lock
//!   would change the thing it is looking at.
//! - **It must work before the scheduler and before the heap.**  Boot recovery
//!   runs while the global lock exists and no threads do, so nothing here may
//!   depend on either.
//! - **It must be removable.**  This is a decision aid, not a feature: the
//!   whole module can be deleted without touching the filesystem.
//!
//! ## Reading the numbers
//!
//! Buckets are powers of two in cycles, because cycles are what the counter
//! provides and their rate is not architectural.
//! [`crate::arch::timer::cycles_per_second`] supplies the scale once
//! calibrated; on a 2 GHz part, 16 Ki cycles ≈ 8 µs and 4 Mi cycles ≈ 2 ms.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

/// Number of power-of-two buckets: up to 2^12, 2^16, 2^20, 2^24, 2^28, and
/// everything above.
pub const LOCK_TIMING_BUCKETS: usize = 6;

/// Lowest bucket boundary, in cycles.  Below this a hold is sub-microsecond on
/// any plausible part and not worth resolving further.
const FIRST_BUCKET_SHIFT: u32 = 12;

/// The scan paths whose duration we are deciding about.
///
/// These are deliberately coarse.  The decision is "which class of hold is
/// long", so a handful of named scopes answers it; tagging all ~100 lock sites
/// would cost far more than it tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockScope {
    /// A filesystem syscall: path resolution, open, metadata, directory read.
    /// This is the common case and the one whose distribution matters most.
    SyscallOperation,
    /// A volume check-and-repair, which scans a whole volume under the lock.
    VolumeRepair,
    /// Boot-time recovery, which walks and repairs every mounted volume.
    BootRecovery,
}

impl LockScope {
    /// Every scope, for reporting.
    const ALL: [Self; 3] = [
        Self::SyscallOperation,
        Self::VolumeRepair,
        Self::BootRecovery,
    ];

    /// Return the name used in the report.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyscallOperation => "syscall-op",
            Self::VolumeRepair => "volume-repair",
            Self::BootRecovery => "boot-recovery",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::SyscallOperation => 0,
            Self::VolumeRepair => 1,
            Self::BootRecovery => 2,
        }
    }
}

/// Per-scope counters.  Every field is a plain atomic so that recording costs
/// a fetch-add and never blocks.
struct ScopeCounters {
    holds: AtomicU64,
    total_cycles: AtomicU64,
    max_cycles: AtomicU64,
    buckets: [AtomicU64; LOCK_TIMING_BUCKETS],
}

impl ScopeCounters {
    const fn new() -> Self {
        Self {
            holds: AtomicU64::new(0),
            total_cycles: AtomicU64::new(0),
            max_cycles: AtomicU64::new(0),
            buckets: [const { AtomicU64::new(0) }; LOCK_TIMING_BUCKETS],
        }
    }

    fn record(&self, cycles: u64) {
        self.holds.fetch_add(1, Ordering::Relaxed);
        self.total_cycles.fetch_add(cycles, Ordering::Relaxed);
        self.max_cycles.fetch_max(cycles, Ordering::Relaxed);
        self.buckets[bucket_for(cycles)].fetch_add(1, Ordering::Relaxed);
    }

    fn is_empty(&self) -> bool {
        self.holds.load(Ordering::Relaxed) == 0
    }
}

static SCOPES: [ScopeCounters; 3] = [
    ScopeCounters::new(),
    ScopeCounters::new(),
    ScopeCounters::new(),
];

/// One scope's measured distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeTiming {
    pub scope: LockScope,
    pub holds: u64,
    pub max_cycles: u64,
    pub total_cycles: u64,
    pub buckets: [u64; LOCK_TIMING_BUCKETS],
}

impl ScopeTiming {
    /// Return the mean hold in cycles, or `None` when nothing was recorded.
    pub fn mean_cycles(&self) -> Option<u64> {
        (self.holds > 0).then(|| self.total_cycles / self.holds)
    }
}

/// Run `body`, recording how long it took against `scope`.
///
/// The closure is the natural shape because every measured site holds the
/// filesystem lock for exactly the duration of one operation.
#[inline]
pub fn measure<T>(scope: LockScope, body: impl FnOnce() -> T) -> T {
    let start = crate::arch::timer::monotonic_cycles();
    let result = body();
    let elapsed = crate::arch::timer::monotonic_cycles().wrapping_sub(start);
    SCOPES[scope.index()].record(elapsed);
    result
}

/// Return every scope that has recorded at least one hold.
pub fn snapshot() -> [Option<ScopeTiming>; 3] {
    let mut out = [None; 3];
    for (index, counters) in SCOPES.iter().enumerate() {
        if counters.is_empty() {
            continue;
        }
        let mut buckets = [0_u64; LOCK_TIMING_BUCKETS];
        for (slot, counter) in buckets.iter_mut().zip(counters.buckets.iter()) {
            *slot = counter.load(Ordering::Relaxed);
        }
        out[index] = Some(ScopeTiming {
            scope: LockScope::ALL[index],
            holds: counters.holds.load(Ordering::Relaxed),
            max_cycles: counters.max_cycles.load(Ordering::Relaxed),
            total_cycles: counters.total_cycles.load(Ordering::Relaxed),
            buckets,
        });
    }
    out
}

/// Forget every measurement.
///
/// The counters are process-global, so a host test that records into them
/// would otherwise change what the next test observes.
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    for counters in SCOPES.iter() {
        counters.holds.store(0, Ordering::Relaxed);
        counters.total_cycles.store(0, Ordering::Relaxed);
        counters.max_cycles.store(0, Ordering::Relaxed);
        for bucket in counters.buckets.iter() {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

/// Which bucket `cycles` falls into.
fn bucket_for(cycles: u64) -> usize {
    let mut boundary = 1_u64 << FIRST_BUCKET_SHIFT;
    for index in 0..LOCK_TIMING_BUCKETS {
        if cycles < boundary {
            return index;
        }
        boundary <<= 4;
    }
    LOCK_TIMING_BUCKETS - 1
}

/// Print every recorded distribution, scaled by the calibrated counter rate.
///
/// Called from the maintenance thread, never from a measured scope, so the
/// formatting cannot distort what it reports.
pub fn report() {
    let rate = crate::arch::timer::cycles_per_second();
    if let Some(rate) = rate {
        crate::println!("[fs-lock] cycles/second={}", rate);
    } else {
        crate::println!("[fs-lock] cycles/second=uncalibrated");
    }

    for timing in snapshot().into_iter().flatten() {
        let max_us = scale_to_micros(timing.max_cycles, rate);
        let mean_us = timing
            .mean_cycles()
            .map(|mean| scale_to_micros(mean, rate))
            .unwrap_or(0);
        crate::println!(
            "[fs-lock] {} holds={} mean_us={} max_us={} buckets={:?}",
            timing.scope.as_str(),
            timing.holds,
            mean_us,
            max_us,
            timing.buckets
        );
    }
}

/// Convert `cycles` to microseconds, or to raw cycles when uncalibrated.
fn scale_to_micros(cycles: u64, rate: Option<u64>) -> u64 {
    match rate {
        Some(rate) if rate > 0 => cycles.saturating_mul(1_000_000) / rate,
        _ => cycles,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_span_powers_of_two_from_the_first_boundary() {
        assert_eq!(bucket_for(0), 0);
        assert_eq!(bucket_for((1 << FIRST_BUCKET_SHIFT) - 1), 0);
        assert_eq!(bucket_for(1 << FIRST_BUCKET_SHIFT), 1);
        assert_eq!(bucket_for((1 << (FIRST_BUCKET_SHIFT + 4)) - 1), 1);
        assert_eq!(bucket_for(1 << (FIRST_BUCKET_SHIFT + 4)), 2);
        // Everything at or above the last boundary shares the top bucket.
        assert_eq!(bucket_for(u64::MAX), LOCK_TIMING_BUCKETS - 1);
    }

    #[test]
    fn measure_records_a_hold_in_its_scope() {
        reset_for_tests();

        let value = measure(LockScope::VolumeRepair, || 7_u32);
        assert_eq!(value, 7);

        let recorded = snapshot()[LockScope::VolumeRepair.index()].expect("recorded");
        assert_eq!(recorded.holds, 1);
        assert_eq!(recorded.buckets.iter().sum::<u64>(), 1);
        assert!(recorded.mean_cycles().is_some());
    }

    #[test]
    fn scopes_are_counted_separately() {
        reset_for_tests();

        measure(LockScope::SyscallOperation, || ());
        measure(LockScope::SyscallOperation, || ());
        measure(LockScope::BootRecovery, || ());

        let snapshot = snapshot();
        assert_eq!(
            snapshot[LockScope::SyscallOperation.index()].unwrap().holds,
            2
        );
        assert_eq!(snapshot[LockScope::BootRecovery.index()].unwrap().holds, 1);
        assert!(snapshot[LockScope::VolumeRepair.index()].is_none());
    }

    #[test]
    fn an_unmeasured_scope_reports_nothing() {
        reset_for_tests();
        assert!(snapshot().iter().all(|entry| entry.is_none()));
    }

    #[test]
    fn scaling_is_identity_when_uncalibrated() {
        assert_eq!(scale_to_micros(1234, None), 1234);
        assert_eq!(scale_to_micros(1234, Some(0)), 1234);
        // At 1 MHz, one cycle is one microsecond.
        assert_eq!(scale_to_micros(5, Some(1_000_000)), 5);
        // At 1 GHz, 1000 cycles is one microsecond.
        assert_eq!(scale_to_micros(1000, Some(1_000_000_000)), 1);
    }
}
