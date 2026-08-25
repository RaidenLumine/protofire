//! src/kernel/fs/filesystem/profiler.rs
//!
//! Filesystem operation counters, gated behind `cfg(feature = "fs_profiler")`.
//! When the feature is disabled, every method is a no-op and `FsProfiler` is
//! a zero-sized type so the field in `SimpleFs` costs zero bytes.
//!
//! Uses `AtomicU64` with `Relaxed` ordering to avoid lock contention with the
//! filesystem's `state: Mutex<SimpleFsState>` on the hot path.

use core::fmt;
#[cfg(feature = "fs_profiler")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "fs_profiler")]
use core::sync::atomic::Ordering;

/// Point-in-time snapshot of all filesystem profiler counters.
/// Always available even when profiling is compiled out (returns all zeros).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsProfilerSnapshot {
    pub lookups: u64,
    pub reads: u64,
    pub writes: u64,
    pub creates: u64,
    pub deletes: u64,
    pub renames: u64,
    pub transactions: u64,
    pub metadata_flushes: u64,
    /// Cumulative profiler tick events, usable as a relative latency proxy.
    pub elapsed_ticks: u64,
}

/// Filesystem profiler.  When `feature = "fs_profiler"` is disabled this is
/// a zero-sized type and every method compiles to a no-op.
#[derive(Default)]
pub struct FsProfiler {
    #[cfg(feature = "fs_profiler")]
    inner: FsProfilerInner,
}

#[cfg(feature = "fs_profiler")]
#[derive(Default)]
struct FsProfilerInner {
    lookups: AtomicU64,
    reads: AtomicU64,
    writes: AtomicU64,
    creates: AtomicU64,
    deletes: AtomicU64,
    renames: AtomicU64,
    transactions: AtomicU64,
    metadata_flushes: AtomicU64,
    elapsed_ticks: AtomicU64,
    /// Monotonically increasing tick sequence for relative timing.
    tick_seq: AtomicU64,
}

impl FsProfiler {
    /// Return a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> FsProfilerSnapshot {
        #[cfg(feature = "fs_profiler")]
        {
            FsProfilerSnapshot {
                lookups: self.inner.lookups.load(Ordering::Relaxed),
                reads: self.inner.reads.load(Ordering::Relaxed),
                writes: self.inner.writes.load(Ordering::Relaxed),
                creates: self.inner.creates.load(Ordering::Relaxed),
                deletes: self.inner.deletes.load(Ordering::Relaxed),
                renames: self.inner.renames.load(Ordering::Relaxed),
                transactions: self.inner.transactions.load(Ordering::Relaxed),
                metadata_flushes: self.inner.metadata_flushes.load(Ordering::Relaxed),
                elapsed_ticks: self.inner.elapsed_ticks.load(Ordering::Relaxed),
            }
        }
        #[cfg(not(feature = "fs_profiler"))]
        {
            FsProfilerSnapshot::default()
        }
    }

    // ─── individual counter incrementers ───

    #[inline]
    pub fn inc_lookups(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.lookups.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_reads(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.reads.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_writes(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.writes.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_creates(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.creates.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_deletes(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.deletes.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_renames(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.renames.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_transactions(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.transactions.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_metadata_flushes(&self) {
        #[cfg(feature = "fs_profiler")]
        self.inner.metadata_flushes.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fs_profiler"))]
        let _ = self;
    }

    // ─── tick-based relative timing ───

    /// Return a monotonically increasing tick value for relative latency
    /// measurement.  Used with [`record_elapsed`] to accumulate a rough
    /// cost-per-operation signal.
    #[inline]
    pub fn tick(&self) -> u64 {
        #[cfg(feature = "fs_profiler")]
        {
            self.inner.tick_seq.fetch_add(1, Ordering::Relaxed)
        }
        #[cfg(not(feature = "fs_profiler"))]
        {
            let _ = self;
            0
        }
    }

    /// Record the number of profiler ticks elapsed since `start_tick`
    /// (obtained from a prior [`tick`] call).
    #[inline]
    pub fn record_elapsed(&self, start_tick: u64) {
        #[cfg(feature = "fs_profiler")]
        {
            let now = self.tick();
            self.inner
                .elapsed_ticks
                .fetch_add(now.wrapping_sub(start_tick), Ordering::Relaxed);
        }
        #[cfg(not(feature = "fs_profiler"))]
        {
            let _ = self;
            let _ = start_tick;
        }
    }
}

impl fmt::Debug for FsProfiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsProfiler")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}
