//! src/kernel/memory/fault_profiler.rs
//!
//! Kernel fault/exception counters, gated behind `cfg(feature =
//! "fault_profiler")`. When the feature is disabled, every method is a no-op
//! and `FaultProfiler` is a zero-sized type so the field in `MemoryManager`
//! costs zero bytes.
//!
//! Uses `AtomicU64` with `Relaxed` ordering to avoid lock contention on the
//! exception hot paths.

use core::fmt;
#[cfg(feature = "fault_profiler")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "fault_profiler")]
use core::sync::atomic::Ordering;

/// Point-in-time snapshot of all fault profiler counters.
/// Always available even when profiling is compiled out (returns all zeros).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultProfilerSnapshot {
    // ─── fault type counters ───
    pub faults_total: u64,
    pub page_faults_total: u64,
    pub page_faults_user: u64,
    pub page_faults_kernel: u64,
    pub page_faults_not_present: u64,
    pub page_faults_protection_violation: u64,
    /// Page faults resolved by demand-paging (lazy allocation).
    pub page_faults_demand_paged: u64,
    /// Page faults resolved by copy-on-write.
    pub page_faults_cow: u64,
    pub double_faults_total: u64,
    pub invalid_opcode_total: u64,
    pub general_protection_total: u64,
    pub device_not_available_total: u64,
    pub other_exceptions_total: u64,
    // ─── outcome counters ───
    pub faults_delivered_to_handler: u64,
    pub faults_no_handler: u64,
    pub faults_terminated: u64,
    pub faults_kernel_fatal: u64,
}

/// Kernel fault profiler.  When `feature = "fault_profiler"` is disabled
/// this is a zero-sized type and every method compiles to a no-op.
#[derive(Default)]
pub struct FaultProfiler {
    #[cfg(feature = "fault_profiler")]
    inner: FaultProfilerInner,
}

#[cfg(feature = "fault_profiler")]
#[derive(Default)]
struct FaultProfilerInner {
    faults_total: AtomicU64,
    page_faults_total: AtomicU64,
    page_faults_user: AtomicU64,
    page_faults_kernel: AtomicU64,
    page_faults_not_present: AtomicU64,
    page_faults_protection_violation: AtomicU64,
    page_faults_demand_paged: AtomicU64,
    page_faults_cow: AtomicU64,
    double_faults_total: AtomicU64,
    invalid_opcode_total: AtomicU64,
    general_protection_total: AtomicU64,
    device_not_available_total: AtomicU64,
    other_exceptions_total: AtomicU64,
    faults_delivered_to_handler: AtomicU64,
    faults_no_handler: AtomicU64,
    faults_terminated: AtomicU64,
    faults_kernel_fatal: AtomicU64,
}

impl FaultProfiler {
    /// Create a new profiler with all counters at zero.
    pub const fn new() -> Self {
        #[cfg(feature = "fault_profiler")]
        {
            Self {
                inner: FaultProfilerInner {
                    faults_total: AtomicU64::new(0),
                    page_faults_total: AtomicU64::new(0),
                    page_faults_user: AtomicU64::new(0),
                    page_faults_kernel: AtomicU64::new(0),
                    page_faults_not_present: AtomicU64::new(0),
                    page_faults_protection_violation: AtomicU64::new(0),
                    page_faults_demand_paged: AtomicU64::new(0),
                    page_faults_cow: AtomicU64::new(0),
                    double_faults_total: AtomicU64::new(0),
                    invalid_opcode_total: AtomicU64::new(0),
                    general_protection_total: AtomicU64::new(0),
                    device_not_available_total: AtomicU64::new(0),
                    other_exceptions_total: AtomicU64::new(0),
                    faults_delivered_to_handler: AtomicU64::new(0),
                    faults_no_handler: AtomicU64::new(0),
                    faults_terminated: AtomicU64::new(0),
                    faults_kernel_fatal: AtomicU64::new(0),
                },
            }
        }
        #[cfg(not(feature = "fault_profiler"))]
        {
            Self {}
        }
    }

    /// Return a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> FaultProfilerSnapshot {
        #[cfg(feature = "fault_profiler")]
        {
            FaultProfilerSnapshot {
                faults_total: self.inner.faults_total.load(Ordering::Relaxed),
                page_faults_total: self.inner.page_faults_total.load(Ordering::Relaxed),
                page_faults_user: self.inner.page_faults_user.load(Ordering::Relaxed),
                page_faults_kernel: self.inner.page_faults_kernel.load(Ordering::Relaxed),
                page_faults_not_present: self.inner.page_faults_not_present.load(Ordering::Relaxed),
                page_faults_protection_violation: self
                    .inner
                    .page_faults_protection_violation
                    .load(Ordering::Relaxed),
                page_faults_demand_paged: self
                    .inner
                    .page_faults_demand_paged
                    .load(Ordering::Relaxed),
                page_faults_cow: self.inner.page_faults_cow.load(Ordering::Relaxed),
                double_faults_total: self.inner.double_faults_total.load(Ordering::Relaxed),
                invalid_opcode_total: self.inner.invalid_opcode_total.load(Ordering::Relaxed),
                general_protection_total: self
                    .inner
                    .general_protection_total
                    .load(Ordering::Relaxed),
                device_not_available_total: self
                    .inner
                    .device_not_available_total
                    .load(Ordering::Relaxed),
                other_exceptions_total: self.inner.other_exceptions_total.load(Ordering::Relaxed),
                faults_delivered_to_handler: self
                    .inner
                    .faults_delivered_to_handler
                    .load(Ordering::Relaxed),
                faults_no_handler: self.inner.faults_no_handler.load(Ordering::Relaxed),
                faults_terminated: self.inner.faults_terminated.load(Ordering::Relaxed),
                faults_kernel_fatal: self.inner.faults_kernel_fatal.load(Ordering::Relaxed),
            }
        }
        #[cfg(not(feature = "fault_profiler"))]
        {
            FaultProfilerSnapshot::default()
        }
    }

    // ─── fault type counters ───

    #[inline]
    pub fn inc_faults_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.faults_total.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.page_faults_total.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_user(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.page_faults_user.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_kernel(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .page_faults_kernel
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_not_present(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .page_faults_not_present
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_protection_violation(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .page_faults_protection_violation
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_demand_paged(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .page_faults_demand_paged
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_faults_cow(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.page_faults_cow.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_double_faults_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .double_faults_total
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_invalid_opcode_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .invalid_opcode_total
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_general_protection_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .general_protection_total
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_device_not_available_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .device_not_available_total
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_other_exceptions_total(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .other_exceptions_total
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    // ─── outcome counters ───

    #[inline]
    pub fn inc_faults_delivered_to_handler(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .faults_delivered_to_handler
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_faults_no_handler(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.faults_no_handler.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_faults_terminated(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner.faults_terminated.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_faults_kernel_fatal(&self) {
        #[cfg(feature = "fault_profiler")]
        self.inner
            .faults_kernel_fatal
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "fault_profiler"))]
        let _ = self;
    }
}

impl fmt::Debug for FaultProfiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FaultProfiler")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_profiler_snapshot_defaults_to_zero() {
        let profiler = FaultProfiler::new();
        let snapshot = profiler.snapshot();
        assert_eq!(snapshot, FaultProfilerSnapshot::default());
    }

    #[test]
    #[cfg(feature = "fault_profiler")]
    fn fault_profiler_increments_faults_total() {
        let profiler = FaultProfiler::new();
        profiler.inc_faults_total();
        profiler.inc_faults_total();
        let snapshot = profiler.snapshot();
        assert_eq!(snapshot.faults_total, 2);
    }

    #[test]
    #[cfg(feature = "fault_profiler")]
    fn fault_profiler_counts_page_faults_by_type() {
        let profiler = FaultProfiler::new();
        profiler.inc_page_faults_total();
        profiler.inc_page_faults_user();
        profiler.inc_page_faults_not_present();
        profiler.inc_page_faults_protection_violation();

        let snapshot = profiler.snapshot();
        assert_eq!(snapshot.page_faults_total, 1);
        assert_eq!(snapshot.page_faults_user, 1);
        assert_eq!(snapshot.page_faults_kernel, 0);
        assert_eq!(snapshot.page_faults_not_present, 1);
        assert_eq!(snapshot.page_faults_protection_violation, 1);
    }

    #[test]
    #[cfg(feature = "fault_profiler")]
    fn fault_profiler_counts_delivery_outcomes() {
        let profiler = FaultProfiler::new();
        profiler.inc_faults_delivered_to_handler();
        profiler.inc_faults_delivered_to_handler();
        profiler.inc_faults_no_handler();
        profiler.inc_faults_terminated();
        profiler.inc_faults_kernel_fatal();

        let snapshot = profiler.snapshot();
        assert_eq!(snapshot.faults_delivered_to_handler, 2);
        assert_eq!(snapshot.faults_no_handler, 1);
        assert_eq!(snapshot.faults_terminated, 1);
        assert_eq!(snapshot.faults_kernel_fatal, 1);
    }

    #[test]
    #[cfg(feature = "fault_profiler")]
    fn fault_profiler_counts_exception_types() {
        let profiler = FaultProfiler::new();
        profiler.inc_double_faults_total();
        profiler.inc_invalid_opcode_total();
        profiler.inc_invalid_opcode_total();
        profiler.inc_general_protection_total();
        profiler.inc_device_not_available_total();
        profiler.inc_other_exceptions_total();

        let snapshot = profiler.snapshot();
        assert_eq!(snapshot.double_faults_total, 1);
        assert_eq!(snapshot.invalid_opcode_total, 2);
        assert_eq!(snapshot.general_protection_total, 1);
        assert_eq!(snapshot.device_not_available_total, 1);
        assert_eq!(snapshot.other_exceptions_total, 1);
    }

    #[test]
    #[cfg(feature = "fault_profiler")]
    fn fault_profiler_snapshot_includes_all_fields() {
        let profiler = FaultProfiler::new();
        profiler.inc_faults_total();
        profiler.inc_page_faults_total();
        profiler.inc_page_faults_kernel();

        let snapshot = profiler.snapshot();
        // Verify known non-zero fields
        assert_eq!(snapshot.faults_total, 1);
        assert_eq!(snapshot.page_faults_total, 1);
        assert_eq!(snapshot.page_faults_kernel, 1);
        // Spot-check a few zero fields to ensure they are present
        assert_eq!(snapshot.faults_delivered_to_handler, 0);
        assert_eq!(snapshot.faults_terminated, 0);
        assert_eq!(snapshot.other_exceptions_total, 0);
    }
}
