//! src/kernel/memory/alloc_profiler.rs
//!
//! Kernel allocator operation counters, gated behind `cfg(feature = "alloc_profiler")`.
//! When the feature is disabled, every method is a no-op and `AllocProfiler` is
//! a zero-sized type so fields in allocator structs cost zero bytes.
//!
//! Uses `AtomicU64` with `Relaxed` ordering to avoid lock contention on the
//! allocation hot paths.

use core::fmt;
#[cfg(feature = "alloc_profiler")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Point-in-time snapshot of all allocator profiler counters.
/// Always available even when profiling is compiled out (returns all zeros).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocProfilerSnapshot {
    // Heap counters
    pub heap_allocs: u64,
    pub heap_frees: u64,
    pub heap_alloc_scan_steps: u64,
    pub heap_bytes_allocated: u64,
    pub heap_bytes_freed: u64,
    // Frame counters
    pub frame_allocs: u64,
    pub frame_frees: u64,
    pub frame_recycled: u64,
    pub frame_bump_allocs: u64,
    pub frame_zero_bytes: u64,
    // Page table counters
    pub page_table_maps: u64,
    pub page_table_unmaps: u64,
    pub page_table_lookups: u64,
}

/// Kernel allocator profiler.  When `feature = "alloc_profiler"` is disabled
/// this is a zero-sized type and every method compiles to a no-op.
#[derive(Default)]
pub struct AllocProfiler {
    #[cfg(feature = "alloc_profiler")]
    inner: AllocProfilerInner,
}

#[cfg(feature = "alloc_profiler")]
#[derive(Default)]
struct AllocProfilerInner {
    heap_allocs: AtomicU64,
    heap_frees: AtomicU64,
    heap_alloc_scan_steps: AtomicU64,
    heap_bytes_allocated: AtomicU64,
    heap_bytes_freed: AtomicU64,
    frame_allocs: AtomicU64,
    frame_frees: AtomicU64,
    frame_recycled: AtomicU64,
    frame_bump_allocs: AtomicU64,
    frame_zero_bytes: AtomicU64,
    page_table_maps: AtomicU64,
    page_table_unmaps: AtomicU64,
    page_table_lookups: AtomicU64,
}

impl AllocProfiler {
    /// Create a new profiler with all counters at zero.
    pub const fn new() -> Self {
        #[cfg(feature = "alloc_profiler")]
        {
            Self {
                inner: AllocProfilerInner {
                    heap_allocs: AtomicU64::new(0),
                    heap_frees: AtomicU64::new(0),
                    heap_alloc_scan_steps: AtomicU64::new(0),
                    heap_bytes_allocated: AtomicU64::new(0),
                    heap_bytes_freed: AtomicU64::new(0),
                    frame_allocs: AtomicU64::new(0),
                    frame_frees: AtomicU64::new(0),
                    frame_recycled: AtomicU64::new(0),
                    frame_bump_allocs: AtomicU64::new(0),
                    frame_zero_bytes: AtomicU64::new(0),
                    page_table_maps: AtomicU64::new(0),
                    page_table_unmaps: AtomicU64::new(0),
                    page_table_lookups: AtomicU64::new(0),
                },
            }
        }
        #[cfg(not(feature = "alloc_profiler"))]
        {
            Self {}
        }
    }

    /// Return a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> AllocProfilerSnapshot {
        #[cfg(feature = "alloc_profiler")]
        {
            AllocProfilerSnapshot {
                heap_allocs: self.inner.heap_allocs.load(Ordering::Relaxed),
                heap_frees: self.inner.heap_frees.load(Ordering::Relaxed),
                heap_alloc_scan_steps: self.inner.heap_alloc_scan_steps.load(Ordering::Relaxed),
                heap_bytes_allocated: self.inner.heap_bytes_allocated.load(Ordering::Relaxed),
                heap_bytes_freed: self.inner.heap_bytes_freed.load(Ordering::Relaxed),
                frame_allocs: self.inner.frame_allocs.load(Ordering::Relaxed),
                frame_frees: self.inner.frame_frees.load(Ordering::Relaxed),
                frame_recycled: self.inner.frame_recycled.load(Ordering::Relaxed),
                frame_bump_allocs: self.inner.frame_bump_allocs.load(Ordering::Relaxed),
                frame_zero_bytes: self.inner.frame_zero_bytes.load(Ordering::Relaxed),
                page_table_maps: self.inner.page_table_maps.load(Ordering::Relaxed),
                page_table_unmaps: self.inner.page_table_unmaps.load(Ordering::Relaxed),
                page_table_lookups: self.inner.page_table_lookups.load(Ordering::Relaxed),
            }
        }
        #[cfg(not(feature = "alloc_profiler"))]
        {
            AllocProfilerSnapshot::default()
        }
    }

    // ─── heap counters ───

    #[inline]
    pub fn inc_heap_allocs(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.heap_allocs.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_heap_frees(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.heap_frees.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn add_heap_alloc_scan_steps(&self, steps: u64) {
        #[cfg(feature = "alloc_profiler")]
        self.inner
            .heap_alloc_scan_steps
            .fetch_add(steps, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = (self, steps);
    }

    #[inline]
    pub fn add_heap_bytes_allocated(&self, bytes: u64) {
        #[cfg(feature = "alloc_profiler")]
        self.inner
            .heap_bytes_allocated
            .fetch_add(bytes, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = (self, bytes);
    }

    #[inline]
    pub fn add_heap_bytes_freed(&self, bytes: u64) {
        #[cfg(feature = "alloc_profiler")]
        self.inner
            .heap_bytes_freed
            .fetch_add(bytes, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = (self, bytes);
    }

    // ─── frame counters ───

    #[inline]
    pub fn inc_frame_allocs(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.frame_allocs.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_frame_frees(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.frame_frees.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_frame_recycled(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.frame_recycled.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_frame_bump_allocs(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.frame_bump_allocs.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn add_frame_zero_bytes(&self, bytes: u64) {
        #[cfg(feature = "alloc_profiler")]
        self.inner
            .frame_zero_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = (self, bytes);
    }

    // ─── page table counters ───

    #[inline]
    pub fn inc_page_table_maps(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.page_table_maps.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_table_unmaps(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner.page_table_unmaps.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }

    #[inline]
    pub fn inc_page_table_lookups(&self) {
        #[cfg(feature = "alloc_profiler")]
        self.inner
            .page_table_lookups
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "alloc_profiler"))]
        let _ = self;
    }
}

impl fmt::Debug for AllocProfiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllocProfiler")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}
