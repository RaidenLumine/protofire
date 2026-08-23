//! src/kernel/memory/heap/wrapper.rs
//! Global allocator wiring, `HeapAllocator` public API, and `heap_model()`
//! accessor.

use super::allocator::KernelGlobalAllocator;

// ─── Global allocator wiring ──────────────────────────────────────────────

#[global_allocator]
#[cfg(target_os = "none")]
static GLOBAL_ALLOCATOR: KernelGlobalAllocator = KernelGlobalAllocator::new();

#[cfg(not(target_os = "none"))]
#[global_allocator]
static HOST_ALLOCATOR: std::alloc::System = std::alloc::System;

#[cfg(not(target_os = "none"))]
pub(crate) static HOST_HEAP_MODEL: KernelGlobalAllocator = KernelGlobalAllocator::new();

#[derive(Clone, Copy, Default)]
pub struct HeapAllocator;

impl HeapAllocator {
    /// Create a new `HeapAllocator` handle.
    ///
    /// The allocator is not initialised until [`init()`] is called.
    pub const fn new() -> Self {
        Self
    }

    /// Initialise the kernel heap allocator.
    ///
    /// Must be called once during kernel initialisation, after the MMU
    /// and page tables are active.  Subsequent calls are idempotent.
    pub fn init(&self) {
        heap_model().ensure_init();
    }

    /// Return the `(start, end)` addresses of the kernel heap region.
    pub fn bounds(&self) -> (usize, usize) {
        heap_model().bounds()
    }

    /// Return the number of free bytes remaining in the kernel heap.
    pub fn remaining(&self) -> usize {
        heap_model().remaining()
    }
}

#[cfg(target_os = "none")]
pub(crate) fn heap_model() -> &'static KernelGlobalAllocator {
    &GLOBAL_ALLOCATOR
}

#[cfg(not(target_os = "none"))]
pub(crate) fn heap_model() -> &'static KernelGlobalAllocator {
    &HOST_HEAP_MODEL
}

/// Verify the integrity of the kernel heap. Returns a human-readable report.
pub fn verify_kernel_heap() {
    heap_model().verify_heap_integrity();
}
