//! src/kernel/memory/heap/mod.rs
//!
//! Kernel heap allocator and global allocation wiring using TLSF for O(1)
//! allocation.

pub(crate) mod allocator;
pub(crate) mod tlsf;
pub(crate) mod wrapper;

#[cfg(test)]
mod tests;

pub use allocator::KernelGlobalAllocator;
pub(crate) use wrapper::heap_model;
pub use wrapper::{verify_kernel_heap, HeapAllocator};
