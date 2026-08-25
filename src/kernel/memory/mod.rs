//! src/kernel/memory/mod.rs
//!
//! Memory manager coordinating frame allocation, heap setup, and virtual
//! mappings.

pub mod alloc_profiler;
pub(crate) mod arch;
pub mod compressed;
pub mod diagnostics;
pub mod dma;
pub mod fault_profiler;
pub mod frame;
pub(crate) mod global;
pub mod heap;
pub(crate) mod manager;
pub mod paging;
pub mod swap;
#[cfg(test)]
mod tests;

pub use arch::{detected_memory, store_detected_memory};
pub use diagnostics::*;
pub use dma::{phys_addr_of, DmaBuffer};
pub(crate) use global::{global, global_mut, install_global_unchecked};
pub use global::{global_mut_for_tests, install_global_for_tests};
pub use manager::MemoryManager;
pub use paging::{AdviceHint, MappingKind, PagePermissions};
