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

pub use arch::detected_memory;
pub use arch::store_detected_memory;
pub use diagnostics::*;
pub use dma::phys_addr_of;
pub use dma::DmaBuffer;
pub(crate) use global::global;
pub(crate) use global::global_mut;
pub use global::global_mut_for_tests;
pub use global::install_global_for_tests;
pub(crate) use global::install_global_unchecked;
pub use manager::MemoryManager;
pub use paging::AdviceHint;
pub use paging::MappingKind;
pub use paging::PagePermissions;
