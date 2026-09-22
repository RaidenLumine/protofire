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
// What the kernel maps, derived once and published.  The two architectures
// that consume it are x86_64 and aarch64; riscv64 derives its own mapping and
// has no reader yet, so the module is compiled where something reads it — the
// two bare-metal targets that do, and the host tests that exercise it.  When
// riscv64 grows a reader, its name joins them.
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    test
))]
pub(crate) mod map_facts;
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
#[cfg(target_arch = "x86_64")]
pub(crate) use global::held_by_current_cpu;
pub use global::install_global_for_tests;
pub(crate) use global::install_global_unchecked;
#[cfg(target_arch = "x86_64")]
pub(crate) use global::try_global_mut;
#[cfg(test)]
pub(crate) use global::uninstall_global_for_tests;
pub use manager::MemoryManager;
pub use paging::AdviceHint;
pub use paging::MappingKind;
pub use paging::PagePermissions;
