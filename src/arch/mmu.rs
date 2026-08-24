//! src/arch/mmu.rs
//!
//! Architecture-neutral MMU facade that dispatches to the active backend.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::mmu::*;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::mmu::*;

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::paging::*;
