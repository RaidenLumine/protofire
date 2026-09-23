//! src/kernel/process/thread/arch.rs
//!
//! The per-architecture halves of the thread context and the user-exception
//! plumbing, whatever the architecture calls them.
//!
//! `arch_x86_64.rs`, `arch_aarch64.rs` and `arch_riscv64.rs` hold the
//! architecture-specific *data* — the saved user context, the handler table,
//! the stack of pending exception frames — and the decisions taken around it.
//! None of it touches a register, which is why it lives here rather than under
//! `src/arch/`: the host test build compiles all three, and the tests exercise
//! the shared logic against every architecture's shape.  Code that does touch
//! registers is in `crate::arch`.
//!
//! This module is the one place that says which of them is in scope.  Without
//! it every consumer of those names carried its own `#[cfg(target_arch = ...)]`
//! per import, and the same gate was written out two dozen times.

#[cfg(any(target_arch = "aarch64", test))]
pub use super::arch_aarch64::*;
#[cfg(any(target_arch = "riscv64", test))]
pub use super::arch_riscv64::*;
#[cfg(target_arch = "x86_64")]
pub use super::arch_x86_64::*;
