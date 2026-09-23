//! src/arch/thread.rs
//!
//! The per-architecture halves of the thread context and the user-exception
//! plumbing.
//!
//! `src/arch/<arch>/thread.rs` holds the architecture's own *data* — the saved
//! user context, the handler table, the stack of pending exception frames —
//! and the decisions taken around it.  It does not touch a register; the parts
//! that do are in the same architecture's other modules.
//!
//! The three are pulled in by `#[path]` with the same gate the files used to
//! carry themselves, rather than by declaring the modules inside each
//! architecture's `mod.rs`.  That is not a detail: `src/arch/aarch64/mod.rs` is
//! compiled only for aarch64, while the host test build compiles *all three*
//! halves — kernel code names them under `#[cfg(any(target_arch = "...",
//! test))]` and the tests drive the shared logic against every architecture's
//! shape.  `crate::arch::fdt` is included the same way, for the same reason.

#[cfg(any(target_arch = "aarch64", test))]
#[path = "aarch64/thread.rs"]
mod aarch64_context;
#[cfg(any(target_arch = "riscv64", test))]
#[path = "riscv64/thread.rs"]
mod riscv64_context;
#[cfg(target_arch = "x86_64")]
#[path = "x86_64/thread.rs"]
mod x86_64_context;

#[cfg(any(target_arch = "aarch64", test))]
pub use aarch64_context::*;
#[cfg(any(target_arch = "riscv64", test))]
pub use riscv64_context::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64_context::*;
