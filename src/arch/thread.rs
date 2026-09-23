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

// ── Dispatch over the per-architecture thread state ─────────────────────
//
// `Thread` holds one state object per architecture, so an operation that
// touches "the user-runtime state" is one statement per architecture.  They
// are gathered here, where the answer to "which architectures exist" already
// lives, rather than repeated in the kernel's own code.

use crate::kernel::process::thread::types::ThreadExecutionState;
use crate::kernel::process::thread::types::ThreadUserRuntimeState;
use crate::kernel::process::thread::Thread;
use crate::Result;

/// Drop every architecture's user-runtime state for a thread that is going
/// away.
///
/// Called on termination.  Each architecture clears what it owns: the saved
/// user context, the handler table, the frames a nested delivery left stacked.
/// riscv64 clears its context — it has no handler table — which is the one
/// thing this dispatch fixed: its clear existed but was never called, so a
/// terminated riscv64 thread kept the registers it last held.
pub(crate) fn clear_user_runtime_state(thread: &Thread) {
    #[cfg(any(target_arch = "aarch64", test))]
    thread.aarch64.clear();
    #[cfg(target_arch = "x86_64")]
    thread.x86_64.clear();
    #[cfg(any(target_arch = "riscv64", test))]
    thread.riscv64.clear();
}

/// Build the user-runtime snapshot, shared part and per-architecture parts.
///
/// All three architectures put their saved context in; only x86_64 and aarch64
/// have a handler table and pending frames to add.
pub(crate) fn new_user_runtime_state(
    thread: &Thread,
    execution_state: ThreadExecutionState,
) -> ThreadUserRuntimeState {
    ThreadUserRuntimeState {
        execution_state,
        #[cfg(any(target_arch = "aarch64", test))]
        aarch64: thread.aarch64.snapshot(),
        #[cfg(target_arch = "x86_64")]
        x86_64: thread.x86_64.snapshot(),
        #[cfg(any(target_arch = "riscv64", test))]
        riscv64: thread.riscv64.snapshot(),
    }
}

/// Reject a snapshot the architecture could not resume from.
///
/// riscv64 has no handler table and no nested-delivery state to check yet, so
/// it has nothing to add here; the shared part of the validation is the
/// kernel's.
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(unused_variables)
)]
pub(crate) fn validate_user_runtime_state(state: &ThreadUserRuntimeState) -> Result<()> {
    #[cfg(any(target_arch = "aarch64", test))]
    state.aarch64.validate()?;
    #[cfg(target_arch = "x86_64")]
    state.x86_64.validate()?;
    Ok(())
}

/// Put a snapshot back into every architecture's state.
///
/// riscv64 has only a saved context to restore, and the kernel's own
/// `restore_user_runtime_state` installs that through the start descriptor; the
/// remaining work here is the handler tables and delivery state that x86_64 and
/// aarch64 keep.
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(unused_variables)
)]
pub(crate) fn restore_user_runtime_state(thread: &Thread, state: ThreadUserRuntimeState) {
    #[cfg(any(target_arch = "aarch64", test))]
    thread.aarch64.restore(state.aarch64);
    #[cfg(target_arch = "x86_64")]
    thread.x86_64.restore(state.x86_64);
}
#[cfg(target_arch = "x86_64")]
pub use x86_64_context::*;
