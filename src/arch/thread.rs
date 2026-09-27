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

// ── The state Thread carries ───────────────────────────────────────────
//
// One object per architecture inside one object here, rather than one field
// on `Thread` per architecture: the saved context, the handler table and the
// pending-frame stack are read and written together, the architecture that
// owns them also owns the rules about them, and a host build compiles all
// three shapes so the tests can drive each architecture's rules against the
// shared logic.

/// The user-runtime state of a thread, for every architecture compiled here.
pub(crate) struct ThreadUserState {
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64: AArch64UserThreadState,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64: X86_64UserThreadState,
    #[cfg(any(target_arch = "riscv64", test))]
    pub(crate) riscv64: RiscV64UserThreadState,
}

impl ThreadUserState {
    /// The state a freshly created thread starts with.
    pub(crate) fn new_for_user_start(
        user_start: Option<crate::kernel::process::UserThreadStart>,
    ) -> Self {
        Self {
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64: AArch64UserThreadState::for_user_start(user_start),
            #[cfg(target_arch = "x86_64")]
            x86_64: X86_64UserThreadState::for_user_start(user_start),
            #[cfg(any(target_arch = "riscv64", test))]
            riscv64: RiscV64UserThreadState::for_user_start(user_start),
        }
    }

    /// The per-architecture halves of a snapshot of this state.
    fn snapshot(&self) -> ThreadUserRuntimeStateSnapshot {
        ThreadUserRuntimeStateSnapshot {
            #[cfg(any(target_arch = "aarch64", test))]
            aarch64: self.aarch64.snapshot(),
            #[cfg(target_arch = "x86_64")]
            x86_64: self.x86_64.snapshot(),
            #[cfg(any(target_arch = "riscv64", test))]
            riscv64: self.riscv64.snapshot(),
        }
    }
}

/// The per-architecture halves of a thread's user-runtime snapshot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadUserRuntimeStateSnapshot {
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64: AArch64UserThreadStateSnapshot,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64: X86_64UserThreadStateSnapshot,
    /// Carried but not yet checked: riscv64 has only a saved context and no
    /// handler table or nested-delivery state to validate.
    #[cfg(any(target_arch = "riscv64", test))]
    #[allow(dead_code)]
    pub(crate) riscv64: RiscV64UserThreadStateSnapshot,
}

impl ThreadUserRuntimeStateSnapshot {
    /// Reject a snapshot the architecture could not resume from.
    fn validate(&self) -> Result<()> {
        #[cfg(any(target_arch = "aarch64", test))]
        self.aarch64.validate()?;
        #[cfg(target_arch = "x86_64")]
        self.x86_64.validate()?;
        Ok(())
    }
}

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
    thread.arch.aarch64.clear();
    #[cfg(target_arch = "x86_64")]
    thread.arch.x86_64.clear();
    #[cfg(any(target_arch = "riscv64", test))]
    thread.arch.riscv64.clear();
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
        arch: thread.arch.snapshot(),
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
    state.arch.validate()
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
    thread.arch.aarch64.restore(state.arch.aarch64);
    #[cfg(target_arch = "x86_64")]
    thread.arch.x86_64.restore(state.arch.x86_64);
}
#[cfg(target_arch = "x86_64")]
pub use x86_64_context::*;

// ── The user image a thread runs ───────────────────────────────────────
//
// A thread that was just loaded, forked or exec'd has a user half the
// architecture owns: the context registers the entry reads, the image the
// MMU maps, and the switch that makes it live.  The syscall layer asks for
// those here rather than naming an architecture to build them.

/// Build the thread a fork creates.
///
/// The child gets the parent's user context with the register its
/// architecture reports a successful fork in zeroed — `rax` on x86_64, `x0`
/// on aarch64, `x10` on riscv64.  A host with no per-process address space to
/// clone says so instead of pretending.
pub(crate) fn new_fork_thread(
    child: alloc::sync::Arc<crate::kernel::process::Process>,
    parent: &Thread,
) -> Result<alloc::sync::Arc<Thread>> {
    #[cfg(target_arch = "x86_64")]
    {
        let parent_ctx = parent
            .validated_x86_64_user_context()?
            .ok_or(crate::Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::X86_64UserThreadContext {
            rax: 0,
            ..parent_ctx
        };
        Thread::new_user_fork(child, child_ctx)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let parent_ctx = parent
            .validated_aarch64_user_context()?
            .ok_or(crate::Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::AArch64UserThreadContext {
            x0: 0,
            ..parent_ctx
        };
        Thread::new_user_fork(child, child_ctx)
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let parent_ctx = parent
            .validated_riscv64_user_context()?
            .ok_or(crate::Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::RiscV64UserThreadContext {
            x10: 0,
            ..parent_ctx
        };
        Thread::new_user_fork(child, child_ctx)
    }

    // A host build has no per-process address space to clone.
    #[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
    {
        let _ = (child, parent);
        Err(crate::Error::Unsupported)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        let _ = (child, parent);
        Err(crate::Error::NotImplemented)
    }
}

/// Check a start descriptor against the rules this architecture has for one.
///
/// x86_64 and aarch64 read the entry's stack and register conventions out of
/// it, so a malformed descriptor is refused before anything is installed;
/// riscv64 takes the shared shape as it is.
pub(crate) fn validate_user_thread_start(
    start: crate::kernel::process::UserThreadStart,
) -> Result<crate::kernel::process::UserThreadStart> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
    {
        start.validate()
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", test)))]
    {
        Ok(start)
    }
}

/// Install a freshly loaded image as the thread's user half.
pub(crate) fn install_user_image(
    thread: &Thread,
    start: crate::kernel::process::UserThreadStart,
) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        thread.replace_x86_64_user_image(start)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        thread.replace_aarch64_user_image(start)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "none")
    )))]
    {
        let _ = (thread, start);
        Err(crate::Error::Unsupported)
    }
}

/// Put a process's address space back in charge after an exec replaced it.
///
/// The machines that switch address spaces say whether the switch happened;
/// riscv64's exec does not activate here, and a host has nothing to switch.
pub(crate) fn activate_for_exec(process: &crate::kernel::process::Process) -> Result<()> {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    {
        if !process.activate_address_space_for_thread() {
            return Err(crate::Error::InternalError);
        }
    }

    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    )))]
    let _ = process;

    Ok(())
}

/// Install a user-exception handler for a thread, where the machine has one.
///
/// x86_64 and aarch64 keep a handler table per thread; riscv64's prototype has
/// no such table yet, so it refuses the request rather than pretending the
/// handler is installed.
pub(crate) fn install_user_exception_handler(
    thread: &Thread,
    vector: u8,
    handler: usize,
    stack_pointer: usize,
    flags: usize,
) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        thread.install_x86_64_exception_handler_with(vector, handler, stack_pointer, flags)
    }

    #[cfg(target_arch = "aarch64")]
    {
        thread.install_aarch64_exception_handler_with(vector, handler, stack_pointer, flags)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (thread, vector, handler, stack_pointer, flags);
        Err(crate::Error::Unsupported)
    }
}

/// The layout of the user exception frame this machine delivers.
///
/// The frame is the ABI's — it is what a handler reads when it returns — and
/// each machine has its own size and alignment.  A machine whose prototype
/// does not deliver user exceptions has no frame to describe, and says so.
pub(crate) fn user_exception_frame_layout() -> Option<(usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        Some((
            core::mem::size_of::<crate::abi::exception::X86_64UserExceptionFrame>(),
            core::mem::align_of::<crate::abi::exception::X86_64UserExceptionFrame>(),
        ))
    }

    #[cfg(target_arch = "aarch64")]
    {
        Some((
            core::mem::size_of::<crate::abi::exception::AArch64UserExceptionFrame>(),
            core::mem::align_of::<crate::abi::exception::AArch64UserExceptionFrame>(),
        ))
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}
