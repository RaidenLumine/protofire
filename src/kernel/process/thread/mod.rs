//! src/kernel/process/thread/mod.rs
//! Thread object state machine, user-context handling, and exception-delivery metadata.

use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8};
use alloc::sync::Arc;

use crate::kernel::sync::{Event, Mutex};

use super::{ContextCell, Process, TerminationReason};

pub(crate) mod constants;
pub(crate) mod kernel_stack;
pub(crate) mod types;

#[cfg(any(target_arch = "aarch64", test))]
pub(crate) mod arch_aarch64;
#[cfg(any(target_arch = "riscv64", test))]
pub(crate) mod arch_riscv64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod arch_x86_64;

pub(crate) mod entry;
pub(crate) mod exception;
pub(crate) mod lifecycle;
#[cfg(test)]
mod tests;
pub(crate) mod user_runtime;

// ── Private imports for Thread struct fields (not in public re-exports) ─

#[cfg(any(target_arch = "aarch64", test))]
use arch_aarch64::{AArch64PendingExceptionFrameStack, AARCH64_EXCEPTION_VECTOR_COUNT};
#[cfg(target_arch = "x86_64")]
use arch_x86_64::{X86_64PendingExceptionFrameStack, X86_64_EXCEPTION_VECTOR_COUNT};

use kernel_stack::KernelStack;

// The following are imported + re-exported by the pub use blocks below,
// which also serve as private imports for the Thread struct definition:
//   ThreadPriority, ThreadSchedPolicy, ThreadSchedStats, ThreadState (via pub use types::)
//   AArch64UserExceptionHandlerRegistration, AArch64UserThreadContext (via pub use arch_aarch64::)
//   X86_64UserExceptionHandlerRegistration, X86_64UserThreadContext (via pub use arch_x86_64::)

// ── Thread struct ───────────────────────────────────────────────────────

pub struct Thread {
    tid: ThreadId,
    process: Arc<Process>,
    execution_state: Mutex<ThreadExecutionState>,
    #[cfg(any(target_arch = "aarch64", test))]
    aarch64_user_context: Mutex<Option<AArch64UserThreadContext>>,
    #[cfg(any(target_arch = "aarch64", test))]
    aarch64_exception_handlers:
        Mutex<[Option<AArch64UserExceptionHandlerRegistration>; AARCH64_EXCEPTION_VECTOR_COUNT]>,
    #[cfg(any(target_arch = "aarch64", test))]
    aarch64_pending_exception_frames: Mutex<AArch64PendingExceptionFrameStack>,
    #[cfg(any(target_arch = "aarch64", test))]
    aarch64_exception_preempt_resume_logged: AtomicBool,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64_user_context: Mutex<Option<X86_64UserThreadContext>>,
    #[cfg(target_arch = "x86_64")]
    x86_64_exception_handlers:
        Mutex<[Option<X86_64UserExceptionHandlerRegistration>; X86_64_EXCEPTION_VECTOR_COUNT]>,
    #[cfg(target_arch = "x86_64")]
    x86_64_pending_exception_frames: Mutex<X86_64PendingExceptionFrameStack>,
    #[cfg(any(target_arch = "riscv64", test))]
    riscv64_user_context: Mutex<Option<RiscV64UserThreadContext>>,
    priority: Mutex<ThreadPriority>,
    context: ContextCell,
    state: Mutex<ThreadState>,
    termination_reason: Mutex<Option<TerminationReason>>,
    termination_event: Event,
    kernel_stack: KernelStack,
    switch_count: AtomicU64,
    cpu_ticks: AtomicU64,
    /// Ticks remaining in the current scheduling quantum.
    time_slice_remaining: AtomicU64,
    /// Maximum ticks per scheduling quantum.
    time_slice_ticks: AtomicU64,
    /// Scheduling policy for this thread.
    sched_policy: Mutex<ThreadSchedPolicy>,
    /// Scheduling statistics (for diagnostics).
    sched_stats: Mutex<ThreadSchedStats>,
    /// Ticks the thread has spent waiting since last dispatch.
    waiting_ticks: AtomicU64,
    /// Tick value recorded when the thread last entered a waiting state.
    pub(crate) last_wait_start: AtomicU64,
    wake_deadline: AtomicU64,
    wait_outcome: AtomicU8,
    /// When `true`, the thread should transition to `Stopped` instead
    /// of `Ready` when woken from `Waiting`.
    stop_pending: AtomicBool,
    /// When `true`, a remote termination request (e.g. SIGKILL delivered
    /// from another CPU) is pending.  The thread honors it at its next
    /// scheduler boundary so the process's resource teardown runs in the
    /// thread's own context instead of racing with it on the sender's CPU.
    terminate_pending: AtomicBool,
    /// Preferred CPU for this thread (0 = any CPU, 1..N = specific CPU).
    cpu_affinity: AtomicU32,
    /// Set to `true` when the scheduler promotes this thread from Normal to High
    /// priority via the starvation-boost mechanism.  Reset to `false` on demotion
    /// back to Normal.  Never `true` for native High or Realtime threads.
    boosted: AtomicBool,
    /// Snapshot of [`Process::current_address_space_generation`] taken after
    /// the most recent successful CR3 activation.
    #[cfg_attr(
        not(all(
            any(target_arch = "x86_64", target_arch = "aarch64"),
            target_os = "none"
        )),
        allow(dead_code)
    )]
    active_address_space_generation: AtomicU64,
    /// Random canary value for the compiler-inserted stack-protector check.
    /// Updated on each context switch from this field into the global
    /// `__stack_chk_guard`.
    ///
    /// Kept (never read) because the per-thread canary → `__stack_chk_guard`
    /// sync is a planned security feature that is not yet wired into the
    /// context-switch path; it is still initialized in `thread/lifecycle.rs`.
    #[allow(dead_code)]
    canary: AtomicU64,
}

// ── Public re-exports ───────────────────────────────────────────────────

pub use constants::ThreadId;
pub use types::{
    ThreadPriority, ThreadSchedPolicy, ThreadSchedStats, ThreadState, ThreadSummary,
    ThreadWaitOutcome, UserThreadStart, THREAD_PRIORITY_COUNT,
};

#[cfg(any(target_arch = "aarch64", test))]
pub use arch_aarch64::{
    AArch64UserExceptionFrame, AArch64UserExceptionHandlerRegistration, AArch64UserThreadContext,
    AARCH64_EXCEPTION_DATA_ABORT_VECTOR, AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR,
    AARCH64_PENDING_USER_EXCEPTION_FRAME_CAPACITY,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED, AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};

#[cfg(any(target_arch = "riscv64", test))]
pub use arch_riscv64::RiscV64UserThreadContext;

#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::{
    X86_64UserExceptionFrame, X86_64UserExceptionHandlerRegistration, X86_64UserThreadContext,
    X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR, X86_64_EXCEPTION_INVALID_OPCODE_VECTOR,
    X86_64_EXCEPTION_PAGE_FAULT_VECTOR, X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED, X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};

// ── crate-internal re-exports ───────────────────────────────────────────

#[allow(unused_imports)]
pub(crate) use lifecycle::*;
#[allow(unused_imports)]
pub(crate) use types::{is_canonical_user_address, ThreadExecutionState, ThreadUserRuntimeState};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(unused_imports)]
pub(crate) use types::{PendingExceptionFrameStack, UserPendingExceptionFrame};

#[allow(unused_imports)]
pub(crate) use constants::USER_THREAD_STACK_ALIGNMENT;

// Re-export items moved to sub-modules that tests still import via `super::`.
#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "none"
)))]
#[allow(unused_imports)]
pub(crate) use entry::unsupported_user_thread_entry;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(unused_imports)]
pub(crate) use exception::align_down;
#[cfg(target_arch = "aarch64")]
#[allow(unused_imports)]
pub(crate) use exception::build_aarch64_exception_delivery;
#[cfg(any(target_arch = "x86_64", test))]
#[allow(unused_imports)]
pub(crate) use exception::build_x86_64_exception_delivery;
