//! src/kernel/process/thread/mod.rs
//!
//! Thread object state machine, user-context handling, and exception-delivery
//! metadata.

use ::core::sync::atomic::AtomicBool;
use ::core::sync::atomic::AtomicU32;
use ::core::sync::atomic::AtomicU64;
use ::core::sync::atomic::AtomicU8;
use alloc::sync::Arc;

use crate::kernel::sync::Event;
use crate::kernel::sync::Mutex;

use super::ContextCell;
use super::Process;
use super::TerminationReason;

pub(crate) mod constants;
pub(crate) mod kernel_stack;
mod stack_window;
pub(crate) mod types;

#[cfg_attr(not(target_os = "none"), allow(unused_imports))]
pub(crate) use stack_window::window_stats;

// The per-architecture halves live beside this file and are selected in one
// place rather than re-gated per name; see `arch.rs`.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
mod arch;
#[cfg(any(target_arch = "aarch64", test))]
pub(crate) mod arch_aarch64;
#[cfg(any(target_arch = "riscv64", test))]
pub(crate) mod arch_riscv64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod arch_x86_64;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
pub use arch::*;

pub(crate) mod entry;
pub(crate) mod exception;
pub(crate) mod lifecycle;
#[cfg(test)]
mod tests;
pub(crate) mod user_runtime;

// ── Thread struct fields ────────────────────────────────────────────────

use kernel_stack::KernelStack;

// The following are imported + re-exported by the pub use blocks below,
// which also serve as private imports for the Thread struct definition:
//   ThreadPriority, ThreadSchedPolicy, ThreadSchedStats, ThreadState (via pub
// use types::)   AArch64UserExceptionHandlerRegistration,
// AArch64UserThreadContext (via pub use arch_aarch64::)
//   X86_64UserExceptionHandlerRegistration, X86_64UserThreadContext (via pub
// use arch_x86_64::)

// ── Thread struct ───────────────────────────────────────────────────────

pub struct Thread {
    tid: ThreadId,
    process: Arc<Process>,
    execution_state: Mutex<ThreadExecutionState>,
    // One state object per architecture rather than one field per thing it
    // holds: the saved context, the handler table and the pending-frame stack
    // are read and written together, and the architecture that owns them also
    // owns the rules about them.
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64: AArch64UserThreadState,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64: X86_64UserThreadState,
    #[cfg(any(target_arch = "riscv64", test))]
    pub(crate) riscv64: RiscV64UserThreadState,
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
    /// Set to `true` when the scheduler promotes this thread from Normal to
    /// High priority via the starvation-boost mechanism.  Reset to `false`
    /// on demotion back to Normal.  Never `true` for native High or
    /// Realtime threads.
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
pub use types::ThreadPriority;
pub use types::ThreadSchedPolicy;
pub use types::ThreadSchedStats;
pub use types::ThreadState;
pub use types::ThreadSummary;
pub use types::ThreadWaitOutcome;
pub use types::UserThreadStart;
pub use types::THREAD_PRIORITY_COUNT;

// ── crate-internal re-exports ───────────────────────────────────────────

#[allow(unused_imports)]
pub(crate) use lifecycle::*;
#[allow(unused_imports)]
pub(crate) use types::is_canonical_user_address;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(unused_imports)]
pub(crate) use types::PendingExceptionFrameStack;
#[allow(unused_imports)]
pub(crate) use types::ThreadExecutionState;
#[allow(unused_imports)]
pub(crate) use types::ThreadUserRuntimeState;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(unused_imports)]
pub(crate) use types::UserPendingExceptionFrame;

#[allow(unused_imports)]
pub(crate) use constants::USER_THREAD_STACK_ALIGNMENT;

// Re-export items moved to sub-modules that tests still import via `super::`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(unused_imports)]
pub(crate) use exception::align_down;
