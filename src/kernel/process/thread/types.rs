//! src/kernel/process/thread/types.rs
//! Pure type definitions for the thread module: user-thread start descriptor,
//! scheduling metadata, thread state, wait outcomes, and runtime state.

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
use crate::{Error, Result};
use core::fmt;

pub(crate) use super::constants::*;

// Arch-type imports needed by ThreadUserRuntimeState.
#[cfg(any(target_arch = "aarch64", test))]
use super::arch_aarch64::{
    AArch64PendingExceptionFrameStack, AArch64UserExceptionHandlerRegistration,
    AArch64UserThreadContext, AARCH64_EXCEPTION_VECTOR_COUNT,
};
#[cfg(any(target_arch = "riscv64", test))]
use super::arch_riscv64::RiscV64UserThreadContext;
#[cfg(target_arch = "x86_64")]
use super::arch_x86_64::{
    X86_64PendingExceptionFrameStack, X86_64UserExceptionHandlerRegistration,
    X86_64UserThreadContext, X86_64_EXCEPTION_VECTOR_COUNT,
};

// ── UserThreadStart ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserThreadStart {
    pub instruction_pointer: usize,
    pub stack_pointer: usize,
    pub exception_stack_pointer: Option<usize>,
    #[cfg(target_arch = "aarch64")]
    pub aarch64_argument_registers: [usize; 3],
    #[cfg(target_arch = "riscv64")]
    pub riscv64_argument_registers: [usize; 3],
}

impl UserThreadStart {
    pub const fn new(
        instruction_pointer: usize,
        stack_pointer: usize,
        exception_stack_pointer: Option<usize>,
    ) -> Self {
        Self {
            instruction_pointer,
            stack_pointer,
            exception_stack_pointer,
            #[cfg(target_arch = "aarch64")]
            aarch64_argument_registers: [0; 3],
            #[cfg(target_arch = "riscv64")]
            riscv64_argument_registers: [0; 3],
        }
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        test
    ))]
    pub(crate) fn validate(self) -> Result<Self> {
        if self.instruction_pointer == 0 || !is_canonical_user_address(self.instruction_pointer) {
            return Err(Error::InvalidArgument);
        }

        if self.stack_pointer == 0
            || !is_canonical_user_address(self.stack_pointer)
            || !is_user_thread_stack_pointer_aligned(self.stack_pointer)
        {
            return Err(Error::InvalidArgument);
        }

        if let Some(exception_stack_pointer) = self.exception_stack_pointer {
            if exception_stack_pointer == 0
                || !is_canonical_user_address(exception_stack_pointer)
                || !is_user_thread_stack_pointer_aligned(exception_stack_pointer)
            {
                return Err(Error::InvalidArgument);
            }
        }

        Ok(self)
    }

    #[cfg(target_arch = "aarch64")]
    pub const fn with_aarch64_argument_registers(mut self, argument_registers: [usize; 3]) -> Self {
        self.aarch64_argument_registers = argument_registers;
        self
    }

    #[cfg(target_arch = "riscv64")]
    pub const fn with_riscv64_argument_registers(mut self, argument_registers: [usize; 3]) -> Self {
        self.riscv64_argument_registers = argument_registers;
        self
    }
}

const fn is_user_thread_stack_pointer_aligned(stack_pointer: usize) -> bool {
    stack_pointer & (USER_THREAD_STACK_ALIGNMENT - 1) == 0
}

// ── Canonical user address check (shared across arch validators) ────────

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    test
))]
pub(crate) const fn is_canonical_user_address(address: usize) -> bool {
    address <= 0x0000_7FFF_FFFF_FFFF
}

// ── Shared exception-frame stack (aarch64 + x86_64) ─────────────────────

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserPendingExceptionFrame {
    pub(crate) frame_pointer: usize,
    pub(crate) flags: usize,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingExceptionFrameStack<const CAPACITY: usize> {
    len: usize,
    entries: [UserPendingExceptionFrame; CAPACITY],
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[cfg_attr(test, allow(dead_code))]
impl<const CAPACITY: usize> PendingExceptionFrameStack<CAPACITY> {
    const EMPTY_ENTRY: UserPendingExceptionFrame = UserPendingExceptionFrame {
        frame_pointer: 0,
        flags: 0,
    };

    pub(crate) const fn new() -> Self {
        Self {
            len: 0,
            entries: [Self::EMPTY_ENTRY; CAPACITY],
        }
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn top(&self) -> Option<UserPendingExceptionFrame> {
        if self.len == 0 {
            None
        } else {
            Some(self.entries[self.len - 1])
        }
    }

    pub(crate) fn push(&mut self, entry: UserPendingExceptionFrame) -> Result<()> {
        if self.len == CAPACITY {
            return Err(Error::Busy);
        }

        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    pub(crate) fn pop_expected(
        &mut self,
        frame_pointer: usize,
    ) -> Result<Option<UserPendingExceptionFrame>> {
        let Some(entry) = self.top() else {
            return Ok(None);
        };

        if entry.frame_pointer != frame_pointer {
            return Err(Error::InvalidArgument);
        }

        self.len -= 1;
        Ok(Some(entry))
    }
}

// ── Scheduling types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ThreadPriority {
    Idle = 0,
    #[default]
    Normal = 1,
    High = 2,
    Realtime = 3,
}

impl fmt::Display for ThreadPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadPriority::Idle => write!(f, "Idle"),
            ThreadPriority::Normal => write!(f, "Norm"),
            ThreadPriority::High => write!(f, "High"),
            ThreadPriority::Realtime => write!(f, "Real"),
        }
    }
}

pub const THREAD_PRIORITY_COUNT: usize = 4;

/// Per-thread scheduling policy.
///
/// - `SchedDefault`: Round-robin with timeslice preemption (default).
/// - `SchedFifo`: Run-to-completion — never preempted by timeslice expiry,
///   requeued at the front when voluntarily preempted.
/// - `SchedRoundRobin`: Explicit round-robin with timeslice preemption,
///   identical in effect to `SchedDefault`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ThreadSchedPolicy {
    #[default]
    SchedDefault,
    SchedFifo,
    SchedRoundRobin,
}

/// Per-thread scheduling statistics (for diagnostics).
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSchedStats {
    pub schedule_count: u64,
    pub preempt_count: u64,
    pub total_wait_ticks: u64,
}

// ── Thread state & diagnostics ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Waiting,
    Stopped,
    Terminated,
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadState::Ready => write!(f, "Ready"),
            ThreadState::Running => write!(f, "Running"),
            ThreadState::Waiting => write!(f, "Waiting"),
            ThreadState::Stopped => write!(f, "Stopped"),
            ThreadState::Terminated => write!(f, "Term"),
        }
    }
}

/// A read-only snapshot of a single thread for diagnostic listing.
#[derive(Debug, Clone)]
pub struct ThreadSummary {
    pub tid: ThreadId,
    pub priority: ThreadPriority,
    pub cpu_ticks: u64,
    pub state: ThreadState,
    pub cpu_affinity: u32,
    pub schedule_count: u64,
    pub preempt_count: u64,
    pub total_wait_ticks: u64,
    pub time_slice_remaining: u64,
    pub sched_policy: ThreadSchedPolicy,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadWaitOutcome {
    Pending,
    Completed,
    TimedOut,
}

// ── Execution state & user runtime state ────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadExecutionState {
    pub(crate) entry_point: usize,
    pub(crate) kernel_entry: Option<fn()>,
    pub(crate) user_start: Option<UserThreadStart>,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64_exception_stack_pointer: Option<usize>,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub(crate) _arch_exception_stack_pointer: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadUserRuntimeState {
    pub(crate) execution_state: ThreadExecutionState,
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64_user_context: Option<AArch64UserThreadContext>,
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64_exception_handlers:
        [Option<AArch64UserExceptionHandlerRegistration>; AARCH64_EXCEPTION_VECTOR_COUNT],
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64_pending_exception_frames: AArch64PendingExceptionFrameStack,
    #[cfg(any(target_arch = "aarch64", test))]
    pub(crate) aarch64_exception_preempt_resume_logged: bool,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64_user_context: Option<X86_64UserThreadContext>,
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64_exception_handlers:
        [Option<X86_64UserExceptionHandlerRegistration>; X86_64_EXCEPTION_VECTOR_COUNT],
    #[cfg(target_arch = "x86_64")]
    pub(crate) x86_64_pending_exception_frames: X86_64PendingExceptionFrameStack,
    #[cfg(any(target_arch = "riscv64", test))]
    #[allow(dead_code)]
    pub(crate) riscv64_user_context: Option<RiscV64UserThreadContext>,
}
