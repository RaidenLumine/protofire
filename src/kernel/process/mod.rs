//! src/kernel/process/mod.rs
//!
//! Process subsystem exports and shared process/thread type definitions.

pub mod context;
pub mod mac;
#[allow(clippy::module_inception)]
pub mod posix_timer;
#[allow(clippy::module_inception)]
pub mod process;
pub mod ptrace;
pub mod scheduler;
pub mod seccomp;
pub mod thread;

pub use crate::kernel::device::{
    CONSOLE_DEVICE_NAME, DEBUG_DEVICE_NAME, KEYBOARD_DEVICE_NAME, KEYBOARD_RAW_DEVICE_NAME,
    NULL_DEVICE_NAME, SERIAL0_DEVICE_NAME, ZERO_DEVICE_NAME,
};
pub use context::{Context, ContextCell};
pub(crate) use process::ProcessExecState;
pub(crate) use process::ProcessUserAddressSpace;
pub use process::{
    home_dir_for_uid, ExceptionTermination, FdFlags, FileDescriptor, GroupId, Handle, HandleEntry,
    IntegrityLevel, KernelObject, LaunchContext, OpenFile, Process, ProcessAddressSpaceSummary,
    ProcessId, ProcessState, ProcessSummary, RawSocketHandle, SecurityToken, TerminationReason,
    UserAddressSpaceSummary, UserId, DEFAULT_GUEST_GROUP_ID, DEFAULT_GUEST_USER_ID,
    HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE, ROOT_GROUP_ID, ROOT_USER_ID, STDERR_FD, STDIN_FD,
    STDOUT_FD,
};
pub use scheduler::{
    on_timer_tick, on_timer_tick_with_preemption, sleep_current, terminate_current,
    terminate_current_with_reason, yield_current, Scheduler,
};
pub use thread::{
    Thread, ThreadId, ThreadPriority, ThreadState, ThreadSummary, ThreadWaitOutcome,
    UserThreadStart, THREAD_PRIORITY_COUNT,
};
#[cfg(target_arch = "x86_64")]
pub use thread::{
    X86_64UserExceptionHandlerRegistration, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    X86_64_PENDING_USER_EXCEPTION_FRAME_CAPACITY, X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE, X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
