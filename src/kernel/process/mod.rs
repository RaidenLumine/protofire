//! src/kernel/process/mod.rs
//!
//! Process subsystem exports and shared process/thread type definitions.

pub mod context;
// The MAC policy is in the security layer, below this module and below `fs`.
// Re-exported so `process::mac::...` keeps naming the same thing.
pub use crate::kernel::security::mac;
#[allow(clippy::module_inception)]
pub mod posix_timer;
#[allow(clippy::module_inception)]
pub mod process;
pub mod ptrace;
pub mod scheduler;
pub mod seccomp;
pub mod thread;
pub mod wait;

pub use crate::kernel::device::CONSOLE_DEVICE_NAME;
pub use crate::kernel::device::DEBUG_DEVICE_NAME;
pub use crate::kernel::device::KEYBOARD_DEVICE_NAME;
pub use crate::kernel::device::KEYBOARD_RAW_DEVICE_NAME;
pub use crate::kernel::device::NULL_DEVICE_NAME;
pub use crate::kernel::device::SERIAL0_DEVICE_NAME;
pub use crate::kernel::device::ZERO_DEVICE_NAME;
pub use context::Context;
pub use context::ContextCell;
pub use process::home_dir_for_uid;
pub use process::ExceptionTermination;
pub use process::FdFlags;
pub use process::FileDescriptor;
pub use process::GroupId;
pub use process::Handle;
pub use process::HandleEntry;
pub use process::IntegrityLevel;
pub use process::KernelObject;
pub use process::LaunchContext;
pub use process::OpenFile;
pub use process::Process;
pub use process::ProcessAddressSpaceSummary;
pub(crate) use process::ProcessExecState;
pub use process::ProcessId;
pub use process::ProcessState;
pub use process::ProcessSummary;
pub(crate) use process::ProcessUserAddressSpace;
pub use process::RawSocketHandle;
pub use process::SecurityToken;
pub use process::TerminationReason;
pub use process::UserAddressSpaceSummary;
pub use process::UserId;
pub use process::DEFAULT_GUEST_GROUP_ID;
pub use process::DEFAULT_GUEST_USER_ID;
pub use process::HANDLE_RIGHT_READ;
pub use process::HANDLE_RIGHT_WRITE;
pub use process::ROOT_GROUP_ID;
pub use process::ROOT_USER_ID;
pub use process::STDERR_FD;
pub use process::STDIN_FD;
pub use process::STDOUT_FD;
pub use scheduler::on_timer_tick;
pub use scheduler::on_timer_tick_with_preemption;
pub use scheduler::sleep_current;
pub use scheduler::terminate_current;
pub use scheduler::terminate_current_with_reason;
pub use scheduler::yield_current;
pub use scheduler::Scheduler;
pub use thread::Thread;
pub use thread::ThreadId;
pub use thread::ThreadPriority;
pub use thread::ThreadState;
pub use thread::ThreadSummary;
pub use thread::ThreadWaitOutcome;
pub use thread::UserThreadStart;
pub use thread::THREAD_PRIORITY_COUNT;
