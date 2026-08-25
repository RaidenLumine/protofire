//! src/kernel/process/process/mod.rs
//!
//! Process subsystem: the `Process` struct plus its submodules.
//!
//! The `Process` struct is defined here so the parent module can re-export a
//! single `Process` symbol.  Behaviour is split across the submodules below:
//! handle table management, lifecycle, fork, sockets, security and the
//! per-process address space.

// ── Submodules ──────────────────────────────────────────────────────────

pub mod address_space;
pub mod constants;
pub mod fork;
pub mod handle_entry;
pub mod handle_ops;
pub mod lifecycle;
pub mod security;
pub mod socket_ops;
pub mod types;

// ── Re-exports (consumed by `crate::kernel::process`) ───────────────────

pub use constants::FileDescriptor;
pub use constants::GroupId;
pub use constants::Handle;
pub use constants::ProcessId;
pub use constants::UserId;
pub use constants::DEFAULT_GUEST_GROUP_ID;
pub use constants::DEFAULT_GUEST_USER_ID;
pub use constants::HANDLE_RIGHT_READ;
pub use constants::HANDLE_RIGHT_WRITE;
pub use constants::ROOT_GROUP_ID;
pub use constants::ROOT_USER_ID;
pub use constants::STDERR_FD;
pub use constants::STDIN_FD;
pub use constants::STDOUT_FD;
pub use handle_entry::home_dir_for_uid;
pub use security::IntegrityLevel;
pub use security::SecurityToken;
pub use types::ExceptionTermination;
pub use types::FdFlags;
pub use types::HandleEntry;
pub use types::KernelObject;
pub use types::LaunchContext;
pub use types::OpenFile;
pub use types::ProcessAddressSpaceSummary;
pub(crate) use types::ProcessExecState;
pub use types::ProcessState;
pub use types::ProcessSummary;
pub(crate) use types::ProcessUserAddressSpace;
pub use types::RawSocketHandle;
pub use types::TerminationReason;
pub use types::UserAddressSpaceSummary;

// ── Imports for the Process struct ──────────────────────────────────────

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicU8;

use self::constants::SignalHandler;
use self::constants::STANDARD_FD_COUNT;
use self::types::FaultRecordRing;
use self::types::PendingProcessSignalState;
use crate::kernel::process::thread::ThreadId;
use crate::kernel::sync::event::Event;
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::sync::Mutex;

// ── Process struct definition ──

pub struct Process {
    pid: ProcessId,
    parent_pid: Mutex<Option<ProcessId>>,
    name: Mutex<String>,
    /// Dumpable flag (0 = not dumpable, 1 = dumpable). Controls core-dump
    /// and ptrace access. Matches Linux PR_SET_DUMPABLE semantics.
    dumpable: AtomicU8,
    /// Keep capabilities flag. When set, the process retains permitted
    /// capabilities across execve (if supported).
    keepcaps: AtomicBool,
    threads: Mutex<Vec<ThreadId>>,
    handle_table: Mutex<BTreeMap<Handle, HandleEntry>>,
    fd_table: Mutex<BTreeMap<FileDescriptor, Handle>>,
    fd_flags: Mutex<BTreeMap<FileDescriptor, FdFlags>>,
    children: Mutex<Vec<ProcessId>>,
    signal_handlers: Mutex<[Option<SignalHandler>; 32]>,
    signal_mask: Mutex<u32>,
    signal_queue: WaitQueue<PendingProcessSignalState>,
    security_token: crate::kernel::sync::Mutex<SecurityToken>,
    current_working_dir: Mutex<String>,
    home_dir: Mutex<String>,
    launch_context: Mutex<Option<LaunchContext>>,
    user_address_space: Mutex<Option<ProcessUserAddressSpace>>,
    termination_event: Event,
    standard_handles: Mutex<[Option<Handle>; STANDARD_FD_COUNT]>,
    state: Mutex<ProcessState>,
    termination_reason: Mutex<Option<TerminationReason>>,
    fault_records: Mutex<FaultRecordRing>,
    /// Thread stored when spawned with START_SUSPENDED; taken by the
    /// scheduler when the process is resumed.
    suspended_thread: Mutex<Option<alloc::sync::Arc<super::Thread>>>,
    /// PID of the tracer process (None = not currently traced).
    pub(crate) tracer_pid: Mutex<Option<ProcessId>>,
    /// Ptrace options flags (PTRACE_O_*).
    pub(crate) ptrace_options: Mutex<u32>,
    /// Queue of ptrace stop events for the tracer to consume.
    pub(crate) ptrace_event_queue: Mutex<alloc::collections::VecDeque<types::PtraceEvent>>,
    /// Deferred-drop slot for the user address space.  During termination
    /// (inside a trap handler with interrupts disabled), the address space is
    /// moved here so its heap-allocated page tables are freed later, when the
    /// parent reaps the process with interrupts enabled.
    deferred_user_address_space_drop: Mutex<Option<ProcessUserAddressSpace>>,
    termination_reaped: AtomicBool,
    address_space_generation: AtomicU64,
    program_break: AtomicU64,
    /// Hint virtual address for the next shared-memory segment attachment.
    shm_va_hint: AtomicU64,
    /// Set of attached shared-memory segments (for cleanup on exit).
    shm_attachments: Mutex<Vec<types::ProcessShmAttachment>>,
    /// Seccomp filter state — syscall allow/deny rules.
    pub(crate) seccomp_filter: Mutex<super::seccomp::SeccompFilterState>,
    /// No new privileges flag (PR_SET_NO_NEW_PRIVS). When set, the process
    /// cannot gain new privileges via execve or similar operations.
    no_new_privs: AtomicBool,
    /// User-space signal handler addresses per signal number (index 0–31).
    /// `Some(addr)` when an async handler is registered; `None` for
    /// cooperative-only or default-action signals.
    /// Read by the bare-metal async-delivery path via
    /// [`lifecycle::Process::user_signal_handler`] (`target_os = "none"`);
    /// on host builds the storage is only written by the syscall handler, so
    /// the never-read lint is suppressed there.
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub(crate) user_signal_handlers: Mutex<[Option<u64>; 32]>,
    /// `SA_*` flags each signal handler was installed with (index 0–31).
    /// Only `SA_RESTART` is currently defined; unknown bits are rejected at
    /// install time, so every slot holds either 0 or a known flag.
    /// Read by the bare-metal async-delivery path (and host tests) via
    /// [`lifecycle::Process::signal_sa_flags`].
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub(crate) signal_sa_flags_storage: Mutex<[u64; 32]>,
    /// Virtual address of the ring3 trampoline function (0 = not set).
    /// Stored once per process; set by the first async-capable call to
    /// `SetSignalHandler`.  Read by the bare-metal async-delivery path via
    /// [`lifecycle::Process::signal_trampoline_addr`].
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub(crate) signal_trampoline_addr: Mutex<u64>,
    /// Bitmask of audit event types enabled for this process (AUDIT_ENABLE_*).
    /// Gates which events the syscall dispatcher emits to the global audit
    /// ring buffer, keeping overhead at zero when auditing is disabled.
    pub(crate) audit_enable_mask: AtomicU64,
    next_handle: AtomicU64,
    next_fd: AtomicU64,
    next_tid: AtomicU32,
}
