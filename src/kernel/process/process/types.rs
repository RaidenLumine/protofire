//! src/kernel/process/process/types.rs
//!
//! Process subsystem type definitions.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::abi::process::ProcessTerminationRecord;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::mmu::ActivatedProcessAddressSpace;
use crate::arch::mmu::PreparedProcessAddressSpace;
#[cfg(target_arch = "x86_64")]
use crate::arch::mmu::PreparedProcessAddressSpaceSummary;
#[cfg(all(target_arch = "x86_64", test))]
use crate::arch::mmu::PreparedProcessTranslation;
#[cfg(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
use crate::arch::mmu::PreparedTranslation;
#[cfg(target_arch = "x86_64")]
use crate::arch::mmu::PreparedUserAddressSpace;
#[cfg(target_arch = "x86_64")]
use crate::arch::mmu::PreparedUserAddressSpaceSummary;
#[cfg(all(target_arch = "x86_64", any(test, target_os = "none")))]
use crate::arch::mmu::PreparedUserTranslation;
use crate::kernel::fs::vfs::MetadataAccessQueryContext;
use crate::kernel::fs::vfs::PermissionMetadataRecord;
use crate::kernel::fs::FileHandle as FsFileHandle;
use crate::kernel::network::LocalSocket;
use crate::kernel::network::TcpConnection;
use crate::kernel::network::TcpListener;
use crate::kernel::network::UdpSocket;
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::sync::Mutex;
use crate::Result;

pub use super::super::thread::ThreadId;
use super::super::thread::ThreadPriority;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use super::super::thread::UserThreadStart;

// Re-export the x86_64 user-thread register context so ptrace helpers can
// reach it via `process::types` (the canonical definition lives in
// `thread::arch_x86_64` and is re-exported from `thread`).
#[cfg(target_arch = "x86_64")]
pub use super::super::thread::X86_64UserThreadContext;

use super::constants::*;

// Re-export types that were moved to the security submodule so existing
// `use super::types::*` imports continue to work.
#[allow(unused_imports)]
pub(crate) use super::security::IntegrityLevel;
#[allow(unused_imports)]
pub(crate) use super::security::SecurityToken;

/// Per-file-descriptor flags stored alongside the handle binding.
///
/// These are process-local flags (like `FD_CLOEXEC` in POSIX) rather than
/// handle-level flags, because the same handle may be shared across processes
/// with different close-on-exec semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FdFlags(pub u8);

impl FdFlags {
    pub const NONE: Self = Self(0);
    /// Close this descriptor when the process calls `exec`.
    pub const CLOEXEC: Self = Self(1 << 0);

    /// Returns `true` when all bits in `flags` are set.
    #[inline]
    pub fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// Set the given flag bits (logical OR).
    #[inline]
    pub fn set(&mut self, flags: Self) {
        self.0 |= flags.0;
    }

    /// Clear the given flag bits (logical AND NOT).
    #[inline]
    pub fn clear(&mut self, flags: Self) {
        self.0 &= !flags.0;
    }
}

/// A read-only snapshot of a process for diagnostic listing (`ps`).
#[derive(Debug, Clone)]
pub struct ProcessSummary {
    pub pid: ProcessId,
    pub ppid: Option<ProcessId>,
    pub name: String,
    pub state: ProcessState,
    pub thread_count: usize,
    pub priority: ThreadPriority,
    pub cpu_ticks: u64,
    pub is_kernel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    New,
    Ready,
    Running,
    Waiting,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionTermination {
    pub vector: u8,
    pub error_code: u64,
    pub fault_address: Option<usize>,
}

impl ExceptionTermination {
    pub const fn new(vector: u8, error_code: u64, fault_address: Option<usize>) -> Self {
        Self {
            vector,
            error_code,
            fault_address,
        }
    }

    pub const fn process_record(self) -> ProcessTerminationRecord {
        ProcessTerminationRecord::exception(self.vector, self.error_code, self.fault_address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    Exit { status: usize },
    Exception(ExceptionTermination),
}

impl TerminationReason {
    pub const fn exception(vector: u8, error_code: u64, fault_address: Option<usize>) -> Self {
        Self::Exception(ExceptionTermination::new(vector, error_code, fault_address))
    }

    pub const fn process_record(self) -> ProcessTerminationRecord {
        match self {
            Self::Exit { status } => ProcessTerminationRecord::exited(status),
            Self::Exception(exception) => exception.process_record(),
        }
    }
}

// ── Per-process fault record ring buffer ──

/// A single fault record stored in the per-process ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct FaultRecord {
    pub vector: u8,
    pub error_code: u64,
    pub fault_address: Option<usize>,
    pub instruction_pointer: u64,
    pub from_user_mode: bool,
}

/// Fixed-size ring buffer of fault records (capacity 4).
/// Oldest entries are silently overwritten on wrap.
#[derive(Debug, Clone)]
pub struct FaultRecordRing {
    entries: [Option<FaultRecord>; 4],
    write_index: usize,
    count: usize,
}

impl FaultRecordRing {
    pub const fn new() -> Self {
        Self {
            entries: [None; 4],
            write_index: 0,
            count: 0,
        }
    }

    /// Push a fault record into the ring buffer, silently overwriting the
    /// oldest entry when the buffer is full.
    pub fn push(&mut self, record: FaultRecord) {
        self.entries[self.write_index] = Some(record);
        self.write_index = (self.write_index + 1) % 4;
        if self.count < 4 {
            self.count += 1;
        }
    }

    /// Return an iterator over stored fault records in oldest-to-newest order.
    pub fn records(&self) -> impl Iterator<Item = &FaultRecord> {
        let start = if self.count < 4 { 0 } else { self.write_index };
        (0..self.count).filter_map(move |i| self.entries[(start + i) % 4].as_ref())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn len(&self) -> usize {
        self.count
    }
}

impl Default for FaultRecordRing {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum KernelObject {
    File(OpenFile),
    Directory(String),
    Device(String),
    Network(TcpConnection),
    TcpListener(TcpListener),
    UdpSocket(UdpSocket),
    /// DCCP connection-oriented datagram socket (RFC 4340).
    DccpSocket(crate::kernel::network::DccpSocket),
    RawSocket(RawSocketHandle),
    LocalSocket(Arc<LocalSocket>),
    /// A TCP connection wrapped with TLS 1.3 encryption.
    TlsConnection(alloc::sync::Arc<crate::kernel::network::tls::TlsWrappedConnection>),
    Process(ProcessId),
    Thread(ThreadId),
    /// Lightweight event notification — readable/writable like a u64 counter.
    EventFd(alloc::sync::Arc<EventFdState>),
    /// Signal notification — dequeues matching signals from the process queue.
    SignalFd(alloc::sync::Arc<SignalFdState>),
    /// Timer notification — becomes readable when the timer expires.
    TimerFd(alloc::sync::Arc<TimerFdState>),
    /// POSIX message queue — named queues with blocking send/receive.
    Mqueue(alloc::sync::Arc<Mutex<MqState>>),
    /// Epoll — event-driven I/O notification.
    Epoll(alloc::sync::Arc<crate::kernel::sync::Mutex<EpollState>>),
    /// io_uring — asynchronous I/O batching.
    IoUring(alloc::sync::Arc<IoUringState>),
}

/// A handle to a raw socket stored in the global network stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSocketHandle {
    pub socket_id: u32,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub object: KernelObject,
    pub rights: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchContext {
    pub catalog_id: String,
    pub manifest_path: String,
    pub image_path: String,
    pub version: String,
    pub working_dir: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingProcessSignal {
    pub(crate) sender_pid: ProcessId,
    pub(crate) signal: usize,
    pub(crate) payload: usize,
    pub(crate) si_code: usize,
    pub(crate) si_uid: usize,
}

impl PendingProcessSignal {
    pub(crate) fn record(self) -> crate::abi::process::ProcessSignalRecord {
        crate::abi::process::ProcessSignalRecord::new(
            self.signal,
            self.sender_pid as usize,
            self.payload,
        )
    }
}

pub(crate) struct PendingProcessSignalState {
    pub(crate) pending: VecDeque<PendingProcessSignal>,
}

impl PendingProcessSignalState {
    pub(crate) fn new() -> Self {
        Self {
            pending: VecDeque::new(),
        }
    }
}

/// eventfd flag bit values (kernel ABI encoding).
///
/// This kernel's encoding is shifted one bit relative to Linux: `SEMAPHORE`
/// is bit 0, `NONBLOCK` bit 1, and `CLOEXEC` bit 2 (Linux uses CLOEXEC=1,
/// NONBLOCK=2, SEMAPHORE=4).  The encoding is stable and documented in
/// `syscall/event_fd.rs` and the ring3 wrapper.
pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK: u32 = 2;
pub const EFD_CLOEXEC: u32 = 4;
/// Mask of all recognised eventfd flags — used to reject unknown bits.
pub const EFD_KNOWN_FLAGS: u32 = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;

/// Flags for `eventfd()` (kernel ABI encoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventFdFlags(pub u32);

impl EventFdFlags {
    pub const SEMAPHORE: Self = Self(EFD_SEMAPHORE);
    pub const NONBLOCK: Self = Self(EFD_NONBLOCK);
    pub const CLOEXEC: Self = Self(EFD_CLOEXEC);
}

/// Per-instance state for an eventfd object.
///
/// The counter is an atomic u64; the WaitQueue provides blocking reads.
pub struct EventFdState {
    pub(crate) counter: core::sync::atomic::AtomicU64,
    pub(crate) wait_queue: WaitQueue<()>,
    pub(crate) flags: u32,
}

impl core::fmt::Debug for EventFdState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventFdState")
            .field(
                "counter",
                &self.counter.load(core::sync::atomic::Ordering::Relaxed),
            )
            .field("wait_queue", &format_args!("WaitQueue(...)"))
            .field("flags", &self.flags)
            .finish()
    }
}

/// Per-instance state for a timerfd object.
///
/// `expiry` is the absolute tick at which the timer fires (0 = disarmed).
/// `interval` is the periodic interval in ticks (0 = one-shot).
/// `expirations` counts the number of expiry events since last read.
pub struct TimerFdState {
    /// Absolute tick of next expiration (0 = disarmed).
    pub(crate) expiry: core::sync::atomic::AtomicU64,
    /// Periodic interval in ticks (0 = one-shot).
    pub(crate) interval: core::sync::atomic::AtomicU64,
    /// Number of expirations since last read.
    pub(crate) expirations: core::sync::atomic::AtomicU64,
    /// WaitQueue for blocking reads.
    pub(crate) wait_queue: WaitQueue<()>,
}

impl core::fmt::Debug for TimerFdState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerFdState")
            .field(
                "expiry",
                &self.expiry.load(core::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "interval",
                &self.interval.load(core::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "expirations",
                &self.expirations.load(core::sync::atomic::Ordering::Relaxed),
            )
            .field("wait_queue", &format_args!("WaitQueue(...)"))
            .finish()
    }
}

/// Per-instance state for a signalfd object.
///
/// `sigset` is a bitmask of signals this signalfd should catch.
/// `process` is a weak reference to the owning process — used to access
/// the per-process signal queue.
pub struct SignalFdState {
    /// Bitmask of signals (bit N = 1 catches signal N).
    pub(crate) sigset: u64,
    /// Weak reference to the owning process.
    pub(crate) process: alloc::sync::Weak<super::Process>,
}

impl core::fmt::Debug for SignalFdState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignalFdState")
            .field("sigset", &self.sigset)
            .field("process", &format_args!("Weak(Process)"))
            .finish()
    }
}

/// Per-instance state for a POSIX message queue.
///
/// Named queues with fixed capacity, blocking send/receive via WaitQueue,
/// and optional signal notification on message arrival.
pub struct MqState {
    pub name: String,
    pub capacity: u32,
    pub msg_size: u32,
    pub messages: VecDeque<Vec<u8>>,
    pub wait_send: WaitQueue<()>,
    pub wait_recv: WaitQueue<()>,
    pub flags: u32,
    /// Optional signal number for mq_notify.
    pub notify_signal: Option<u32>,
}

impl MqState {
    pub(crate) fn new(name: String, capacity: u32, msg_size: u32, flags: u32) -> Self {
        Self {
            name,
            capacity: capacity.clamp(1, 64),
            msg_size: msg_size.clamp(1, 4096),
            messages: VecDeque::new(),
            wait_send: WaitQueue::new(),
            wait_recv: WaitQueue::new(),
            flags,
            notify_signal: None,
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.messages.len() >= self.capacity as usize
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl core::fmt::Debug for MqState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MqState")
            .field("name", &self.name)
            .field("capacity", &self.capacity)
            .field("msg_size", &self.msg_size)
            .field("msg_count", &self.messages.len())
            .finish()
    }
}

// ── Epoll types ───────────────────────────────────────────────────────────

/// Per-fd event registration for an epoll instance.
#[derive(Debug, Clone, Copy)]
pub struct EpollEvent {
    /// Bitmask of events the caller is interested in (EPOLLIN, EPOLLOUT, etc.).
    pub events: u32,
    /// Opaque user data returned via epoll_wait.
    pub data: u64,
}

/// Per-instance state for an epoll fd.
pub struct EpollState {
    pub monitored: alloc::collections::BTreeMap<usize, EpollEvent>,
}

impl core::fmt::Debug for EpollState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpollState")
            .field("monitored_count", &self.monitored.len())
            .finish()
    }
}

// ── io_uring types ─────────────────────────────────────────────────────────

/// A pending (in-flight) io_uring operation that could not complete
/// immediately (e.g. a read on a fd with no data available).
#[derive(Debug, Clone)]
pub(crate) struct IoUringPendingOp {
    /// The SQE that was submitted (stored so we can retry or complete).
    pub(crate) sqe: crate::abi::io_uring::IoUringSqe,
    /// Deadline for TIMEOUT ops (absolute tick, 0 = no deadline).
    pub(crate) deadline: u64,
    /// Whether this op has been retried at least once.
    /// Set by the re-probe loop in `syscall/io_uring.rs` but not yet read by
    /// any completion/retry policy; kept as store-only metadata so a future
    /// retry-limit policy can consume it without a struct-layout change.
    #[allow(dead_code)]
    pub(crate) retried: bool,
}

/// Per-instance state for an io_uring fd.
///
/// Keeps a queue of completed operations and a list of in-flight ops
/// that are waiting for I/O readiness.
pub struct IoUringState {
    /// Maximum number of in-flight entries.
    pub(crate) entries: u32,
    /// Setup flags (IORING_SETUP_*).
    pub(crate) flags: u32,
    /// Completed CQEs ready for userspace to reap.
    pub(crate) completion_queue:
        crate::kernel::sync::Mutex<alloc::collections::VecDeque<crate::abi::io_uring::IoUringCqe>>,
    /// WaitQueue for blocking in `io_uring_enter`.
    pub(crate) wait_queue: WaitQueue<()>,
    /// Operations that are in-flight (waiting on I/O).
    pub(crate) pending_ops: crate::kernel::sync::Mutex<alloc::vec::Vec<IoUringPendingOp>>,
}

impl core::fmt::Debug for IoUringState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoUringState")
            .field("entries", &self.entries)
            .field("flags", &self.flags)
            .field("completion_count", &self.completion_queue.lock().len())
            .field("pending_count", &self.pending_ops.lock().len())
            .finish()
    }
}

pub(crate) struct ProcessExecState {
    pub(crate) current_working_dir: String,
    pub(crate) home_dir: String,
    pub(crate) launch_context: Option<LaunchContext>,
    pub(crate) user_address_space: Option<ProcessUserAddressSpace>,
}

/// One shared-memory segment attached to a process.
#[derive(Debug, Clone)]
pub(crate) struct ProcessShmAttachment {
    pub(crate) shmid: usize,
    /// Base virtual address of the mapping in the process address space.
    pub(crate) virtual_address: usize,
    /// Size of the attachment in bytes.
    ///
    /// Recorded at attach time and kept for future shm accounting
    /// (shmdt/unmap); not currently read by the detach path, which uses
    /// `frame_count`.
    #[allow(dead_code)]
    pub(crate) size: usize,
}

// ── Ptrace types
// ──────────────────────────────────────────────────────────────

/// Per-process flag constants for ptrace tracing state.
pub(crate) mod ptrace_flags {
    /// This process is being traced (tracer_pid != None).
    pub(crate) const PF_TRACED: u32 = 1 << 0;
    /// Stop at syscall entry (PTRACE_SYSCALL mode).
    pub(crate) const PF_SYSCALL_TRACE: u32 = 1 << 1;
}

/// A ptrace stop event enqueued in the processʼs `ptrace_event_queue`.
#[derive(Debug, Clone)]
pub(crate) struct PtraceEvent {
    /// Thread ID that stopped.
    pub(crate) tid: super::ThreadId,
    /// Event code (PTRACE_EVENT_* or signal number).
    pub(crate) event: u32,
    /// Event-specific payload.
    pub(crate) message: usize,
    /// The syscall number for syscall-entry/exit stops (0 otherwise).
    pub(crate) syscall_number: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAddressSpaceSummary {
    pub root_table_address: usize,
    pub mapped_page_count: usize,
    pub image_page_count: usize,
    pub stack_page_count: usize,
    pub table_page_count: usize,
    pub pml4_entry_count: usize,
    pub pdpt_count: usize,
    pub page_directory_count: usize,
    pub page_table_count: usize,
}

#[cfg(target_arch = "x86_64")]
impl From<PreparedUserAddressSpaceSummary> for UserAddressSpaceSummary {
    fn from(summary: PreparedUserAddressSpaceSummary) -> Self {
        Self {
            root_table_address: summary.root_table_address,
            mapped_page_count: summary.mapped_page_count,
            image_page_count: summary.image_page_count,
            stack_page_count: summary.stack_page_count,
            table_page_count: summary.table_page_count,
            pml4_entry_count: summary.pml4_entry_count,
            pdpt_count: summary.pdpt_count,
            page_directory_count: summary.page_directory_count,
            page_table_count: summary.page_table_count,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessAddressSpaceSummary {
    pub root_table_address: usize,
    pub mapped_page_count: usize,
    pub kernel_page_count: usize,
    pub user_page_count: usize,
    pub table_page_count: usize,
    pub pml4_entry_count: usize,
    pub pdpt_count: usize,
    pub page_directory_count: usize,
    pub page_table_count: usize,
}

#[cfg(target_arch = "x86_64")]
impl From<PreparedProcessAddressSpaceSummary> for ProcessAddressSpaceSummary {
    fn from(summary: PreparedProcessAddressSpaceSummary) -> Self {
        Self {
            root_table_address: summary.root_table_address,
            mapped_page_count: summary.mapped_page_count,
            kernel_page_count: summary.kernel_page_count,
            user_page_count: summary.user_page_count,
            table_page_count: summary.table_page_count,
            pml4_entry_count: summary.pml4_entry_count,
            pdpt_count: summary.pdpt_count,
            page_directory_count: summary.page_directory_count,
            page_table_count: summary.page_table_count,
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub(crate) enum ProcessAddressSpaceStorage {
    // Host-side/unit-test execution can keep only the user mapping when a full
    // process root is unnecessary.
    UserOnly(PreparedUserAddressSpace),
    // Bare-metal execution and deeper tests keep one combined kernel+user root
    // that can be activated directly for the running thread.
    Combined(PreparedProcessAddressSpace),
}

pub(crate) struct ProcessUserAddressSpace {
    summary: UserAddressSpaceSummary,
    process_summary: Option<ProcessAddressSpaceSummary>,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    storage: PreparedProcessAddressSpace,
    // The prepared hierarchy is only consumed on bare-metal or unit-test builds.
    #[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
    #[cfg(target_arch = "x86_64")]
    storage: ProcessAddressSpaceStorage,
}

impl ProcessUserAddressSpace {
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn from_prepared_user(prepared: PreparedUserAddressSpace) -> Self {
        let summary = UserAddressSpaceSummary::from(prepared.summary());
        Self {
            summary,
            process_summary: None,
            storage: ProcessAddressSpaceStorage::UserOnly(prepared),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn from_prepared_process(prepared: PreparedProcessAddressSpace) -> Self {
        let summary = UserAddressSpaceSummary::from(prepared.user_address_space_summary());
        let process_summary = Some(ProcessAddressSpaceSummary::from(prepared.summary()));
        Self {
            summary,
            process_summary,
            #[cfg(target_arch = "aarch64")]
            slot: unreachable!("aarch64 slot should not be constructed on x86_64"),
            storage: ProcessAddressSpaceStorage::Combined(prepared),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(crate) fn from_prepared_process(prepared: PreparedProcessAddressSpace) -> Self {
        let summary = UserAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.user_page_count(),
            image_page_count: prepared.image_page_count(),
            stack_page_count: prepared.stack_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: prepared.root_entry_count(),
            pdpt_count: prepared.second_level_entry_count(),
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        };
        let process_summary = Some(ProcessAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.mapped_page_count(),
            kernel_page_count: prepared.kernel_page_count(),
            user_page_count: prepared.user_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: prepared.root_entry_count(),
            pdpt_count: prepared.second_level_entry_count(),
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        });
        Self {
            summary,
            process_summary,
            storage: prepared,
        }
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    pub(crate) fn from_prepared_process(prepared: PreparedProcessAddressSpace) -> Self {
        let summary = UserAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.user_page_count(),
            image_page_count: prepared.image_page_count(),
            stack_page_count: prepared.stack_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: 1, // Sv39: one PGD entry for kernel RAM
            pdpt_count: 1,       // Sv39: one PMD
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        };
        let process_summary = Some(ProcessAddressSpaceSummary {
            root_table_address: prepared.root_table_address(),
            mapped_page_count: prepared.mapped_page_count(),
            kernel_page_count: prepared.kernel_page_count(),
            user_page_count: prepared.user_page_count(),
            table_page_count: prepared.table_page_count(),
            pml4_entry_count: 1,
            pdpt_count: 1,
            page_directory_count: 0,
            page_table_count: prepared.leaf_table_count(),
        });
        Self {
            summary,
            process_summary,
            storage: prepared,
        }
    }

    pub(crate) fn summary(&self) -> UserAddressSpaceSummary {
        self.summary
    }

    pub(crate) fn process_summary(&self) -> Option<ProcessAddressSpaceSummary> {
        self.process_summary
    }

    /// Return the virtual address range `(start, end_exclusive)` covering all
    /// user pages, or `None` when there are no user pages.
    pub(crate) fn user_page_va_range(&self) -> Option<(usize, usize)> {
        #[cfg(target_arch = "x86_64")]
        {
            match &self.storage {
                ProcessAddressSpaceStorage::UserOnly(prepared) => prepared.user_page_va_range(),
                ProcessAddressSpaceStorage::Combined(prepared) => prepared.user_page_va_range(),
            }
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            self.storage.user_page_va_range()
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub(crate) fn user_thread_start(&self) -> UserThreadStart {
        self.storage.user_thread_start()
    }

    #[cfg(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    ))]
    pub(crate) fn matches_prepared_user_thread_start(&self, start: UserThreadStart) -> bool {
        let prepared = self.storage.user_thread_start();
        start.instruction_pointer == prepared.instruction_pointer
            && start.stack_pointer == prepared.stack_pointer
            && start.exception_stack_pointer == prepared.exception_stack_pointer
    }

    // The x86_64 test introspection helpers below are the mirror of the
    // `Process`-level wrappers in `process/address_space.rs`; those wrappers
    // are currently unexercised (no live caller), so the underlying
    // accessors are kept for the test-only address-space API without a
    // dead-code warning.
    #[cfg(all(target_arch = "x86_64", test))]
    #[allow(dead_code)]
    pub(crate) fn user_root_table_address(&self) -> usize {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(prepared) => prepared.root_table_address(),
            ProcessAddressSpaceStorage::Combined(prepared) => prepared.user_root_table_address(),
        }
    }

    #[cfg(all(target_arch = "x86_64", test))]
    #[allow(dead_code)]
    pub(crate) fn process_root_table_address(&self) -> Option<usize> {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(_) => None,
            ProcessAddressSpaceStorage::Combined(prepared) => Some(prepared.root_table_address()),
        }
    }

    #[cfg(all(target_arch = "x86_64", any(test, target_os = "none")))]
    pub(crate) fn translate(&self, address: usize) -> Option<PreparedUserTranslation> {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(prepared) => prepared.translate(address),
            ProcessAddressSpaceStorage::Combined(prepared) => prepared.translate_user(address),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(crate) fn translate(&self, address: usize) -> Option<PreparedTranslation> {
        self.storage.translate_user(address)
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    pub(crate) fn translate(&self, address: usize) -> Option<PreparedTranslation> {
        self.storage.translate_user(address)
    }

    #[cfg(all(target_arch = "x86_64", test))]
    #[allow(dead_code)]
    pub(crate) fn translate_process_address(
        &self,
        address: usize,
    ) -> Option<PreparedProcessTranslation> {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(_) => None,
            ProcessAddressSpaceStorage::Combined(prepared) => prepared.translate(address),
        }
    }

    #[cfg(all(target_arch = "x86_64", test))]
    #[allow(dead_code)]
    pub(crate) fn read_byte(&self, address: usize) -> Option<u8> {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(prepared) => prepared.read_byte(address),
            ProcessAddressSpaceStorage::Combined(prepared) => prepared.read_byte(address),
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub(crate) fn activate_process_root(&self) -> Option<ActivatedProcessAddressSpace> {
        match &self.storage {
            ProcessAddressSpaceStorage::UserOnly(_) => None,
            ProcessAddressSpaceStorage::Combined(prepared) => prepared.activate(),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub(crate) fn activate_process_root(&self) -> bool {
        self.storage.activate().is_some()
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    #[cfg_attr(target_arch = "riscv64", allow(dead_code))]
    pub(crate) fn activate_process_root(&self) -> bool {
        self.storage.activate().is_some()
    }

    /// Return a mutable reference to the underlying
    /// [`PreparedProcessAddressSpace`] for fork operations.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn prepared_process_address_space_mut(
        &mut self,
    ) -> Option<&mut crate::arch::mmu::PreparedProcessAddressSpace> {
        match &mut self.storage {
            ProcessAddressSpaceStorage::Combined(prepared) => Some(prepared),
            ProcessAddressSpaceStorage::UserOnly(_) => None,
        }
    }

    /// Return a mutable reference to the underlying
    /// [`PreparedProcessAddressSpace`] for fork operations.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub(crate) fn prepared_process_address_space_mut(
        &mut self,
    ) -> Option<&mut crate::arch::mmu::PreparedProcessAddressSpace> {
        Some(&mut self.storage)
    }
}

#[derive(Clone)]
pub struct OpenFile {
    path: String,
    inner: Arc<Mutex<FsFileHandle>>,
}

impl OpenFile {
    /// Wrap a filesystem file handle as an [`OpenFile`] tracked by its path.
    pub fn new(path: &str, handle: FsFileHandle) -> Self {
        Self {
            path: path.to_string(),
            inner: Arc::new(Mutex::new(handle)),
        }
    }

    /// Path used when the file was opened.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Filesystem node kind (file, directory, symlink, etc.).
    pub fn kind(&self) -> crate::kernel::fs::NodeKind {
        self.inner.lock().kind()
    }

    /// File size in bytes.
    pub fn size(&self) -> usize {
        self.inner.lock().size()
    }

    /// Read from the file at the current seek position into `buffer`.
    /// Returns the number of bytes read.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.inner.lock().read(buffer)
    }

    /// Write `buffer` to the file at the current seek position.
    /// Returns the number of bytes written.
    pub fn write(&self, buffer: &[u8]) -> Result<usize> {
        self.inner.lock().write(buffer)
    }

    /// Move the read/write offset according to `whence`:
    /// 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END.
    /// Returns the new absolute offset.
    pub fn seek(&self, offset: i64, whence: usize) -> Result<u64> {
        self.inner.lock().seek(offset, whence)
    }

    /// Current seek position in bytes.
    pub fn position(&self) -> u64 {
        self.inner.lock().position()
    }

    /// Truncate or extend the file to `length` bytes.  Returns the new length.
    pub fn set_len(&self, length: u64) -> Result<u64> {
        self.inner.lock().set_len(length)
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.inner.lock().sync()
    }

    pub(crate) fn sync_data(&self) -> Result<()> {
        self.inner.lock().sync_data()
    }

    pub(crate) fn permission_metadata_record(&self) -> Result<PermissionMetadataRecord> {
        self.inner.lock().permission_metadata_record()
    }

    pub(crate) fn access_query_context_for(
        &self,
        required_access: u16,
        security_token: SecurityToken,
    ) -> Result<MetadataAccessQueryContext> {
        self.inner
            .lock()
            .access_query_context_for(required_access, security_token)
    }

    /// Run `f` against the underlying [`FsFileHandle`] (e.g. for fd-level
    /// operations like `fcntl` pipe resizing / non-blocking flags).
    pub(crate) fn with_file_handle<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&FsFileHandle) -> Result<T>,
    {
        f(&self.inner.lock())
    }
}

impl fmt::Debug for OpenFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}
