//! src/kernel/syscall/table.rs
//! Syscall number routing table and per-syscall handler dispatch glue.

use crate::abi::{process as process_abi, syscall as syscall_abi};
use crate::{Error, Result};

#[path = "exception_control.rs"]
mod exception_control;

#[path = "fs/metadata.rs"]
mod fs_metadata;

#[path = "fs/path.rs"]
mod fs_path;

#[path = "fs/path_ops.rs"]
mod fs_path_ops;

#[path = "io_fd.rs"]
mod io_fd;

#[path = "launch_metadata.rs"]
mod launch_metadata;

#[path = "misc.rs"]
mod misc;

#[path = "network.rs"]
mod network;

#[path = "memory/map.rs"]
mod memory_map;

#[path = "process/signal.rs"]
mod process_signal;

#[path = "process/sigsuspend.rs"]
mod process_sigsuspend;

#[path = "process/restart_syscall.rs"]
mod process_restart_syscall;

#[path = "network/local.rs"]
mod network_local;

#[path = "process/signal_mask.rs"]
mod process_signal_mask;

#[path = "process/launch/mod.rs"]
mod process_launch;

#[path = "process/wait.rs"]
mod process_wait;

#[path = "abi_info.rs"]
mod abi_info;

#[path = "runtime.rs"]
pub(crate) mod runtime;

#[path = "memory/user.rs"]
pub(crate) mod user_memory;

#[path = "process/wait_common.rs"]
mod wait_common;

#[path = "diagnostic.rs"]
mod diagnostic;

#[path = "process/identity.rs"]
mod process_identity;

#[path = "process/chdir.rs"]
mod process_chdir;

#[path = "memory/brk.rs"]
mod memory_brk;

#[path = "memory/shm_handlers.rs"]
mod memory_shm;

#[path = "fs/query.rs"]
mod fs_query;

#[path = "fs/user_mgmt.rs"]
mod fs_user_mgmt;

#[path = "fs/fuse_mount.rs"]
mod fs_fuse_mount;

#[path = "futex.rs"]
mod futex;

#[path = "event_fd.rs"]
mod event_fd;

#[path = "signal_fd.rs"]
mod signal_fd;

#[path = "timer_fd.rs"]
pub(crate) mod timer_fd;

#[path = "sched_affinity.rs"]
mod sched_affinity;

#[path = "mq.rs"]
pub(crate) mod mq;

#[path = "epoll.rs"]
mod epoll;

#[path = "tls.rs"]
mod tls_handler;

#[path = "filter.rs"]
mod filter_handler;

#[path = "ipsec.rs"]
mod ipsec_handler;

#[path = "mrt.rs"]
mod mrt_handler;

#[path = "mac.rs"]
mod mac_handler;

#[path = "fcntl.rs"]
mod fcntl_handler;

#[path = "gpu.rs"]
mod gpu_handler;
#[path = "sync.rs"]
mod sync_handler;

#[path = "io_uring.rs"]
mod io_uring_handler;

#[path = "ptrace.rs"]
mod ptrace_handler;

#[path = "seccomp.rs"]
mod seccomp_handler;

#[path = "posix_timer.rs"]
mod posix_timer;

#[path = "misc/prctl.rs"]
mod prctl_handler;

#[path = "audit.rs"]
mod audit_handler;

#[path = "power.rs"]
mod power_handler;

#[path = "memory/mlock.rs"]
mod memory_mlock;

#[path = "memory/madvise.rs"]
mod memory_madvise;

#[path = "fs/xattr.rs"]
mod fs_xattr;

#[cfg(test)]
#[path = "test_support.rs"]
pub(crate) mod test_support;

const MAX_SYSCALLS: usize = 256;
const PROCESS_LAUNCH_OVERRIDE_FLAGS: usize = process_abi::PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS
    | process_abi::PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT
    | process_abi::PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR
    | process_abi::PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR;
pub(crate) const PROCESS_SPAWN_KNOWN_FLAGS: usize = PROCESS_LAUNCH_OVERRIDE_FLAGS
    | process_abi::PROCESS_SPAWN_FLAG_INHERIT_STDIO
    | process_abi::PROCESS_SPAWN_FLAG_INHERIT_FDS
    | process_abi::PROCESS_SPAWN_FLAG_START_SUSPENDED;
pub(crate) const PROCESS_EXEC_KNOWN_FLAGS: usize = PROCESS_LAUNCH_OVERRIDE_FLAGS;

pub type SyscallHandler = fn(&mut SyscallContext) -> Result<SyscallDispatch>;

#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    Yield = 0,
    WriteDebug = 1,
    Open = 2,
    Exit = 3,
    ReadConsole = 4,
    Read = 5,
    Write = 6,
    Close = 7,
    Dup = 8,
    Dup2 = 69,
    Seek = 9,
    ArgCount = 10,
    ArgValue = 11,
    EnvCount = 12,
    EnvValue = 13,
    CurrentDir = 14,
    AppId = 15,
    AppVersion = 16,
    ImagePath = 17,
    ManifestPath = 18,
    CreateDir = 19,
    SetLength = 20,
    RemovePath = 21,
    InstallExceptionHandler = 22,
    ReturnFromException = 23,
    WaitProcess = 24,
    SpawnProcess = 25,
    ExecProcess = 26,
    Stat = 27,
    ReadDir = 28,
    Rename = 29,
    StatFd = 30,
    ReadDirFd = 31,
    OpenAt = 32,
    StatAt = 33,
    RenameAt = 34,
    CreateDirAt = 35,
    RemovePathAt = 36,
    NetworkStatus = 37,
    ConnectTcp = 38,
    AbiInfo = 39,
    SendSignal = 40,
    WaitSignal = 41,
    AccessQuery = 42,
    AccessQueryAt = 43,
    AccessQueryFd = 44,
    PermissionMetadata = 45,
    PermissionMetadataAt = 46,
    PermissionMetadataFd = 47,
    SetFdFlags = 48,
    Sleep = 49,
    ListProcesses = 50,
    ListThreads = 51,
    KernelLog = 52,
    SystemInfo = 53,
    Fsync = 54,
    Fdatasync = 55,
    ListenTcp = 56,
    AcceptTcp = 57,
    BindUdp = 58,
    SendToUdp = 59,
    RecvFromUdp = 60,
    ListProcessFaults = 61,
    Fork = 62,
    ReclaimPages = 63,
    Pipe = 64,
    Mount = 65,
    Umount = 66,
    Mmap = 67,
    Munmap = 68,
    GetTimeOfDay = 70,
    GetHostName = 71,
    SetHostName = 72,
    GetSockName = 73,
    GetPeerName = 74,
    GetRandom = 75,
    CreateRawSocket = 76,
    SendRawPacket = 77,
    RecvRawPacket = 78,
    SetSockOpt = 79,
    GetSockOpt = 80,
    GetPid = 81,
    GetPpid = 82,
    GetUid = 83,
    GetGid = 84,
    SetCurrentDir = 85,
    ListMounts = 86,
    ListBlockDevices = 87,
    SetSecurityDescriptor = 88,
    AddUser = 89,
    RemoveUser = 90,
    SetUserPassword = 91,
    Brk = 92,
    ResolveHostname = 93,
    SetSignalMask = 94,
    RepairVolume = 95,
    Poll = 96,
    BindLocal = 97,
    ConnectLocal = 98,
    AcceptLocal = 99,
    // Priority Gap #2: SystV shared memory
    ShmGet = 100,
    ShmAt = 101,
    ShmDt = 102,
    ShmCtl = 103,
    SetSignalHandler = 104,
    /// FUSE (Filesystem in Userspace) mount syscall.
    FuseMount = 105,
    /// Futex — fast userspace mutex (FUTEX_WAIT / FUTEX_WAKE).
    Futex = 106,
    /// eventfd — lightweight event notification.
    EventFd = 107,
    /// signalfd — signal notification via file descriptor.
    SignalFd = 108,
    /// timerfd — timer expiration notification.
    TimerFd = 109,
    /// sched_setaffinity — pin thread to specific CPUs.
    SchedSetAffinity = 110,
    /// sched_getaffinity — get thread CPU affinity mask.
    SchedGetAffinity = 111,
    /// mq_open — open or create a named message queue.
    MqOpen = 112,
    /// mq_close — close a message queue fd.
    MqClose = 113,
    /// mq_send — send a message to a queue.
    MqSend = 114,
    /// mq_receive — receive a message from a queue.
    MqReceive = 115,
    /// mq_notify — register for signal notification on a queue.
    MqNotify = 116,
    /// mq_unlink — remove a named message queue.
    MqUnlink = 117,
    /// epoll_create — create an epoll instance.
    EpollCreate = 118,
    /// epoll_ctl — control epoll interest list.
    EpollCtl = 119,
    /// epoll_wait — wait for events on epoll fds.
    EpollWait = 120,
    /// tls_connect — establish a TLS 1.3 encrypted connection.
    TlsConnect = 121,
    /// filter_add_rule — add a packet filter rule.
    FilterAddRule = 122,
    /// filter_remove_rule — remove a packet filter rule.
    FilterRemoveRule = 123,
    /// filter_set_default_action — set default filter policy.
    FilterSetDefaultAction = 124,
    /// filter_get_stats — retrieve filter statistics.
    FilterGetStats = 125,
    /// io_uring_setup — create an io_uring async I/O instance.
    IoUringSetup = 126,
    /// io_uring_enter — submit SQEs and/or reap CQEs.
    IoUringEnter = 127,
    /// ptrace — process tracing and debugging control.
    Ptrace = 128,
    /// seccomp — secure computing / syscall filtering.
    Seccomp = 129,
    /// prctl — process control operations.
    Prctl = 130,
    /// mlock — lock memory pages to prevent swapping.
    Mlock = 131,
    /// munlock — unlock memory pages.
    Munlock = 132,
    /// madvise — give advice about memory use.
    Madvise = 133,
    /// sigreturn — restore user context after async signal handler.
    SigReturn = 134,
    /// sigsuspend — atomically set signal mask and suspend execution.
    SigSuspend = 135,
    /// restart_syscall — re-issue an interrupted blocking syscall.
    RestartSyscall = 136,
    /// timer_create — create a POSIX per-process timer.
    TimerCreate = 137,
    /// timer_settime — arm/disarm a POSIX timer.
    TimerSetTime = 138,
    /// timer_gettime — get remaining time on a POSIX timer.
    TimerGetTime = 139,
    /// timer_delete — delete a POSIX timer.
    TimerDelete = 140,
    /// audit_set_enable — enable/disable audit event types for current process.
    AuditSetEnable = 143,
    /// audit_read_log — read events from the global audit ring buffer.
    AuditReadLog = 144,
    /// cpufreq_get — get current CPU frequency in KHz.
    CpufreqGet = 145,
    /// cpufreq_set — request a CPU frequency in KHz.
    CpufreqSet = 146,
    /// cpufreq_get_range — get (min, max) frequency in KHz (packed).
    CpufreqGetRange = 147,
    /// cpufreq_set_governor — select a frequency-scaling governor.
    CpufreqSetGovernor = 148,
    /// cpufreq_get_temp — get CPU temperature in millidegrees Celsius.
    CpufreqGetTemp = 149,
    /// compact_memory — trigger memory defragmentation (frame compaction).
    CompactMemory = 150,
    /// set_xattr — set an extended attribute on a file/dir (#151).
    SetXattr = 151,
    /// get_xattr — read an extended attribute value (#152).
    GetXattr = 152,
    /// list_xattr — list extended attribute names (#153).
    ListXattr = 153,
    /// remove_xattr — remove an extended attribute (#154).
    RemoveXattr = 154,
    /// set_file_flags — toggle per-file data-reduction flags (#155).
    SetFileFlags = 155,
    /// get_file_flags — read per-file data-reduction flags (#156).
    GetFileFlags = 156,
    /// dccp_bind — bind a DCCP socket to a local port (#157).
    DccpBind = 157,
    /// dccp_listen — start listening for DCCP Requests (#158).
    DccpListen = 158,
    /// dccp_connect — initiate a DCCP connection (#159).
    DccpConnect = 159,
    /// dccp_accept — accept the next pending DCCP connection (#160).
    DccpAccept = 160,
    /// dccp_send — send one DCCP datagram (#161).
    DccpSend = 161,
    /// dccp_recv — receive one DCCP datagram (#162).
    DccpRecv = 162,
    /// dccp_close — close a DCCP socket (#163).
    DccpClose = 163,
    /// ipsec_add_sp — add an IPsec security-policy entry (#164).
    IpsecAddSp = 164,
    /// ipsec_del_sp — remove an IPsec security-policy entry (#165).
    IpsecDelSp = 165,
    /// ipsec_add_sa — add an IPsec security association (#166).
    IpsecAddSa = 166,
    /// ipsec_del_sa — remove an IPsec security association by SPI (#167).
    IpsecDelSa = 167,
    /// ipsec_get_stats — read IPsec statistics (#168).
    IpsecGetStats = 168,
    /// mrt_init — enable multicast routing (#169).
    MrtInit = 169,
    /// mrt_done — disable multicast routing (#170).
    MrtDone = 170,
    /// mrt_add_vif — add a multicast virtual interface (#171).
    MrtAddVif = 171,
    /// mrt_del_vif — remove a multicast virtual interface (#172).
    MrtDelVif = 172,
    /// mrt_add_mfc — add a multicast forwarding-cache entry (#173).
    MrtAddMfc = 173,
    /// mrt_del_mfc — remove a multicast forwarding-cache entry (#174).
    MrtDelMfc = 174,
    /// mac_set_mode — enable/disable MAC enforcement and set the default (#175).
    MacSetMode = 175,
    /// mac_add_rule — add a MAC allow rule (#176).
    MacAddRule = 176,
    /// mac_set_path_type — set an object type override for a path (#177).
    MacSetPathType = 177,
    /// mac_get_status — read MAC policy status (#178).
    MacGetStatus = 178,
    /// fcntl — descriptor control incl. F_SETPIPE_SZ/F_GETPIPE_SZ (#179).
    Fcntl = 179,
    /// sync — flush all filesystems' dirty data to persistent storage (#180).
    Sync = 180,
    /// gpu_ctx_create — create a VIRGL rendering context (#181).
    GpuCtxCreate = 181,
    /// gpu_ctx_destroy — destroy a VIRGL rendering context (#182).
    GpuCtxDestroy = 182,
    /// gpu_res_create_3d — create a 3D resource with kernel-backed DMA (#183).
    GpuResCreate3d = 183,
    /// gpu_res_unref — destroy a 3D resource and release its backing (#184).
    GpuResUnref = 184,
    /// gpu_transfer_to_host_3d — upload user data into a resource (#185).
    GpuTransferToHost3d = 185,
    /// gpu_transfer_from_host_3d — read a resource region back to user (#186).
    GpuTransferFromHost3d = 186,
    /// gpu_submit_3d — submit a VIRGL command stream to a context (#187).
    GpuSubmit3d = 187,
    /// gpu_set_scanout — present a resource on the display (#188).
    GpuSetScanout = 188,
    /// gpu_device_info — report GPU presence and capabilities (#189).
    GpuDeviceInfo = 189,
}

pub(crate) const PUBLIC_SYSCALL_COUNT: u32 = SyscallNumber::GpuDeviceInfo as u32 + 1;

#[derive(Debug, Clone, Copy)]
pub struct SyscallContext {
    pub number: usize,
    pub args: [usize; syscall_abi::ARG_COUNT],
    pub caller_pid: Option<u32>,
}

impl SyscallContext {
    pub const fn new(number: usize, args: [usize; syscall_abi::ARG_COUNT]) -> Self {
        Self {
            number,
            args,
            caller_pid: None,
        }
    }

    /// Return the syscall argument at `index` (0-based).
    ///
    /// # Panics
    ///
    /// Panics if `index >= ARG_COUNT`.  All syscall handlers are expected to
    /// use compile-time-constant indices within bounds; an out-of-bounds
    /// access is a kernel bug and should fail loudly rather than silently
    /// returning 0.
    pub fn arg(&self, index: usize) -> usize {
        self.args[index]
    }
}

pub(crate) fn validate_zeroed_args(context: &SyscallContext, start: usize) -> Result<()> {
    let start = start.min(context.args.len());
    if context.args[start..].iter().any(|&arg| arg != 0) {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

pub(crate) fn validate_known_flags(flags: usize, known_flags: usize) -> Result<()> {
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallAction {
    None,
    Yield,
    Exit {
        status: usize,
    },
    ReturnFromException {
        frame_pointer: usize,
    },
    ExecProcess,
    /// Restore user context from the saved SignalFrame after async signal.
    SigReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallDispatch {
    pub value: usize,
    pub action: SyscallAction,
}

impl SyscallDispatch {
    pub const fn complete(value: usize) -> Self {
        Self {
            value,
            action: SyscallAction::None,
        }
    }

    pub const fn yield_now() -> Self {
        Self {
            value: 0,
            action: SyscallAction::Yield,
        }
    }

    pub const fn exit(status: usize) -> Self {
        Self {
            value: status,
            action: SyscallAction::Exit { status },
        }
    }

    pub const fn return_from_exception(frame_pointer: usize) -> Self {
        Self {
            value: 0,
            action: SyscallAction::ReturnFromException { frame_pointer },
        }
    }

    pub const fn exec_process() -> Self {
        Self {
            value: 0,
            action: SyscallAction::ExecProcess,
        }
    }
}

pub struct Table {
    entries: [Option<SyscallHandler>; MAX_SYSCALLS],
}

const SYSCALL_REGISTRY: &[(usize, SyscallHandler)] = &[
    // Keep all public syscall number-to-handler bindings in one table.
    (SyscallNumber::Yield as usize, misc::yield_now),
    (SyscallNumber::WriteDebug as usize, misc::write_debug),
    (SyscallNumber::Open as usize, fs_path_ops::open),
    (SyscallNumber::OpenAt as usize, fs_path_ops::open_at),
    (SyscallNumber::Exit as usize, misc::exit),
    (SyscallNumber::ReadConsole as usize, misc::read_console),
    (SyscallNumber::Read as usize, io_fd::read),
    (SyscallNumber::Write as usize, io_fd::write),
    (SyscallNumber::Close as usize, io_fd::close),
    (SyscallNumber::Dup as usize, io_fd::duplicate),
    (SyscallNumber::Seek as usize, io_fd::seek),
    (SyscallNumber::ArgCount as usize, launch_metadata::arg_count),
    (SyscallNumber::ArgValue as usize, launch_metadata::arg_value),
    (SyscallNumber::EnvCount as usize, launch_metadata::env_count),
    (SyscallNumber::EnvValue as usize, launch_metadata::env_value),
    (
        SyscallNumber::CurrentDir as usize,
        launch_metadata::current_dir,
    ),
    (SyscallNumber::AppId as usize, launch_metadata::app_id),
    (
        SyscallNumber::AppVersion as usize,
        launch_metadata::app_version,
    ),
    (
        SyscallNumber::ImagePath as usize,
        launch_metadata::image_path,
    ),
    (
        SyscallNumber::ManifestPath as usize,
        launch_metadata::manifest_path,
    ),
    (SyscallNumber::CreateDir as usize, fs_path_ops::create_dir),
    (
        SyscallNumber::CreateDirAt as usize,
        fs_path_ops::create_dir_at,
    ),
    (SyscallNumber::SetLength as usize, io_fd::set_length),
    (SyscallNumber::RemovePath as usize, fs_path_ops::remove_path),
    (
        SyscallNumber::RemovePathAt as usize,
        fs_path_ops::remove_path_at,
    ),
    (SyscallNumber::NetworkStatus as usize, network::status),
    (SyscallNumber::ConnectTcp as usize, network::connect_tcp),
    (SyscallNumber::ListenTcp as usize, network::listen_tcp),
    (SyscallNumber::AcceptTcp as usize, network::accept_tcp),
    (SyscallNumber::BindUdp as usize, network::bind_udp),
    (SyscallNumber::SendToUdp as usize, network::send_to_udp),
    (SyscallNumber::RecvFromUdp as usize, network::recv_from_udp),
    (
        SyscallNumber::ListProcessFaults as usize,
        diagnostic::list_process_faults,
    ),
    (SyscallNumber::Fork as usize, process_launch::fork),
    (
        SyscallNumber::ReclaimPages as usize,
        diagnostic::reclaim_pages,
    ),
    (SyscallNumber::AbiInfo as usize, abi_info::query),
    (SyscallNumber::SendSignal as usize, process_signal::send),
    (SyscallNumber::WaitSignal as usize, process_signal::wait),
    (SyscallNumber::StatAt as usize, fs_metadata::stat_at),
    (
        SyscallNumber::InstallExceptionHandler as usize,
        exception_control::install_handler,
    ),
    (
        SyscallNumber::ReturnFromException as usize,
        exception_control::return_from_exception,
    ),
    (SyscallNumber::WaitProcess as usize, process_wait::dispatch),
    (SyscallNumber::SpawnProcess as usize, process_launch::spawn),
    (SyscallNumber::ExecProcess as usize, process_launch::exec),
    (SyscallNumber::Stat as usize, fs_metadata::stat),
    (SyscallNumber::ReadDir as usize, fs_metadata::read_dir),
    (SyscallNumber::Rename as usize, fs_metadata::rename),
    (SyscallNumber::RenameAt as usize, fs_metadata::rename_at),
    (SyscallNumber::StatFd as usize, fs_metadata::stat_fd),
    (SyscallNumber::ReadDirFd as usize, fs_metadata::read_dir_fd),
    (
        SyscallNumber::AccessQuery as usize,
        fs_metadata::access_query,
    ),
    (
        SyscallNumber::AccessQueryAt as usize,
        fs_metadata::access_query_at,
    ),
    (
        SyscallNumber::AccessQueryFd as usize,
        fs_metadata::access_query_fd,
    ),
    (
        SyscallNumber::PermissionMetadata as usize,
        fs_metadata::permission_metadata,
    ),
    (
        SyscallNumber::PermissionMetadataAt as usize,
        fs_metadata::permission_metadata_at,
    ),
    (
        SyscallNumber::PermissionMetadataFd as usize,
        fs_metadata::permission_metadata_fd,
    ),
    (SyscallNumber::SetFdFlags as usize, io_fd::set_fd_flags),
    (SyscallNumber::Sleep as usize, diagnostic::sleep),
    (
        SyscallNumber::ListProcesses as usize,
        diagnostic::list_processes,
    ),
    (
        SyscallNumber::ListThreads as usize,
        diagnostic::list_threads,
    ),
    (SyscallNumber::KernelLog as usize, diagnostic::kernel_log),
    (SyscallNumber::SystemInfo as usize, diagnostic::system_info),
    (SyscallNumber::Fsync as usize, io_fd::fsync),
    (SyscallNumber::Fdatasync as usize, io_fd::fdatasync),
    (SyscallNumber::Pipe as usize, io_fd::pipe),
    (SyscallNumber::Mount as usize, fs_path_ops::mount),
    (SyscallNumber::Umount as usize, fs_path_ops::umount),
    (SyscallNumber::Mmap as usize, memory_map::mmap),
    (SyscallNumber::Munmap as usize, memory_map::munmap),
    (SyscallNumber::Dup2 as usize, io_fd::duplicate2),
    (SyscallNumber::GetTimeOfDay as usize, misc::gettimeofday),
    (SyscallNumber::GetHostName as usize, misc::gethostname),
    (SyscallNumber::SetHostName as usize, misc::sethostname),
    (SyscallNumber::GetSockName as usize, network::getsockname),
    (SyscallNumber::GetPeerName as usize, network::getpeername),
    (SyscallNumber::GetRandom as usize, misc::getrandom),
    (
        SyscallNumber::CreateRawSocket as usize,
        network::create_raw_socket,
    ),
    (
        SyscallNumber::SendRawPacket as usize,
        network::send_raw_packet,
    ),
    (
        SyscallNumber::RecvRawPacket as usize,
        network::recv_raw_packet,
    ),
    (SyscallNumber::SetSockOpt as usize, network::setsockopt),
    (SyscallNumber::GetSockOpt as usize, network::getsockopt),
    // Phase 1: identity + chdir syscalls
    (SyscallNumber::GetPid as usize, process_identity::getpid),
    (SyscallNumber::GetPpid as usize, process_identity::getppid),
    (SyscallNumber::GetUid as usize, process_identity::getuid),
    (SyscallNumber::GetGid as usize, process_identity::getgid),
    (
        SyscallNumber::SetCurrentDir as usize,
        process_chdir::set_current_dir,
    ),
    // Phase 3: filesystem query syscalls
    (SyscallNumber::ListMounts as usize, fs_query::list_mounts),
    (
        SyscallNumber::ListBlockDevices as usize,
        fs_query::list_block_devices,
    ),
    (
        SyscallNumber::SetSecurityDescriptor as usize,
        fs_query::set_security_descriptor,
    ),
    // Phase 3: user management syscalls
    (SyscallNumber::AddUser as usize, fs_user_mgmt::add_user),
    (
        SyscallNumber::RemoveUser as usize,
        fs_user_mgmt::remove_user,
    ),
    (
        SyscallNumber::SetUserPassword as usize,
        fs_user_mgmt::set_user_password,
    ),
    // Phase 4a: brk syscall
    (SyscallNumber::Brk as usize, memory_brk::brk),
    // Phase 7c: DNS hostname resolution (reuses freed AppService slot).
    (
        SyscallNumber::ResolveHostname as usize,
        network::resolve_hostname,
    ),
    // Phase 8c: POSIX signal mask control.
    (
        SyscallNumber::SetSignalMask as usize,
        process_signal_mask::set_signal_mask,
    ),
    // Phase 8c: user-space signal handler registration.
    (
        SyscallNumber::SetSignalHandler as usize,
        process_signal::set_handler,
    ),
    // Phase 6e: volume check-and-repair.
    (
        SyscallNumber::RepairVolume as usize,
        fs_query::repair_volume,
    ),
    // Phase 8d: multi-fd readiness polling.
    (SyscallNumber::Poll as usize, io_fd::poll),
    // Phase 8d: Unix domain (local) sockets.
    (
        SyscallNumber::BindLocal as usize,
        network_local::bind_local_socket,
    ),
    (
        SyscallNumber::ConnectLocal as usize,
        network_local::connect_local_socket,
    ),
    (
        SyscallNumber::AcceptLocal as usize,
        network_local::accept_local_socket,
    ),
    // Priority Gap #2: SystV shared memory.
    (SyscallNumber::ShmGet as usize, memory_shm::shmget),
    (SyscallNumber::ShmAt as usize, memory_shm::shmat),
    (SyscallNumber::ShmDt as usize, memory_shm::shmdt),
    (SyscallNumber::ShmCtl as usize, memory_shm::shmctl),
    // FUSE (Filesystem in Userspace) mount.
    (SyscallNumber::FuseMount as usize, fs_fuse_mount::fuse_mount),
    // Futex — fast userspace mutex (FUTEX_WAIT / FUTEX_WAKE).
    (SyscallNumber::Futex as usize, futex::futex),
    // eventfd — lightweight event notification.
    (SyscallNumber::EventFd as usize, event_fd::eventfd),
    // signalfd — signal notification via file descriptor.
    (SyscallNumber::SignalFd as usize, signal_fd::signalfd),
    // timerfd — timer expiration notification.
    (SyscallNumber::TimerFd as usize, timer_fd::timerfd),
    // sched_setaffinity — pin thread to specific CPUs.
    (
        SyscallNumber::SchedSetAffinity as usize,
        sched_affinity::sched_setaffinity,
    ),
    // sched_getaffinity — get thread CPU affinity mask.
    (
        SyscallNumber::SchedGetAffinity as usize,
        sched_affinity::sched_getaffinity,
    ),
    // mq_open — open or create a named message queue.
    (SyscallNumber::MqOpen as usize, mq::mq_open),
    // mq_close — close a message queue fd.
    (SyscallNumber::MqClose as usize, mq::mq_close),
    // mq_send — send a message to a queue.
    (SyscallNumber::MqSend as usize, mq::mq_send),
    // mq_receive — receive a message from a queue.
    (SyscallNumber::MqReceive as usize, mq::mq_receive),
    // mq_notify — register for signal notification.
    (SyscallNumber::MqNotify as usize, mq::mq_notify),
    // mq_unlink — remove a named message queue.
    (SyscallNumber::MqUnlink as usize, mq::mq_unlink),
    // epoll_create — create an epoll instance.
    (SyscallNumber::EpollCreate as usize, epoll::epoll_create),
    // epoll_ctl — control epoll interest list.
    (SyscallNumber::EpollCtl as usize, epoll::epoll_ctl),
    // epoll_wait — wait for events on epoll fds.
    (SyscallNumber::EpollWait as usize, epoll::epoll_wait),
    // tls_connect — establish a TLS 1.3 encrypted connection.
    (SyscallNumber::TlsConnect as usize, tls_handler::tls_connect),
    // filter_add_rule — add a packet filter rule.
    (
        SyscallNumber::FilterAddRule as usize,
        filter_handler::filter_add_rule,
    ),
    // filter_remove_rule — remove a packet filter rule.
    (
        SyscallNumber::FilterRemoveRule as usize,
        filter_handler::filter_remove_rule,
    ),
    // filter_set_default_action — set default filter policy.
    (
        SyscallNumber::FilterSetDefaultAction as usize,
        filter_handler::filter_set_default_action,
    ),
    // filter_get_stats — retrieve filter statistics.
    (
        SyscallNumber::FilterGetStats as usize,
        filter_handler::filter_get_stats,
    ),
    // io_uring_setup — create an io_uring async I/O instance.
    (
        SyscallNumber::IoUringSetup as usize,
        io_uring_handler::io_uring_setup,
    ),
    // io_uring_enter — submit SQEs and/or reap CQEs.
    (
        SyscallNumber::IoUringEnter as usize,
        io_uring_handler::io_uring_enter,
    ),
    // ptrace — process tracing control.
    (SyscallNumber::Ptrace as usize, ptrace_handler::ptrace),
    // seccomp — secure computing / syscall filtering.
    (SyscallNumber::Seccomp as usize, seccomp_handler::seccomp),
    // prctl — process control operations.
    (SyscallNumber::Prctl as usize, prctl_handler::prctl),
    // mlock — lock memory pages.
    (SyscallNumber::Mlock as usize, memory_mlock::mlock),
    // munlock — unlock memory pages.
    (SyscallNumber::Munlock as usize, memory_mlock::munlock),
    // madvise — give advice about memory use.
    (SyscallNumber::Madvise as usize, memory_madvise::madvise),
    // sigreturn — restore user context after async signal handler.
    (SyscallNumber::SigReturn as usize, process_signal::sigreturn),
    // sigsuspend — atomically set signal mask and suspend execution.
    (
        SyscallNumber::SigSuspend as usize,
        process_sigsuspend::sigsuspend,
    ),
    // restart_syscall — re-issue an interrupted blocking syscall.
    (
        SyscallNumber::RestartSyscall as usize,
        process_restart_syscall::restart_syscall,
    ),
    // ── POSIX per-process timers (#137–140) ────────────────────────────────
    (
        SyscallNumber::TimerCreate as usize,
        posix_timer::timer_create,
    ),
    (
        SyscallNumber::TimerSetTime as usize,
        posix_timer::timer_settime,
    ),
    (
        SyscallNumber::TimerGetTime as usize,
        posix_timer::timer_gettime,
    ),
    (
        SyscallNumber::TimerDelete as usize,
        posix_timer::timer_delete,
    ),
    // Gap filler for unused slots (#141–#142).
    (141, |_| Err(Error::NotImplemented)),
    (142, |_| Err(Error::NotImplemented)),
    // ── Audit subsystem (#143–144) ─────────────────────────────────────────
    (
        SyscallNumber::AuditSetEnable as usize,
        audit_handler::audit_set_enable,
    ),
    (
        SyscallNumber::AuditReadLog as usize,
        audit_handler::audit_read_log,
    ),
    // ── CPU frequency scaling (#145–149) ───────────────────────────────────
    (
        SyscallNumber::CpufreqGet as usize,
        power_handler::cpufreq_get,
    ),
    (
        SyscallNumber::CpufreqSet as usize,
        power_handler::cpufreq_set,
    ),
    (
        SyscallNumber::CpufreqGetRange as usize,
        power_handler::cpufreq_get_range,
    ),
    (
        SyscallNumber::CpufreqSetGovernor as usize,
        power_handler::cpufreq_set_governor,
    ),
    (
        SyscallNumber::CpufreqGetTemp as usize,
        power_handler::cpufreq_get_temp,
    ),
    // ── Memory defragmentation (#150) ──────────────────────────────────────
    (
        SyscallNumber::CompactMemory as usize,
        diagnostic::compact_memory,
    ),
    // ── Extended attributes + per-file data-reduction flags (#151-156) ───
    (SyscallNumber::SetXattr as usize, fs_xattr::set_xattr),
    (SyscallNumber::GetXattr as usize, fs_xattr::get_xattr),
    (SyscallNumber::ListXattr as usize, fs_xattr::list_xattr),
    (SyscallNumber::RemoveXattr as usize, fs_xattr::remove_xattr),
    (
        SyscallNumber::SetFileFlags as usize,
        fs_xattr::set_file_flags,
    ),
    (
        SyscallNumber::GetFileFlags as usize,
        fs_xattr::get_file_flags,
    ),
    // ── DCCP transport (#157-163) ─────────────────────────────────────────
    (SyscallNumber::DccpBind as usize, network::dccp_bind),
    (SyscallNumber::DccpListen as usize, network::dccp_listen),
    (SyscallNumber::DccpConnect as usize, network::dccp_connect),
    (SyscallNumber::DccpAccept as usize, network::dccp_accept),
    (SyscallNumber::DccpSend as usize, network::dccp_send),
    (SyscallNumber::DccpRecv as usize, network::dccp_recv),
    (SyscallNumber::DccpClose as usize, network::dccp_close),
    // ── IPsec SPD/SAD (#164-168) ───────────────────────────────────────
    (
        SyscallNumber::IpsecAddSp as usize,
        ipsec_handler::ipsec_add_sp,
    ),
    (
        SyscallNumber::IpsecDelSp as usize,
        ipsec_handler::ipsec_del_sp,
    ),
    (
        SyscallNumber::IpsecAddSa as usize,
        ipsec_handler::ipsec_add_sa,
    ),
    (
        SyscallNumber::IpsecDelSa as usize,
        ipsec_handler::ipsec_del_sa,
    ),
    (
        SyscallNumber::IpsecGetStats as usize,
        ipsec_handler::ipsec_get_stats,
    ),
    // ── Multicast routing (#169-174) ────────────────────────────────────
    (SyscallNumber::MrtInit as usize, mrt_handler::mrt_init),
    (SyscallNumber::MrtDone as usize, mrt_handler::mrt_done),
    (SyscallNumber::MrtAddVif as usize, mrt_handler::mrt_add_vif),
    (SyscallNumber::MrtDelVif as usize, mrt_handler::mrt_del_vif),
    (SyscallNumber::MrtAddMfc as usize, mrt_handler::mrt_add_mfc),
    (SyscallNumber::MrtDelMfc as usize, mrt_handler::mrt_del_mfc),
    // ── MAC type enforcement (#175-178) ──────────────────────────────────
    (
        SyscallNumber::MacSetMode as usize,
        mac_handler::mac_set_mode,
    ),
    (
        SyscallNumber::MacAddRule as usize,
        mac_handler::mac_add_rule,
    ),
    (
        SyscallNumber::MacSetPathType as usize,
        mac_handler::mac_set_path_type,
    ),
    (
        SyscallNumber::MacGetStatus as usize,
        mac_handler::mac_get_status,
    ),
    // ── fcntl descriptor control (#179) ─────────────────────────────────
    (SyscallNumber::Fcntl as usize, fcntl_handler::fcntl),
    // ── Global filesystem sync (#180) ──────────────────────────────────
    (SyscallNumber::Sync as usize, sync_handler::sync),
    // ── VIRGL 3D userspace interface (#181-189) ────────────────────────
    (
        SyscallNumber::GpuCtxCreate as usize,
        gpu_handler::gpu_ctx_create,
    ),
    (
        SyscallNumber::GpuCtxDestroy as usize,
        gpu_handler::gpu_ctx_destroy,
    ),
    (
        SyscallNumber::GpuResCreate3d as usize,
        gpu_handler::gpu_res_create_3d,
    ),
    (
        SyscallNumber::GpuResUnref as usize,
        gpu_handler::gpu_res_unref,
    ),
    (
        SyscallNumber::GpuTransferToHost3d as usize,
        gpu_handler::gpu_transfer_to_host_3d,
    ),
    (
        SyscallNumber::GpuTransferFromHost3d as usize,
        gpu_handler::gpu_transfer_from_host_3d,
    ),
    (
        SyscallNumber::GpuSubmit3d as usize,
        gpu_handler::gpu_submit_3d,
    ),
    (
        SyscallNumber::GpuSetScanout as usize,
        gpu_handler::gpu_set_scanout,
    ),
    (
        SyscallNumber::GpuDeviceInfo as usize,
        gpu_handler::gpu_device_info,
    ),
];

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SYSCALLS],
        }
    }

    pub fn init(&mut self) {
        // Register in bulk from the canonical static registry.
        for &(number, handler) in SYSCALL_REGISTRY {
            let _ = self.register(number, handler);
        }
    }

    pub fn register(&mut self, number: usize, handler: SyscallHandler) -> Result<()> {
        let slot = self.entries.get_mut(number).ok_or(Error::InvalidArgument)?;
        *slot = Some(handler);
        Ok(())
    }

    pub fn dispatch_with_action(&self, context: &mut SyscallContext) -> Result<SyscallDispatch> {
        let number = context.number;

        // ── Seccomp pre-dispatch check ────────────────────────────────────────
        // Check the seccomp filter before calling the syscall handler so that
        // blocked syscalls are never executed.  KILL terminates the process
        // immediately; TRAP returns an error (SIGSYS semantics); ALLOW continues.
        if let Ok(process) = runtime::current_process() {
            match crate::kernel::process::seccomp::check_syscall(&process, number) {
                crate::abi::seccomp::SECCOMP_ACTION_KILL => {
                    // Process killed by seccomp (exit status = 128 + SIGSYS).
                    return Ok(SyscallDispatch::exit(159));
                }
                crate::abi::seccomp::SECCOMP_ACTION_TRAP => {
                    return Err(Error::PermissionDenied);
                }
                _ => {} // SECCOMP_ACTION_ALLOW — continue normally.
            }
        }

        let result = self
            .entries
            .get(number)
            .and_then(|entry| *entry)
            .ok_or(Error::NotImplemented)?(context);

        // ── Ptrace syscall-exit hook ────────────────────────────────────────
        // When the tracee is being syscall-traced, notify ptrace after every
        // syscall completes.  If the tracee was suspended we yield the CPU
        // so the tracer can process the event.
        if result.is_ok() {
            if let Ok(process) = runtime::current_process() {
                let dispatch_value: Result<usize> =
                    result.as_ref().map(|d| d.value).map_err(|e| *e);
                if crate::kernel::process::ptrace::notify_syscall_exit(
                    &process,
                    number,
                    &dispatch_value,
                ) {
                    return Ok(SyscallDispatch {
                        value: 0,
                        action: SyscallAction::Yield,
                    });
                }
            }
        }

        // ── Audit syscall-exit hook ───────────────────────────────────────────
        // When the current process has enabled SYSCALL auditing, emit an audit
        // record with the syscall number, arguments, and status.
        if let Ok(process) = runtime::current_process() {
            let mask = process.audit_enable_mask();
            if mask & crate::kernel::audit::types::AUDIT_ENABLE_SYSCALL != 0 {
                let syscall_number = number;
                let args = context.args;
                let result_value = match &result {
                    Ok(disp) => disp.value as i64,
                    Err(err) => -(*err as i64),
                };

                let mut record = crate::kernel::audit::types::AuditRecord::zeroed();
                let ts = crate::kernel::process::Scheduler::global()
                    .map(|s| s.current_tick())
                    .unwrap_or(0);
                let pid = process.pid();
                let uid = process.security_token().user_id;

                // Build a compact payload: syscall number + up to 6 args.
                let mut payload = [0u8; 56];
                let payload_size = {
                    let n = &mut payload;
                    n[..8].copy_from_slice(&syscall_number.to_ne_bytes());
                    for (i, arg) in args.iter().enumerate() {
                        let base = 8 + i * 8;
                        n[base..base + 8].copy_from_slice(&arg.to_ne_bytes());
                    }
                    56usize
                };

                record.fill(
                    0,
                    0,
                    ts,
                    crate::kernel::audit::types::AuditEventType::Syscall,
                    pid,
                    uid,
                    result_value,
                    &payload[..payload_size],
                );

                let _ = crate::kernel::audit::emit_record(record);
            }
        }

        result
    }

    pub fn dispatch(&self, context: &mut SyscallContext) -> Result<usize> {
        self.dispatch_with_action(context)
            .map(|dispatch| dispatch.value)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use crate::arch::mmu::materialize_user_address_space;
    use crate::kernel::memory::paging::PagePermissions;
    use crate::kernel::process::{Process, ProcessUserAddressSpace};
    use crate::kernel::sync::Mutex as KernelMutex;
    use crate::user::program::{
        UserImageLoadPlan, UserImageSegmentPlan, USER_EXCEPTION_STACK_GUARD_SIZE,
        USER_EXCEPTION_STACK_SIZE, USER_IMAGE_STACK_GAP, USER_PAGE_SIZE, USER_STACK_GUARD_SIZE,
        USER_STACK_SIZE, X86_64_USER_STACK_TOP,
    };
    use crate::Error;

    use super::user_memory::{copy_user_bytes, validate_user_mapping};
    use super::{
        validate_known_flags, validate_zeroed_args, SyscallContext, SyscallNumber, Table,
        PUBLIC_SYSCALL_COUNT,
    };

    #[derive(Clone)]
    struct ValidationFixture {
        process: Arc<crate::kernel::process::Process>,
        entry_point: usize,
        image_end: usize,
        stack_bottom: usize,
        stack_pointer: usize,
        guard_start: usize,
    }

    fn build_validation_fixture() -> ValidationFixture {
        let entry_point = 0x0000_0000_0040_1000;
        let image_start = 0x0000_0000_0040_1000;
        let image_end = image_start + USER_PAGE_SIZE;
        let stack_top = X86_64_USER_STACK_TOP;
        let stack_bottom = stack_top - USER_STACK_SIZE;
        let stack_guard_start = stack_bottom - USER_STACK_GUARD_SIZE;
        let exception_stack_top = stack_guard_start;
        let exception_stack_bottom = exception_stack_top - USER_EXCEPTION_STACK_SIZE;
        let exception_stack_guard_start = exception_stack_bottom - USER_EXCEPTION_STACK_GUARD_SIZE;

        assert!(image_end + USER_IMAGE_STACK_GAP <= exception_stack_guard_start);

        let plan = UserImageLoadPlan {
            entry_point,
            image_start,
            image_end,
            stack_guard_start,
            stack_guard_end: stack_bottom,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end: exception_stack_bottom,
            exception_stack_bottom,
            exception_stack_top,
            segments: alloc::vec![UserImageSegmentPlan {
                virtual_start: image_start,
                virtual_end: image_end,
                page_start: image_start,
                page_end: image_end,
                file_offset: 0,
                file_size: USER_PAGE_SIZE,
                zero_start: image_end,
                zero_end: image_end,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };
        let image = alloc::vec![0x90_u8; USER_PAGE_SIZE];
        let prepared =
            materialize_user_address_space(&plan, &image).expect("materialize user address space");
        let process = Process::new(7, "validation-user");
        process.install_user_address_space(ProcessUserAddressSpace::from_prepared_user(prepared));

        ValidationFixture {
            process,
            entry_point,
            image_end,
            stack_bottom,
            stack_pointer: stack_top - core::mem::size_of::<usize>(),
            guard_start: stack_guard_start,
        }
    }

    fn validation_fixture() -> ValidationFixture {
        static FIXTURE: KernelMutex<Option<ValidationFixture>> = KernelMutex::new(None);
        let mut slot = FIXTURE.lock();
        if let Some(fixture) = slot.as_ref() {
            return fixture.clone();
        }

        let fixture = build_validation_fixture();
        *slot = Some(fixture.clone());
        fixture
    }

    #[test]
    fn table_init_registers_every_public_syscall_slot() {
        let mut table = Table::new();
        table.init();

        for number in 0..PUBLIC_SYSCALL_COUNT as usize {
            assert!(
                table.entries[number].is_some(),
                "syscall slot {number} should be registered"
            );
        }

        assert_eq!(
            PUBLIC_SYSCALL_COUNT,
            SyscallNumber::GpuDeviceInfo as u32 + 1
        );
        assert!(table.entries[PUBLIC_SYSCALL_COUNT as usize].is_none());
    }

    #[test]
    fn validate_user_mapping_accepts_readable_user_pages() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.stack_pointer,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_zero_length_without_translation() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                usize::MAX,
                0,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_single_byte_at_mapped_page_tail() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.image_end - 1,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_exact_mapped_page_range() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                USER_PAGE_SIZE,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_rejects_unmapped_user_pages() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.guard_start,
                1,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_mapping_rejects_missing_permissions() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                1,
                PagePermissions::WRITE,
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn validate_user_mapping_accepts_ranges_crossing_mapped_stack_pages() {
        let fixture = validation_fixture();
        let cross_page_start = fixture.stack_bottom + USER_PAGE_SIZE - 1;

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                cross_page_start,
                2,
                PagePermissions::READ,
            ),
            Ok(())
        );
        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                cross_page_start,
                2,
                PagePermissions::WRITE,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_rejects_ranges_crossing_into_unmapped_gap() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.image_end - 1,
                2,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_mapping_rejects_address_range_overflow() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                usize::MAX,
                2,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn copy_user_bytes_allows_zero_length_size_query() {
        assert_eq!(copy_user_bytes(b"hello", core::ptr::null_mut(), 0), Ok(5));
    }

    #[test]
    fn copy_user_bytes_rejects_null_buffer_for_non_empty_copy() {
        assert_eq!(
            copy_user_bytes(b"hello", core::ptr::null_mut(), 5),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn copy_user_bytes_rejects_short_buffer() {
        let mut buffer = [0_u8; 4];

        assert_eq!(
            copy_user_bytes(b"hello", buffer.as_mut_ptr(), buffer.len()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(buffer, [0; 4]);
    }

    #[test]
    fn validate_zeroed_args_accepts_zeroed_trailing_slots() {
        let context = SyscallContext::new(0, [1, 2, 0, 0, 0, 0]);

        assert_eq!(validate_zeroed_args(&context, 2), Ok(()));
        assert_eq!(validate_zeroed_args(&context, 6), Ok(()));
    }

    #[test]
    fn validate_zeroed_args_rejects_non_zero_trailing_slots() {
        let context = SyscallContext::new(0, [1, 2, 0, 0, 7, 0]);

        assert_eq!(
            validate_zeroed_args(&context, 2),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_zeroed_args(&context, 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_known_flags_accepts_subsets_and_rejects_unknown_bits() {
        assert_eq!(validate_known_flags(0b0011, 0b0111), Ok(()));
        assert_eq!(
            validate_known_flags(0b1000, 0b0111),
            Err(Error::InvalidArgument)
        );
    }
}
