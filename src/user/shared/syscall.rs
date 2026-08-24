//! src/user/shared/syscall.rs
//!
//! Syscall abstraction bridge between ring0 (kernel) and ring3 (user-space).
//!
//! This module declares `extern "Rust"` functions that each environment must
//! implement.  The kernel wires them to `UserSyscall` + `syscall::dispatch()`;
//! ring3 programs wire them to `int 0x80` / `svc #0`.
//!
//! Higher-level wrapper functions (`sys_open`, `sys_read`, etc.) provide
//! a safe, typed interface that command implementations call.
//!
//! # Syscall numbers
//!
//! The canonical syscall-number definitions live in `crate::user::shared::abi::syscall`
//! (single source of truth, shared with the kernel's `SyscallNumber` enum).
//! They are re-exported below so existing `SYS_*` references keep resolving.

// ── Syscall numbers ─────────────────────────────────────────────────────
//
// Canonical syscall-number definitions live in `crate::user::shared::abi::syscall`
// (the single source of truth shared with the kernel).  Re-exported here
// so existing bare `SYS_*` references keep resolving.

pub use crate::user::shared::abi::syscall::*;

// ── Raw syscall entry points ─────────────────────────────────────────────
//
// Each environment (kernel, ring3-shell) provides these symbols.  In the
// kernel the real definitions live in `crate::user::program::shell::syscall_bridge`,
// which satisfies these declarations in both host tests and bare-metal builds
// (the extern declarations are kept unconditional so host-side unit tests can
// resolve the bare `__shell_syscallN` names against the `#[no_mangle]` bridge).

extern "Rust" {
    fn __shell_syscall0(number: usize) -> isize;
    fn __shell_syscall1(number: usize, a0: usize) -> isize;
    fn __shell_syscall2(number: usize, a0: usize, a1: usize) -> isize;
    fn __shell_syscall3(number: usize, a0: usize, a1: usize, a2: usize) -> isize;
    fn __shell_syscall4(number: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize;
    fn __shell_syscall5(
        number: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> isize;
    fn __shell_syscall6(
        number: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
    ) -> isize;
}

// NOTE: the former crate shipped `#[cfg(test)] #[no_mangle]` stubs for the
// `__shell_syscallN` symbols so it could unit-test standalone.  Merged into
// the kernel, those would collide with the real definitions in
// `crate::user::program::shell::syscall_bridge`, so they were dropped; the
// bridge satisfies the extern declarations above in both host tests and
// bare-metal builds.

/// Decode a raw syscall status word into `Ok(value)` or `Err(negative errno)`.
/// The kernel encodes errors as large unsigned values near `usize::MAX`.
#[inline(always)]
fn decode(status: isize) -> Result<usize, isize> {
    if status < 0 {
        Err(status)
    } else {
        Ok(status as usize)
    }
}

// ── Higher-level syscall wrappers ───────────────────────────────────────

/// Open a file by path.  Returns fd on success.
pub fn sys_open(path: &str, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_OPEN, path.as_ptr() as usize, path.len(), flags) };
    decode(rc)
}

/// Read from a file descriptor into `buf`.  Returns bytes read (0 = EOF).
pub fn sys_read(fd: usize, buf: &mut [u8], timeout_ticks: u64) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_READ,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            timeout_ticks as usize,
            0,
        )
    };
    decode(rc)
}

/// Write `data` to a file descriptor.  Returns bytes written.
pub fn sys_write(fd: usize, data: &[u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_WRITE, fd, data.as_ptr() as usize, data.len()) };
    decode(rc)
}

/// Close a file descriptor.
pub fn sys_close(fd: usize) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall1(SYS_CLOSE, fd) };
    decode(rc).map(|_| ())
}

/// Stat a file by path, filling the provided `FileStat` record.
pub fn sys_stat(path: &str, record: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_STAT,
            path.as_ptr() as usize,
            path.len(),
            record.as_mut_ptr() as usize,
            record.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Stat a file by fd, filling the provided `FileStat` record.
pub fn sys_stat_fd(fd: usize, record: &mut [u8]) -> Result<(), isize> {
    let rc =
        unsafe { __shell_syscall3(SYS_STAT_FD, fd, record.as_mut_ptr() as usize, record.len()) };
    decode(rc).map(|_| ())
}

/// Read a directory entry at `index`.  The entry is written into `buf`.
pub fn sys_read_dir(path: &str, index: usize, buf: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_READ_DIR,
            path.as_ptr() as usize,
            path.len(),
            index,
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Read a directory entry by fd at `index`.
pub fn sys_read_dir_fd(fd: usize, index: usize, buf: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_READ_DIR_FD,
            fd,
            index,
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Get the current working directory.  Returns bytes written to `buf`.
pub fn sys_current_dir(buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_CURRENT_DIR, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Set the current working directory.
pub fn sys_set_current_dir(path: &str) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall2(SYS_SET_CURRENT_DIR, path.as_ptr() as usize, path.len()) };
    decode(rc).map(|_| ())
}

/// Create a directory.
pub fn sys_make_dir(path: &str) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall2(SYS_CREATE_DIR, path.as_ptr() as usize, path.len()) };
    decode(rc).map(|_| ())
}

/// Remove a file or empty directory.
pub fn sys_remove_path(path: &str) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall2(SYS_REMOVE_PATH, path.as_ptr() as usize, path.len()) };
    decode(rc).map(|_| ())
}

/// Rename a file or directory.
pub fn sys_rename(old_path: &str, new_path: &str) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_RENAME,
            old_path.as_ptr() as usize,
            old_path.len(),
            new_path.as_ptr() as usize,
            new_path.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Truncate a file to `len` bytes.
pub fn sys_set_len(fd: usize, len: usize) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall2(SYS_SET_LENGTH, fd, len) };
    decode(rc).map(|_| ())
}

/// List processes into `buf`.  Returns bytes written.
pub fn sys_list_processes(buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_LIST_PROCESSES, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// List threads for a process.  Returns bytes written.
pub fn sys_list_threads(pid: usize, buf: &mut [u8]) -> Result<usize, isize> {
    let rc =
        unsafe { __shell_syscall3(SYS_LIST_THREADS, pid, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Query system information.  Returns bytes written to `buf`.
pub fn sys_system_info(selector: u64, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_SYSTEM_INFO,
            selector as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    };
    decode(rc)
}

/// SystemInfo selector: interrupt profiler (per-CPU/per-vector IRQ counts,
/// IPI/NMI totals, and load-balancer state).
pub const SYSTEM_INFO_IRQ_PROFILER: u64 = 9;

/// Query the interrupt profiler into `buf`.  Returns bytes written.
pub fn sys_irq_profiler(buf: &mut [u8]) -> Result<usize, isize> {
    sys_system_info(SYSTEM_INFO_IRQ_PROFILER, buf)
}

/// Read kernel log.  Returns bytes written to `buf`.
pub fn sys_kernel_log(buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_KERNEL_LOG, 0, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Probe kernel log size without copying data.  Returns total byte count.
pub fn sys_kernel_log_probe() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_KERNEL_LOG, 0, 0, 0) };
    decode(rc)
}

/// Get current process ID.
pub fn sys_getpid() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_GETPID) };
    decode(rc)
}

/// Get current user ID.
pub fn sys_getuid() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_GETUID) };
    decode(rc)
}

/// Return the current process's group ID.
/// Returns the primary GID as a `usize`, or a negative error code on failure.
pub fn sys_getgid() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_GETGID) };
    decode(rc)
}

/// Send a signal to a process.
pub fn sys_send_signal(pid: usize, signal: usize, payload: usize) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall4(SYS_SEND_SIGNAL, pid, signal, payload, 0) };
    decode(rc).map(|_| ())
}

/// Wait for a signal.  Fills `record` buffer.
pub fn sys_wait_signal(timeout_ticks: u64, record: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_WAIT_SIGNAL,
            timeout_ticks as usize,
            record.as_mut_ptr() as usize,
            record.len(),
            0,
        )
    };
    decode(rc).map(|_| ())
}

/// Wait for a child process to terminate.  Fills `record` buffer.
pub fn sys_wait_process(pid: usize, timeout_ticks: u64, record: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_WAIT_PROCESS,
            pid,
            timeout_ticks as usize,
            record.as_mut_ptr() as usize,
            record.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Spawn a new process.
pub fn sys_spawn_process(
    path: &str,
    options_ptr: usize,
    options_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_SPAWN_PROCESS,
            path.as_ptr() as usize,
            path.len(),
            options_ptr,
            options_len,
        )
    };
    decode(rc)
}

/// Query access permissions for a path.
pub fn sys_access_query(path: &str, required_access: u16, record: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_ACCESS_QUERY,
            path.as_ptr() as usize,
            path.len(),
            required_access as usize,
            record.as_mut_ptr() as usize,
            record.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Query permission metadata for a path.
pub fn sys_permission_metadata(path: &str, record: &mut [u8]) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_PERMISSION_METADATA,
            path.as_ptr() as usize,
            path.len(),
            record.as_mut_ptr() as usize,
            record.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Sleep for `seconds` (converted to scheduler ticks internally).
pub fn sys_sleep(seconds: u64) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall1(SYS_SLEEP, seconds as usize) };
    decode(rc).map(|_| ())
}

/// List mount points.  Returns bytes written to `buf`.
pub fn sys_list_mounts(buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_LIST_MOUNTS, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// List block devices.  Returns bytes written to `buf`.
pub fn sys_list_block_devices(buf: &mut [u8]) -> Result<usize, isize> {
    let rc =
        unsafe { __shell_syscall2(SYS_LIST_BLOCK_DEVICES, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Volume check-and-repair report returned by [`sys_repair_volume`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VolumeRepairReport {
    pub issues_detected: u64,
    pub repairs_applied: u64,
    pub orphan_data_blocks: u64,
    pub checksum_failures: u64,
    pub staging_orphans_cleaned: u64,
    pub orphan_blocks_cleaned: u64,
    pub interrupted_commits: u64,
}

impl VolumeRepairReport {
    pub const fn is_clean(self) -> bool {
        self.issues_detected == 0 && self.orphan_data_blocks == 0 && self.checksum_failures == 0
    }

    pub const fn repaired(self) -> bool {
        self.repairs_applied != 0
    }
}

/// Check and repair a mounted volume at `path`.
///
/// Writes the [`VolumeRepairReport`] into `buf` and returns the number of
/// bytes written (always `core::mem::size_of::<VolumeRepairReport>()` on
/// success).
pub fn sys_repair_volume(path: &str, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_REPAIR_VOLUME,
            path.as_ptr() as usize,
            path.len(),
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    };
    decode(rc)
}

/// Set security descriptor (mode, owner) on a path.
pub fn sys_set_security_descriptor(
    path: &str,
    flags: u32,
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_SET_SECURITY_DESCRIPTOR,
            path.as_ptr() as usize,
            path.len(),
            flags as usize,
            mode as usize,
            uid as usize,
            gid as usize,
        )
    };
    decode(rc).map(|_| ())
}

/// Add a new user to the kernel user database (syscall 89).
///
/// On success the user record is persisted to `/data/etc/passwd` and a home
/// directory skeleton is created.  Returns an error if the user already exists.
pub fn sys_add_user(username: &str, uid: u32, gid: u32, home: &str) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_ADD_USER,
            username.as_ptr() as usize,
            username.len(),
            uid as usize,
            gid as usize,
            home.as_ptr() as usize,
            home.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Remove a user from the kernel user database (syscall 90).
///
/// Refuses to remove the root user (uid 0).  On success the user record is
/// removed from the passwd database and persisted.
pub fn sys_remove_user(uid: u32) -> Result<(), isize> {
    let rc = unsafe { __shell_syscall2(SYS_REMOVE_USER, uid as usize, 0) };
    decode(rc).map(|_| ())
}

/// Set a user's password (syscall 91).
///
/// The password is hashed with a random salt and stored in the shadow database
/// (`/data/etc/shadow`).
pub fn sys_set_user_password(username: &str, password: &str) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_SET_USER_PASSWORD,
            username.as_ptr() as usize,
            username.len(),
            password.as_ptr() as usize,
            password.len(),
        )
    };
    decode(rc).map(|_| ())
}

/// Exit the current process.  Does not return.
pub fn sys_exit(code: usize) -> ! {
    unsafe {
        __shell_syscall1(SYS_EXIT, code);
    }
    loop {
        // Compiler barrier — unreachable.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack))
        };
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack))
        };
    }
}

// ── Network syscall wrappers ──────────────────────────────────────────────

/// Query network subsystem status.
///
/// Returns a bitmask of capability flags.  See the `NETWORK_STATUS_FLAG_*`
/// constants for interpretation.
///
/// On bare-metal builds where no network stack is available this returns 0.
pub fn sys_network_status() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_NETWORK_STATUS) };
    decode(rc)
}

/// Resolve a hostname to an IPv4 address via kernel-side DNS.
///
/// Returns the 4-byte IPv4 address in network byte order (e.g. `[127, 0, 0, 1]`),
/// or a negative error code on failure.
pub fn sys_resolve_hostname(host: &str) -> Result<[u8; 4], isize> {
    let rc = unsafe { __shell_syscall2(SYS_RESOLVE_HOSTNAME, host.as_ptr() as usize, host.len()) };
    match decode(rc) {
        Ok(addr) => Ok(u32::to_be_bytes(addr as u32)),
        Err(e) => Err(e),
    }
}

/// Connect to a TCP server at `host:port`.
///
/// `host` may be an IPv4 address (e.g. `"127.0.0.1"`), an IPv6 address, or a
/// hostname (DNS resolution happens kernel-side).  Returns a file descriptor
/// that can be used with [`sys_read`], [`sys_write`], and [`sys_close`].
///
/// `flags` must be 0 (reserved for future use).
pub fn sys_connect_tcp(host: &str, port: u16, flags: usize) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_CONNECT_TCP,
            host.as_ptr() as usize,
            host.len(),
            port as usize,
            flags,
        )
    };
    decode(rc)
}

/// Listen for incoming TCP connections on `port`.
///
/// Returns a listener fd that can be passed to [`sys_accept_tcp`].
/// `backlog` specifies the maximum number of pending connections (typically
/// 4–128).  Use [`sys_close`] to release the listener.
pub fn sys_listen_tcp(port: u16, backlog: u16, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_LISTEN_TCP, port as usize, backlog as usize, flags) };
    decode(rc)
}

/// Accept an incoming TCP connection on a listener fd.
///
/// Blocks until a client connects, then returns a new fd for the connection.
/// The returned fd supports [`sys_read`], [`sys_write`], and [`sys_close`].
pub fn sys_accept_tcp(listener_fd: usize, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_ACCEPT_TCP, listener_fd, flags) };
    decode(rc)
}

/// Bind a UDP socket to `port`.
///
/// Returns a fd that can be used with [`sys_send_to_udp`] and
/// [`sys_recv_from_udp`].  Use [`sys_close`] to release the socket.
pub fn sys_bind_udp(port: u16, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_BIND_UDP, port as usize, flags) };
    decode(rc)
}

/// Send a UDP datagram to `dest_ip:dest_port`.
///
/// `dest_ip` is 4 bytes (IPv4) or 16 bytes (IPv6).  Set `flags` to
/// `NETWORK_SENDTO_UDP_FLAG_IPV6` for IPv6 destinations.
/// Returns the number of bytes sent on success.
pub fn sys_send_to_udp(
    fd: usize,
    dest_ip: &[u8],
    dest_port: u16,
    data: &[u8],
    flags: usize,
) -> Result<usize, isize> {
    let ip_arg: usize = if dest_ip.len() == 16 {
        // IPv6: dest_ip is a pointer to 16 bytes in user memory
        dest_ip.as_ptr() as usize
    } else {
        // IPv4: pack 4 bytes into a usize
        ((dest_ip[0] as usize) << 24)
            | ((dest_ip[1] as usize) << 16)
            | ((dest_ip[2] as usize) << 8)
            | (dest_ip[3] as usize)
    };
    let rc = unsafe {
        __shell_syscall6(
            SYS_SENDTO_UDP,
            fd,
            ip_arg,
            dest_port as usize,
            data.as_ptr() as usize,
            data.len(),
            flags,
        )
    };
    decode(rc)
}

/// Receive a UDP datagram.
///
/// `buf` receives the payload.  If `src_addr_out` is non-empty (8 bytes for
/// IPv4, 20 bytes for IPv6), the sender's address is written there.
/// Set `flags` to `NETWORK_RECVFROM_UDP_FLAG_IPV6` for IPv6 sockets.
/// Returns the number of bytes received on success.
pub fn sys_recv_from_udp(
    fd: usize,
    buf: &mut [u8],
    src_addr_out: &mut [u8],
    flags: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_RECVFROM_UDP,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            src_addr_out.as_mut_ptr() as usize,
            flags,
        )
    };
    decode(rc)
}

/// Read the kernel hostname into `buf`.
///
/// Returns the number of bytes written (not including any NUL terminator).
pub fn sys_gethostname(buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_GETHOSTNAME, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Set the kernel hostname from `name`.
///
/// Returns 0 on success.
pub fn sys_sethostname(name: &[u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_SETHOSTNAME, name.as_ptr() as usize, name.len()) };
    decode(rc)
}

/// Get the local address (IP + port) bound to socket `fd`.
///
/// Writes a 16-byte `sockaddr_in` struct to `buf`.
/// Returns the number of bytes written (16).
pub fn sys_getsockname(fd: usize, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_GETSOCKNAME, fd, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Get the remote (peer) address connected to TCP socket `fd`.
///
/// Writes a 16-byte `sockaddr_in` struct to `buf`.
/// Returns the number of bytes written (16).
/// Only works for TCP connections; UDP sockets return an error.
pub fn sys_getpeername(fd: usize, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_GETPEERNAME, fd, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Create a raw socket bound to the given IP protocol number.
///
/// `protocol` is an IP protocol number (e.g. 1 = ICMP, 6 = TCP, 17 = UDP).
/// Returns a fd that can be used with [`sys_send_raw_packet`] and
/// [`sys_recv_raw_packet`].  Use [`sys_close`] to release the socket.
pub fn sys_create_raw_socket(protocol: u8, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_CREATE_RAW_SOCKET, protocol as usize, flags) };
    decode(rc)
}

/// Send a raw IP packet on a raw socket.
///
/// `dest_ip` is 4 bytes (IPv4) or 16 bytes (IPv6).  `data` is the packet
/// payload (including any protocol headers).  `flags` must be 0.
/// Returns the number of bytes sent on success.
pub fn sys_send_raw_packet(
    fd: usize,
    dest_ip: &[u8],
    data: &[u8],
    flags: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_SEND_RAW_PACKET,
            fd,
            dest_ip.as_ptr() as usize,
            dest_ip.len(),
            data.as_ptr() as usize,
            data.len(),
            flags,
        )
    };
    decode(rc)
}

/// Receive a raw packet from a raw socket (non-blocking).
///
/// `buf` receives the packet payload.  If `src_addr_out` is non-empty
/// (4 bytes for IPv4, 16 for IPv6), the source IP address is written there.
/// `flags` must be 0.  Returns the number of bytes received, or
/// `Err(ENOTSUP)` if no packet is available.
pub fn sys_recv_raw_packet(
    fd: usize,
    buf: &mut [u8],
    src_addr_out: &mut [u8],
    flags: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_RECV_RAW_PACKET,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            src_addr_out.as_mut_ptr() as usize,
            flags,
        )
    };
    decode(rc)
}

/// Set a socket option on a TCP connection.
///
/// `level` is `SOL_SOCKET` or `IPPROTO_TCP`.  `name` is the option name
/// (e.g. `SO_KEEPALIVE`, `TCP_NODELAY`).  `val` is the option value
/// (up to 64 bytes).  Returns 0 on success.
pub fn sys_setsockopt(fd: usize, level: u32, name: u32, val: &[u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_SETSOCKOPT,
            fd,
            level as usize,
            name as usize,
            val.as_ptr() as usize,
            val.len(),
        )
    };
    decode(rc)
}

/// Get a socket option from a TCP connection.
///
/// `level` is `SOL_SOCKET` or `IPPROTO_TCP`.  `name` is the option name.
/// Writes the option value to `buf`.  Returns the number of bytes written.
pub fn sys_getsockopt(fd: usize, level: u32, name: u32, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_GETSOCKOPT,
            fd,
            level as usize,
            name as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
        )
    };
    decode(rc)
}

// ── Network status flag constants ─────────────────────────────────────────
// These MUST match the kernel's abi::net flags.

/// Network subsystem is available.
pub const NETWORK_STATUS_FLAG_AVAILABLE: u32 = 1 << 0;
/// Network requires host-runtime TCP stack (not native).
pub const NETWORK_STATUS_FLAG_REQUIRES_HOST_RUNTIME: u32 = 1 << 1;
/// TCP connect is supported.
pub const NETWORK_STATUS_FLAG_TCP_CONNECT: u32 = 1 << 2;
/// Byte-stream read/write semantics are supported.
pub const NETWORK_STATUS_FLAG_STREAM_IO: u32 = 1 << 3;
/// Read timeouts are supported.
pub const NETWORK_STATUS_FLAG_READ_TIMEOUTS: u32 = 1 << 4;
/// A zero timeout read is a non-blocking poll (returns `TimedOut` if no data).
pub const NETWORK_STATUS_FLAG_ZERO_TIMEOUT_READ_IS_POLL: u32 = 1 << 5;
/// TCP listen/accept is supported.
pub const NETWORK_STATUS_FLAG_TCP_LISTEN: u32 = 1 << 6;
/// UDP datagram send/recv is supported.
pub const NETWORK_STATUS_FLAG_UDP_DATAGRAM: u32 = 1 << 7;
/// IPv6 addressing is supported.
pub const NETWORK_STATUS_FLAG_IPV6: u32 = 1 << 8;

/// Flag passed to [`sys_send_to_udp`] when the destination address is IPv6.
pub const NETWORK_SENDTO_UDP_FLAG_IPV6: usize = 1 << 0;

/// Flag passed to [`sys_recv_from_udp`] when the socket is bound to IPv6.
pub const NETWORK_RECVFROM_UDP_FLAG_IPV6: usize = 1 << 0;

/// Set the per-process POSIX signal mask.
///
/// `mask` is a 64-bit bitmask where bit N blocks signal N.
/// Returns the previous signal mask value.
pub fn sys_set_signal_mask(mask: u64) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_SET_SIGNAL_MASK, mask as usize) };
    decode(rc)
}

/// Register or unregister a kernel-side signal handler for user-space dispatch.
///
/// `signal` must be a valid POSIX signal number (1..=31).
/// `action`: 0 = restore default action (terminate/stop/ignore),
///           1 = install a proxy handler so the signal is enqueued for
///               user-space consumption via [`wait_signal`].
///
/// When action is 1, the POSIX default action (e.g. terminate on SIGTERM) is
/// suppressed and the calling process can retrieve the signal via the
/// cooperative `wait_signal` / `signal_dispatch_loop` API.
pub fn sys_set_signal_handler(
    signal: usize,
    action: u32,
    user_handler_addr: usize,
    trampoline_addr: usize,
    sa_flags: u32,
) -> Result<(), isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_SET_SIGNAL_HANDLER,
            signal,
            action as usize,
            user_handler_addr,
            trampoline_addr,
            sa_flags as usize,
        )
    };
    decode(rc).map(|_| ())
}

// ── POSIX signal constants ─────────────────────────────────────────────────

pub const SIGHUP: usize = 1;
pub const SIGINT: usize = 2;
pub const SIGQUIT: usize = 3;
pub const SIGKILL: usize = 9;
pub const SIGUSR1: usize = 10;
pub const SIGUSR2: usize = 12;
pub const SIGPIPE: usize = 13;
pub const SIGALRM: usize = 14;
pub const SIGTERM: usize = 15;
pub const SIGCHLD: usize = 17;
pub const SIGCONT: usize = 18;
pub const SIGSTOP: usize = 19;
pub const SIGTSTP: usize = 20;

/// Poll a set of file descriptors for readiness.
///
/// `fds` is a mutable slice of `PollFd` structs.  On return, each
/// element's `revents` field is set to indicate which of the requested
/// events are ready.  Returns the number of ready file descriptors.
///
/// The `PollFd` struct layout must match the kernel's `repr(C)` definition:
/// ```ignore
/// #[repr(C)]
/// pub struct PollFd {
///     pub fd: i32,
///     pub events: u16,
///     pub revents: u16,
/// }
/// ```
pub fn sys_poll(fds: &mut [PollFd], _timeout_ticks: u64) -> Result<usize, isize> {
    if fds.is_empty() {
        return Ok(0);
    }
    let rc = unsafe {
        __shell_syscall3(
            SYS_POLL,
            fds.as_mut_ptr() as usize,
            fds.len(),
            _timeout_ticks as usize,
        )
    };
    decode(rc)
}

/// User-space pollfd struct (must match kernel layout exactly).
#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

/// Poll event flags.
pub const POLLIN: u16 = 0x001;
pub const POLLOUT: u16 = 0x004;

// ── Unix domain (local) sockets ─────────────────────────────────────────────

/// Bind a local (Unix domain) socket at the given filesystem path.
///
/// Returns a file descriptor for the listening socket.
/// Other processes can connect to this socket via `sys_connect_local`.
pub fn sys_bind_local(path: &str, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_BIND_LOCAL, path.as_ptr() as usize, path.len(), flags) };
    decode(rc)
}

/// Connect to a local (Unix domain) socket at the given path.
///
/// Returns a file descriptor for the connected bidirectional stream.
pub fn sys_connect_local(path: &str, flags: usize) -> Result<usize, isize> {
    let rc =
        unsafe { __shell_syscall3(SYS_CONNECT_LOCAL, path.as_ptr() as usize, path.len(), flags) };
    decode(rc)
}

/// Accept a pending connection on a bound local socket.
///
/// `listener_fd` is the file descriptor returned by `sys_bind_local`.
/// Returns a file descriptor for the accepted stream.
pub fn sys_accept_local(listener_fd: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_ACCEPT_LOCAL, listener_fd) };
    decode(rc)
}

// ── SystV shared memory (shm) ───────────────────────────────────────────────

/// Create or open a shared memory segment.
///
/// `key` is an IPC key (use `IPC_PRIVATE = 0` for a new anonymous segment).
/// `size` is the segment size in bytes (rounded up to page boundary).
/// `flags` can include `IPC_CREAT`, `IPC_EXCL`, and permission bits.
///
/// Returns the shared memory ID (shmid) on success.
pub fn sys_shmget(key: usize, size: usize, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_SHMGET, key, size, flags) };
    decode(rc)
}

/// Attach a shared memory segment to the calling process's address space.
///
/// `shmid` is the ID returned by `sys_shmget`.
/// `addr_hint` is a preferred virtual address (use 0 to let the kernel pick).
/// Returns the virtual address where the segment was attached.
pub fn sys_shmat(shmid: usize, addr_hint: usize, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_SHMAT, shmid, addr_hint, flags) };
    decode(rc)
}

/// Detach a shared memory segment.
///
/// `shmid` is the ID returned by `sys_shmget`.
pub fn sys_shmdt(shmid: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_SHMDT, shmid) };
    decode(rc)
}

/// Control operations on a shared memory segment.
///
/// `shmid` is the ID returned by `sys_shmget`.
/// `cmd` is one of `IPC_RMID`, `IPC_STAT`, `IPC_SET`.
pub fn sys_shmctl(shmid: usize, cmd: usize, buf: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_SHMCTL, shmid, cmd, buf) };
    decode(rc)
}

/// Minimum transport contract required for TCP-based HTTP downloads.
pub fn network_supports_tcp_stream_transport(flags: u32) -> bool {
    flags
        & (NETWORK_STATUS_FLAG_AVAILABLE
            | NETWORK_STATUS_FLAG_TCP_CONNECT
            | NETWORK_STATUS_FLAG_STREAM_IO
            | NETWORK_STATUS_FLAG_READ_TIMEOUTS)
        == (NETWORK_STATUS_FLAG_AVAILABLE
            | NETWORK_STATUS_FLAG_TCP_CONNECT
            | NETWORK_STATUS_FLAG_STREAM_IO
            | NETWORK_STATUS_FLAG_READ_TIMEOUTS)
}

// ── Utility helpers ─────────────────────────────────────────────────────

/// Probe read_dir to discover the required buffer size for a directory.
/// Returns the total byte count needed, or an error.
pub fn sys_read_dir_probe(path: &str) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall5(SYS_READ_DIR, path.as_ptr() as usize, path.len(), 0, 0, 0) };
    decode(rc)
}

// ── FUSE (Filesystem in Userspace) ───────────────────────────────────────

/// Mount a FUSE filesystem at the given path.
///
/// `mount_path` is the VFS path where the filesystem will appear.
/// `fs_name` is a unique name identifying this FUSE instance.
///
/// On success, returns `(req_fd, resp_fd)` — the two file descriptors
/// that the FUSE daemon should use to communicate with the kernel.
/// The daemon reads requests from `req_fd` and writes responses to `resp_fd`.
pub fn sys_fuse_mount(mount_path: &str, fs_name: &str) -> Result<(usize, usize), isize> {
    let mut fds = [0usize; 2];
    let rc = unsafe {
        __shell_syscall6(
            SYS_FUSE_MOUNT,
            mount_path.as_ptr() as usize,
            mount_path.len(),
            fs_name.as_ptr() as usize,
            fs_name.len(),
            fds.as_mut_ptr() as usize,
            core::mem::size_of::<[usize; 2]>(),
        )
    };
    if rc < 0 {
        Err(rc)
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// Futex — fast userspace mutex.
///
/// `op` is `FUTEX_WAIT` (0) or `FUTEX_WAKE` (1).
/// `timeout_ticks` is only used for `FUTEX_WAIT`:
///   - 0: return immediately
///   - `u64::MAX`: wait indefinitely
///   - other: wait for that many timer ticks
///
/// Returns 0 on successful wait, number of threads woken on wake,
/// or a negative errno on error.
pub fn sys_futex(
    uaddr: *const u32,
    op: usize,
    val: u32,
    timeout_ticks: u64,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_FUTEX,
            uaddr as usize,
            op,
            val as usize,
            timeout_ticks as usize,
            0,
            0,
        )
    };
    decode(rc)
}

// ── eventfd ──────────────────────────────────────────────────────────────

/// eventfd flags (kernel ABI encoding; note the kernel's bits are shifted one
/// relative to Linux — `SEMAPHORE` is bit 0 here, `CLOEXEC` bit 2).
pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK: u32 = 2;
pub const EFD_CLOEXEC: u32 = 4;

/// Create an eventfd file descriptor.
///
/// `initval` is the initial counter value.
/// `flags` can include `EFD_SEMAPHORE` (reads return 1 and decrement),
/// `EFD_NONBLOCK` (reads of a zero counter report `EAGAIN` instead of
/// blocking), and `EFD_CLOEXEC` (the descriptor closes on `exec`).
///
/// Returns a file descriptor on success.
pub fn sys_eventfd(initval: u32, flags: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_EVENTFD, initval as usize, flags as usize) };
    decode(rc)
}

// ── signalfd ─────────────────────────────────────────────────────────────

/// Create a signalfd file descriptor.
///
/// `sigset` is a bitmask of signals to catch (bit N = 1 catches signal N).
/// `flags` is reserved (pass 0).
///
/// Returns a file descriptor on success.  Read from the fd to receive
/// [`ProcessSignalRecord`] values for pending matching signals.
pub fn sys_signalfd(sigset: u64, flags: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_SIGNALFD, sigset as usize, flags as usize) };
    decode(rc)
}

// ── timerfd ──────────────────────────────────────────────────────────────

/// Create a timerfd file descriptor.
///
/// `expiry_delta` is the number of timer ticks from now until the first
/// expiration.  `interval_ticks` is the periodic interval (0 = one-shot).
///
/// Returns a file descriptor on success.  Read from the fd to receive a
/// `u64` count of expirations since the last read.
pub fn sys_timerfd(expiry_delta: u64, interval_ticks: u64, flags: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_TIMERFD,
            expiry_delta as usize,
            interval_ticks as usize,
            flags as usize,
        )
    };
    decode(rc)
}

// ── CPU affinity ─────────────────────────────────────────────────────────

/// Set the calling thread's CPU affinity.
///
/// `cpu_mask` is a bitmask of allowed CPUs (bit N = 1 allows CPU N).
/// Returns 0 on success or a negative error code.
pub fn sys_sched_setaffinity(cpu_mask: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_SCHED_SETAFFINITY, cpu_mask as usize) };
    decode(rc)
}

/// Get the calling thread's CPU affinity mask.
///
/// Returns a bitmask of allowed CPUs.
pub fn sys_sched_getaffinity() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_SCHED_GETAFFINITY) };
    decode(rc)
}

// ── Message queues (#112–#117) ──────────────────────────────────────────────

/// Open or create a named message queue.
///
/// Returns a file descriptor on success.
pub fn sys_mq_open(name: &str, oflags: u32, max_msg: u32, msg_size: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_MQOPEN,
            name.as_ptr() as usize,
            name.len(),
            oflags as usize,
            max_msg as usize,
            msg_size as usize,
        )
    };
    decode(rc)
}

/// Close a message queue file descriptor.
pub fn sys_mq_close(fd: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_MQCLOSE, fd) };
    decode(rc)
}

/// Send a message to a queue.
pub fn sys_mq_send(fd: usize, buf: &[u8], priority: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_MQSEND,
            fd,
            buf.as_ptr() as usize,
            buf.len(),
            priority as usize,
        )
    };
    decode(rc)
}

/// Receive a message from a queue. Returns the number of bytes received.
pub fn sys_mq_receive(fd: usize, buf: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_MQRECEIVE, fd, buf.as_mut_ptr() as usize, buf.len()) };
    decode(rc)
}

/// Register for signal notification when a message arrives on the queue.
/// Pass `signo = 0` to deregister.
pub fn sys_mq_notify(fd: usize, signo: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_MQNOTIFY, fd, signo as usize) };
    decode(rc)
}

/// Remove a named message queue.
pub fn sys_mq_unlink(name: &str) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_MQUNLINK, name.as_ptr() as usize, name.len()) };
    decode(rc)
}

// ── epoll (#118–#120) ────────────────────────────────────────────────────

/// epoll_ctl operations.
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

/// Alias for epoll_event.events flags.
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

/// Create an epoll instance. Returns an epoll fd.
pub fn sys_epoll_create(flags: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_EPOLL_CREATE, flags as usize) };
    decode(rc)
}

/// Control an epoll instance's interest list.
pub fn sys_epoll_ctl(
    epfd: usize,
    op: u32,
    fd: usize,
    event: &[u8], // 12-byte epoll_event
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_EPOLL_CTL,
            epfd,
            op as usize,
            fd,
            event.as_ptr() as usize,
            event.len(),
        )
    };
    decode(rc)
}

/// Wait for events on monitored fds.
/// Returns the number of ready events.
pub fn sys_epoll_wait(epfd: usize, events: &mut [u8], timeout_ticks: u64) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_EPOLL_WAIT,
            epfd,
            events.as_mut_ptr() as usize,
            events.len(),
            timeout_ticks as usize,
        )
    };
    decode(rc)
}

// ── mount / umount (#65, #66) ────────────────────────────────────────

/// Mount a filesystem at the given target path.
///
/// `fstype` is a filesystem driver name (e.g. "simplefs", "tmpfs", "ext4").
/// `flags` is a bitmask of MOUNT_* flags (MOUNT_READ_ONLY = 1, etc.).
pub fn sys_mount(target: &str, fstype: &str, flags: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_MOUNT,
            target.as_ptr() as usize,
            target.len(),
            fstype.as_ptr() as usize,
            fstype.len(),
            flags as usize,
        )
    };
    decode(rc)
}

/// Unmount a filesystem at the given path.
pub fn sys_umount(target: &str) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_UMOUNT, target.as_ptr() as usize, target.len()) };
    decode(rc)
}

// ── TLS connect (#121) ─────────────────────────────────────────────────────

/// Connect to a remote TLS 1.3 server at `host:port`.
///
/// Performs a TCP connection followed by a full TLS 1.3 handshake (including
/// certificate verification). Returns a file descriptor that transparently
/// encrypts outgoing data and decrypts incoming data via the standard
/// [`sys_read`], [`sys_write`], and [`sys_close`] calls.
///
/// `flags` must be 0 (reserved for future use).
pub fn sys_tls_connect(host: &str, port: u16, flags: usize) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_TLS_CONNECT,
            host.as_ptr() as usize,
            host.len(),
            port as usize,
            flags,
        )
    };
    decode(rc)
}

// ─── Packet filter / firewall syscalls (#122–#125) ───────────────────────

/// Add a packet filter rule (syscall 122).
pub fn sys_filter_add_rule(def: *const u8, def_len: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_FILTER_ADD_RULE, def as usize, def_len, 0) };
    decode(rc)
}

/// Remove a packet filter rule by id (syscall 123).
pub fn sys_filter_remove_rule(rule_id: u64) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_FILTER_REMOVE_RULE, rule_id as usize, 0) };
    decode(rc)
}

/// Set the default filter action (syscall 124).
pub fn sys_filter_set_default_action(action: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_FILTER_SET_DEFAULT_ACTION, action, 0) };
    decode(rc)
}

/// Get filter statistics (syscall 125).
pub fn sys_filter_get_stats(stats: *mut u8, stats_len: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_FILTER_GET_STATS, stats as usize, stats_len, 0) };
    decode(rc)
}

// ── io_uring syscalls (#126–#127) ──────────────────────────────────────

/// Create an io_uring async I/O instance (syscall 126).
///
/// `entries` is the max number of concurrent operations (1..=256).
/// `flags` is IORING_SETUP_* bits (pass 0).
///
/// Returns a file descriptor on success.
pub fn sys_io_uring_setup(entries: u32, flags: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_IO_URING_SETUP, entries as usize, flags as usize) };
    decode(rc)
}

/// Submit SQEs and/or reap CQEs (syscall 127).
///
/// Arguments are packed into 6 syscall ABI slots:
///
/// | slot | field                           |
/// |------|---------------------------------|
/// | 0    | `fd`                            |
/// | 1    | low 32b: `to_submit`, high 32b: `min_complete` |
/// | 2    | `sqes_ptr`                      |
/// | 3    | low 32b: `sqes_len`, high 32b: `cqes_capacity` |
/// | 4    | `cqes_ptr`                      |
/// | 5    | `flags` (IORING_ENTER_*)        |
///
/// Returns the number of CQEs written (zero-extended to `usize`).
#[allow(clippy::too_many_arguments)]
pub fn sys_io_uring_enter(
    fd: i32,
    to_submit: u32,
    min_complete: u32,
    sqes_ptr: *const u8,
    sqes_len: u32,
    cqes_ptr: *mut u8,
    cqes_capacity: u32,
    flags: u32,
) -> Result<usize, isize> {
    let arg0 = fd as usize;
    let arg1 = (to_submit as usize) | ((min_complete as usize) << 32);
    let arg2 = sqes_ptr as usize;
    let arg3 = (sqes_len as usize) | ((cqes_capacity as usize) << 32);
    let arg4 = cqes_ptr as usize;
    let arg5 = flags as usize;
    let rc = unsafe { __shell_syscall6(SYS_IO_URING_ENTER, arg0, arg1, arg2, arg3, arg4, arg5) };
    decode(rc)
}

// ── ptrace syscall (#128) ─────────────────────────────────────────────

/// Process tracing control (syscall 128).
pub fn sys_ptrace(
    request: i32,
    pid: i32,
    addr: usize,
    data: *const u8,
    data_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_PTRACE,
            request as usize,
            pid as usize,
            addr,
            data as usize,
            data_len,
        )
    };
    decode(rc)
}

/// Sigreturn — restore user context after async signal handler (syscall 134).
pub const SIGRTMIN: usize = 32;
pub const SIGRTMAX: usize = 42;
pub fn sys_sigreturn(frame_ptr: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_SIGRETURN, frame_ptr) };
    decode(rc)
}

/// sigsuspend — atomically replace signal mask and suspend until a signal is
/// delivered, then restore the original mask (syscall 135).
///
/// `new_mask` is the 64-bit signal mask to apply during the suspension.
/// Returns 0 on success (a signal was delivered), or a negative errno.
pub fn sys_sigsuspend(new_mask: u64) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_SIGSUSPEND, new_mask as usize) };
    decode(rc)
}

/// prctl — process control operations (syscall 130).
pub fn sys_prctl(
    option: i32,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall5(SYS_PRCTL, option as usize, arg2, arg3, arg4, arg5) };
    decode(rc)
}

/// mlock — lock memory pages (syscall 131).
pub fn sys_mlock(addr: usize, len: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_MLOCK, addr, len) };
    decode(rc)
}

/// munlock — unlock memory pages (syscall 132).
pub fn sys_munlock(addr: usize, len: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_MUNLOCK, addr, len) };
    decode(rc)
}

/// madvise — give advice about memory use (syscall 133).
pub fn sys_madvise(addr: usize, len: usize, advice: i32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_MADVISE, addr, len, advice as usize) };
    decode(rc)
}

/// Secure computing / syscall filtering (syscall 129).
pub fn sys_seccomp(
    operation: i32,
    flags: u32,
    data: *const u8,
    data_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_SECCOMP,
            operation as usize,
            flags as usize,
            data as usize,
            data_len,
        )
    };
    decode(rc)
}

// ── POSIX per-process timers (#137–140) ──────────────────────────────────

/// timer_create(clock_id, sevp) → timer_id
pub fn sys_timer_create(clock_id: u32, _sevp: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_TIMER_CREATE, clock_id as usize, _sevp) };
    decode(rc)
}

/// timer_settime(timer_id, flags, new_value, old_value) → 0 or error
pub fn sys_timer_settime(
    timer_id: u32,
    flags: u32,
    new_value: *const u8,
    _old_value: *mut u8,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_TIMER_SETTIME,
            timer_id as usize,
            flags as usize,
            new_value as usize,
            _old_value as usize,
        )
    };
    decode(rc)
}

/// timer_gettime(timer_id, value) → 0 or error
pub fn sys_timer_gettime(timer_id: u32, value: *mut u8) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_TIMER_GETTIME, timer_id as usize, value as usize) };
    decode(rc)
}

/// timer_delete(timer_id) → 0 or error
pub fn sys_timer_delete(timer_id: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_TIMER_DELETE, timer_id as usize) };
    decode(rc)
}

// ── Audit subsystem (#143–144) ───────────────────────────────────────────

/// Audit enable-mask bit constants.
/// These must match `src/kernel/audit/types.rs`.
pub const AUDIT_ENABLE_SYSCALL: u64 = 1 << 0;
pub const AUDIT_ENABLE_FILE_OP: u64 = 1 << 1;
pub const AUDIT_ENABLE_PROCESS_CREATE: u64 = 1 << 2;
pub const AUDIT_ENABLE_NETWORK_CONNECT: u64 = 1 << 3;
pub const AUDIT_ENABLE_AUTH_EVENT: u64 = 1 << 4;
pub const AUDIT_ENABLE_CONFIG_CHANGE: u64 = 1 << 5;
pub const AUDIT_ENABLE_ALL: u64 = AUDIT_ENABLE_SYSCALL
    | AUDIT_ENABLE_FILE_OP
    | AUDIT_ENABLE_PROCESS_CREATE
    | AUDIT_ENABLE_NETWORK_CONNECT
    | AUDIT_ENABLE_AUTH_EVENT
    | AUDIT_ENABLE_CONFIG_CHANGE;

/// Enable or disable audit event types for the current process.
///
/// `mask` is a bitmask of `AUDIT_ENABLE_*` values. Pass 0 to disable all
/// auditing. Returns the previous enable mask.
pub fn sys_audit_set_enable(mask: u64) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_AUDIT_SET_ENABLE, mask as usize) };
    decode(rc)
}

/// Size of a single audit record in bytes (must match kernel's AuditRecord).
pub const AUDIT_RECORD_SIZE: usize = 256;

/// Read audit events from the kernel ring buffer.
///
/// `buf` must have capacity for at least one `AuditRecord` (256 bytes).
/// Each record is a fixed-size structure. Returns the number of records
/// actually read (may be 0 if no events are pending).
pub fn sys_audit_read_log(buf: &mut [u8]) -> Result<usize, isize> {
    let max_records = buf.len() / AUDIT_RECORD_SIZE;
    if max_records == 0 {
        return Ok(0);
    }
    let rc = unsafe {
        __shell_syscall3(
            SYS_AUDIT_READ_LOG,
            buf.as_mut_ptr() as usize,
            max_records,
            AUDIT_RECORD_SIZE,
        )
    };
    decode(rc)
}

// ── CPU frequency scaling (#145–149) ─────────────────────────────────────

/// Frequency-scaling governor identifiers (must match the kernel enum).
pub const GOVERNOR_PERFORMANCE: usize = 0;
pub const GOVERNOR_POWERSAVE: usize = 1;
pub const GOVERNOR_ONDEMAND: usize = 2;
pub const GOVERNOR_SCHEDUTIL: usize = 3;
pub const GOVERNOR_USERSPACE: usize = 4;

/// Get the current CPU frequency in KHz.
pub fn sys_cpufreq_get() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_CPUFREQ_GET) };
    decode(rc)
}

/// Request a CPU frequency in KHz.
pub fn sys_cpufreq_set(freq_khz: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_CPUFREQ_SET, freq_khz) };
    decode(rc)
}

/// Get the (min, max) CPU frequency range in KHz, packed as
/// `max << 32 | min`.
pub fn sys_cpufreq_get_range() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_CPUFREQ_GET_RANGE) };
    decode(rc)
}

/// Select a frequency-scaling governor.
pub fn sys_cpufreq_set_governor(gov: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_CPUFREQ_SET_GOVERNOR, gov) };
    decode(rc)
}

/// Get the current CPU temperature in millidegrees Celsius.
pub fn sys_cpufreq_get_temp() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_CPUFREQ_GET_TEMP) };
    decode(rc)
}

/// Trigger memory defragmentation: relocate movable user frames so the
/// physical frame pool's free ranges coalesce.  Returns the number of frames
/// moved.
pub fn sys_compact_memory() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_COMPACT_MEMORY) };
    decode(rc)
}

// ── Extended attributes + per-file data-reduction flags (#151-156) ───────

/// Set an extended attribute on a file/directory.
pub fn sys_set_xattr(path: &str, name: &[u8], value: &[u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_SET_XATTR,
            path.as_ptr() as usize,
            path.len(),
            name.as_ptr() as usize,
            name.len(),
            value.as_ptr() as usize,
            value.len(),
        )
    };
    decode(rc)
}

/// Read an extended attribute value.  `out` must be large enough; pass an
/// empty slice to probe the required size.
pub fn sys_get_xattr(path: &str, name: &[u8], out: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall6(
            SYS_GET_XATTR,
            path.as_ptr() as usize,
            path.len(),
            name.as_ptr() as usize,
            name.len(),
            out.as_mut_ptr() as usize,
            out.len(),
        )
    };
    decode(rc)
}

/// List extended attribute names as NUL-terminated byte strings (Linux
/// `listxattr` format).  Returns the total byte length.
pub fn sys_list_xattr(path: &str, out: &mut [u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_LIST_XATTR,
            path.as_ptr() as usize,
            path.len(),
            out.as_mut_ptr() as usize,
            out.len(),
        )
    };
    decode(rc)
}

/// Remove an extended attribute.
pub fn sys_remove_xattr(path: &str, name: &[u8]) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_REMOVE_XATTR,
            path.as_ptr() as usize,
            path.len(),
            name.as_ptr() as usize,
            name.len(),
        )
    };
    decode(rc)
}

/// Toggle per-file data-reduction flags (e.g. `FILE_FLAG_COMPRESSED`).
pub fn sys_set_file_flags(path: &str, set: u32, clear: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_SET_FILE_FLAGS,
            path.as_ptr() as usize,
            path.len(),
            set as usize,
            clear as usize,
        )
    };
    decode(rc)
}

/// Read the per-file data-reduction flags (`FILE_FLAG_*` bitmask).
pub fn sys_get_file_flags(path: &str) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_GET_FILE_FLAGS, path.as_ptr() as usize, path.len()) };
    decode(rc)
}

// ── DCCP transport (#157-163) ────────────────────────────────────────────

/// Flag passed to [`sys_dccp_connect`] when the destination is IPv6.
pub const NETWORK_DCCP_FLAG_IPV6: usize = 1 << 0;

/// Bind a DCCP socket to a local port.
pub fn sys_dccp_bind(port: u16, service_code: u32, flags: usize) -> Result<usize, isize> {
    let rc =
        unsafe { __shell_syscall3(SYS_DCCP_BIND, port as usize, service_code as usize, flags) };
    decode(rc)
}

/// Start listening for DCCP Requests on `port`.
pub fn sys_dccp_listen(
    port: u16,
    backlog: u16,
    service_code: u32,
    flags: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_DCCP_LISTEN,
            port as usize,
            backlog as usize,
            service_code as usize,
            flags,
        )
    };
    decode(rc)
}

/// Initiate a DCCP connection to `dest_ip:dest_port`.
///
/// `dest_ip` is 4 bytes (IPv4) or 16 bytes (IPv6).  Set `flags` to
/// `NETWORK_DCCP_FLAG_IPV6` for IPv6 destinations.
pub fn sys_dccp_connect(
    dest_ip: &[u8],
    dest_port: u16,
    service_code: u32,
    flags: usize,
) -> Result<usize, isize> {
    let ip_arg: usize = if dest_ip.len() == 16 {
        dest_ip.as_ptr() as usize
    } else {
        ((dest_ip[0] as usize) << 24)
            | ((dest_ip[1] as usize) << 16)
            | ((dest_ip[2] as usize) << 8)
            | (dest_ip[3] as usize)
    };
    let rc = unsafe {
        __shell_syscall4(
            SYS_DCCP_CONNECT,
            ip_arg,
            dest_port as usize,
            service_code as usize,
            flags,
        )
    };
    decode(rc)
}

/// Accept the next pending DCCP connection on the listener `fd`.
pub fn sys_dccp_accept(fd: usize, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_DCCP_ACCEPT, fd, flags) };
    decode(rc)
}

/// Send one DCCP datagram on the connected socket `fd`.
pub fn sys_dccp_send(fd: usize, data: &[u8], flags: usize) -> Result<usize, isize> {
    let rc =
        unsafe { __shell_syscall4(SYS_DCCP_SEND, fd, data.as_ptr() as usize, data.len(), flags) };
    decode(rc)
}

/// Receive one DCCP datagram on the connected socket `fd`.
///
/// `buf` receives the payload.  If `src_addr_out` is non-empty (8 bytes for
/// IPv4, 20 bytes for IPv6), the peer's address is written there.
pub fn sys_dccp_recv(
    fd: usize,
    buf: &mut [u8],
    src_addr_out: &mut [u8],
    flags: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall5(
            SYS_DCCP_RECV,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            src_addr_out.as_mut_ptr() as usize,
            flags,
        )
    };
    decode(rc)
}

/// Close a DCCP socket.
pub fn sys_dccp_close(fd: usize, flags: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_DCCP_CLOSE, fd, flags) };
    decode(rc)
}

// ── IPsec SPD/SAD (#164-168) ─────────────────────────────────────────────

/// Add an IPsec security-policy entry.  Returns the policy id.
pub fn sys_ipsec_add_sp(sp: &crate::user::shared::abi::ipsec::IpsecSpDef) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_IPSEC_ADD_SP,
            sp as *const _ as usize,
            core::mem::size_of::<crate::user::shared::abi::ipsec::IpsecSpDef>(),
            0,
        )
    };
    decode(rc)
}

/// Remove an IPsec security-policy entry by id.
pub fn sys_ipsec_del_sp(sp_id: u64) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_IPSEC_DEL_SP, sp_id as usize, 0) };
    decode(rc)
}

/// Add an IPsec security association.  Returns the SA id.
pub fn sys_ipsec_add_sa(sa: &crate::user::shared::abi::ipsec::IpsecSaDef) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_IPSEC_ADD_SA,
            sa as *const _ as usize,
            core::mem::size_of::<crate::user::shared::abi::ipsec::IpsecSaDef>(),
            0,
        )
    };
    decode(rc)
}

/// Remove an IPsec security association by SPI.
pub fn sys_ipsec_del_sa(spi: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_IPSEC_DEL_SA, spi as usize, 0) };
    decode(rc)
}

/// Read IPsec statistics into `stats`.
pub fn sys_ipsec_get_stats(
    stats: &mut crate::user::shared::abi::ipsec::IpsecStats,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_IPSEC_GET_STATS,
            stats as *mut _ as usize,
            core::mem::size_of::<crate::user::shared::abi::ipsec::IpsecStats>(),
            0,
        )
    };
    decode(rc)
}

// ── Multicast routing (#169-174) ─────────────────────────────────────────

/// Enable multicast routing.
pub fn sys_mrt_init() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_MRT_INIT, 0) };
    decode(rc)
}

/// Disable multicast routing.
pub fn sys_mrt_done() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall1(SYS_MRT_DONE, 0) };
    decode(rc)
}

/// Add a multicast virtual interface.  Returns the VIF index.
pub fn sys_mrt_add_vif(vif: &crate::user::shared::abi::mrt::MrtVifDef) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_MRT_ADD_VIF,
            vif as *const _ as usize,
            core::mem::size_of::<crate::user::shared::abi::mrt::MrtVifDef>(),
            0,
        )
    };
    decode(rc)
}

/// Remove a multicast virtual interface.
pub fn sys_mrt_del_vif(vif_index: u32) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall2(SYS_MRT_DEL_VIF, vif_index as usize, 0) };
    decode(rc)
}

/// Add a multicast forwarding-cache entry.
pub fn sys_mrt_add_mfc(mfc: &crate::user::shared::abi::mrt::MrtMfcDef) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_MRT_ADD_MFC,
            mfc as *const _ as usize,
            core::mem::size_of::<crate::user::shared::abi::mrt::MrtMfcDef>(),
            0,
        )
    };
    decode(rc)
}

/// Remove a multicast forwarding-cache entry.
pub fn sys_mrt_del_mfc(source: [u8; 4], group: [u8; 4]) -> Result<usize, isize> {
    let src = ((source[0] as usize) << 24)
        | ((source[1] as usize) << 16)
        | ((source[2] as usize) << 8)
        | (source[3] as usize);
    let grp = ((group[0] as usize) << 24)
        | ((group[1] as usize) << 16)
        | ((group[2] as usize) << 8)
        | (group[3] as usize);
    let rc = unsafe { __shell_syscall3(SYS_MRT_DEL_MFC, src, grp, 0) };
    decode(rc)
}

// ── MAC type enforcement (#175-178) ───────────────────────────────────────

/// Enable/disable MAC enforcement and set the default-deny mode.  Returns the
/// previous `enabled` value.
pub fn sys_mac_set_mode(enabled: u32, default_deny: u32, flags: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_MAC_SET_MODE,
            enabled as usize,
            default_deny as usize,
            flags as usize,
        )
    };
    decode(rc)
}

/// Add a MAC allow rule.
pub fn sys_mac_add_rule(rule: &crate::user::shared::abi::mac::MacRule) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_MAC_ADD_RULE,
            rule as *const _ as usize,
            core::mem::size_of::<crate::user::shared::abi::mac::MacRule>(),
            0,
        )
    };
    decode(rc)
}

/// Set an object-type override for a path.
pub fn sys_mac_set_path_type(path: &str, mac_type: u32, flags: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            SYS_MAC_SET_PATH_TYPE,
            path.as_ptr() as usize,
            path.len(),
            mac_type as usize,
            flags as usize,
        )
    };
    decode(rc)
}

/// Read the MAC policy status into `status`.
pub fn sys_mac_get_status(
    status: &mut crate::user::shared::abi::mac::MacStatus,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            SYS_MAC_GET_STATUS,
            status as *mut _ as usize,
            core::mem::size_of::<crate::user::shared::abi::mac::MacStatus>(),
            0,
        )
    };
    decode(rc)
}

// ── fcntl descriptor control (#179) ────────────────────────────────────────

/// Generic descriptor control.  `cmd` is one of the `F_*` constants from
/// `crate::user::shared::abi::fs`.  Returns the command's result value.
pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall3(SYS_FCNTL, fd, cmd, arg) };
    decode(rc)
}

/// Convenience: query the pipe buffer capacity of `fd`.
pub fn sys_fcntl_get_pipe_sz(fd: usize) -> Result<usize, isize> {
    sys_fcntl(fd, crate::user::shared::abi::fs::F_GETPIPE_SZ, 0)
}

/// Convenience: resize the pipe buffer of `fd` to (at least) `size` bytes.
pub fn sys_fcntl_set_pipe_sz(fd: usize, size: usize) -> Result<usize, isize> {
    sys_fcntl(fd, crate::user::shared::abi::fs::F_SETPIPE_SZ, size)
}

// ── Global filesystem sync (#180) ──────────────────────────────────────────

/// Flush all mounted filesystems' dirty data to persistent storage.
pub fn sys_sync() -> Result<usize, isize> {
    let rc = unsafe { __shell_syscall0(SYS_SYNC) };
    decode(rc)
}

// ── VIRGL 3D userspace interface (#181-189) ─────────────────────────────────

/// Create a VIRGL rendering context.  Returns the context id.
pub fn sys_gpu_ctx_create(ctx_id: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall1(
            crate::user::shared::abi::gpu::SYS_GPU_CTX_CREATE,
            ctx_id as usize,
        )
    };
    decode(rc)
}

/// Destroy a VIRGL rendering context.
pub fn sys_gpu_ctx_destroy(ctx_id: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall1(
            crate::user::shared::abi::gpu::SYS_GPU_CTX_DESTROY,
            ctx_id as usize,
        )
    };
    decode(rc)
}

/// Create a 3D resource with kernel-managed DMA backing.  `desc` is a
/// `crate::user::shared::abi::gpu::GpuResCreate3dDesc`.  Returns the resource id.
pub fn sys_gpu_res_create_3d(
    desc_ptr: *const crate::user::shared::abi::gpu::GpuResCreate3dDesc,
    desc_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall2(
            crate::user::shared::abi::gpu::SYS_GPU_RES_CREATE_3D,
            desc_ptr as usize,
            desc_len,
        )
    };
    decode(rc)
}

/// Destroy a 3D resource and release its backing.
pub fn sys_gpu_res_unref(resource_id: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall1(
            crate::user::shared::abi::gpu::SYS_GPU_RES_UNREF,
            resource_id as usize,
        )
    };
    decode(rc)
}

/// Copy user data into a resource's backing and upload it to the host.
/// `desc` is a `crate::user::shared::abi::gpu::GpuTransfer3dDesc`; `data` holds the bytes.
pub fn sys_gpu_transfer_to_host_3d(
    desc_ptr: *const crate::user::shared::abi::gpu::GpuTransfer3dDesc,
    desc_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            crate::user::shared::abi::gpu::SYS_GPU_TRANSFER_TO_HOST_3D,
            desc_ptr as usize,
            desc_len,
            data_ptr as usize,
            data_len,
        )
    };
    decode(rc)
}

/// Transfer a resource region back from the host into a user buffer.
pub fn sys_gpu_transfer_from_host_3d(
    desc_ptr: *const crate::user::shared::abi::gpu::GpuTransfer3dDesc,
    desc_len: usize,
    data_ptr: *mut u8,
    data_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall4(
            crate::user::shared::abi::gpu::SYS_GPU_TRANSFER_FROM_HOST_3D,
            desc_ptr as usize,
            desc_len,
            data_ptr as usize,
            data_len,
        )
    };
    decode(rc)
}

/// Submit a VIRGL command stream to a context for rendering.
pub fn sys_gpu_submit_3d(ctx_id: u32, cmd_ptr: *const u8, cmd_len: usize) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            crate::user::shared::abi::gpu::SYS_GPU_SUBMIT_3D,
            ctx_id as usize,
            cmd_ptr as usize,
            cmd_len,
        )
    };
    decode(rc)
}

/// Present a resource on the display.
pub fn sys_gpu_set_scanout(resource_id: u32, width: u32, height: u32) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall3(
            crate::user::shared::abi::gpu::SYS_GPU_SET_SCANOUT,
            resource_id as usize,
            width as usize,
            height as usize,
        )
    };
    decode(rc)
}

/// Report GPU presence and capabilities into a `crate::user::shared::abi::gpu::GpuDeviceInfo`.
pub fn sys_gpu_device_info(
    info_ptr: *mut crate::user::shared::abi::gpu::GpuDeviceInfo,
    info_len: usize,
) -> Result<usize, isize> {
    let rc = unsafe {
        __shell_syscall2(
            crate::user::shared::abi::gpu::SYS_GPU_DEVICE_INFO,
            info_ptr as usize,
            info_len,
        )
    };
    decode(rc)
}
