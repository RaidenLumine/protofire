//! src/user/syscall/process.rs
//!
//! Process, signal, spawn, exec, network, and diagnostic syscall builders.

use crate::abi::process as process_abi;
use crate::kernel::syscall::SyscallContext;
use crate::kernel::syscall::SyscallNumber;

use super::USER_EXCEPTION_HANDLER_FLAGS_NONE;

impl super::UserSyscall {
    // ── Hostname syscalls ────────────────────────────────────────────

    /// Read the kernel hostname into `buffer`.
    pub const fn gethostname(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::GetHostName as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    /// Set the kernel hostname from `name`.
    pub const fn sethostname(name: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::SetHostName as usize,
            [name, length, 0, 0, 0, 0],
        )
    }

    pub const fn arg_count() -> SyscallContext {
        SyscallContext::new(SyscallNumber::ArgCount as usize, [0; 6])
    }

    pub const fn arg_value(index: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ArgValue as usize,
            [index, buffer, length, 0, 0, 0],
        )
    }

    pub const fn env_count() -> SyscallContext {
        SyscallContext::new(SyscallNumber::EnvCount as usize, [0; 6])
    }

    pub const fn env_value(index: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::EnvValue as usize,
            [index, buffer, length, 0, 0, 0],
        )
    }

    pub const fn current_dir(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::CurrentDir as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn app_id(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::AppId as usize, [buffer, length, 0, 0, 0, 0])
    }

    pub const fn app_version(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::AppVersion as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn image_path(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ImagePath as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn manifest_path(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ManifestPath as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn abi_info(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::AbiInfo as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn network_status() -> SyscallContext {
        SyscallContext::new(SyscallNumber::NetworkStatus as usize, [0; 6])
    }

    pub const fn connect_tcp(
        host: usize,
        length: usize,
        port: usize,
        flags: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ConnectTcp as usize,
            [host, length, port, flags, 0, 0],
        )
    }

    pub const fn send_signal(
        pid: usize,
        signal: usize,
        payload: usize,
        flags: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [pid, signal, payload, flags, 0, 0],
        )
    }

    pub const fn wait_signal(
        timeout_ticks: usize,
        record: usize,
        record_length: usize,
        flags: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::WaitSignal as usize,
            [timeout_ticks, record, record_length, flags, 0, 0],
        )
    }

    pub const fn wait_signal_blocking(record: usize, record_length: usize) -> SyscallContext {
        // Reuse the shared ABI sentinel so user space has one blocking-wait
        // convention across process waits and cooperative signals.
        Self::wait_signal(
            process_abi::WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS,
            record,
            record_length,
            process_abi::PROCESS_SIGNAL_FLAG_NONE,
        )
    }

    pub const fn install_exception_handler(vector: usize, handler: usize) -> SyscallContext {
        Self::install_exception_handler_with(vector, handler, 0, USER_EXCEPTION_HANDLER_FLAGS_NONE)
    }

    pub const fn install_exception_handler_with(
        vector: usize,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::InstallExceptionHandler as usize,
            [vector, handler, stack_pointer, flags, 0, 0],
        )
    }

    pub const fn return_from_exception(frame_pointer: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ReturnFromException as usize,
            [frame_pointer, 0, 0, 0, 0, 0],
        )
    }

    pub const fn wait_process(
        pid: usize,
        timeout_ticks: usize,
        record: usize,
        record_length: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::WaitProcess as usize,
            [pid, timeout_ticks, record, record_length, 0, 0],
        )
    }

    pub const fn wait_process_blocking(
        pid: usize,
        record: usize,
        record_length: usize,
    ) -> SyscallContext {
        // Reuse the ABI-defined "block forever" sentinel instead of inventing a
        // separate wrapper-only convention.
        Self::wait_process(
            pid,
            process_abi::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS,
            record,
            record_length,
        )
    }

    pub const fn spawn_process(path: usize, length: usize) -> SyscallContext {
        Self::spawn_process_with(path, length, 0, 0)
    }

    pub const fn spawn_process_with(
        path: usize,
        length: usize,
        options: usize,
        options_length: usize,
    ) -> SyscallContext {
        // The options buffer uses the shared process-spawn ABI layout; passing
        // zeroes requests the manifest/default launch behavior.
        SyscallContext::new(
            SyscallNumber::SpawnProcess as usize,
            [path, length, options, options_length, 0, 0],
        )
    }

    pub const fn exec_process(path: usize, length: usize) -> SyscallContext {
        Self::exec_process_with(path, length, 0, 0)
    }

    pub const fn exec_process_with(
        path: usize,
        length: usize,
        options: usize,
        options_length: usize,
    ) -> SyscallContext {
        // `exec` reuses the same options structure as `spawn`; the kernel
        // applies the stricter exec-specific limits when decoding it.
        SyscallContext::new(
            SyscallNumber::ExecProcess as usize,
            [path, length, options, options_length, 0, 0],
        )
    }

    // ── Diagnostic / management syscalls ─────────────────────────────

    /// Yield the current timeslice so the scheduler can run another thread.
    pub const fn yield_now() -> SyscallContext {
        SyscallContext::new(SyscallNumber::Yield as usize, [0; 6])
    }

    pub const fn sleep(ticks: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Sleep as usize, [ticks, 0, 0, 0, 0, 0])
    }

    pub const fn list_processes(buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ListProcesses as usize,
            [buffer, length, 0, 0, 0, 0],
        )
    }

    pub const fn list_threads(pid: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::ListThreads as usize,
            [pid, buffer, length, 0, 0, 0],
        )
    }

    pub const fn kernel_log(offset: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::KernelLog as usize,
            [offset, buffer, length, 0, 0, 0],
        )
    }

    pub const fn system_info(info_type: usize, buffer: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::SystemInfo as usize,
            [info_type, buffer, length, 0, 0, 0],
        )
    }

    // ── Identity syscalls ────────────────────────────────────────────

    pub const fn getpid() -> SyscallContext {
        SyscallContext::new(SyscallNumber::GetPid as usize, [0; 6])
    }

    pub const fn getppid() -> SyscallContext {
        SyscallContext::new(SyscallNumber::GetPpid as usize, [0; 6])
    }

    pub const fn getuid() -> SyscallContext {
        SyscallContext::new(SyscallNumber::GetUid as usize, [0; 6])
    }

    pub const fn getgid() -> SyscallContext {
        SyscallContext::new(SyscallNumber::GetGid as usize, [0; 6])
    }

    pub const fn set_current_dir(path: usize, length: usize) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::SetCurrentDir as usize,
            [path, length, 0, 0, 0, 0],
        )
    }

    pub const fn add_user(
        username: usize,
        username_len: usize,
        uid: usize,
        gid: usize,
        home: usize,
        home_len: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::AddUser as usize,
            [username, username_len, uid, gid, home, home_len],
        )
    }

    pub const fn remove_user(uid: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::RemoveUser as usize, [uid, 0, 0, 0, 0, 0])
    }

    pub const fn set_user_password(
        username: usize,
        username_len: usize,
        password: usize,
        password_len: usize,
    ) -> SyscallContext {
        SyscallContext::new(
            SyscallNumber::SetUserPassword as usize,
            [username, username_len, password, password_len, 0, 0],
        )
    }

    // ── Memory syscalls ────────────────────────────────────────────

    /// Set the program break (heap end) for the current process.
    /// Returns the new program break on success.
    /// `brk(0)` queries the current break without changing it.
    pub const fn brk(addr: usize) -> SyscallContext {
        SyscallContext::new(SyscallNumber::Brk as usize, [addr, 0, 0, 0, 0, 0])
    }
}
