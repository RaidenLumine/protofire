//! src/kernel/syscall/process/launch/pipeline.rs
//!
//! Process-launch pipeline: request building, spawn/exec dispatch, fork, and exec transaction.

use alloc::string::String;
use alloc::sync::Arc;

use crate::abi::process::{self as process_abi};
use crate::kernel::process::thread::ThreadUserRuntimeState;
use crate::kernel::process::{
    HandleEntry, Process, ProcessExecState, SecurityToken, Thread, UserThreadStart, STDERR_FD,
    STDIN_FD, STDOUT_FD,
};
use crate::user::program::SpawnProcessOverrides;
use crate::{Error, Result};

use super::decode::{
    DecodedLaunchOptions, LaunchDecodeProfile, EXEC_LAUNCH_DECODE_PROFILE,
    SPAWN_LAUNCH_DECODE_PROFILE,
};
use super::MAX_LAUNCH_REFERENCE_BYTES;

// ── Standard handle specs ─────────────────────────────────────────────

const STANDARD_HANDLE_SPECS: [(usize, usize); 3] = [
    (STDIN_FD, process_abi::PROCESS_SPAWN_FLAG_INHERIT_STDIN),
    (STDOUT_FD, process_abi::PROCESS_SPAWN_FLAG_INHERIT_STDOUT),
    (STDERR_FD, process_abi::PROCESS_SPAWN_FLAG_INHERIT_STDERR),
];

// ── Launch input ──────────────────────────────────────────────────────

pub(super) struct LaunchInput {
    launch_reference: String,
    current_working_dir: String,
    overrides: SpawnProcessOverrides,
}

impl LaunchInput {
    fn load(self) -> Result<crate::user::program::LoadedProgram> {
        let Self {
            launch_reference,
            current_working_dir,
            overrides,
        } = self;
        crate::user::program::load_installed_launch_with_overrides_from_global(
            &current_working_dir,
            &launch_reference,
            overrides,
        )
    }
}

// ── Launch target ─────────────────────────────────────────────────────

enum ProcessLaunchTarget {
    Spawn {
        standard_handle_overrides: SpawnProcessStandardHandleOverrides,
        security_token: SecurityToken,
        parent_pid: crate::kernel::process::ProcessId,
        inherit_fds: bool,
        start_suspended: bool,
    },
    Exec {
        thread: Arc<Thread>,
        process: Arc<Process>,
    },
}

impl ProcessLaunchTarget {
    fn build_spawn(option_flags: usize, process: &Process) -> Result<Self> {
        let standard_handle_overrides =
            SpawnProcessStandardHandleOverrides::capture_from_process(process, option_flags)?;
        let inherit_fds = option_flags & crate::abi::process::PROCESS_SPAWN_FLAG_INHERIT_FDS != 0;
        let start_suspended =
            option_flags & crate::abi::process::PROCESS_SPAWN_FLAG_START_SUSPENDED != 0;

        Ok(Self::Spawn {
            standard_handle_overrides,
            security_token: process.security_token(),
            parent_pid: process.pid(),
            inherit_fds,
            start_suspended,
        })
    }

    fn build_exec(thread: Arc<Thread>) -> Result<Self> {
        let process = exec_process_target(&thread)?;
        Ok(Self::Exec { thread, process })
    }

    fn dispatch_loaded(
        self,
        loaded: crate::user::program::LoadedProgram,
    ) -> Result<super::super::SyscallDispatch> {
        match self {
            Self::Spawn {
                standard_handle_overrides,
                security_token,
                parent_pid,
                inherit_fds,
                start_suspended,
            } => spawn_process_dispatch(
                loaded,
                standard_handle_overrides,
                security_token,
                parent_pid,
                inherit_fds,
                start_suspended,
            ),
            Self::Exec { thread, process } => {
                process.close_cloexec_fds();
                install_exec_loaded_program_with(
                    loaded,
                    process.as_ref(),
                    thread.as_ref(),
                    activate_exec_process_address_space,
                    install_exec_thread_image,
                )?;
                Ok(super::super::SyscallDispatch::exec_process())
            }
        }
    }
}

// ── Launch request types ──────────────────────────────────────────────

struct ProcessLaunchRequest {
    input: LaunchInput,
    target: ProcessLaunchTarget,
}

impl ProcessLaunchRequest {
    fn load(self) -> Result<LoadedProcessLaunchRequest> {
        let Self { input, target } = self;
        Ok(LoadedProcessLaunchRequest {
            loaded: input.load()?,
            target,
        })
    }
}

struct LoadedProcessLaunchRequest {
    loaded: crate::user::program::LoadedProgram,
    target: ProcessLaunchTarget,
}

impl LoadedProcessLaunchRequest {
    fn dispatch(self) -> Result<super::super::SyscallDispatch> {
        let Self { loaded, target } = self;
        target.dispatch_loaded(loaded)
    }
}

// ── Exec install transaction ──────────────────────────────────────────

struct ExecInstallTransaction<'a> {
    process: &'a Process,
    thread: &'a Thread,
    previous_state: Option<ProcessExecState>,
    previous_thread_state: Option<ThreadUserRuntimeState>,
}

impl<'a> ExecInstallTransaction<'a> {
    fn new(
        process: &'a Process,
        thread: &'a Thread,
        previous_state: ProcessExecState,
        previous_thread_state: ThreadUserRuntimeState,
    ) -> Self {
        Self {
            process,
            thread,
            previous_state: Some(previous_state),
            previous_thread_state: Some(previous_thread_state),
        }
    }

    fn run_stage(&mut self, stage: impl FnOnce() -> Result<()>) -> Result<()> {
        if let Err(error) = stage() {
            self.rollback();
            return Err(error);
        }
        Ok(())
    }

    fn commit(mut self) {
        self.previous_state = None;
        self.previous_thread_state = None;
    }

    fn rollback(&mut self) {
        let Some(previous_state) = self.previous_state.take() else {
            return;
        };
        let previous_thread_state = self
            .previous_thread_state
            .take()
            .expect("exec transaction keeps process and thread snapshots paired");
        rollback_exec_process_state(
            self.process,
            self.thread,
            previous_state,
            previous_thread_state,
        );
    }
}

// ── SpawnProcessStandardHandleOverrides ───────────────────────────────

#[derive(Debug, Clone, Default)]
pub(super) struct SpawnProcessStandardHandleOverrides {
    stdin: Option<HandleEntry>,
    stdout: Option<HandleEntry>,
    stderr: Option<HandleEntry>,
}

impl SpawnProcessStandardHandleOverrides {
    fn capture_from_process(process: &Process, flags: usize) -> Result<Self> {
        Self::capture_with(process, |process, fd, inherit_flag| {
            Self::capture_standard_handle(process, fd, flags & inherit_flag != 0)
        })
    }

    fn capture_current_process_bindings(process: &Process) -> Result<Self> {
        Self::capture_with(process, |process, fd, _| {
            optional_if_not_found(process.fd_entry(fd))
        })
    }

    fn capture_with(
        process: &Process,
        mut capture_entry: impl FnMut(&Process, usize, usize) -> Result<Option<HandleEntry>>,
    ) -> Result<Self> {
        let [(stdin_fd, stdin_inherit_flag), (stdout_fd, stdout_inherit_flag), (stderr_fd, stderr_inherit_flag)] =
            STANDARD_HANDLE_SPECS;
        Ok(Self {
            stdin: capture_entry(process, stdin_fd, stdin_inherit_flag)?,
            stdout: capture_entry(process, stdout_fd, stdout_inherit_flag)?,
            stderr: capture_entry(process, stderr_fd, stderr_inherit_flag)?,
        })
    }

    fn capture_standard_handle(
        process: &Process,
        fd: usize,
        inherit_requested: bool,
    ) -> Result<Option<HandleEntry>> {
        if !inherit_requested {
            return Ok(None);
        }

        match optional_if_not_found(process.fd_entry(fd)) {
            Ok(Some(entry)) => Ok(Some(entry)),
            Ok(None) => {
                crate::println!(
                    "[sys   ] skipping stdio inherit for pid {} fd {} because source descriptor is unbound",
                    process.pid(),
                    fd
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn try_for_each_entry(
        self,
        mut f: impl FnMut(usize, Option<HandleEntry>) -> Result<()>,
    ) -> Result<()> {
        let Self {
            stdin,
            stdout,
            stderr,
        } = self;
        f(STDIN_FD, stdin)?;
        f(STDOUT_FD, stdout)?;
        f(STDERR_FD, stderr)?;
        Ok(())
    }

    fn install_with<F>(self, process: &Process, mut install: F) -> Result<()>
    where
        F: FnMut(&Process, usize, HandleEntry) -> Result<()>,
    {
        let previous = Self::capture_current_process_bindings(process)?;
        self.try_for_each_entry(|fd, entry| {
            let Some(entry) = entry else {
                return Ok(());
            };
            if let Err(error) = install(process, fd, entry) {
                if let Err(rollback_error) = previous.clone().restore_into_process(process) {
                    crate::println!(
                        "[sys   ] failed to roll back inherited stdio handles for spawned pid {} after fd {} install error {}: {}",
                        process.pid(),
                        fd,
                        error.as_str(),
                        rollback_error.as_str()
                    );
                }
                return Err(error);
            }
            Ok(())
        })
    }

    fn restore_into_process(self, process: &Process) -> Result<()> {
        self.try_for_each_entry(|fd, entry| match entry {
            Some(entry) => process.install_standard_handle_entry(fd, entry),
            None => ignore_not_found(process.close_fd(fd)),
        })
    }
}

fn optional_if_not_found<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn ignore_not_found(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) | Err(Error::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

// ── Syscall entry points ──────────────────────────────────────────────

pub(crate) fn spawn(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    dispatch_process_launch(process_launch_request_spawn(context)?)
}

pub(crate) fn exec(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    dispatch_process_launch(process_launch_request_exec(context)?)
}

// ── Fork syscall handler ──────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub(crate) fn fork(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;

    let scheduler = super::super::runtime::global_scheduler()?;
    let process = super::super::runtime::current_process()?;
    let thread = super::super::runtime::current_thread()?;
    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    let child = process.fork(&mut memory, scheduler.allocate_pid())?;

    child.set_parent_pid(process.pid());
    process.add_child(child.pid());

    let child_thread = {
        let parent_ctx = thread
            .validated_x86_64_user_context()?
            .ok_or(Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::X86_64UserThreadContext {
            rax: 0,
            ..parent_ctx
        };
        crate::kernel::process::thread::Thread::new_user_fork(child.clone(), child_ctx)?
    };

    scheduler.register_spawned_thread(child.clone(), child_thread, false);

    Ok(super::super::SyscallDispatch::complete(child.pid() as usize))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) fn fork(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;

    let scheduler = super::super::runtime::global_scheduler()?;
    let process = super::super::runtime::current_process()?;
    let thread = super::super::runtime::current_thread()?;
    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    let child = process.fork(&mut memory, scheduler.allocate_pid())?;

    child.set_parent_pid(process.pid());
    process.add_child(child.pid());

    let child_thread = {
        let parent_ctx = thread
            .validated_aarch64_user_context()?
            .ok_or(Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::AArch64UserThreadContext {
            x0: 0,
            ..parent_ctx
        };
        crate::kernel::process::thread::Thread::new_user_fork(child.clone(), child_ctx)?
    };

    scheduler.register_spawned_thread(child.clone(), child_thread, false);

    Ok(super::super::SyscallDispatch::complete(child.pid() as usize))
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn fork(
    context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    super::super::validate_zeroed_args(context, 0)?;

    let scheduler = super::super::runtime::global_scheduler()?;
    let process = super::super::runtime::current_process()?;
    let thread = super::super::runtime::current_thread()?;
    let mut memory = crate::kernel::memory::global_mut().ok_or(Error::InternalError)?;

    let child = process.fork(&mut memory, scheduler.allocate_pid())?;

    child.set_parent_pid(process.pid());
    process.add_child(child.pid());

    let child_thread = {
        let parent_ctx = thread
            .validated_riscv64_user_context()?
            .ok_or(Error::InvalidArgument)?;
        let child_ctx = crate::kernel::process::thread::RiscV64UserThreadContext {
            x10: 0,
            ..parent_ctx
        };
        crate::kernel::process::thread::Thread::new_user_fork(child.clone(), child_ctx)?
    };

    scheduler.register_spawned_thread(child.clone(), child_thread, false);

    Ok(super::super::SyscallDispatch::complete(child.pid() as usize))
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
pub(crate) fn fork(
    _context: &mut super::super::SyscallContext,
) -> Result<super::super::SyscallDispatch> {
    let _ = _context;
    Err(Error::NotImplemented)
}

// ── Launch request building ───────────────────────────────────────────

fn launch_request(context: &super::super::SyscallContext) -> Result<(String, *const u8, usize)> {
    super::super::validate_zeroed_args(context, 4)?;
    let len = context.arg(1);
    if len > MAX_LAUNCH_REFERENCE_BYTES {
        return Err(Error::InvalidArgument);
    }
    Ok((
        super::super::user_memory::user_string(context.arg(0) as *const u8, len)?,
        context.arg(2) as *const u8,
        context.arg(3),
    ))
}

fn process_launch_request_with_target<BuildTarget>(
    context: &super::super::SyscallContext,
    process: &Process,
    profile: LaunchDecodeProfile,
    build_target: BuildTarget,
) -> Result<ProcessLaunchRequest>
where
    BuildTarget: FnOnce(usize, &Process) -> Result<ProcessLaunchTarget>,
{
    let (launch_reference, options_ptr, options_len) = launch_request(context)?;
    let current_working_dir = process.current_working_dir();
    let DecodedLaunchOptions {
        option_flags,
        overrides,
    } = profile.decode(&current_working_dir, options_ptr, options_len)?;

    let target = build_target(option_flags, process)?;
    Ok(ProcessLaunchRequest {
        input: LaunchInput {
            launch_reference,
            current_working_dir,
            overrides,
        },
        target,
    })
}

fn process_launch_request_spawn(
    context: &super::super::SyscallContext,
) -> Result<ProcessLaunchRequest> {
    super::super::runtime::with_current_process(|process| {
        process_launch_request_with_target(
            context,
            process,
            SPAWN_LAUNCH_DECODE_PROFILE,
            ProcessLaunchTarget::build_spawn,
        )
    })
}

fn process_launch_request_exec(
    context: &super::super::SyscallContext,
) -> Result<ProcessLaunchRequest> {
    let thread = super::super::runtime::current_thread()?;
    let decode_process = thread.process().clone();
    process_launch_request_with_target(
        context,
        decode_process.as_ref(),
        EXEC_LAUNCH_DECODE_PROFILE,
        move |_option_flags, _process| ProcessLaunchTarget::build_exec(thread),
    )
}

fn dispatch_process_launch(request: ProcessLaunchRequest) -> Result<super::super::SyscallDispatch> {
    request.load()?.dispatch()
}

// ── Spawn dispatch ────────────────────────────────────────────────────

fn spawn_process_dispatch(
    loaded: crate::user::program::LoadedProgram,
    standard_handle_overrides: SpawnProcessStandardHandleOverrides,
    security_token: SecurityToken,
    parent_pid: crate::kernel::process::ProcessId,
    inherit_fds: bool,
    start_suspended: bool,
) -> Result<super::super::SyscallDispatch> {
    let scheduler = super::super::runtime::global_scheduler()?;
    let launched = crate::user::program::launch_loaded_program_with_security_token(
        scheduler,
        loaded,
        security_token,
        start_suspended,
    )?;
    install_spawn_standard_handles(launched.process.as_ref(), standard_handle_overrides);

    launched.process.set_parent_pid(parent_pid);
    if let Some(parent) = scheduler.process_by_pid(parent_pid) {
        parent.add_child(launched.process.pid());
        if inherit_fds {
            if let Err(error) = launched.process.inherit_fds_from(parent.as_ref()) {
                crate::println!(
                    "[sys   ] fd inheritance from pid {} to pid {} failed: {}",
                    parent_pid,
                    launched.process.pid(),
                    error.as_str()
                );
            }
        }
    }

    Ok(super::super::SyscallDispatch::complete(
        launched.process.pid() as usize,
    ))
}

fn install_spawn_standard_handles(
    process: &Process,
    standard_handle_overrides: SpawnProcessStandardHandleOverrides,
) {
    if let Err(error) = standard_handle_overrides.install_with(process, |process, fd, entry| {
        process.install_standard_handle_entry(fd, entry)
    }) {
        crate::println!(
            "[sys   ] failed to install inherited stdio handles for spawned pid {}: {}",
            process.pid(),
            error.as_str()
        );
    }
}

// ── Exec installation ─────────────────────────────────────────────────

pub(super) fn install_exec_loaded_program_with<Activate, InstallThreadImage>(
    mut loaded: crate::user::program::LoadedProgram,
    process: &Process,
    thread: &Thread,
    activate: Activate,
    install_thread_image: InstallThreadImage,
) -> Result<()>
where
    Activate: FnOnce(&Process) -> Result<()>,
    InstallThreadImage: FnOnce(&Thread, UserThreadStart) -> Result<()>,
{
    let (launch_context, prepared_user_address_space, start) =
        loaded.take_install_state()?.into_exec_parts();
    let start = validate_exec_user_thread_start(start)?;
    let previous_thread_state = thread.snapshot_user_runtime_state()?;
    let previous_state = process.replace_exec_state(launch_context, prepared_user_address_space)?;
    let mut transaction =
        ExecInstallTransaction::new(process, thread, previous_state, previous_thread_state);
    transaction.run_stage(|| activate(process))?;
    transaction.run_stage(|| install_thread_image(thread, start))?;
    transaction.commit();

    Ok(())
}

fn validate_exec_user_thread_start(start: Option<UserThreadStart>) -> Result<UserThreadStart> {
    let start = start.ok_or(Error::Unsupported)?;

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
    {
        start.validate()
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", test)))]
    {
        Ok(start)
    }
}

fn rollback_exec_process_state(
    process: &Process,
    thread: &Thread,
    previous_state: ProcessExecState,
    previous_thread_state: ThreadUserRuntimeState,
) {
    if let Err(error) = process.restore_exec_state(previous_state) {
        crate::println!(
            "[sys   ] failed to roll back exec process state for pid {}: {}",
            process.pid(),
            error.as_str()
        );
        return;
    }

    if let Err(error) = activate_exec_process_address_space(process) {
        crate::println!(
            "[sys   ] failed to reactivate address space while rolling back exec for pid {}: {}",
            process.pid(),
            error.as_str()
        );
    }

    if let Err(error) = thread.restore_user_runtime_state(previous_thread_state) {
        crate::println!(
            "[sys   ] failed to roll back exec thread state for pid {} tid {}: {}",
            process.pid(),
            thread.tid(),
            error.as_str()
        );
    }
}

fn install_exec_thread_image(thread: &Thread, start: UserThreadStart) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        thread.replace_x86_64_user_image(start)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        thread.replace_aarch64_user_image(start)
    }

    #[cfg(all(
        not(target_arch = "x86_64"),
        not(all(target_arch = "aarch64", target_os = "none"))
    ))]
    {
        let _ = thread;
        let _ = start;
        Err(Error::Unsupported)
    }
}

fn activate_exec_process_address_space(_process: &Process) -> Result<()> {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    {
        if !_process.activate_address_space_for_thread() {
            return Err(Error::InternalError);
        }
    }

    Ok(())
}

fn exec_process_target(thread: &Arc<Thread>) -> Result<Arc<Process>> {
    let process = thread.process().clone();
    validate_exec_install_target(process.as_ref(), thread.as_ref())?;
    Ok(process)
}

fn validate_exec_install_target(process: &Process, thread: &Thread) -> Result<()> {
    if thread.user_start().is_none() {
        return Err(Error::Unsupported);
    }

    if !core::ptr::eq(thread.process().as_ref(), process) {
        return Err(Error::InvalidArgument);
    }

    let thread_ids = process.thread_ids();
    if thread_ids.len() != 1 || thread_ids[0] != thread.tid() {
        return Err(Error::Busy);
    }

    Ok(())
}
