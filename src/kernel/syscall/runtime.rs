//! src/kernel/syscall/runtime.rs
//! Syscall runtime accessors for current thread/process, scheduler, and filesystem.

use alloc::sync::Arc;

use crate::kernel::fs;
use crate::kernel::process::{
    FileDescriptor, HandleEntry, LaunchContext, Process, Scheduler, SecurityToken, Thread,
};
use crate::{Error, Result};

pub(super) fn current_process() -> Result<Arc<Process>> {
    current_thread().map(|thread| thread.process().clone())
}

pub(super) fn current_thread() -> Result<Arc<Thread>> {
    // Syscall handlers must execute in a scheduler-owned thread context.
    global_scheduler()?
        .current_thread()
        .ok_or(Error::InternalError)
}

pub(super) fn global_scheduler() -> Result<&'static Scheduler> {
    Scheduler::global().ok_or(Error::InternalError)
}

pub(super) fn global_fs() -> Result<&'static crate::kernel::sync::Mutex<fs::FileSystem>> {
    fs::global().ok_or(Error::InternalError)
}

pub(super) fn with_current_process<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&Process) -> Result<T>,
{
    current_process().and_then(|process| f(process.as_ref()))
}

pub(super) fn with_current_thread<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&Thread) -> Result<T>,
{
    current_thread().and_then(|thread| f(thread.as_ref()))
}

pub(super) fn current_process_pid() -> Result<u32> {
    with_current_process(|process| Ok(process.pid()))
}

pub(super) fn with_current_launch_context<F, T>(f: F) -> Result<Option<T>>
where
    F: FnOnce(&LaunchContext) -> Result<T>,
{
    with_current_process(|process| process.with_launch_context(f).transpose())
}

pub(super) fn require_current_launch_context<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&LaunchContext) -> Result<T>,
{
    with_current_launch_context(f)?.ok_or(Error::NotFound)
}

pub(super) fn current_process_fd_entry(fd: FileDescriptor) -> Result<HandleEntry> {
    with_current_process(|process| process.fd_entry(fd))
}

pub(super) fn with_global_fs<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut fs::FileSystem) -> Result<T>,
{
    // Keep syscall-side filesystem locking in one place so thin wrappers do
    // not each repeat `global_fs()?.lock()` boilerplate.
    let fs = global_fs()?;
    let mut fs = fs.lock();
    f(&mut fs)
}

pub(super) fn with_current_process_security_token_fs<F, T>(f: F) -> Result<T>
where
    F: FnOnce(SecurityToken, &mut fs::FileSystem) -> Result<T>,
{
    // Some syscall wrappers only need the caller's stable security context plus
    // a locked filesystem. Keep that thinner path centralized so token plumbing
    // does not get repeated at each mutation entry point.
    let security_token = with_current_process(|process| Ok(process.security_token()))?;
    with_global_fs(|fs| f(security_token, fs))
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::{
        current_process, current_process_fd_entry, current_process_pid, current_thread,
        global_scheduler, require_current_launch_context, with_current_launch_context,
        with_current_thread,
    };
    use crate::kernel::device;
    use crate::kernel::process::{KernelObject, HANDLE_RIGHT_WRITE, STDERR_FD, STDOUT_FD};
    use crate::Error;

    #[test]
    fn runtime_accessors_report_internal_error_without_installed_scheduler() {
        let _guard = test_support::test_lock();
        {
            let (_scheduler, _process) =
                test_support::scheduled_current_process("runtime-accessor-drop");
        }

        assert!(matches!(global_scheduler(), Err(Error::InternalError)));
        assert!(matches!(current_thread(), Err(Error::InternalError)));
        assert!(matches!(current_process(), Err(Error::InternalError)));
        assert_eq!(current_process_pid(), Err(Error::InternalError));
    }

    #[test]
    fn runtime_accessors_resolve_scheduled_current_process_and_thread() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("runtime-accessor-ok");
        let pid = process.pid();

        let current = current_thread().expect("current thread");
        assert_eq!(current.process().pid(), pid);

        let current_process = current_process().expect("current process");
        assert_eq!(current_process.pid(), pid);
        assert_eq!(current_process_pid(), Ok(pid));
        assert_eq!(with_current_thread(|thread| Ok(thread.pid())), Ok(pid));
    }

    #[test]
    fn runtime_launch_context_accessors_distinguish_absent_and_present_state() {
        let (_guard, _scheduler, process) =
            test_support::locked_scheduled_current_process("runtime-launch-none");

        assert_eq!(
            with_current_launch_context(|launch| Ok(launch.catalog_id.clone())),
            Ok(None)
        );
        assert_eq!(
            require_current_launch_context(|launch| Ok(launch.catalog_id.clone())),
            Err(Error::NotFound)
        );

        let launch = test_support::sample_launch_context();
        process.configure_launch(launch.clone());

        assert_eq!(
            with_current_launch_context(|current| Ok(current.catalog_id.clone())),
            Ok(Some(launch.catalog_id.clone()))
        );
        assert_eq!(
            require_current_launch_context(|current| Ok(current.arguments.len())),
            Ok(launch.arguments.len())
        );
    }

    #[test]
    fn runtime_fd_entry_accessor_resolves_stable_stdout_descriptor() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("runtime-fd-ok");

        let entry = current_process_fd_entry(STDOUT_FD).expect("stdout fd entry");
        assert_eq!(entry.rights, HANDLE_RIGHT_WRITE);
        assert!(matches!(
            entry.object,
            KernelObject::Device(ref name) if name == device::DEBUG_DEVICE_NAME
        ));
    }

    #[test]
    fn runtime_fd_entry_accessor_rejects_missing_descriptor() {
        let (_guard, _scheduler, _process) =
            test_support::locked_scheduled_current_process("runtime-fd-miss");

        assert!(matches!(
            current_process_fd_entry(STDERR_FD + 1),
            Err(Error::NotFound)
        ));
    }
}
