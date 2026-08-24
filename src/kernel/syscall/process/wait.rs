//! src/kernel/syscall/process/wait.rs
//!
//! Process-wait syscall path including timeout/reap semantics and record encoding.

use crate::abi::process as process_abi;
use crate::kernel::process::{ProcessState, Scheduler, TerminationReason};
use crate::{Error, Result};

pub(super) fn dispatch(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    super::validate_zeroed_args(context, 4)?;

    let pid = super::user_memory::process_pid_arg(context.arg(0))?;
    let wait = super::wait_common::timed_output_request::<process_abi::ProcessTerminationRecord>(
        context, 1, 2, 3,
    )?;
    let scheduler = super::runtime::global_scheduler()?;
    wait.finish_with(|timeout_ticks| {
        wait_for_process_termination(scheduler, pid, timeout_ticks)?;
        let reason = scheduler.reap_process(pid)?;
        Ok(reason.map_or_else(
            process_abi::ProcessTerminationRecord::none,
            TerminationReason::process_record,
        ))
    })
}

fn wait_for_process_termination(scheduler: &Scheduler, pid: u32, timeout_ticks: u64) -> Result<()> {
    // Disallow self-wait to prevent deadlock-like behavior.
    if super::runtime::current_process_pid()? == pid {
        return Err(Error::InvalidArgument);
    }

    let process = scheduler.process_by_pid(pid).ok_or(Error::NotFound)?;
    // If the child was spawned with START_SUSPENDED, it is still in New state
    // and has not yet been enqueued.  Resume it now so it can run and
    // eventually reach Terminated state (or be waited on).
    scheduler.resume_suspended_process(&process);
    super::wait_common::wait_until_ready(
        timeout_ticks,
        process_abi::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS as u64,
        || (process.state() == ProcessState::Terminated).then_some(()),
        || process.wait_for_termination(),
        |remaining| process.wait_for_termination_timeout(remaining),
        super::wait_common::current_wait_timed_out,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::wait_for_process_termination;
    use crate::abi::process::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS;
    use crate::Error;

    #[test]
    fn wait_for_process_termination_rejects_self_wait_before_blocking_path() {
        let (_guard, scheduler, process) =
            test_support::locked_scheduled_current_process("wait-self");

        assert_eq!(
            wait_for_process_termination(
                &scheduler,
                process.pid(),
                WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS as u64,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wait_for_process_termination_rejects_missing_pid_before_blocking_path() {
        let (_guard, scheduler, process) =
            test_support::locked_scheduled_current_process("wait-missing");
        let missing_pid = process.pid() + 1000;

        assert_eq!(
            wait_for_process_termination(
                &scheduler,
                missing_pid,
                WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS as u64,
            ),
            Err(Error::NotFound)
        );
    }
}
