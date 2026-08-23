//! src/kernel/syscall/process/signal.rs
//! Process-signal send/wait syscalls built on the bounded process signal queue.

use crate::abi::process as process_abi;
use crate::{Error, Result};

pub(super) fn send(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let (pid, signal, payload) = send_signal_request(context)?;
    let scheduler = super::runtime::global_scheduler()?;
    let sender_pid = super::runtime::current_process_pid()?;
    scheduler.send_signal(sender_pid, pid, signal, payload)?;

    // Kernel-level handling for job-control signals.
    match signal {
        18 => {
            // SIGCONT — resume all stopped threads of the target process.
            let _ = scheduler.continue_process(pid);
        }
        19 | 20 => {
            // SIGSTOP (19) / SIGTSTP (20) — suspend all threads.
            let _ = scheduler.stop_process(pid);
        }
        _ => {}
    }

    Ok(super::SyscallDispatch::complete(0))
}

fn send_signal_request(context: &super::SyscallContext) -> Result<(u32, usize, usize)> {
    let pid = super::user_memory::process_pid_arg(context.arg(0))?;
    let signal = context.arg(1);
    let payload = context.arg(2);
    let flags = context.arg(3);

    if !process_abi::is_valid_process_signal(signal) {
        return Err(Error::InvalidArgument);
    }
    super::validate_known_flags(flags, process_abi::PROCESS_SIGNAL_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 4)?;

    Ok((pid, signal, payload))
}

pub(super) fn wait(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let flags = context.arg(3);
    super::validate_known_flags(flags, process_abi::PROCESS_SIGNAL_KNOWN_FLAGS)?;
    super::validate_zeroed_args(context, 4)?;
    let request: super::wait_common::TimedOutputRequest<process_abi::ProcessSignalRecord> =
        super::wait_common::timed_output_request(context, 0, 1, 2)?;
    request.finish_with(|timeout_ticks| {
        super::runtime::with_current_process(|process| {
            wait_for_process_signal(process, timeout_ticks)
        })
    })
}

/// Handle `SYS_SIGRETURN` (#134).
///
/// `arg0` = pointer to a `SignalFrame` on the user stack.
/// Reads the frame and restores the saved RIP/RSP/RFLAGS by overwriting
/// the current thread's user context.  The `handle_syscall` dispatch layer
/// applies the restored context to the `InterruptContext` before `iretq`.
pub(super) fn sigreturn(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::abi::process::SignalFrame;

        let frame_ptr = context.arg(0) as *const u8;

        // Read the SignalFrame from user memory.
        let frame: SignalFrame = super::user_memory::read_user_value(
            frame_ptr,
            core::mem::size_of::<SignalFrame>(),
            core::mem::size_of::<SignalFrame>(),
        )?;

        // Restore the thread's saved user context from the SignalFrame.
        super::runtime::with_current_thread(|thread| {
            let mut user_ctx = thread
                .x86_64_user_context()
                .ok_or(crate::Error::InternalError)?;
            user_ctx.instruction_pointer = frame.orig_rip;
            user_ctx.rflags = frame.orig_rflags;
            user_ctx.stack_pointer = frame.orig_rsp;
            thread.set_x86_64_user_context(user_ctx);
            Ok(())
        })?;

        // Signal that the dispatch layer should apply the restored context
        // to the InterruptContext before returning to user mode.
        Ok(super::SyscallDispatch {
            value: 0,
            action: super::SyscallAction::SigReturn,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = context;
        Err(crate::Error::NotImplemented)
    }
}

/// A no-op proxy handler that prevents the kernel default action for a signal.
///
/// When installed via [`set_handler`], this handler tells `enqueue_signal()` to
/// enqueue the signal rather than applying the POSIX default action (terminate,
/// stop, etc.).  The user-space `signal_dispatch_loop` can then handle the
/// signal via `wait_signal()`.
fn user_signal_proxy(_signal: i32) {}

/// Handle the `SetSignalHandler` syscall (#104).
///
/// `arg0` = signal number (1..=31)
/// `arg1` = action: 0 = restore default, 1 = enable user-space handling
/// `arg2` = user_handler_addr: when action=1 and addr!=0, stores as async
///          handler address; when addr=0, cooperative only (current behaviour)
/// `arg3` = trampoline_addr: address of ring3 signal_trampoline function
///          (required when user_handler_addr is non-zero)
/// `arg4` = `SA_*` flags (only `SA_RESTART` is supported; unknown bits are
///          rejected).  Only meaningful with action=1.
pub(super) fn set_handler(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let signal = context.arg(0);
    let action = context.arg(1);
    let user_handler_addr = context.arg(2);
    let trampoline_addr = context.arg(3);
    let sa_flags = context.arg(4);

    if !process_abi::is_valid_process_signal(signal) {
        return Err(Error::InvalidArgument);
    }
    if action > 1 {
        return Err(Error::InvalidArgument);
    }
    if action == 1 && user_handler_addr != 0 && trampoline_addr == 0 {
        // Trampoline address is required when requesting async delivery.
        return Err(Error::InvalidArgument);
    }
    super::validate_zeroed_args(context, 5)?;

    super::runtime::with_current_process(|process| {
        if action == 1 {
            // Install the proxy handler — prevents default action, signal
            // gets enqueued for user-space consumption.
            process.install_signal_handler(signal, user_signal_proxy)?;
            process.install_signal_sa_flags(signal, sa_flags as u64)?;
            if user_handler_addr != 0 {
                process.install_user_signal_handler(signal, user_handler_addr as u64)?;
                process.set_signal_trampoline_addr(trampoline_addr as u64);
            }
            Ok(super::SyscallDispatch::complete(0))
        } else {
            // action == 0 — remove handler, restore POSIX default action.
            process.remove_signal_handler(signal)?;
            process.remove_user_signal_handler(signal)?;
            process.remove_signal_sa_flags(signal)?;
            Ok(super::SyscallDispatch::complete(0))
        }
    })
}

pub(super) fn wait_for_process_signal(
    process: &crate::kernel::process::Process,
    timeout_ticks: u64,
) -> Result<process_abi::ProcessSignalRecord> {
    super::wait_common::wait_until_ready(
        timeout_ticks,
        process_abi::WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS as u64,
        || process.take_pending_signal(),
        || process.wait_for_signal(),
        |remaining| process.wait_for_signal_timeout(remaining),
        super::wait_common::current_wait_timed_out,
    )
}

#[cfg(test)]
mod tests {
    use super::{send as send_signal, send_signal_request, wait as wait_signal};
    use crate::abi::process::{PROCESS_SIGNAL_KNOWN_FLAGS, PROCESS_SIGNAL_MAX, PROCESS_SIGNAL_MIN};
    use crate::kernel::syscall::{SyscallContext, SyscallNumber};
    use crate::Error;

    #[test]
    fn send_signal_request_decodes_valid_payload() {
        let context = SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [
                7,
                PROCESS_SIGNAL_MIN,
                0xfeed_cafe,
                PROCESS_SIGNAL_KNOWN_FLAGS,
                0,
                0,
            ],
        );

        assert_eq!(
            send_signal_request(&context),
            Ok((7, PROCESS_SIGNAL_MIN, 0xfeed_cafe))
        );
    }

    #[test]
    fn send_signal_request_rejects_invalid_signal_id() {
        let context = SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [
                7,
                PROCESS_SIGNAL_MAX + 1,
                0xfeed_cafe,
                PROCESS_SIGNAL_KNOWN_FLAGS,
                0,
                0,
            ],
        );

        assert_eq!(send_signal_request(&context), Err(Error::InvalidArgument));
    }

    #[test]
    fn send_signal_request_rejects_unknown_flags() {
        let context = SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [7, PROCESS_SIGNAL_MIN, 0xfeed_cafe, 1, 0, 0],
        );

        assert_eq!(send_signal_request(&context), Err(Error::InvalidArgument));
    }

    #[test]
    fn send_signal_request_rejects_non_zero_reserved_args() {
        let context = SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [
                7,
                PROCESS_SIGNAL_MIN,
                0xfeed_cafe,
                PROCESS_SIGNAL_KNOWN_FLAGS,
                99,
                0,
            ],
        );

        assert_eq!(send_signal_request(&context), Err(Error::InvalidArgument));
    }

    #[test]
    fn wait_signal_rejects_unknown_flags_before_runtime_dispatch() {
        let mut context =
            SyscallContext::new(SyscallNumber::WaitSignal as usize, [1, 0, 0, 1, 0, 0]);

        assert_eq!(wait_signal(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn send_signal_rejects_non_zero_reserved_args_before_runtime_dispatch() {
        let mut context = SyscallContext::new(
            SyscallNumber::SendSignal as usize,
            [
                7,
                PROCESS_SIGNAL_MIN,
                0xfeed_cafe,
                PROCESS_SIGNAL_KNOWN_FLAGS,
                1,
                0,
            ],
        );

        assert_eq!(send_signal(&mut context), Err(Error::InvalidArgument));
    }
}
