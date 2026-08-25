//! src/kernel/syscall/io_uring.rs
//!
//! io_uring — asynchronous I/O batching syscalls.
//!
//! Provides two syscalls:
//! - `IoUringSetup` (#126) — create an io_uring instance, returns an fd
//! - `IoUringEnter` (#127) — submit SQEs and/or reap CQEs

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::abi::io_uring::{
    IoUringCqe, IoUringSqe, IORING_ENTER_GETEVENTS, IORING_OP_NOP, IORING_OP_POLL_ADD,
    IORING_OP_READ, IORING_OP_TIMEOUT, IORING_OP_WRITE, IORING_SETUP_IOPOLL, IO_URING_CQE_SIZE,
    IO_URING_MAX_ENTRIES, IO_URING_SQE_SIZE,
};
use crate::kernel::io;
use crate::kernel::process::process::types::{IoUringPendingOp, IoUringState};
use crate::kernel::process::Scheduler;
use crate::kernel::process::{FileDescriptor, KernelObject, Process};
use crate::kernel::sync::wait::WaitQueue;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::user_memory;
use super::{runtime, SyscallContext, SyscallDispatch};

// ── Constants
// ──────────────────────────────────────────────────────────────────

/// The default timeout for the blocking wait inside io_uring_enter (in ticks).
/// At 100 Hz this is ~1 second.
const DEFAULT_ENTER_WAIT_TICKS: u64 = 100;

// ── IoUringSetup (#126)
// ────────────────────────────────────────────────────────

/// Syscall #126: IoUringSetup — create an io_uring instance.
///
/// Arguments:
///   arg0 = entries (u32) — max number of in-flight entries (1..=256)
///   arg1 = flags (u32) — IORING_SETUP_* flags
///
/// Returns a file descriptor.
pub(super) fn io_uring_setup(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let entries = context.arg(0) as u32;
    let flags = context.arg(1) as u32;

    super::validate_known_flags(flags as usize, IORING_SETUP_IOPOLL as usize)?;
    super::validate_zeroed_args(context, 2)?;

    if entries == 0 || entries > IO_URING_MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }

    let state = Arc::new(IoUringState {
        entries,
        flags,
        completion_queue: Mutex::new(VecDeque::new()),
        wait_queue: WaitQueue::new(),
        pending_ops: Mutex::new(alloc::vec::Vec::new()),
    });

    let process = runtime::current_process()?;
    let fd = process.open_io_uring_descriptor(state)?;

    Ok(SyscallDispatch::complete(fd))
}

// ── IoUringEnter (#127)
// ────────────────────────────────────────────────────────

/// Syscall #127: IoUringEnter — submit SQEs and/or reap CQEs.
///
/// Argument packing (6 ABI slots):
///   arg0 = fd (i32)
///   arg1 = low 32b: to_submit; high 32b: min_complete
///   arg2 = sqes_ptr (*const IoUringSqe)
///   arg3 = low 32b: sqes_len; high 32b: cqes_capacity
///   arg4 = cqes_ptr (*mut IoUringCqe)
///   arg5 = flags (IORING_ENTER_*)
///
/// Returns the number of CQEs written (u32, zero-extended to usize).
pub(super) fn io_uring_enter(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    // ── Unpack arguments ────────────────────────────────────────────────────
    let fd = context.arg(0) as i32;
    let to_submit = context.arg(1) as u32;
    let min_complete = (context.arg(1) >> 32) as u32;
    let sqes_ptr = context.arg(2) as *const IoUringSqe;
    let sqes_len = context.arg(3) as u32;
    let cqes_capacity = (context.arg(3) >> 32) as u32;
    let cqes_ptr = context.arg(4) as *mut IoUringCqe;
    let flags = context.arg(5) as u32;

    // ── Validation ──────────────────────────────────────────────────────────
    super::validate_known_flags(flags as usize, IORING_ENTER_GETEVENTS as usize)?;

    if to_submit > IO_URING_MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    if sqes_len != to_submit * (IO_URING_SQE_SIZE as u32) {
        return Err(Error::InvalidArgument);
    }
    if cqes_capacity > IO_URING_MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    if to_submit > 0 && sqes_ptr.is_null() {
        return Err(Error::InvalidArgument);
    }
    if cqes_capacity > 0 && cqes_ptr.is_null() {
        return Err(Error::InvalidArgument);
    }

    let process = runtime::current_process()?;
    let entry = process.fd_entry(fd as FileDescriptor)?;

    let state = match entry.object {
        KernelObject::IoUring(state) => state,
        _ => return Err(Error::InvalidArgument),
    };

    // ── Phase 1: Re-probe pending operations ───────────────────────────────
    let mut completed_this_round = reprobe_pending_ops(&state, &process)?;

    // ── Phase 2: Submit new SQEs ───────────────────────────────────────────
    if to_submit > 0 {
        let sqe_count = to_submit as usize;
        user_memory::with_optional_input_slice(
            sqes_ptr as *const u8,
            sqe_count * IO_URING_SQE_SIZE,
            |bytes| {
                // Read SQEs one at a time from the user-space array.
                for i in 0..sqe_count {
                    let offset = i * IO_URING_SQE_SIZE;
                    let sqe_bytes = &bytes[offset..offset + IO_URING_SQE_SIZE];
                    // Safe: IoUringSqe is repr(C) and PaddingFree.
                    let sqe: IoUringSqe =
                        unsafe { core::ptr::read(sqe_bytes.as_ptr() as *const IoUringSqe) };
                    if let Some(cqe) = execute_sqe(&sqe, &process, &state)? {
                        state.completion_queue.lock().push_back(cqe);
                        completed_this_round += 1;
                    }
                }
                Ok::<(), Error>(())
            },
        )?;
    }

    // ── Phase 3: Wait if needed ─────────────────────────────────────────────
    let should_wait = (flags & IORING_ENTER_GETEVENTS) != 0;
    if should_wait && min_complete > 0 && completed_this_round < min_complete as usize {
        // Wait with a default timeout, re-probing pending ops on wake.
        let deadline = Scheduler::global()
            .map(|s| s.current_tick())
            .unwrap_or(0)
            .saturating_add(DEFAULT_ENTER_WAIT_TICKS);

        // prepare returns `false` (don't block) if enough completions are
        // already available, `true` (block) if we need to keep waiting.
        let _ = state
            .wait_queue
            .block_current_until_if(deadline, |_, waiters, thread| {
                // Re-probe pending ops while holding the wait queue lock.
                let ready = reprobe_pending_ops_internal(&state, &process).unwrap_or(0);
                let completed = state.completion_queue.lock().len();
                if completed + ready >= min_complete as usize {
                    return false; // don't block, completions available
                }
                waiters.push_back(thread.clone());
                true // proceed to block
            });

        // One more re-probe after waking, in case the prepare closure's
        // reprobe wasn't conclusive.
        let _ = reprobe_pending_ops(&state, &process)?;
    }

    // ── Phase 4: Write CQEs to user space ──────────────────────────────────
    let written = flush_cqes(&state, cqes_ptr, cqes_capacity)?;

    Ok(SyscallDispatch::complete(written))
}

// ── SQE execution
// ──────────────────────────────────────────────────────────────

/// Execute a single SQE and return an optional CQE.
///
/// Returns `Ok(None)` when the operation was enqueued as pending (e.g. a
/// POLL_ADD on a fd that is not yet ready).  Returns `Ok(Some(cqe))` when
/// the operation completed immediately.
fn execute_sqe(
    sqe: &IoUringSqe,
    process: &Process,
    state: &IoUringState,
) -> Result<Option<IoUringCqe>> {
    // Check reserved fields are zero.
    if sqe.reserved != 0 {
        return Err(Error::InvalidArgument);
    }

    let user_data = sqe.user_data;

    match sqe.opcode {
        IORING_OP_NOP => Ok(Some(cqe_ok(user_data, 0))),

        IORING_OP_READ => {
            let fd = sqe.fd as FileDescriptor;
            let addr = u64_to_ptr_mut::<u8>(sqe.addr);
            let len = sqe.len as usize;
            let timeout_ticks = sqe.timeout_ticks as u64;

            // Validate and execute a non-blocking read.
            let result = user_memory::with_optional_output_slice(addr, len, |buffer| {
                io::read(process, fd, buffer, timeout_ticks)
            });

            match result {
                Ok(n) => Ok(Some(cqe_ok(user_data, n as i32))),
                Err(e) => Ok(Some(cqe_err(user_data, e))),
            }
        }

        IORING_OP_WRITE => {
            let fd = sqe.fd as FileDescriptor;
            let addr = u64_to_ptr::<u8>(sqe.addr);
            let len = sqe.len as usize;

            let result = user_memory::with_optional_input_slice(addr, len, |buffer| {
                io::write(process, fd, buffer)
            });

            match result {
                Ok(n) => Ok(Some(cqe_ok(user_data, n as i32))),
                Err(e) => Ok(Some(cqe_err(user_data, e))),
            }
        }

        IORING_OP_POLL_ADD => {
            let fd = sqe.fd as FileDescriptor;
            let events = sqe.poll_events;

            // Check if the fd matches the requested poll events.
            let is_ready = poll_check_fd(process, fd, events).unwrap_or(false);

            if is_ready {
                Ok(Some(cqe_ok(user_data, 0)))
            } else {
                // Enqueue as pending operation.
                state.pending_ops.lock().push(IoUringPendingOp {
                    sqe: *sqe,
                    deadline: 0,
                    retried: false,
                });
                Ok(None)
            }
        }

        IORING_OP_TIMEOUT => {
            let timeout_ticks = sqe.timeout_ticks as u64;

            if timeout_ticks == 0 {
                // Immediate timeout — complete immediately.
                Ok(Some(cqe_ok(user_data, 0)))
            } else {
                // Enqueue with deadline.
                let deadline = Scheduler::global()
                    .map(|s| s.current_tick())
                    .unwrap_or(0)
                    .saturating_add(timeout_ticks);

                state.pending_ops.lock().push(IoUringPendingOp {
                    sqe: *sqe,
                    deadline,
                    retried: false,
                });
                Ok(None)
            }
        }

        _ => {
            // Unknown opcode.
            Ok(Some(cqe_err(user_data, Error::NotImplemented)))
        }
    }
}

// ── Pending op re-probe
// ────────────────────────────────────────────────────────

/// Re-probe pending operations and produce CQEs for those that are ready.
/// Returns the number of new completions produced.
fn reprobe_pending_ops(state: &IoUringState, process: &Process) -> Result<usize> {
    let count = reprobe_pending_ops_internal(state, process).unwrap_or(0);
    Ok(count)
}

/// Internal re-probe that returns a plain usize (for use inside wait-queue
/// closures where `Result` propagation is inconvenient).
fn reprobe_pending_ops_internal(
    state: &IoUringState,
    process: &Process,
) -> core::result::Result<usize, ()> {
    let mut new_completions = 0usize;
    let mut still_pending: alloc::vec::Vec<IoUringPendingOp> = alloc::vec::Vec::new();

    {
        let mut pending = state.pending_ops.lock();
        let current_tick = Scheduler::global().map(|s| s.current_tick()).unwrap_or(0);

        for op in pending.drain(..) {
            let ready = match op.sqe.opcode {
                IORING_OP_POLL_ADD => {
                    let fd = op.sqe.fd as FileDescriptor;
                    let events = op.sqe.poll_events;
                    poll_check_fd(process, fd, events).unwrap_or(false)
                }
                IORING_OP_TIMEOUT => op.deadline > 0 && current_tick >= op.deadline,
                _ => false,
            };

            if ready {
                let cqe = cqe_ok(op.sqe.user_data, 0);
                state.completion_queue.lock().push_back(cqe);
                new_completions += 1;
            } else {
                // Keep as pending.
                still_pending.push(IoUringPendingOp {
                    retried: true,
                    ..op
                });
            }
        }

        // Return unconsumed ops back to the pending list.
        *pending = still_pending;
    }

    // If we produced new completions, wake a waiter.
    if new_completions > 0 {
        state.wait_queue.wake_one();
    }

    Ok(new_completions)
}

// ── CQE flushing
// ───────────────────────────────────────────────────────────────

/// Drain completed CQEs from the ring and write them to user memory.
/// Returns the number of CQEs written.
fn flush_cqes(
    state: &IoUringState,
    cqes_ptr: *mut IoUringCqe,
    cqes_capacity: u32,
) -> Result<usize> {
    let capacity = cqes_capacity as usize;
    if capacity == 0 || cqes_ptr.is_null() {
        return Ok(0);
    }

    let mut cq = state.completion_queue.lock();
    let to_write = cq.len().min(capacity);

    if to_write == 0 {
        return Ok(0);
    }

    // Serialize CQEs into a temporary buffer, then copy to user space.
    // Each CQE is 16 bytes (2 × u64).
    let buf_size = to_write * IO_URING_CQE_SIZE;
    let mut buf = alloc::vec![0u8; buf_size];

    for i in 0..to_write {
        let cqe = cq.pop_front().ok_or(Error::InternalError)?;
        let offset = i * IO_URING_CQE_SIZE;
        // user_data (u64) at offset 0.
        buf[offset..offset + 8].copy_from_slice(&cqe.user_data.to_ne_bytes());
        // result (i32) at offset 8 followed by flags (u32) at offset 12.
        let result_bytes = cqe.result.to_ne_bytes();
        let flags_bytes = cqe.flags.to_ne_bytes();
        buf[offset + 8..offset + 12].copy_from_slice(&result_bytes);
        buf[offset + 12..offset + 16].copy_from_slice(&flags_bytes);
    }

    drop(cq); // release the lock before the user-space copy

    user_memory::copy_user_bytes(&buf, cqes_ptr as *mut u8, buf_size)?;

    Ok(to_write)
}

// ── Helpers
// ────────────────────────────────────────────────────────────────────

/// Create a success CQE.
fn cqe_ok(user_data: u64, result: i32) -> IoUringCqe {
    IoUringCqe {
        user_data,
        result,
        flags: 0,
    }
}

/// Create an error CQE.
fn cqe_err(user_data: u64, err: Error) -> IoUringCqe {
    IoUringCqe {
        user_data,
        result: -(err as i32),
        flags: 0,
    }
}

/// Convert a `[u8; 8]` buffer (holding a pointer value) to a `*const T`.
fn u64_to_ptr<T>(addr: [u8; 8]) -> *const T {
    let val = u64::from_ne_bytes(addr);
    val as *const T
}

/// Convert a `[u8; 8]` buffer (holding a pointer value) to a `*mut T`.
fn u64_to_ptr_mut<T>(addr: [u8; 8]) -> *mut T {
    let val = u64::from_ne_bytes(addr);
    val as *mut T
}

/// Check whether `fd` satisfies the given poll events.
fn poll_check_fd(process: &Process, fd: FileDescriptor, events: u16) -> Result<bool> {
    use crate::abi::io_uring::{IORING_POLL_ERR, IORING_POLL_HUP, IORING_POLL_IN, IORING_POLL_OUT};

    let mut ready = false;

    if events & (IORING_POLL_IN | IORING_POLL_ERR | IORING_POLL_HUP) != 0
        && io::fd_readable(process, fd)?
    {
        ready = true;
    }

    if events & (IORING_POLL_OUT | IORING_POLL_ERR | IORING_POLL_HUP) != 0
        && io::fd_writable(process, fd)?
    {
        ready = true;
    }

    Ok(ready)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::io_uring::{IO_URING_CQE_SIZE, IO_URING_SQE_SIZE};

    #[test]
    fn cqe_ok_and_err_values() {
        let ok = cqe_ok(42, 128);
        assert_eq!(ok.user_data, 42);
        assert_eq!(ok.result, 128);
        assert_eq!(ok.flags, 0);

        let err = cqe_err(99, Error::InvalidArgument);
        assert_eq!(err.user_data, 99);
        assert_eq!(err.result, -(Error::InvalidArgument as i32));
        assert_eq!(err.flags, 0);
    }

    #[test]
    fn u64_ptr_roundtrip() {
        let val: usize = 0x1234_5678_9ABC_DEF0;
        let bytes = val.to_ne_bytes();
        let ptr: *const u8 = u64_to_ptr(bytes);
        assert_eq!(ptr as usize, val);
    }

    #[test]
    fn io_uring_sqe_size_align() {
        assert_eq!(core::mem::size_of::<IoUringSqe>(), IO_URING_SQE_SIZE);
        assert_eq!(core::mem::size_of::<IoUringCqe>(), IO_URING_CQE_SIZE);
    }
}
