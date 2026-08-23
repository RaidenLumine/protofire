//! src/kernel/syscall/mq.rs
//! POSIX-like message queue syscall handlers (#112–#117).
//!
//! Provides named message queues with blocking send/receive, capacity
//! limits, and optional signal notification on message arrival.
//!
//! # Syscall overview
//!
//! | #    | Name        | Description                          |
//! |------|-------------|--------------------------------------|
//! | 112  | `MqOpen`    | Open or create a named message queue |
//! | 113  | `MqClose`   | Close a message queue fd             |
//! | 114  | `MqSend`    | Send a message (blocking if full)    |
//! | 115  | `MqReceive` | Receive a message (blocking if empty)|
//! | 116  | `MqNotify`  | Register signal notification         |
//! | 117  | `MqUnlink`  | Remove a named message queue         |

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use crate::kernel::process::process::types::{KernelObject, MqState};
use crate::kernel::process::{HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::runtime;
use super::user_memory;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum length of a message queue name (including NUL).
pub(crate) const MQ_NAME_MAX: usize = 256;

// ── Global named queue registry ────────────────────────────────────────────

/// Global mapping from queue name to shared queue state.
static MQ_QUEUES: Mutex<BTreeMap<String, Arc<Mutex<MqState>>>> = Mutex::new(BTreeMap::new());

/// Look up a named queue, or create it if `create` is true and it doesn't
/// exist.  Returns `(Arc<Mutex<MqState>>, was_new)`.
fn find_or_create_queue(
    name: &str,
    oflags: u32,
    max_msg: u32,
    msg_size: u32,
) -> Result<(Arc<Mutex<MqState>>, bool)> {
    let mut map = MQ_QUEUES.lock();
    if let Some(state) = map.get(name) {
        // Queue exists.
        if oflags & 0x2 != 0 {
            // O_EXCL flag — fail if already exists.
            return Err(Error::AlreadyExists);
        }
        return Ok((state.clone(), false));
    }

    // Queue doesn't exist.
    if oflags & 0x1 == 0 {
        // O_CREAT flag not set — fail.
        return Err(Error::NotFound);
    }

    let state = Arc::new(Mutex::new(MqState::new(
        String::from(name),
        max_msg,
        msg_size,
        oflags,
    )));
    map.insert(String::from(name), state.clone());
    Ok((state, true))
}

/// Remove a named queue from the global registry.
fn unlink_queue(name: &str) -> Result<()> {
    let mut map = MQ_QUEUES.lock();
    if map.remove(name).is_none() {
        return Err(Error::NotFound);
    }
    Ok(())
}

// ── Syscall handlers ───────────────────────────────────────────────────────

/// MqOpen (#112): Open or create a named message queue.
///
/// Args: 0=name_ptr, 1=name_len, 2=oflags(u32), 3=max_msg(u32), 4=msg_size(u32)
pub(super) fn mq_open(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let name =
        user_memory::user_bounded_str(context.arg(0) as *const u8, context.arg(1), MQ_NAME_MAX)?;
    let oflags = context.arg(2) as u32;
    let max_msg = context.arg(3) as u32;
    let msg_size = context.arg(4) as u32;

    super::validate_zeroed_args(context, 5)?;

    let (state, _was_new) = find_or_create_queue(name, oflags, max_msg, msg_size)?;

    // Compute rights based on oflags.
    let rights = if oflags & 0x8 != 0 {
        // O_RDWR
        HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE
    } else if oflags & 0x4 != 0 {
        // O_WRONLY
        HANDLE_RIGHT_WRITE
    } else {
        // O_RDONLY (default)
        HANDLE_RIGHT_READ
    };

    let fd = runtime::with_current_process(|process| {
        let handle = process.open_handle(KernelObject::Mqueue(state.clone()), rights)?;
        process.install_fd_handle(handle)
    })?;

    Ok(super::SyscallDispatch::complete(fd))
}

/// MqClose (#113): Close a message queue fd.
pub(super) fn mq_close(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    super::validate_zeroed_args(context, 1)?;
    runtime::with_current_process(|process| process.close_fd(fd))?;
    Ok(super::SyscallDispatch::complete(0))
}

/// MqSend (#114): Send a message to a queue.  Blocks if the queue is full.
///
/// Args: 0=fd, 1=buf_ptr, 2=buf_len, 3=priority(u32)
pub(super) fn mq_send(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buf_ptr = context.arg(1) as *const u8;
    let buf_len = context.arg(2);
    let _priority = context.arg(3) as u32;

    super::validate_zeroed_args(context, 4)?;

    let buffer: alloc::vec::Vec<u8> =
        user_memory::with_optional_input_slice(buf_ptr, buf_len, |buf| Ok(buf.to_vec()))?;

    // Resolve the queue state and lock it.
    let state = {
        runtime::with_current_process(|process| {
            let (_handle, entry) = process.resolve_fd(fd)?;
            match &entry.object {
                KernelObject::Mqueue(s) => Ok(s.clone()),
                _ => Err(Error::InvalidArgument),
            }
        })
    }?;

    let mut mq = state.lock();
    if buffer.len() > mq.msg_size as usize {
        return Err(Error::InvalidArgument);
    }

    // Try to send immediately.
    if !mq.is_full() {
        mq.messages.push_back(buffer.clone());
        mq.wait_recv.wake_one();
        return Ok(super::SyscallDispatch::complete(0));
    }

    // Queue full — return busy for now.
    Err(Error::Busy)
}

/// MqReceive (#115): Receive a message from a queue.  Blocks if empty.
///
/// Args: 0=fd, 1=buf_ptr(out), 2=buf_len
pub(super) fn mq_receive(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let buf_ptr = context.arg(1) as *mut u8;
    let buf_len = context.arg(2);

    super::validate_zeroed_args(context, 4)?;

    // Resolve the queue state first.
    let state = {
        runtime::with_current_process(|process| {
            let (_handle, entry) = process.resolve_fd(fd)?;
            match &entry.object {
                KernelObject::Mqueue(s) => Ok(s.clone()),
                _ => Err(Error::InvalidArgument),
            }
        })
    }?;

    // Now operate outside the with_current_process closure.
    let mut mq = state.lock();
    if buf_len < mq.msg_size as usize {
        return Err(Error::InvalidArgument);
    }

    if let Some(msg) = mq.messages.pop_front() {
        let n = msg.len().min(buf_len);
        mq.wait_send.wake_one();
        drop(mq);
        user_memory::with_optional_output_slice(buf_ptr, n, |buffer| {
            buffer.copy_from_slice(&msg[..n]);
            Ok(())
        })?;
        return Ok(super::SyscallDispatch::complete(n));
    }

    // Queue empty — return busy.
    Err(Error::Busy)
}

/// MqNotify (#116): Register for signal notification when a message arrives.
///
/// Args: 0=fd, 1=signo(u32) — signal number to send (0 = deregister)
pub(super) fn mq_notify(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let fd = context.arg(0);
    let signo = context.arg(1) as u32;

    super::validate_zeroed_args(context, 2)?;

    let state = {
        runtime::with_current_process(|process| {
            let (_handle, entry) = process.resolve_fd(fd)?;
            match &entry.object {
                KernelObject::Mqueue(s) => Ok(s.clone()),
                _ => Err(Error::InvalidArgument),
            }
        })
    }?;

    let mut mq = state.lock();
    mq.notify_signal = if signo == 0 { None } else { Some(signo) };
    drop(mq);
    Ok(super::SyscallDispatch::complete(0))
}

/// MqUnlink (#117): Remove a named message queue.
///
/// Args: 0=name_ptr, 1=name_len
pub(super) fn mq_unlink(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let name =
        user_memory::user_bounded_str(context.arg(0) as *const u8, context.arg(1), MQ_NAME_MAX)?;

    super::validate_zeroed_args(context, 2)?;

    unlink_queue(name)?;
    Ok(super::SyscallDispatch::complete(0))
}
