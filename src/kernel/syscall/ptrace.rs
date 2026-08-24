//! src/kernel/syscall/ptrace.rs
//!
//! Ptrace syscall handler (#128).
//!
//! Dispatches ptrace requests to the core logic in `src/kernel/process/ptrace.rs`.

use crate::abi::ptrace::{
    PtraceEventRecord, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_EVENT_RECORD_SIZE,
    PTRACE_GETEVENTMSG, PTRACE_GETREGS, PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_REGS_SIZE_X86_64,
    PTRACE_SETREGS, PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_TRACEME,
};
use crate::kernel::process::ptrace as ptrace_core;
use crate::{Error, Result};

use super::user_memory;
use super::{runtime, SyscallContext, SyscallDispatch};

/// Syscall #128: Ptrace — process tracing control.
///
/// Arguments:
///   arg0 = request (i32) — PTRACE_* request code
///   arg1 = pid (i32) — target process ID
///   arg2 = addr (usize) — address in tracee's address space (PEEKDATA/POKEDATA)
///   arg3 = data (usize) — data pointer or flags
///   arg4 = data_len (usize) — length of data buffer
///
/// Returns 0 on success, or an error code.
pub(super) fn ptrace(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let request = context.arg(0) as i32;
    let pid = context.arg(1) as i32;
    let addr = context.arg(2);
    let data = context.arg(3);
    let data_len = context.arg(4);

    let process = runtime::current_process()?;

    match request {
        PTRACE_TRACEME => {
            // arg1 (pid), arg2 (addr), arg3 (data), arg4 (data_len) must be 0
            if pid != 0 || addr != 0 || data != 0 || data_len != 0 {
                return Err(Error::InvalidArgument);
            }
            ptrace_core::ptrace_traceme(&process)?;
        }

        PTRACE_ATTACH => {
            let target_pid = pid as u32;
            if target_pid == 0 || data != 0 || data_len != 0 {
                return Err(Error::InvalidArgument);
            }
            ptrace_core::ptrace_attach(&process, target_pid)?;
        }

        PTRACE_DETACH => {
            let target_pid = pid as u32;
            if target_pid == 0 || data_len != 0 {
                return Err(Error::InvalidArgument);
            }
            ptrace_core::ptrace_detach(&process, target_pid)?;
        }

        PTRACE_CONT => {
            let target_pid = pid as u32;
            let signal = data as i32;
            if target_pid == 0 || data_len != 0 {
                return Err(Error::InvalidArgument);
            }
            ptrace_core::ptrace_continue(&process, target_pid, signal)?;
        }

        PTRACE_SYSCALL => {
            let target_pid = pid as u32;
            let signal = data as i32;
            if target_pid == 0 || data_len != 0 {
                return Err(Error::InvalidArgument);
            }
            ptrace_core::ptrace_syscall(&process, target_pid, signal)?;
        }

        PTRACE_SINGLESTEP => {
            // Not yet implemented.
            return Err(Error::NotImplemented);
        }

        PTRACE_GETREGS => {
            let target_pid = pid as u32;
            if target_pid == 0 {
                return Err(Error::InvalidArgument);
            }
            // `data` is the user-space buffer pointer, `data_len` is its size.
            let out_ptr = data as *mut u8;
            let out_len = data_len;
            if out_ptr.is_null() || out_len < PTRACE_REGS_SIZE_X86_64 {
                return Err(Error::InvalidArgument);
            }
            user_memory::with_optional_output_slice(out_ptr, out_len, |buffer| {
                ptrace_core::ptrace_get_regs(&process, target_pid, buffer)
            })?;
        }

        PTRACE_SETREGS => {
            let target_pid = pid as u32;
            if target_pid == 0 {
                return Err(Error::InvalidArgument);
            }
            let in_ptr = data as *const u8;
            let in_len = data_len;
            if in_ptr.is_null() || in_len < PTRACE_REGS_SIZE_X86_64 {
                return Err(Error::InvalidArgument);
            }
            user_memory::with_optional_input_slice(in_ptr, in_len, |buffer| {
                ptrace_core::ptrace_set_regs(&process, target_pid, buffer)
            })?;
        }

        PTRACE_PEEKDATA => {
            let target_pid = pid as u32;
            if target_pid == 0 || data_len > 8 {
                return Err(Error::InvalidArgument);
            }
            let out_ptr = data as *mut u8;
            if out_ptr.is_null() {
                return Err(Error::InvalidArgument);
            }
            let len = if data_len == 0 { 8 } else { data_len };
            user_memory::with_optional_output_slice(out_ptr, len, |buffer| {
                ptrace_core::ptrace_peek_data(&process, target_pid, addr, buffer)
            })?;
        }

        PTRACE_POKEDATA => {
            let target_pid = pid as u32;
            if target_pid == 0 || data_len > 8 {
                return Err(Error::InvalidArgument);
            }
            let in_ptr = data as *const u8;
            if in_ptr.is_null() {
                return Err(Error::InvalidArgument);
            }
            let len = if data_len == 0 { 8 } else { data_len };
            user_memory::with_optional_input_slice(in_ptr, len, |buffer| {
                ptrace_core::ptrace_poke_data(&process, target_pid, addr, buffer)
            })?;
        }

        PTRACE_GETEVENTMSG => {
            let target_pid = pid as u32;
            if target_pid == 0 {
                return Err(Error::InvalidArgument);
            }
            let out_ptr = data as *mut u8;
            let out_len = data_len;
            if out_ptr.is_null() || out_len < PTRACE_EVENT_RECORD_SIZE {
                return Err(Error::InvalidArgument);
            }
            let mut record = PtraceEventRecord {
                tid: 0,
                event: 0,
                message: 0,
                syscall_number: 0,
            };
            ptrace_core::ptrace_get_event_msg(&process, target_pid, &mut record)?;

            // Serialize and copy to user space.
            let mut buf = [0u8; PTRACE_EVENT_RECORD_SIZE];
            buf[0..4].copy_from_slice(&record.tid.to_ne_bytes());
            buf[4..8].copy_from_slice(&record.event.to_ne_bytes());
            let msg_bytes = record.message.to_ne_bytes();
            let sc_bytes = record.syscall_number.to_ne_bytes();
            buf[8..8 + msg_bytes.len()].copy_from_slice(&msg_bytes);
            buf[8 + msg_bytes.len()..].copy_from_slice(&sc_bytes);

            user_memory::copy_user_bytes(&buf, out_ptr, out_len.min(PTRACE_EVENT_RECORD_SIZE))?;
        }

        _ => {
            // Unknown ptrace request.
            return Err(Error::NotImplemented);
        }
    }

    Ok(SyscallDispatch::complete(0))
}
