//! src/kernel/process/ptrace.rs
//!
//! Core ptrace (process tracing) logic.
//!
//! Provides functions used by the Ptrace syscall handler (#128) and the
//! syscall-entry/exit hooks in the trap dispatch path.

use alloc::sync::Arc;

// `PTRACE_REGS_SIZE_X86_64` is only referenced from x86_64-gated helpers
// below; on aarch64 / riscv64 the import is unused, so silence it.
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
use crate::abi::ptrace::PtraceEventRecord;
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
use crate::abi::ptrace::PTRACE_EVENT_ATTACH;
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
use crate::abi::ptrace::PTRACE_EVENT_SYSCALL_EXIT;
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
use crate::abi::ptrace::PTRACE_REGS_SIZE_X86_64;
use crate::kernel::process::process::types::ptrace_flags::*;
use crate::kernel::process::process::types::PtraceEvent;
use crate::kernel::process::process::types::ThreadId;
use crate::kernel::process::Process;
use crate::kernel::process::ProcessId;
use crate::kernel::process::Scheduler;
use crate::kernel::process::Thread;
use crate::Error;
use crate::Result;

// ── Public API
// ────────────────────────────────────────────────────────────────

/// PTRACE_TRACEME: mark the calling process as traceable by its parent.
///
/// Must be called before the parent attaches.  After this call, the parent
/// (determined by `parent_pid`) can use ptrace requests on this process.
pub fn ptrace_traceme(process: &Process) -> Result<()> {
    let parent = process.parent_pid().ok_or(Error::InvalidArgument)?;

    let mut tracer = process.tracer_pid.lock();
    if tracer.is_some() {
        return Err(Error::Busy);
    }
    *tracer = Some(parent);

    let mut flags = process.ptrace_options.lock();
    *flags |= PF_TRACED;

    Ok(())
}

/// PTRACE_ATTACH: attach to a target process.
///
/// The caller must have suitable privileges (same UID or system integrity).
pub fn ptrace_attach(tracer: &Process, target_pid: ProcessId) -> Result<()> {
    let scheduler = Scheduler::global().ok_or(Error::Unsupported)?;

    // Look up the target process.
    let target = find_process(target_pid)?;

    // Permission check: tracer must dominate tracee's integrity level.
    check_ptrace_permission(tracer, &target)?;

    // Must not already be traced.
    {
        let mut tracer_pid = target.tracer_pid.lock();
        if tracer_pid.is_some() {
            return Err(Error::Busy);
        }
        *tracer_pid = Some(tracer.pid());
    }

    // Mark as traced and set syscall-trace flag so we stop at the next
    // syscall boundary.
    {
        let mut flags = target.ptrace_options.lock();
        *flags |= PF_TRACED | PF_SYSCALL_TRACE;
    }

    // Stop the target process.
    scheduler.stop_process(target_pid).ok();

    // Enqueue the attach event for the tracer to consume.
    ptrace_event_queue_push(
        &target,
        PtraceEvent {
            tid: target.pid() as ThreadId,
            event: PTRACE_EVENT_ATTACH as u32,
            message: 0,
            syscall_number: 0,
        },
    );

    Ok(())
}

/// PTRACE_DETACH: detach from a tracee and let it continue normally.
pub fn ptrace_detach(tracer: &Process, target_pid: ProcessId) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    // Clear ptrace flags.
    {
        let mut flags = target.ptrace_options.lock();
        *flags &= !(PF_TRACED | PF_SYSCALL_TRACE);
    }
    {
        let mut tracer_pid = target.tracer_pid.lock();
        *tracer_pid = None;
    }

    // Resume the tracee.
    resume_tracee(target_pid)
}

/// PTRACE_CONT: continue a stopped tracee (optionally injecting a signal).
pub fn ptrace_continue(tracer: &Process, target_pid: ProcessId, _signal: i32) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    // Clear syscall-trace so the tracee runs freely.
    let mut flags = target.ptrace_options.lock();
    *flags &= !PF_SYSCALL_TRACE;
    drop(flags);

    resume_tracee(target_pid)
}

/// PTRACE_SYSCALL: continue but stop at the next syscall exit.
pub fn ptrace_syscall(tracer: &Process, target_pid: ProcessId, _signal: i32) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    // Set syscall-trace so we stop after the next syscall.
    let mut flags = target.ptrace_options.lock();
    *flags |= PF_SYSCALL_TRACE;
    drop(flags);

    resume_tracee(target_pid)
}

/// PTRACE_GETREGS: read the tracee's user-mode register file.
#[cfg(target_arch = "x86_64")]
pub fn ptrace_get_regs(tracer: &Process, target_pid: ProcessId, buffer: &mut [u8]) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    // Find the first thread of the target process.
    let thread = find_first_thread(&target)?;

    let ctx = thread.x86_64_user_context().ok_or(Error::Unsupported)?;

    // Serialize the register context into the buffer.
    let regs = abi_to_ptrace_regs(&ctx);
    let regs_bytes = unsafe {
        core::slice::from_raw_parts(
            &regs as *const crate::abi::ptrace::PtraceUserRegsStruct as *const u8,
            PTRACE_REGS_SIZE_X86_64,
        )
    };

    let len = buffer.len().min(PTRACE_REGS_SIZE_X86_64);
    buffer[..len].copy_from_slice(&regs_bytes[..len]);
    Ok(())
}

/// PTRACE_SETREGS: write the tracee's user-mode register file.
#[cfg(target_arch = "x86_64")]
pub fn ptrace_set_regs(tracer: &Process, target_pid: ProcessId, buffer: &[u8]) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    let thread = find_first_thread(&target)?;

    let len = buffer.len().min(PTRACE_REGS_SIZE_X86_64);
    if len < PTRACE_REGS_SIZE_X86_64 {
        return Err(Error::InvalidArgument);
    }

    // Deserialize from buffer into PtraceUserRegsStruct.
    let mut regs: crate::abi::ptrace::PtraceUserRegsStruct = unsafe { core::mem::zeroed() };
    let regs_slice = unsafe {
        core::slice::from_raw_parts_mut(
            &mut regs as *mut crate::abi::ptrace::PtraceUserRegsStruct as *mut u8,
            PTRACE_REGS_SIZE_X86_64,
        )
    };
    regs_slice.copy_from_slice(&buffer[..PTRACE_REGS_SIZE_X86_64]);

    // Convert to kernel user context and write it.
    let ctx = ptrace_to_abi_regs(&regs);
    thread.set_x86_64_user_context(ctx);
    Ok(())
}

/// Non-x86_64 stub for PTRACE_GETREGS.
#[cfg(not(target_arch = "x86_64"))]
pub fn ptrace_get_regs(
    _tracer: &Process,
    _target_pid: ProcessId,
    _buffer: &mut [u8],
) -> Result<()> {
    Err(Error::Unsupported)
}

/// Non-x86_64 stub for PTRACE_SETREGS.
#[cfg(not(target_arch = "x86_64"))]
pub fn ptrace_set_regs(_tracer: &Process, _target_pid: ProcessId, _buffer: &[u8]) -> Result<()> {
    Err(Error::Unsupported)
}

/// PTRACE_PEEKDATA: read a word from the tracee's address space.
pub fn ptrace_peek_data(
    tracer: &Process,
    target_pid: ProcessId,
    addr: usize,
    data_out: &mut [u8],
) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    // Use the user memory access helper with the tracee's address space.
    // We need to validate the mapping in the tracee's page table.
    use crate::kernel::syscall::user_memory;

    let len = data_out.len();
    user_memory::validate_user_mapping(
        &target,
        addr,
        len,
        crate::kernel::memory::paging::PagePermissions::READ,
    )?;

    // Read from the tracee's address space using raw pointer access.
    // SAFETY: we validated the mapping above.
    unsafe {
        core::ptr::copy_nonoverlapping(addr as *const u8, data_out.as_mut_ptr(), len);
    }
    Ok(())
}

/// PTRACE_POKEDATA: write a word to the tracee's address space.
pub fn ptrace_poke_data(
    tracer: &Process,
    target_pid: ProcessId,
    addr: usize,
    data: &[u8],
) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    use crate::kernel::syscall::user_memory;

    let len = data.len();
    user_memory::validate_user_mapping(
        &target,
        addr,
        len,
        crate::kernel::memory::paging::PagePermissions::READ
            | crate::kernel::memory::paging::PagePermissions::WRITE,
    )?;

    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, len);
    }
    Ok(())
}

/// PTRACE_GETEVENTMSG: consume the next ptrace event from the tracee's queue.
pub fn ptrace_get_event_msg(
    tracer: &Process,
    target_pid: ProcessId,
    record_out: &mut PtraceEventRecord,
) -> Result<()> {
    let target = find_process(target_pid)?;
    verify_tracer(tracer, &target)?;

    let mut queue = target.ptrace_event_queue.lock();
    let event = queue.pop_front().ok_or(Error::NotFound)?;

    record_out.tid = event.tid as u64;
    record_out.event = event.event as u64;
    record_out.message = event.message as u64;
    record_out.syscall_number = event.syscall_number as u64;

    Ok(())
}

// ── Syscall hooks (called from dispatch_with_action)
// ──────────────────────────

/// Called AFTER a syscall handler completes, just before returning to user
/// mode.
///
/// If the process is being syscall-traced, we enqueue a stop event and
/// suspend the current thread.  The caller should then yield the CPU so
/// the tracer can process the event.
///
/// Returns `true` if the thread should yield (trace-stop occurred).
pub fn notify_syscall_exit(
    process: &Process,
    syscall_number: usize,
    _result: &Result<usize>,
) -> bool {
    let flags = *process.ptrace_options.lock();

    if (flags & (PF_TRACED | PF_SYSCALL_TRACE)) != (PF_TRACED | PF_SYSCALL_TRACE) {
        return false;
    }

    // We only stop at syscall exit, not entry (see module docs for rationale).
    // Enqueue a syscall-exit event.
    ptrace_event_queue_push(
        process,
        PtraceEvent {
            tid: process.pid() as ThreadId,
            event: PTRACE_EVENT_SYSCALL_EXIT as u32,
            message: syscall_number,
            syscall_number,
        },
    );

    // Suspend the current thread so the tracer can process the event.
    if let Some(scheduler) = Scheduler::global() {
        if let Some(current) = scheduler.current_thread() {
            current.suspend();
            return true; // tell caller to yield
        }
    }
    false
}

// ── Helpers
// ───────────────────────────────────────────────────────────────────

/// Look up a process by PID from the global scheduler.
fn find_process(pid: ProcessId) -> Result<Arc<Process>> {
    let scheduler = Scheduler::global().ok_or(Error::Unsupported)?;
    scheduler.process_by_pid(pid).ok_or(Error::NotFound)
}

/// Verify that `tracer` is indeed the tracer of `target`.
fn verify_tracer(tracer: &Process, target: &Process) -> Result<()> {
    let expected = target.tracer_pid.lock();
    match *expected {
        Some(pid) if pid == tracer.pid() => Ok(()),
        _ => Err(Error::PermissionDenied),
    }
}

/// Check that the tracer has permission to trace the target.
///
/// Currently: must be same PID (for TRACEME), same UID, or a system process.
fn check_ptrace_permission(tracer: &Process, target: &Process) -> Result<()> {
    let tracer_uid = tracer.security_token().user_id;
    let target_uid = target.security_token().user_id;

    // Allow when same user or when tracer has system integrity.
    if tracer_uid == target_uid
        || tracer.security_token().integrity >= crate::kernel::process::IntegrityLevel::High
    {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// Find the first thread of a process.
/// Only used by the x86_64 register helpers below.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn find_first_thread(target: &Process) -> Result<Arc<Thread>> {
    let scheduler = Scheduler::global().ok_or(Error::Unsupported)?;
    let threads = target.thread_ids();
    let tid = *threads.first().ok_or(Error::NotFound)?;
    scheduler.find_thread_by_tid(tid).ok_or(Error::NotFound)
}

/// Push a ptrace event onto the process's event queue.
fn ptrace_event_queue_push(process: &Process, event: PtraceEvent) {
    process.ptrace_event_queue.lock().push_back(event);
}

/// Resume a tracee by continuing its process.
fn resume_tracee(pid: ProcessId) -> Result<()> {
    let scheduler = Scheduler::global().ok_or(Error::Unsupported)?;
    scheduler.continue_process(pid).ok();
    Ok(())
}

// ── Register format conversion (x86_64)
// ───────────────────────────────────────

/// Convert a kernel `X86_64UserThreadContext` to the ABI
/// `PtraceUserRegsStruct`.
#[cfg(target_arch = "x86_64")]
fn abi_to_ptrace_regs(
    ctx: &crate::kernel::process::process::types::X86_64UserThreadContext,
) -> crate::abi::ptrace::PtraceUserRegsStruct {
    crate::abi::ptrace::PtraceUserRegsStruct {
        rax: ctx.rax,
        rbx: ctx.rbx,
        rcx: ctx.rcx,
        rdx: ctx.rdx,
        rsi: ctx.rsi,
        rdi: ctx.rdi,
        rbp: ctx.rbp,
        r8: ctx.r8,
        r9: ctx.r9,
        r10: ctx.r10,
        r11: ctx.r11,
        r12: ctx.r12,
        r13: ctx.r13,
        r14: ctx.r14,
        r15: ctx.r15,
        rip: ctx.instruction_pointer,
        cs: ctx.code_segment,
        rflags: ctx.rflags,
        rsp: ctx.stack_pointer,
        ss: ctx.stack_segment,
        fs_base: 0,
        gs_base: 0,
    }
}

/// Convert an ABI `PtraceUserRegsStruct` back to a kernel
/// `X86_64UserThreadContext`.
#[cfg(target_arch = "x86_64")]
fn ptrace_to_abi_regs(
    regs: &crate::abi::ptrace::PtraceUserRegsStruct,
) -> crate::kernel::process::process::types::X86_64UserThreadContext {
    crate::kernel::process::process::types::X86_64UserThreadContext {
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        rbp: regs.rbp,
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        instruction_pointer: regs.rip,
        code_segment: regs.cs,
        rflags: regs.rflags,
        stack_pointer: regs.rsp,
        stack_segment: regs.ss,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::process::process::types::X86_64UserThreadContext;

    #[test]
    fn abi_ptrace_regs_roundtrip() {
        let ctx = X86_64UserThreadContext {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rbp: 7,
            r8: 8,
            r9: 9,
            r10: 10,
            r11: 11,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,
            instruction_pointer: 0x4000_1000,
            code_segment: 0x33,
            rflags: 0x202,
            stack_pointer: 0x7FFF_FF00,
            stack_segment: 0x2B,
        };

        let regs = abi_to_ptrace_regs(&ctx);
        assert_eq!(regs.rax, 1);
        assert_eq!(regs.rbx, 2);
        assert_eq!(regs.r15, 15);
        assert_eq!(regs.rip, 0x4000_1000);
        assert_eq!(regs.rflags, 0x202);
        assert_eq!(regs.rsp, 0x7FFF_FF00);
        assert_eq!(regs.cs, 0x33);
        assert_eq!(regs.ss, 0x2B);
        assert_eq!(core::mem::size_of_val(&regs), PTRACE_REGS_SIZE_X86_64);

        let roundtrip = ptrace_to_abi_regs(&regs);
        assert_eq!(roundtrip.rax, ctx.rax);
        assert_eq!(roundtrip.instruction_pointer, ctx.instruction_pointer);
        assert_eq!(roundtrip.stack_pointer, ctx.stack_pointer);
    }
}
