//! src/arch/ptrace.rs
//!
//! A tracee's user registers, per architecture.
//!
//! The ptrace register requests read and write the tracee's saved user context
//! in the fixed layout the ABI declares for that machine.  x86_64 is the only
//! machine with such a layout so far; the others refuse the request rather
//! than invent one, which is what the syscall's error return is for.

use crate::kernel::process::Thread;
use crate::Error;
use crate::Result;

/// Read `thread`'s user registers into `buffer`, in this machine's layout.
#[cfg(target_arch = "x86_64")]
pub(crate) fn get_regs(thread: &Thread, buffer: &mut [u8]) -> Result<()> {
    use crate::abi::ptrace::PTRACE_REGS_SIZE_X86_64;

    let ctx = thread.x86_64_user_context().ok_or(Error::Unsupported)?;

    let regs = context_to_ptrace_regs(&ctx);
    // SAFETY: the struct is `repr(C)` and holds only integers, so its bytes
    // are a valid read of that many bytes from a live, initialised value.
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

/// Write `buffer` into `thread`'s user registers.
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_regs(thread: &Thread, buffer: &[u8]) -> Result<()> {
    use crate::abi::ptrace::PTRACE_REGS_SIZE_X86_64;

    if buffer.len() < PTRACE_REGS_SIZE_X86_64 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: an all-zero byte pattern is a valid `PtraceUserRegsStruct` — it
    // holds integers and has no padding invariants — and the conversion below
    // overwrites every field it reads.
    let mut regs: crate::abi::ptrace::PtraceUserRegsStruct = unsafe { core::mem::zeroed() };
    // SAFETY: the struct is `repr(C)` and holds only integers, so its bytes
    // are a valid write target for exactly that many bytes.
    let regs_slice = unsafe {
        core::slice::from_raw_parts_mut(
            &mut regs as *mut crate::abi::ptrace::PtraceUserRegsStruct as *mut u8,
            PTRACE_REGS_SIZE_X86_64,
        )
    };
    regs_slice.copy_from_slice(&buffer[..PTRACE_REGS_SIZE_X86_64]);

    thread.set_x86_64_user_context(ptrace_regs_to_context(&regs));
    Ok(())
}

/// A machine with no ptrace register layout says so.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn get_regs(_thread: &Thread, _buffer: &mut [u8]) -> Result<()> {
    Err(Error::Unsupported)
}

/// A machine with no ptrace register layout says so.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn set_regs(_thread: &Thread, _buffer: &[u8]) -> Result<()> {
    Err(Error::Unsupported)
}

/// The tracee's saved context, in the layout the ABI declares.
#[cfg(target_arch = "x86_64")]
fn context_to_ptrace_regs(
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

/// The context that corresponds to what a tracer wrote.
#[cfg(target_arch = "x86_64")]
fn ptrace_regs_to_context(
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

// ── Tests ──────────────────────────────────────────────────────────────

/// The register layout only exists on x86_64, so the round trip is only
/// meaningful in that build.
#[cfg(all(test, target_arch = "x86_64"))]
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

        let regs = context_to_ptrace_regs(&ctx);
        assert_eq!(regs.rax, 1);
        assert_eq!(regs.rbx, 2);
        assert_eq!(regs.r15, 15);
        assert_eq!(regs.rip, 0x4000_1000);
        assert_eq!(regs.rflags, 0x202);
        assert_eq!(regs.rsp, 0x7FFF_FF00);
        assert_eq!(regs.cs, 0x33);
        assert_eq!(regs.ss, 0x2B);
        assert_eq!(
            core::mem::size_of_val(&regs),
            crate::abi::ptrace::PTRACE_REGS_SIZE_X86_64
        );

        let roundtrip = ptrace_regs_to_context(&regs);
        assert_eq!(roundtrip.rax, ctx.rax);
        assert_eq!(roundtrip.instruction_pointer, ctx.instruction_pointer);
        assert_eq!(roundtrip.stack_pointer, ctx.stack_pointer);
    }
}
