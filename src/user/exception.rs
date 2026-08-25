//! src/user/exception.rs
//!
//! User-side typed wrappers around the shared exception ABI and exception
//! syscalls.

use super::syscall::UserSyscall;
pub use crate::abi::exception::{
    AArch64AbortSyndrome, AArch64UserExceptionFrame, AARCH64_ABORT_ACCESS_KIND_EXECUTE,
    AARCH64_ABORT_ACCESS_KIND_READ, AARCH64_ABORT_ACCESS_KIND_UNKNOWN,
    AARCH64_ABORT_ACCESS_KIND_WRITE, AARCH64_EXCEPTION_DATA_ABORT_VECTOR,
    AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR, AARCH64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_INSTRUCTION_POINTER_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_SAVED_PROGRAM_STATUS_OFFSET, AARCH64_USER_EXCEPTION_FRAME_SIZE,
    AARCH64_USER_EXCEPTION_FRAME_STACK_POINTER_OFFSET, AARCH64_USER_EXCEPTION_FRAME_VECTOR_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X0_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X10_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X11_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X12_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X13_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X14_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X15_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X16_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X17_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X18_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X19_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X1_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X20_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X21_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X22_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X23_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X24_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X25_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X26_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X27_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X28_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X29_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X2_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X30_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X3_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X4_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X5_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X6_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X7_OFFSET, AARCH64_USER_EXCEPTION_FRAME_X8_OFFSET,
    AARCH64_USER_EXCEPTION_FRAME_X9_OFFSET, AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE, AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
pub use crate::abi::exception::{
    X86_64PageFaultError, X86_64UserExceptionFrame, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    X86_64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET, X86_64_USER_EXCEPTION_FRAME_R10_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_R11_OFFSET, X86_64_USER_EXCEPTION_FRAME_R12_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_R13_OFFSET, X86_64_USER_EXCEPTION_FRAME_R14_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_R15_OFFSET, X86_64_USER_EXCEPTION_FRAME_R8_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_R9_OFFSET, X86_64_USER_EXCEPTION_FRAME_RAX_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_RBP_OFFSET, X86_64_USER_EXCEPTION_FRAME_RBX_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_RCX_OFFSET, X86_64_USER_EXCEPTION_FRAME_RDI_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_RDX_OFFSET, X86_64_USER_EXCEPTION_FRAME_RFLAGS_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_RIP_OFFSET, X86_64_USER_EXCEPTION_FRAME_RSI_OFFSET,
    X86_64_USER_EXCEPTION_FRAME_RSP_OFFSET, X86_64_USER_EXCEPTION_FRAME_SIZE,
    X86_64_USER_EXCEPTION_FRAME_VECTOR_OFFSET, X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE, X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT,
    X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK,
};
// `SyscallNumber` is only used from the x86_64/AArch64 dispatchers below; on
// RISC-V the import is unused, so silence it for that target only.
#[cfg_attr(target_arch = "riscv64", allow(unused_imports))]
use crate::kernel::syscall::{SyscallContext, SyscallNumber};

pub struct AArch64UserException;

impl AArch64UserException {
    pub const fn install_handler(vector: u8, handler: usize) -> SyscallContext {
        UserSyscall::install_exception_handler(vector as usize, handler)
    }

    pub const fn install_handler_with(
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> SyscallContext {
        UserSyscall::install_exception_handler_with(vector as usize, handler, stack_pointer, flags)
    }

    pub fn return_from_frame(frame: *const AArch64UserExceptionFrame) -> SyscallContext {
        UserSyscall::return_from_exception(frame as usize)
    }
}

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
impl AArch64UserException {
    #[inline(always)]
    pub unsafe fn install_handler_from_user_mode(vector: u8, handler: usize) -> usize {
        Self::install_handler_from_user_mode_with(vector, handler, 0, 0)
    }

    #[inline(always)]
    pub unsafe fn install_handler_from_user_mode_with(
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> usize {
        UserSyscall::invoke_raw_status_from_user_mode(
            SyscallNumber::InstallExceptionHandler as usize,
            vector as usize,
            handler,
            stack_pointer,
            flags,
            0,
            0,
        )
    }

    #[inline(always)]
    pub unsafe fn return_from_frame_from_user_mode(
        frame: *const AArch64UserExceptionFrame,
    ) -> usize {
        UserSyscall::invoke_raw_status_from_user_mode(
            SyscallNumber::ReturnFromException as usize,
            frame as usize,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

pub struct X86_64UserException;

impl X86_64UserException {
    pub const fn install_handler(vector: u8, handler: usize) -> SyscallContext {
        UserSyscall::install_exception_handler(vector as usize, handler)
    }

    pub const fn install_handler_with(
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> SyscallContext {
        UserSyscall::install_exception_handler_with(vector as usize, handler, stack_pointer, flags)
    }

    pub fn return_from_frame(frame: *const X86_64UserExceptionFrame) -> SyscallContext {
        UserSyscall::return_from_exception(frame as usize)
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
impl X86_64UserException {
    #[inline(always)]
    /// Install an x86_64 exception handler from ring 3 using the raw syscall
    /// ABI.
    ///
    /// # Safety
    /// The caller must provide a valid user-space handler entry point for the
    /// current process image. Supplying an invalid address will fault when the
    /// kernel later dispatches the exception back to user mode.
    pub unsafe fn install_handler_from_user_mode(vector: u8, handler: usize) -> usize {
        Self::install_handler_from_user_mode_with(
            vector,
            handler,
            0,
            X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE,
        )
    }

    #[inline(always)]
    /// Install an x86_64 exception handler with an explicit user stack and
    /// flags.
    ///
    /// # Safety
    /// The caller must ensure `handler` and `stack_pointer` are valid
    /// user-space addresses for the current process and that `flags` satisfy
    /// the exception ABI contract.
    pub unsafe fn install_handler_from_user_mode_with(
        vector: u8,
        handler: usize,
        stack_pointer: usize,
        flags: usize,
    ) -> usize {
        UserSyscall::invoke_raw_status_from_user_mode(
            SyscallNumber::InstallExceptionHandler as usize,
            vector as usize,
            handler,
            stack_pointer,
            flags,
            0,
            0,
        )
    }

    #[inline(always)]
    /// Return to user mode from a previously delivered exception frame.
    ///
    /// # Safety
    /// `frame` must point at a live user exception frame with the exact layout
    /// expected by the running architecture. Passing any other pointer is
    /// invalid and may fault during kernel validation.
    pub unsafe fn return_from_frame_from_user_mode(
        frame: *const X86_64UserExceptionFrame,
    ) -> usize {
        UserSyscall::invoke_raw_status_from_user_mode(
            SyscallNumber::ReturnFromException as usize,
            frame as usize,
            0,
            0,
            0,
            0,
            0,
        )
    }
}
