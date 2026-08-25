//! src/user/exception.rs
//!
//! User-side typed wrappers around the shared exception ABI and exception
//! syscalls.

use super::syscall::UserSyscall;
pub use crate::abi::exception::AArch64AbortSyndrome;
pub use crate::abi::exception::AArch64UserExceptionFrame;
pub use crate::abi::exception::X86_64PageFaultError;
pub use crate::abi::exception::X86_64UserExceptionFrame;
pub use crate::abi::exception::AARCH64_ABORT_ACCESS_KIND_EXECUTE;
pub use crate::abi::exception::AARCH64_ABORT_ACCESS_KIND_READ;
pub use crate::abi::exception::AARCH64_ABORT_ACCESS_KIND_UNKNOWN;
pub use crate::abi::exception::AARCH64_ABORT_ACCESS_KIND_WRITE;
pub use crate::abi::exception::AARCH64_EXCEPTION_DATA_ABORT_VECTOR;
pub use crate::abi::exception::AARCH64_EXCEPTION_INSTRUCTION_ABORT_VECTOR;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_INSTRUCTION_POINTER_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_SAVED_PROGRAM_STATUS_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_SIZE;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_STACK_POINTER_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_VECTOR_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X0_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X10_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X11_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X12_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X13_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X14_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X15_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X16_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X17_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X18_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X19_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X1_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X20_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X21_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X22_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X23_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X24_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X25_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X26_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X27_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X28_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X29_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X2_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X30_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X3_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X4_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X5_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X6_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X7_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X8_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_FRAME_X9_OFFSET;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
pub use crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
pub use crate::abi::exception::X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR;
pub use crate::abi::exception::X86_64_EXCEPTION_INVALID_OPCODE_VECTOR;
pub use crate::abi::exception::X86_64_EXCEPTION_PAGE_FAULT_VECTOR;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_ERROR_CODE_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_FAULT_ADDRESS_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R10_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R11_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R12_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R13_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R14_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R15_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R8_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_R9_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RAX_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RBP_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RBX_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RCX_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RDI_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RDX_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RFLAGS_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RIP_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RSI_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_RSP_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_SIZE;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_FRAME_VECTOR_OFFSET;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
pub use crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
// `SyscallNumber` is only used from the x86_64/AArch64 dispatchers below; on
// RISC-V the import is unused, so silence it for that target only.
#[cfg_attr(target_arch = "riscv64", allow(unused_imports))]
use crate::kernel::syscall::SyscallContext;
#[cfg_attr(target_arch = "riscv64", allow(unused_imports))]
use crate::kernel::syscall::SyscallNumber;

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
