//! src/user/syscall/invoke_x86_64.rs
//!
//! Entering the kernel from x86_64 user mode.
//!
//! The syscall number goes in `rax`, the arguments in the interrupt
//! registers, and the encoded status comes back in `rax` — the ABI the
//! kernel's own entry establishes.

use core::arch::asm;

use crate::abi::syscall as syscall_abi;

/// Invoke the kernel and return the encoded status word.
///
/// # Safety
///
/// Must be called from x86_64 user mode.  The caller must pass arguments
/// exactly as the raw ABI requires and guarantee that any pointer-valued
/// argument is a valid user address for the duration of the trap.
pub(super) unsafe fn raw_status(
    number: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> usize {
    let status: usize;
    // SAFETY: the trap is the only way into the kernel from here, and the
    // register assignment below is exactly the ABI the kernel's entry reads.
    // The caller's contract covers the arguments; nothing else is touched.
    unsafe {
        asm!(
            "int {vector}",
            vector = const syscall_abi::X86_64_INTERRUPT_VECTOR,
            inlateout("rax") number => status,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("rcx") arg3,
            in("r8") arg4,
            in("r9") arg5,
        );
    }
    status
}
