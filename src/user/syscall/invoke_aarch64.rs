//! src/user/syscall/invoke_aarch64.rs
//!
//! Entering the kernel from aarch64 user mode.
//!
//! The syscall number goes in `x8`, the arguments in `x0..x5`, and the encoded
//! status comes back in `x0` — the ABI the kernel's own entry establishes.

use core::arch::asm;

/// Invoke the kernel and return the encoded status word.
///
/// # Safety
///
/// Must be called from AArch64 user mode (EL0).  The `svc #0` instruction
/// traps to the kernel; the caller must pass arguments exactly as the raw ABI
/// requires and guarantee that any pointer-valued argument is a valid user
/// address for the duration of the trap.
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
            "svc #0",
            in("x8") number,
            inlateout("x0") arg0 => status,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            options(nostack),
        );
    }
    status
}
