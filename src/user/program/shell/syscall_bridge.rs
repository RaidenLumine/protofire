//! src/user/program/shell/syscall_bridge.rs
//! Kernel-side implementations of the `extern "Rust"` syscall entry points
//! declared by `crate::user::shared::syscall`.
//!
//! Each function wraps the kernel's `UserSyscall` builders + `syscall::dispatch()`
//! so that shared shared command code can call syscalls without knowing
//! whether it runs in ring0 or ring3.

use crate::kernel::syscall;
use crate::kernel::syscall::SyscallContext;

/// Convert a `Result<usize, Error>` from `syscall::dispatch` into an `isize`
/// compatible with the shared syscall ABI (negative = error).
///
/// Error discriminants are encoded as `-(discriminant + 1)` so that shared
/// can distinguish error kinds:
///   InvalidArgument(0)→-1  NotFound(1)→-2  AlreadyExists(2)→-3
///   PermissionDenied(3)→-4  OutOfMemory(4)→-5  DeviceError(5)→-6
///   Busy(6)→-7  TimedOut(7)→-8  Unsupported(8)→-9
///   NotImplemented(9)→-10  InternalError(10)→-11  InvalidCredential(11)→-12
#[inline(always)]
fn to_isize(result: Result<usize, crate::Error>) -> isize {
    match result {
        Ok(v) => v as isize,
        Err(e) => -((e as isize) + 1),
    }
}

#[no_mangle]
extern "Rust" fn __shell_syscall0(number: usize) -> isize {
    let mut ctx = SyscallContext::new(number, [0usize; 6]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall1(number: usize, a0: usize) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, 0, 0, 0, 0, 0]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall2(number: usize, a0: usize, a1: usize) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, a1, 0, 0, 0, 0]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall3(number: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, a1, a2, 0, 0, 0]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall4(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, a1, a2, a3, 0, 0]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall5(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, a1, a2, a3, a4, 0]);
    to_isize(syscall::dispatch(&mut ctx))
}

#[no_mangle]
extern "Rust" fn __shell_syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    let mut ctx = SyscallContext::new(number, [a0, a1, a2, a3, a4, a5]);
    to_isize(syscall::dispatch(&mut ctx))
}
