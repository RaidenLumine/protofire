//! src/user/syscall/mod.rs
//! User-side syscall builders and architecture-specific invocation helpers.

#[cfg(any(
    all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
    all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
))]
use core::arch::asm;

#[cfg(any(
    all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
    all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
))]
use crate::abi::syscall as syscall_abi;
// Needed only by the architecture-specific invocation primitives below.
#[cfg(any(
    all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
    all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
))]
use crate::kernel::syscall::SyscallNumber;

pub struct UserSyscall;

// Re-export the architecture-specific exception-handler flags behind one user
// API so demo/runtime code can stay target-agnostic.
#[cfg(target_arch = "x86_64")]
pub const USER_EXCEPTION_HANDLER_FLAGS_NONE: usize =
    crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_NONE;
#[cfg(target_arch = "aarch64")]
pub const USER_EXCEPTION_HANDLER_FLAGS_NONE: usize =
    crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_NONE;
#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(target_arch = "aarch64"))]
pub const USER_EXCEPTION_HANDLER_FLAGS_NONE: usize = 0;

#[cfg(target_arch = "x86_64")]
pub const USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT: usize =
    crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
#[cfg(target_arch = "aarch64")]
pub const USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT: usize =
    crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(target_arch = "aarch64"))]
pub const USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT: usize = 0;

#[cfg(target_arch = "x86_64")]
pub const USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK: usize =
    crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
#[cfg(target_arch = "aarch64")]
pub const USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK: usize =
    crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(target_arch = "aarch64"))]
pub const USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK: usize = 0;

#[cfg(target_arch = "x86_64")]
pub const USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED: usize =
    crate::abi::exception::X86_64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
#[cfg(target_arch = "aarch64")]
pub const USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED: usize =
    crate::abi::exception::AARCH64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
#[cfg(not(target_arch = "x86_64"))]
#[cfg(not(target_arch = "aarch64"))]
pub const USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED: usize = 0;

// ── submodules ────────────────────────────────────────────────────

mod fs;
mod payload;
mod process;

// ── invocation primitives ──────────────────────────────────────────

impl UserSyscall {
    #[cfg(any(
        all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
        all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
    ))]
    #[inline(always)]
    /// Invoke a typed syscall directly from user mode.
    ///
    /// # Safety
    /// The caller must satisfy the architecture's raw syscall ABI and ensure
    /// every pointer encoded in `args` references valid user memory for the
    /// duration of the trap.
    pub unsafe fn invoke_from_user_mode(
        number: SyscallNumber,
        args: [usize; syscall_abi::ARG_COUNT],
    ) -> crate::Result<usize> {
        Self::invoke_raw_from_user_mode(number as usize, args)
    }

    #[cfg(any(
        all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
        all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
    ))]
    #[inline(always)]
    /// Invoke a raw syscall number directly from user mode.
    ///
    /// # Safety
    /// The caller must ensure `number` names a valid syscall for the current
    /// ABI and that every pointer encoded in `args` is a valid user-space
    /// pointer visible to the kernel.
    pub unsafe fn invoke_raw_from_user_mode(
        number: usize,
        args: [usize; syscall_abi::ARG_COUNT],
    ) -> crate::Result<usize> {
        // The raw trap returns the shared encoded syscall status word; decode it
        // here so higher layers can work with `Result<usize>` directly.
        let status = Self::invoke_raw_status_from_user_mode(
            number, args[0], args[1], args[2], args[3], args[4], args[5],
        );
        syscall_abi::decode_result(status)
    }

    // Keep a scalar-only raw path available for extracted payload sections so
    // they do not need to materialize large syscall context temporaries.
    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
    #[inline(always)]
    /// Invoke the x86_64 raw syscall entry and return the encoded status word.
    ///
    /// # Safety
    /// The caller must pass arguments exactly as required by the raw syscall
    /// ABI and guarantee that any pointer-valued arguments are valid user-space
    /// addresses for kernel access.
    pub unsafe fn invoke_raw_status_from_user_mode(
        number: usize,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> usize {
        let status: usize;
        // Match the x86_64 user->kernel syscall ABI: syscall number in `rax`,
        // arguments in the standard interrupt registers, encoded status back in
        // `rax`.
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
        status
    }

    // Keep a scalar-only raw path available for extracted payload sections so
    // they do not need to materialize large syscall context temporaries.
    /// Invoke a raw syscall from AArch64 user mode and return the status.
    ///
    /// # Safety
    ///
    /// Must be called from AArch64 user mode (EL0).  The `svc #0`
    /// instruction traps to the kernel; arguments are passed in
    /// registers `x8` (syscall number) and `x0..x5` per the AArch64
    /// user→kernel calling convention.
    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
    #[inline(always)]
    pub unsafe fn invoke_raw_status_from_user_mode(
        number: usize,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> usize {
        let status: usize;
        // Match the AArch64 user->kernel syscall ABI: syscall number in `x8`,
        // arguments in `x0..x5`, encoded status returned through `x0`.
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
        status
    }
}

// ── payload-runtime macros ──────────────────────────────────────────

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[allow(unused_imports)]
pub(crate) use payload::define_aarch64_payload_runtime;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[allow(unused_imports)]
pub(crate) use payload::define_x86_64_payload_runtime;
