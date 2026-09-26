//! src/user/syscall/mod.rs
//!
//! User-side syscall builders and the trap that enters the kernel.
//!
//! The builders are target-independent — they put a request in registers the
//! ABI fixes — and the trap itself is the machine's, so it lives one file per
//! machine beside this one.  Everything here that is gated is a single
//! statement about which machines have a user-mode syscall surface at all.

pub struct UserSyscall;

// Re-export the exception-handler flags behind one user API so demo and
// runtime code can stay target-agnostic.  They live in the ABI module, where
// the per-architecture names are, and where the assertion that their
// numbering agrees is.
pub use crate::abi::exception::USER_EXCEPTION_HANDLER_FLAGS_NONE;
pub use crate::abi::exception::USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
pub use crate::abi::exception::USER_EXCEPTION_HANDLER_FLAG_ONE_SHOT;
pub use crate::abi::exception::USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;

// ── submodules ────────────────────────────────────────────────────

mod fs;
mod gpu;
mod payload;
mod process;

// ── invocation primitives ──────────────────────────────────────────
//
// The instruction that enters the kernel from user mode is the machine's:
// `int` with the interrupt registers on x86_64, `svc` with `x8` and `x0..x5`
// on aarch64.  One file per machine holds it, and nothing else here names one.
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[path = "invoke_x86_64.rs"]
mod invoke;
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[path = "invoke_aarch64.rs"]
mod invoke;

/// The trap entry, where this target has one.
///
/// Every method below is the same instruction with a different calling
/// convention wrapped around it, so the gate is on the block rather than
/// repeated on each one: a target that cannot enter the kernel from user mode
/// has no `UserSyscall` at all, which is what the absent methods said.
#[cfg(any(
    all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")),
    all(target_arch = "aarch64", any(target_os = "linux", target_os = "none"))
))]
impl UserSyscall {
    #[inline(always)]
    /// Invoke a typed syscall directly from user mode.
    ///
    /// # Safety
    /// The caller must satisfy the architecture's raw syscall ABI and ensure
    /// every pointer encoded in `args` references valid user memory for the
    /// duration of the trap.
    pub unsafe fn invoke_from_user_mode(
        number: crate::syscall::SyscallNumber,
        args: [usize; crate::abi::syscall::ARG_COUNT],
    ) -> crate::Result<usize> {
        unsafe { Self::invoke_raw_from_user_mode(number as usize, args) }
    }

    #[inline(always)]
    /// Invoke a raw syscall number directly from user mode.
    ///
    /// # Safety
    /// The caller must ensure `number` names a valid syscall for the current
    /// ABI and that every pointer encoded in `args` is a valid user-space
    /// pointer visible to the kernel.
    pub unsafe fn invoke_raw_from_user_mode(
        number: usize,
        args: [usize; crate::abi::syscall::ARG_COUNT],
    ) -> crate::Result<usize> {
        unsafe {
            // The raw trap returns the shared encoded syscall status word; decode it
            // here so higher layers can work with `Result<usize>` directly.
            let status = Self::invoke_raw_status_from_user_mode(
                number, args[0], args[1], args[2], args[3], args[4], args[5],
            );
            crate::abi::syscall::decode_result(status)
        }
    }

    /// Invoke this machine's raw syscall entry and return the encoded status
    /// word.
    ///
    /// Keep a scalar-only raw path available for extracted payload sections so
    /// they do not need to materialize large syscall context temporaries.
    ///
    /// # Safety
    ///
    /// The caller must pass arguments exactly as required by the raw syscall
    /// ABI and guarantee that any pointer-valued arguments are valid user-space
    /// addresses for kernel access.
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
        unsafe { invoke::raw_status(number, arg0, arg1, arg2, arg3, arg4, arg5) }
    }
}

// ── payload-runtime macros ──────────────────────────────────────────

#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "none")))]
#[allow(unused_imports)]
pub(crate) use payload::define_aarch64_payload_runtime;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "none")))]
#[allow(unused_imports)]
pub(crate) use payload::define_x86_64_payload_runtime;
