//! src/arch/aarch64/user_access.rs
//! PAN-aware user-memory access helpers: PSTATE.PAN control and a RAII guard
//! that brackets supervisor access to user pages.
//!
//! When SCTLR_EL1.SPAN (bit 23) is set, the PE automatically sets PSTATE.PAN
//! to 1 on exception entry from EL0, preventing EL1 from reading or writing
//! any page mapped as EL0-accessible.  This is the AArch64 analogue of x86_64
//! SMAP.
//!
//! To temporarily grant access (e.g. during a syscall copy), we clear
//! PSTATE.PAN with `MSR PAN, #0`.  The corresponding `UserAccessGuard`
//! restores PSTATE.PAN to 1 on drop.
//!
//! SCTLR_EL1.SPAN is set during `mmu::install_translation_configuration`,
//! so these instructions are active once the MMU is enabled.
//!
//! ## PAN enablement gating
//!
//! When `mmu::SPAN_ENABLED` is false, the PAN toggles in this module become
//! no-ops — the hardware is not configured to automatically set PAN, so
//! explicit management would introduce spurious permission faults for code
//! paths that hold user-memory references across function boundaries.
//! Re-enable SPAN (`mmu::SPAN_ENABLED = true`) once all user-memory access
//! paths are audited.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::asm;

/// Grant EL1 access to EL0-accessible pages (clear PSTATE.PAN).
///
/// # Safety
///
/// Must be paired with a subsequent `deny_user_access()` before any kernel
/// code that assumes PAN protection is active.  Prefer `UserAccessGuard`
/// over raw enable/disable calls.
///
/// When `mmu::SPAN_ENABLED` is false, this is a no-op.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
unsafe fn allow_user_access() {
    if super::mmu::SPAN_ENABLED {
        unsafe {
            asm!("msr PAN, #0", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Revoke EL1 access to EL0-accessible pages (set PSTATE.PAN).
///
/// # Safety
///
/// Must only be called after a prior `allow_user_access()` when the
/// user-memory access window is finished.  Prefer `UserAccessGuard` over raw
/// enable/disable calls.
///
/// When `mmu::SPAN_ENABLED` is false, this is a no-op.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
unsafe fn deny_user_access() {
    if super::mmu::SPAN_ENABLED {
        unsafe {
            asm!("msr PAN, #1", options(nomem, nostack, preserves_flags));
        }
    }
}

/// RAII guard that brackets a user-memory access window.
///
/// Constructing the guard clears PSTATE.PAN (allowing EL1 access to
/// EL0-accessible pages).  Dropping the guard sets PSTATE.PAN again,
/// restoring PAN protection.
///
/// # Safety
///
/// The guard must not outlive the user pages it accesses, and no kernel
/// code that assumes PAN protection is active should run while the guard
/// is held.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub struct UserAccessGuard(());

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl UserAccessGuard {
    /// Create a new user-access window.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the user pages accessed inside this
    /// window are valid and mapped.  The guard must be dropped before any
    /// kernel code that assumes PAN protection is active.
    #[inline]
    pub unsafe fn new() -> Self {
        unsafe { allow_user_access() };
        Self(())
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Drop for UserAccessGuard {
    #[inline]
    fn drop(&mut self) {
        unsafe { deny_user_access() };
    }
}

/// Convenience: execute a closure inside a user-access window.
///
/// # Safety
///
/// Same contract as `UserAccessGuard::new()`.  The closure receives no
/// arguments and runs with PAN cleared.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    let _guard = unsafe { UserAccessGuard::new() };
    f()
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    f()
}
