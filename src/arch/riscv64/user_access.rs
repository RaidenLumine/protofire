//! src/arch/riscv64/user_access.rs
//! SUM-aware user-memory access helpers: sstatus.SUM control and a RAII guard
//! that brackets supervisor access to user pages.
//!
//! When sstatus.SUM (Supervisor User Memory access, bit 18) is set, S-mode
//! can read and write U-mode-accessible pages.  This is the riscv64 analogue
//! of x86_64 SMAP and AArch64 PAN.
//!
//! To temporarily grant access (e.g. during a syscall copy), we set SUM with
//! `csrs sstatus, ...`.  The corresponding `UserAccessGuard` clears SUM on
//! drop.

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use core::arch::asm;

/// sstatus.SUM (bit 18): permit Supervisor access to User-accessible pages.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
const SSTATUS_SUM: u64 = 1 << 18;

/// Grant S-mode access to U-mode-accessible pages (set SUM).
///
/// # Safety
///
/// Must be paired with a subsequent `deny_user_access()` before any kernel
/// code that assumes SUM protection is active.  Prefer `UserAccessGuard`
/// over raw enable/disable calls.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[inline]
unsafe fn allow_user_access() {
    unsafe {
        // SUM = 1 << 18 does not fit in the 5-bit `csrsi` immediate, and the
        // immediate form is silently dropped on some toolchains — use the
        // register form (same caveat as `interrupts::enable`).
        asm!("csrs sstatus, {sum}", sum = in(reg) SSTATUS_SUM, options(nomem, nostack, preserves_flags));
    }
}

/// Revoke S-mode access to U-mode-accessible pages (clear SUM).
///
/// # Safety
///
/// Must only be called after a prior `allow_user_access()`.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[inline]
unsafe fn deny_user_access() {
    unsafe {
        // Register form — see `allow_user_access`.
        asm!("csrc sstatus, {sum}", sum = in(reg) SSTATUS_SUM, options(nomem, nostack, preserves_flags));
    }
}

/// RAII guard that brackets a user-memory access window.
///
/// Constructing the guard sets sstatus.SUM (allowing S-mode access to
/// U-mode-accessible pages).  Dropping the guard clears SUM again,
/// restoring the protection.
///
/// # Safety
///
/// The guard must not outlive the user pages it accesses, and no kernel
/// code that assumes SUM protection is active should run while the guard
/// is held.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub struct UserAccessGuard(());

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
impl UserAccessGuard {
    /// Create a new user-access window.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the user pages accessed inside this
    /// window are valid and mapped.  The guard must be dropped before any
    /// kernel code that assumes SUM protection is active.
    #[inline]
    pub unsafe fn new() -> Self {
        unsafe { allow_user_access() };
        Self(())
    }
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
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
/// arguments and runs with SUM set.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    let _guard = unsafe { UserAccessGuard::new() };
    f()
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    f()
}
