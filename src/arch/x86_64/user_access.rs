//! src/arch/x86_64/user_access.rs
//!
//! SMAP-aware user-memory access helpers: `stac`/`clac` instructions and
//! a RAII guard that brackets supervisor access to user pages.
//!
//! When SMAP (CR4 bit 21) is enabled the kernel cannot read or write
//! user-accessible pages unless EFLAGS.AC is set.  The `UserAccessGuard`
//! sets AC on construction and clears it on drop, providing a safe RAII
//! window for copy-to/from-user and user-context save/restore paths.
//!
//! When SMAP is **not** supported by the CPU (or not yet enabled) the
//! `stac`/`clac` instructions are skipped — they would raise #UD on
//! hardware without SMAP.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::arch::asm;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` once `enable_smap()` successfully sets CR4.SMAP.
/// Guards the `stac`/`clac` instructions themselves — on CPUs without
/// SMAP they are undefined and raise #UD.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static SMAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark SMAP as active after CR4.SMAP has been set.
///
/// # Safety
///
/// Must only be called after CR4.SMAP is written successfully.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn set_smap_active() {
    SMAP_ACTIVE.store(true, Ordering::Release);
}

/// Set the AC flag in EFLAGS, allowing supervisor access to user pages.
///
/// # Safety
///
/// Must be paired with a subsequent `clac()` before any kernel code that
/// assumes SMAP protection is active.  Prefer `UserAccessGuard` over raw
/// stac/clac calls.
///
/// When SMAP is not active this is a no-op.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[inline]
pub unsafe fn stac() {
    if SMAP_ACTIVE.load(Ordering::Acquire) {
        unsafe {
            // `nomem` is deliberately absent: the compiler must not reorder
            // user-memory loads/stores across the AC-setting instruction,
            // because they fault when EFLAGS.AC=0.  Without a memory clobber
            // or fence, LLVM is free to schedule a load that appears after
            // `stac` before the instruction, or defer part of a
            // `read_unaligned` past the corresponding `clac`.
            asm!("stac", options(nostack));
        }
    }
}

/// Clear the AC flag in EFLAGS, restoring SMAP protection.
///
/// # Safety
///
/// Must only be called after a prior `stac()` when the user-memory access
/// window is finished.  Prefer `UserAccessGuard` over raw stac/clac calls.
///
/// When SMAP is not active this is a no-op.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[inline]
pub unsafe fn clac() {
    if SMAP_ACTIVE.load(Ordering::Acquire) {
        unsafe {
            // `nomem` is deliberately absent — see `stac`.
            asm!("clac", options(nostack));
        }
    }
}

/// RAII guard that brackets a user-memory access window.
///
/// Constructing the guard calls `stac()` (set AC), allowing supervisor
/// access to user-accessible pages.  Dropping the guard calls `clac()`
/// (clear AC), restoring SMAP protection.
///
/// # Safety
///
/// The guard must not outlive the user pages it accesses, and no kernel
/// code that assumes SMAP protection is active should run while the guard
/// is held.  (The guard is intentionally short-lived — scoped to a single
/// copy-to/from-user operation.)
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct UserAccessGuard(());

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl UserAccessGuard {
    /// Create a new user-access window.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the user pages accessed inside this
    /// window are valid and mapped.  The guard must be dropped before
    /// any kernel code that assumes SMAP is active.
    #[inline]
    pub unsafe fn new() -> Self {
        unsafe { stac() };
        Self(())
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl Drop for UserAccessGuard {
    #[inline]
    fn drop(&mut self) {
        unsafe { clac() };
    }
}

/// Convenience: execute a closure inside a user-access window.
///
/// # Safety
///
/// Same contract as `UserAccessGuard::new()`.  The closure receives no
/// arguments and runs with AC set.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    let _guard = unsafe { UserAccessGuard::new() };
    f()
}
