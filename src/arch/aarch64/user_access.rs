//! src/arch/aarch64/user_access.rs
//!
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
        // SAFETY: clearing PAN is an EL1 system-register write; the comment above
        // explains why no `nomem` is claimed.
        unsafe {
            // `nomem` is deliberately absent (matching the x86 `stac`/`clac`
            // helpers): the compiler must not reorder user-memory loads/stores
            // across the PAN-clearing instruction, because they fault when
            // PSTATE.PAN=1.  Without a memory clobber LLVM is free to defer
            // part of a wide `read_unaligned` of a user struct past the
            // matching `msr PAN, #1` and re-load those bytes with PAN set —
            // a spurious permission fault in syscall decode.
            asm!("msr PAN, #0", options(nostack, preserves_flags));
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
        // SAFETY: as `allow_user_access` — setting PAN, same reasoning.
        unsafe {
            // `nomem` deliberately absent — see `allow_user_access`.
            asm!("msr PAN, #1", options(nostack, preserves_flags));
        }
    }
}

/// RAII guard that brackets a user-memory access window.
///
/// Constructing the guard clears PSTATE.PAN (allowing EL1 access to
/// EL0-accessible pages).  Dropping it puts PAN back the way it found it: the
/// window is per-hart state, so a helper called from inside another window must
/// not close the one it is running in.  Setting PAN unconditionally on drop
/// did exactly that, and the enclosing window's later accesses faulted.
///
/// # Safety
///
/// The guard must not outlive the user pages it accesses, and no kernel
/// code that assumes PAN protection is active should run while the guard
/// is held.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub struct UserAccessGuard {
    /// Whether PAN was already clear when this guard opened.
    already_open: bool,
}

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
        let already_open = !pan_is_set();
        // SAFETY: the guard's own contract, which its doc above states; `Drop` below
        // pairs with it.
        unsafe { allow_user_access() };
        Self { already_open }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Drop for UserAccessGuard {
    #[inline]
    fn drop(&mut self) {
        // Only close what this guard opened: PAN is per-hart state and another
        // window may be holding it open further out on the stack.
        if !self.already_open {
            // SAFETY: as above — restoring PAN when the guard goes away.
            unsafe { deny_user_access() };
        }
    }
}

/// Whether PSTATE.PAN is currently set (user access denied).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn pan_is_set() -> bool {
    let pan: u64;
    // SAFETY: reading a PSTATE field register has no side effects.  The field
    // is one bit and the register zero-extends it, so a non-zero read is PAN
    // set whatever position the architecture puts the bit in.
    unsafe {
        asm!("mrs {pan}, PAN", pan = out(reg) pan, options(nomem, nostack, preserves_flags));
    }
    pan != 0
}

/// Convenience: execute a closure inside a user-access window.
///
/// # Safety
///
/// Same contract as `UserAccessGuard::new()`.  The closure receives no
/// arguments and runs with PAN cleared.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: forwarding to `UserAccessGuard::new`, whose contract the caller met.
    let _guard = unsafe { UserAccessGuard::new() };
    f()
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
/// Convenience: execute a closure outside a user-access window.
///
/// # Safety
///
/// Same contract as the bare-metal variant: the caller must ensure the user
/// memory touched by `f` is valid.  Host builds have no PAN state, so the
/// closure runs directly.
pub unsafe fn with_user_access<T>(f: impl FnOnce() -> T) -> T {
    f()
}
