//! src/arch/mmu.rs
//!
//! Architecture-neutral MMU facade that dispatches to the active backend.
//!
//! Three of the entries below are primitives the *kernel* asks for on every
//! target rather than ones every target has: mapping a page inside a stack
//! window, restoring an identity-mapped frame, and naming the window itself.
//! A target that has none of them says so here — with a stub that returns the
//! same answer a missing window would give — so that kernel code can ask once
//! instead of writing the same `#[cfg]` ladder for each architecture.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use super::aarch64::mmu::*;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use super::riscv64::mmu::*;

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::paging::*;

// ── AArch64 hosts ───────────────────────────────────────────────────────
//
// Bare-metal AArch64 owns the real preparation machinery (above).  A host
// that is not x86_64 does not emulate a user address space at all, so the
// placeholder below only has to exist for the process types that name it;
// nothing can construct one, and the accessors that would hand one out
// report its absence instead.
#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
#[derive(Debug, Default)]
pub struct PreparedProcessAddressSpace;

#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
impl PreparedProcessAddressSpace {
    /// A host never clones an address space.  The caller that would consume
    /// the result bails out with `InvalidArgument` before reaching here.
    pub fn fork_clone(&mut self) -> Option<ForkClonedAddressSpace> {
        None
    }

    /// A host keeps no frame bookkeeping, so nothing can be unlinked.
    pub fn remove_user_page_frame(&mut self, _virtual_address: usize) -> Option<usize> {
        None
    }
}

/// What a fork clone hands back: the child hierarchy plus the copy-on-write
/// and non-shared page triples.
#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
pub type ForkClonedAddressSpace = (
    PreparedProcessAddressSpace,
    alloc::vec::Vec<(usize, usize, crate::kernel::memory::paging::PagePermissions)>,
    alloc::vec::Vec<(usize, usize, crate::kernel::memory::paging::PagePermissions)>,
);

// ── Primitives a target may not have ────────────────────────────────────
//
// Each stub names the reason in one line; the kernel-side documentation for
// what they mean is on the real implementations (`aarch64::mmu`,
// `x86_64::paging`).

/// A target whose stacks are frames at their own addresses — riscv64, and
/// every host that is not x86_64 — has no separate window to map into.
///
/// # Safety
///
/// The signature matches the real implementation's, which the caller owes the
/// same guarantees to; this one has no tables to touch.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none")
)))]
pub unsafe fn map_stack_page(_virtual_address: usize, _physical_address: usize) -> bool {
    false
}

/// The counterpart of [`map_stack_page`], absent for the same reason.
///
/// # Safety
///
/// As [`map_stack_page`].
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none")
)))]
pub unsafe fn unmap_stack_page(_virtual_address: usize) -> bool {
    false
}

/// Restoring a frame the allocator handed back is a page-table edit only on
/// the architectures that un-present a guard page; there is nothing to
/// restore where a guard has no frame.
///
/// # Safety
///
/// The signature matches the real implementation's; this one touches nothing.
#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "none")
)))]
pub unsafe fn restore_page(_virtual_address: usize) -> bool {
    false
}

/// The address range this architecture reserves for kernel stacks, if it has
/// one.
///
/// Asked once by the stack allocator, which uses `None` to mean "keep the
/// stack shape you had": a window is a range nothing else is mapped in, and
/// only the architecture knows whether it can carry one.
pub fn stack_window() -> Option<(usize, usize)> {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        Some((
            super::x86_64::paging::X86_STACK_WINDOW_BASE,
            super::x86_64::paging::X86_STACK_WINDOW_END,
        ))
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        Some((
            super::aarch64::mmu::STACK_WINDOW_BASE,
            super::aarch64::mmu::STACK_WINDOW_END,
        ))
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none")
    )))]
    {
        None
    }
}

/// A host that is not x86_64 has no page tables of the shape the kernel
/// installs user pages into.
///
/// # Safety
///
/// As [`map_stack_page`]: the signature is the real one's, and there is no
/// table here to install into.
#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
pub unsafe fn install_user_page(
    _virtual_address: usize,
    _physical_address: usize,
    _permissions: crate::kernel::memory::paging::PagePermissions,
) -> Option<usize> {
    None
}

/// The counterpart of [`install_user_page`], absent for the same reason.
///
/// # Safety
///
/// As [`install_user_page`].
#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
pub unsafe fn unmap_page(_virtual_address: usize) -> bool {
    false
}
