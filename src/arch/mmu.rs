//! src/arch/mmu.rs
//!
//! Architecture-neutral MMU facade that dispatches to the active backend.

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
