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

use crate::memory::paging::PagePermissions;

/// One translated user page, as much of it as the kernel acts on.
///
/// The kernel asks two questions of a user mapping — where does it land, and
/// may this access use it — and every architecture can answer both.  What an
/// architecture's own translation type carries beyond that stays in the
/// architecture: x86_64 also knows whether the page came from the image or the
/// stack, and nothing above the architecture reads it.
///
/// This is the shape [`ProcessAddressSpace::translate_user`] answers in, so the
/// process layer has one type to name rather than one per architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
}

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

/// The address space a process holds, as the architecture prepared it.
///
/// A bare-metal architecture owns this type: it is what a loader hands over and
/// what the process layer keeps for the life of a process, and what it must
/// answer is the same question on every architecture — the summaries, the user
/// range, the thread start, a translation, an activation, and the mutable
/// handle fork needs.  Each architecture defines it beside its own prepared
/// hierarchy and exports it through this module, so the process layer names one
/// type rather than one per architecture.
///
/// Nothing can construct the placeholder below: a host that is not x86_64 does
/// not emulate a user address space, and every accessor reports that absence.
#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    not(target_os = "none")
))]
#[derive(Debug, Default)]
pub struct ProcessAddressSpace;

#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    not(target_os = "none")
))]
impl ProcessAddressSpace {
    /// A host never prepared a hierarchy, so there is nothing to hold.
    pub fn from_prepared_process(_prepared: PreparedProcessAddressSpace) -> Self {
        Self
    }

    pub fn user_summary(&self) -> crate::kernel::process::UserAddressSpaceSummary {
        crate::kernel::process::UserAddressSpaceSummary {
            root_table_address: 0,
            mapped_page_count: 0,
            image_page_count: 0,
            stack_page_count: 0,
            table_page_count: 0,
            pml4_entry_count: 0,
            pdpt_count: 0,
            page_directory_count: 0,
            page_table_count: 0,
        }
    }

    pub fn process_summary(&self) -> Option<crate::kernel::process::ProcessAddressSpaceSummary> {
        None
    }

    pub fn user_page_va_range(&self) -> Option<(usize, usize)> {
        None
    }

    pub fn user_thread_start(&self) -> Option<crate::kernel::process::UserThreadStart> {
        None
    }

    pub fn matches_user_thread_start(
        &self,
        _start: crate::kernel::process::UserThreadStart,
    ) -> Option<bool> {
        None
    }

    pub fn translate_user(&self, _address: usize) -> Option<UserTranslation> {
        None
    }

    pub fn activate(&self) -> bool {
        false
    }

    pub fn process_mut(&mut self) -> Option<&mut PreparedProcessAddressSpace> {
        None
    }
}

/// A host has no runtime kernel page tables to switch to.
///
/// The caller only asks whether the switch happened, so the shape of the
/// details a bare-metal architecture would return does not have to exist here.
#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    not(target_os = "none")
))]
pub fn activate_prepared_runtime_kernel_page_tables() -> Option<()> {
    None
}

/// What a fork clone hands back: the child hierarchy plus the copy-on-write
/// and non-shared page triples.
#[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
pub type ForkClonedAddressSpace = (
    PreparedProcessAddressSpace,
    alloc::vec::Vec<(usize, usize, crate::memory::paging::PagePermissions)>,
    alloc::vec::Vec<(usize, usize, crate::memory::paging::PagePermissions)>,
);

// ── Primitives a target may not have ────────────────────────────────────
//
// Each stub names the reason in one line; the kernel-side documentation for
// what they mean is on the real implementations (`aarch64::mmu`,
// `x86_64::paging`).

/// A target whose stacks are frames at their own addresses — every host that
/// is not x86_64, and any future architecture without a window — has no
/// separate window to map into.
///
/// # Safety
///
/// The signature matches the real implementation's, which the caller owes the
/// same guarantees to; this one has no tables to touch.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
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
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
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
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        Some((
            super::riscv64::mmu::STACK_WINDOW_BASE,
            super::riscv64::mmu::STACK_WINDOW_END,
        ))
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
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
    _permissions: crate::memory::paging::PagePermissions,
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

// ── Diagnostics an architecture may not be able to answer ───────────────
//
// The kernel asks these about the tables it *prepared*, which is a thing only
// x86_64 does here: it is the architecture whose runtime tables are built
// ahead of the switch and described in the kernel's own vocabulary.  The
// answers are the kernel's diagnostic types (`BootstrapTranslation`,
// `PreparedTranslation`, `PlannedKernelRegion`), which is not a layering
// problem: `x86_64::paging` already produces them, and the stubs below are
// what a target that has no such tables says instead of guessing.

#[cfg(target_arch = "x86_64")]
pub fn bootstrap_translation(
    virtual_address: usize,
) -> Option<crate::memory::diagnostics::BootstrapTranslation> {
    let mapping = super::x86_64::paging::bootstrap_identity_mapping();
    // Report early identity-map view to aid diagnosis before full runtime
    // mappings stabilize.
    super::x86_64::paging::bootstrap_translate(virtual_address).map(|physical_address| {
        crate::memory::diagnostics::BootstrapTranslation {
            physical_address,
            page_size: mapping.page_size,
            writable: mapping.writable,
            executable: mapping.executable,
        }
    })
}

/// No bootstrap identity map of this shape to describe.
#[cfg(not(target_arch = "x86_64"))]
pub fn bootstrap_translation(
    _virtual_address: usize,
) -> Option<crate::memory::diagnostics::BootstrapTranslation> {
    None
}

/// Are the prepared runtime kernel page tables the active ones?
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn prepared_page_tables_active() -> bool {
    super::x86_64::paging::prepared_runtime_kernel_page_tables_active()
}

/// Only x86_64 bare metal prepares a table set it can switch to.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn prepared_page_tables_active() -> bool {
    false
}

/// What the kernel's prepared tables say about an address, if it can say.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn prepared_translation(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<crate::memory::diagnostics::PreparedTranslation> {
    super::x86_64::paging::runtime_prepared_translation(virtual_address, heap_bounds)
        .map(crate::memory::diagnostics::PreparedTranslation::from)
}

/// No prepared table set to read.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn prepared_translation(
    _virtual_address: usize,
    _heap_bounds: (usize, usize),
) -> Option<crate::memory::diagnostics::PreparedTranslation> {
    None
}

/// Which intended kernel page-layout region an address falls in, if any.
#[cfg(target_arch = "x86_64")]
pub fn planned_kernel_region(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<crate::memory::diagnostics::PlannedKernelRegion> {
    // Classify the address against the intended kernel page-layout plan.
    super::x86_64::paging::runtime_kernel_page_plan(heap_bounds)?
        .classify(virtual_address)
        .map(crate::memory::diagnostics::PlannedKernelRegion::from)
}

/// No page-layout plan to classify against.
#[cfg(not(target_arch = "x86_64"))]
pub fn planned_kernel_region(
    _virtual_address: usize,
    _heap_bounds: (usize, usize),
) -> Option<crate::memory::diagnostics::PlannedKernelRegion> {
    None
}

/// Report whether the running tables cover what the kernel's facts describe.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn report_kernel_map_coverage() {
    super::x86_64::paging::report_kernel_map_coverage();
}

/// Nothing to check where this build has no kernel page-table plan.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn report_kernel_map_coverage() {}
