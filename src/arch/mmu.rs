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

/// Translate a kernel virtual address to the physical address it maps to,
/// where the machine's own mapping is the identity on it.
///
/// This is the question a DMA buffer asks before it hands an address to a
/// device, and the answer is a property of the machine's mapping rather than
/// of the buffer: it belongs here, once, instead of in every caller that has
/// a physical address to produce.
///
/// `None` means "not translatable", and every caller treats it as a refusal:
/// an address that means something else in device space is worse than no
/// buffer at all.
#[must_use]
pub fn phys_addr_of(virtual_address: usize) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        // The kernel is identity-mapped inside the 0 – 1 GiB bootstrap
        // region (see `BOOTSTRAP_IDENTITY_MAP_END`), and the frame
        // allocator's pool lives inside it, so the two addresses are the
        // same number.
        if virtual_address < 0x4000_0000 {
            return Some(virtual_address);
        }
        None
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // The runtime tables map the RAM window identity — the kernel's link
        // address and the address the frame allocator hands out are the same
        // number — so an address inside it is its own physical address.  A
        // device programmed with one sees the buffer the kernel wrote.
        use super::aarch64::mmu::KERNEL_TEXT_BASE;
        use super::aarch64::mmu::KERNEL_TEXT_END;

        if (KERNEL_TEXT_BASE..KERNEL_TEXT_END).contains(&virtual_address) {
            return Some(virtual_address);
        }
        None
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "none")
    )))]
    {
        // The device-tree machines reach their frames through a window of
        // their own rather than the identity map, and this translation is not
        // wired for them yet: a caller that needs it fails rather than hand a
        // device an address that means something else.
        let _ = virtual_address;
        None
    }
}

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

/// Prepare, activate and check the runtime kernel page tables, saying what
/// happened in each step.
///
/// The three machines do the same three things in the same order — prepare
/// tables that describe the kernel, switch to them, then check that the CPU is
/// standing on what the tables claim — and differ only in which tables those
/// are, which is what the calls below already resolve.  The log names the
/// machine because the machine knows its own name.
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
pub(crate) fn install_runtime_kernel_page_tables(heap_bounds: (usize, usize)) {
    let arch = crate::arch::boot::current_architecture();

    let Some(summary) = prepare_runtime_kernel_page_tables(heap_bounds) else {
        crate::println!("[mem   ] failed to prepare {} kernel page tables", arch);
        return;
    };
    crate::println!(
        "[mem   ] prepared {} kernel page tables root={:#018x} windows={} pages={}",
        arch,
        summary.root_table_address,
        summary.window_count,
        summary.mapped_page_count
    );

    let Some(active) = activate_prepared_runtime_kernel_page_tables() else {
        crate::println!("[mem   ] failed to activate {} kernel page tables", arch);
        return;
    };
    crate::println!(
        "[mem   ] activated {} kernel page tables old={:#018x} new={:#018x} already_active={} windows={} pages={}",
        arch,
        active.previous_root_table_address,
        active.active_root_table_address,
        active.already_active,
        active.window_count,
        active.mapped_page_count
    );

    match active_runtime_kernel_page_table_check(heap_bounds) {
        Some(check) => {
            crate::println!(
                "[mem   ] active paging check root={:#018x} rip={:#018x}/{}:{} rsp={:#018x}/{}:{} heap={:#018x}/{}:{}",
                check.root_table_address,
                check.instruction_pointer.virtual_address,
                check.instruction_pointer.kind.as_str(),
                check.instruction_pointer.permissions.as_rwx(),
                check.stack_pointer.virtual_address,
                check.stack_pointer.kind.as_str(),
                check.stack_pointer.permissions.as_rwx(),
                check.heap_pointer.virtual_address,
                check.heap_pointer.kind.as_str(),
                check.heap_pointer.permissions.as_rwx()
            );
        }
        None => {
            #[cfg(target_arch = "x86_64")]
            crate::println!("[mem   ] active paging self-check failed");
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!("[mem   ] active {} paging self-check unavailable", arch);
        }
    }
}

/// A host has no runtime kernel page tables of its own to switch to.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn install_runtime_kernel_page_tables(_heap_bounds: (usize, usize)) {}

/// Clear the present/valid bit on every guard page below a stack, and report
/// whether every one of them was actually cleared.
///
/// The result is returned rather than discarded because a guard that silently
/// did not get installed is indistinguishable from one that did: the same boot
/// either way, and the difference only shows up much later as a stack overflow
/// that corrupts memory instead of faulting.  `unmap_page` refuses to act on a
/// page inside a large mapping, which it has no way to split, so a missing
/// guard is a real outcome rather than a theoretical one.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn enforce_stack_guard(base: *mut u8, guard_size: usize) -> bool {
    let page_size = crate::memory::frame::FRAME_SIZE;
    let mut enforced = true;
    for offset in (0..guard_size).step_by(page_size) {
        // SAFETY: the range is the guard region of a kernel stack this kernel
        // allocated, so each address is mapped and owned here; `unmap_page`
        // answers whether the entry could be cleared.
        let cleared = unsafe { super::x86_64::paging::unmap_page(base.add(offset) as usize) };
        enforced &= cleared;
    }
    enforced
}

/// Only the frame-backed fallback reaches this now: a window-backed stack's
/// guard is not installed by anyone, so there is nothing here to install.
///
/// For the fallback the answer is still that the guard is not there — its
/// frames sit at their own addresses, which this walk cannot derive, and
/// clearing the wrong page took the machine down inside the exception entry
/// the last time it was tried.  The kernel reports that, which is the honest
/// answer for a shape this architecture cannot guarantee.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) fn enforce_stack_guard(_base: *mut u8, _guard_size: usize) -> bool {
    false
}

/// riscv64's window is where its guards come from; this is the exhausted-window
/// fallback, and for that one there is no guard to install.  Say so rather than
/// claiming one.
///
/// The frame-backed fallback's guard is a hole in the kernel's own identity
/// mapping, and clearing it means splitting the block that covers it — the same
/// walk that faulted on aarch64 the first time (`split_l2_block` carries that
/// story).  The answer here is therefore the aarch64 one: the kernel reports
/// that the guard is not enforced, which is true of this shape.  The window
/// itself does not come here: a guard inside it is a leaf nobody maps, so an
/// overflow faults on the first byte.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn enforce_stack_guard(_base: *mut u8, _guard_size: usize) -> bool {
    false
}

/// A bare-metal machine of another shape has no hardware guard of the kind
/// this walks, and nothing to enforce.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn enforce_stack_guard(_base: *mut u8, _guard_size: usize) -> bool {
    true
}
