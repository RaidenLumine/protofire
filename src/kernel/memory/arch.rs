//! src/kernel/memory/arch.rs
//!
//! Platform-dispatch functions — TLB shootdown, page alignment, user-page
//! install/unmap, memory detection, and bootstrap/prepared/planned translation
//! probes.  These are thin wrappers around arch-specific MMU primitives.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use super::diagnostics::BootstrapTranslation;
use super::diagnostics::PlannedKernelRegion;
use super::diagnostics::PreparedTranslation;
use super::frame;
use super::paging;

/// Detected total physical RAM in bytes, populated during early boot by parsing
/// the bootloader memory map (Multiboot2 / FDT).  Zero means "not yet
/// detected"; callers fall back to the static pool size.
static DETECTED_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);

/// Store the detected physical memory size (in bytes).
///
/// Called once during early boot, before `MemoryManager::init()`, from the
/// architecture-specific boot path (binary crate).  Allowed dead_code because
/// the library-crate check cannot see the binary crate's call sites.
#[allow(dead_code)]
pub fn store_detected_memory(size: usize) {
    DETECTED_PHYSICAL_MEMORY.store(size as u64, Ordering::Release);
}

/// Return the detected physical memory size, or `None` if detection has not
/// run.
///
/// Allowed dead_code because the library-crate check cannot see binary callers.
#[allow(dead_code)]
pub fn detected_memory() -> Option<usize> {
    let val = DETECTED_PHYSICAL_MEMORY.load(Ordering::Acquire);
    if val > 0 {
        Some(val as usize)
    } else {
        None
    }
}

/// Invalidate the TLB for every page in `[virtual_address, virtual_address +
/// length)` on all CPUs.
///
/// On single-CPU / non-bare-metal targets this is a no-op.  On SMP-capable
/// targets, sends an IPI to each online AP and waits for acknowledgment
/// before returning.
pub(crate) fn shootdown_range(virtual_address: usize, length: usize) {
    let start = align_down_page(virtual_address);
    let end = match virtual_address.checked_add(length) {
        Some(end) => end,
        None => return,
    };
    let mut va = start;
    while va < end {
        crate::kernel::smp::tlb_shootdown(va);
        va = va.saturating_add(paging::PAGE_SIZE);
    }
}

pub(crate) const fn align_down_page(value: usize) -> usize {
    value & !(paging::PAGE_SIZE - 1)
}

/// Install a user page in the live hardware page tables via the arch MMU.
pub(crate) fn install_user_page_arch(
    virtual_address: usize,
    physical_address: usize,
    permissions: super::paging::PagePermissions,
) -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        unsafe {
            crate::arch::mmu::install_user_page(virtual_address, physical_address, permissions)
        }
        .is_some()
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        unsafe {
            crate::arch::mmu::install_user_page(virtual_address, physical_address, permissions)
        }
        .is_some()
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        unsafe {
            crate::arch::mmu::install_user_page(virtual_address, physical_address, permissions)
        }
        .is_some()
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        // Host-side / other arch: stub.
        let _ = (virtual_address, physical_address, permissions);
        false
    }
}

/// Ensure a range of identity-mapped kernel frames is present in the live
/// hardware page tables.
///
/// The frame allocator promises that a frame it hands out is writable, and it
/// keeps that promise here rather than relying on whoever un-mapped the page
/// to put it back.  The frame pool is identity-mapped by construction, so
/// "present" is the invariant; the allocator is the only place that sees every
/// path a frame travels on, which is what makes it the right boundary for the
/// guarantee.  A kernel stack's guard page is the source today, on the targets
/// whose stacks are frames at their own addresses: the guard is un-presented on
/// purpose, and without this the frame comes back to the pool still
/// un-presented and faults the allocator's own zeroing write.  A stack in an
/// architecture's stack window never un-presents a frame — its guard has no
/// frame to un-present — so this is a no-op for those.
///
/// On x86_64 this is a set-bit: `unmap_page` clears only the Present bit and
/// leaves the rest of the entry intact.  aarch64 cleared the valid bit the same
/// way (`invalidate_page`) and puts it back the same way (`restore_page`), so
/// the repair is a set-bit on both.
pub(crate) fn ensure_identity_mapped_range(address: usize, byte_len: usize) {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let mut offset = 0;
        while offset < byte_len {
            unsafe { crate::arch::x86_64::paging::restore_page(address + offset) };
            offset += super::frame::FRAME_SIZE;
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // The aarch64 guard clears only the valid bit, so restoring it is the
        // same set-bit walk x86_64 uses.
        let mut offset = 0;
        while offset < byte_len {
            unsafe { crate::arch::aarch64::mmu::restore_page(address + offset) };
            offset += super::frame::FRAME_SIZE;
        }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none")
    )))]
    {
        let _ = (address, byte_len);
    }
}

/// Map one frame at an address inside the kernel's stack window.
///
/// The window is the architecture's own range and the tables under it belong
/// to stacks alone, which is why this is a separate call from the user-page
/// shims: mapping there cannot disturb anything else, and a target without a
/// separate window says so rather than quietly mapping somewhere shared.
///
/// Piece by piece rather than a range, because a stack's pages are the pages
/// the stack allocator handed out and nothing else; the guard is simply not in
/// the list.
pub(crate) fn map_stack_page_arch(virtual_address: usize, physical_address: usize) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        unsafe { crate::arch::aarch64::mmu::map_stack_page(virtual_address, physical_address) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = (virtual_address, physical_address);
        false
    }
}

/// Remove one frame from the stack window.
///
/// Counterpart of [`map_stack_page_arch`]; a target without a window has
/// nothing to remove, which is also what `false` says.
pub(crate) fn unmap_stack_page_arch(virtual_address: usize) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        unsafe { crate::arch::aarch64::mmu::unmap_stack_page(virtual_address) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = virtual_address;
        false
    }
}

/// The address range the architecture reserves for kernel stacks, if it has
/// one.
///
/// A window is the architecture's declaration and not a kernel-side constant,
/// because only the architecture knows whether it can carry a range nothing
/// else is mapped in — and a range that nothing else is mapped in is what
/// makes a guard page a page the kernel never allocated rather than a hole
/// punched in shared storage.  A target without one answers `None` here, and
/// its stacks keep the shape they had.
pub(crate) fn stack_window() -> Option<(usize, usize)> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        Some((
            crate::arch::aarch64::mmu::STACK_WINDOW_BASE,
            crate::arch::aarch64::mmu::STACK_WINDOW_END,
        ))
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        None
    }
}

/// Unmap a user page from the live hardware page tables via the arch MMU.
pub(crate) fn unmap_user_page_arch(virtual_address: usize) -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        unsafe { crate::arch::mmu::unmap_page(virtual_address) }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        unsafe { crate::arch::mmu::unmap_page(virtual_address) }
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        unsafe { crate::arch::mmu::unmap_page(virtual_address) }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        let _ = virtual_address;
        false
    }
}

pub(crate) fn detect_memory() -> usize {
    let detected = DETECTED_PHYSICAL_MEMORY.load(Ordering::Acquire);
    if detected > 0 {
        detected as usize
    } else {
        frame::physical_pool_size()
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn bootstrap_translation(virtual_address: usize) -> Option<BootstrapTranslation> {
    let mapping = crate::arch::mmu::bootstrap_identity_mapping();
    // Report early identity-map view to aid diagnosis before full runtime mappings
    // stabilize.
    crate::arch::mmu::bootstrap_translate(virtual_address).map(|physical_address| {
        BootstrapTranslation {
            physical_address,
            page_size: mapping.page_size,
            writable: mapping.writable,
            executable: mapping.executable,
        }
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn bootstrap_translation(_virtual_address: usize) -> Option<BootstrapTranslation> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn prepared_page_tables_active() -> bool {
    // Only meaningful on bare-metal x86_64 where prepared runtime tables can be
    // switched in.
    crate::arch::mmu::prepared_runtime_kernel_page_tables_active()
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn prepared_page_tables_active() -> bool {
    false
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn prepared_translation(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<PreparedTranslation> {
    crate::arch::mmu::runtime_prepared_translation(virtual_address, heap_bounds)
        .map(PreparedTranslation::from)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn prepared_translation(
    _virtual_address: usize,
    _heap_bounds: (usize, usize),
) -> Option<PreparedTranslation> {
    None
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn planned_kernel_region(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<PlannedKernelRegion> {
    // Classify the address against the intended kernel page-layout plan.
    crate::arch::mmu::runtime_kernel_page_plan(heap_bounds)?
        .classify(virtual_address)
        .map(PlannedKernelRegion::from)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn planned_kernel_region(
    _virtual_address: usize,
    _heap_bounds: (usize, usize),
) -> Option<PlannedKernelRegion> {
    None
}
/// Check that the running kernel tables cover what the kernel's facts describe.
///
/// Arch-neutral entry point so the boot path asks once, the same way on every
/// architecture that can answer; a target whose tables this does not cover
/// says nothing rather than lying.
pub(crate) fn check_kernel_map_coverage() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        crate::arch::x86_64::paging::report_kernel_map_coverage();
    }
}
