//! src/kernel/memory/arch.rs
//!
//! Platform-dispatch functions — TLB shootdown, page alignment, user-page
//! install/unmap, memory detection, and bootstrap/prepared/planned translation
//! probes.  These are thin wrappers around arch-specific MMU primitives.

use core::sync::atomic::{AtomicU64, Ordering};

use super::diagnostics::{BootstrapTranslation, PlannedKernelRegion, PreparedTranslation};
use super::frame;
use super::paging;

/// Detected total physical RAM in bytes, populated during early boot by parsing
/// the bootloader memory map (Multiboot2 / FDT).  Zero means "not yet detected";
/// callers fall back to the static pool size.
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

/// Return the detected physical memory size, or `None` if detection has not run.
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

/// Invalidate the TLB for every page in `[virtual_address, virtual_address + length)`
/// on all CPUs.
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
    // Report early identity-map view to aid diagnosis before full runtime mappings stabilize.
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
    // Only meaningful on bare-metal x86_64 where prepared runtime tables can be switched in.
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
