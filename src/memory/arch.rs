//! src/memory/arch.rs
//!
//! Platform-dispatch functions — TLB shootdown, page alignment, user-page
//! install/unmap, memory detection, and bootstrap/prepared/planned translation
//! probes.  These are thin wrappers around arch-specific MMU primitives.

use alloc::vec::Vec;
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

/// Ask the machine how much RAM it has, record it, and answer its usable
/// regions.
///
/// This is the one job the machine's memory map has ([RFC
/// 0019](../../docs/rfcs/0019-what-a-frame-is.md)): **be asked, be checked
/// against, and be reported — never allocated from.**  A frame stays an
/// address inside the kernel's own image, and the map's answer is what says
/// the image is somewhere it is allowed to be, and what the boot prints beside
/// the pool's own size.
///
/// `None` means the machine described nothing (a bare hand-off with no map
/// tag, or a host build), which is not the same as describing no usable RAM.
pub fn record_machine_memory() -> Option<Vec<(usize, usize)>> {
    // Which machine is running, and how it describes its memory, is the
    // architecture's answer rather than this layer's.
    let regions = crate::arch::platform::described_memory_regions()?;
    let total = regions
        .iter()
        .fold(0usize, |total, (_, length)| total.saturating_add(*length));
    store_detected_memory(total);
    Some(regions)
}

/// Whether `range` lies inside one of the regions the machine called usable.
///
/// This is the check a loader cannot make for itself: the loader is free to
/// place the kernel anywhere, and a kernel whose own memory is a region the
/// firmware withheld is a kernel that corrupts whatever that region belongs to.
// The check below only runs on a machine: a host build's "image" is a test
// binary.  The host test drives it directly, which is the one place the
// predicate is asked on a host.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub fn range_is_in_usable_memory(range: (usize, usize), regions: &[(usize, usize)]) -> bool {
    let (start, end) = range;
    if end <= start {
        return false;
    }
    regions
        .iter()
        .any(|(base, length)| start >= *base && end <= base.saturating_add(*length))
}

/// The kernel's own image, as the linker placed it.
///
/// Only a bare-metal build has these symbols; a host build's "image" is the
/// test binary, which is not a kernel and is not a kernel's question.
#[cfg(target_os = "none")]
pub fn kernel_image_range() -> (usize, usize) {
    extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    // The addresses of the linker's own symbols for the image this code is
    // running from; neither is dereferenced, and taking one is safe.
    let start = core::ptr::addr_of!(__kernel_start) as usize;
    let end = core::ptr::addr_of!(__kernel_end) as usize;
    (start, end)
}

/// Whether the kernel's own memory can be given to a device.
///
/// The question is the machine's ([`crate::arch::mmu::phys_addr_of`]), and it
/// is asked of the pool's first and last byte: a pool outside the window that
/// function answers for is a kernel that can allocate and cannot do DMA, and
/// that is worth knowing at boot rather than at the first driver's first
/// buffer.
pub fn pool_is_addressable_by_a_device() -> bool {
    let (start, end) = crate::memory::frame::pool_range();
    end > start
        && crate::arch::mmu::phys_addr_of(start).is_some()
        && crate::arch::mmu::phys_addr_of(end - 1).is_some()
}

/// Ask the machine, record its answer, check the kernel against it, and say
/// what it said.
///
/// The three answers the check has are the ones [RFC
/// 0019](../../docs/rfcs/0019-what-a-frame-is.md) decides: a map that contains
/// the image boots, one that excludes it refuses loudly — a kernel over RAM
/// the firmware withheld is already broken — and no map at all is printed and
/// booted through, because a protocol that describes nothing is not a machine
/// whose memory is unusable.
pub fn report_machine_memory() {
    let regions = record_machine_memory();
    let pool_mib = crate::memory::frame::physical_pool_size() / (1024 * 1024);

    if let Some(regions) = &regions {
        crate::println!(
            "[mem   ] machine reports {} MiB in {} region(s); the kernel's pool is {} MiB",
            detected_memory().unwrap_or(0) / (1024 * 1024),
            regions.len(),
            pool_mib
        );
    } else {
        crate::println!(
            "[mem   ] the machine described no memory map; the kernel's pool is {} MiB",
            pool_mib
        );
    }

    // The answer is a machine's; a host build asks it and does not enforce it.
    let pool_addressable = pool_is_addressable_by_a_device();

    // The two checks below are bare-metal questions: a host build's "image" is
    // a test binary and its pool is not a machine's memory.
    #[cfg(not(target_os = "none"))]
    {
        let _ = pool_addressable;
    }

    #[cfg(target_os = "none")]
    {
        if !pool_addressable {
            let (start, end) = crate::memory::frame::pool_range();
            crate::println!(
                "[mem   ] FATAL: the pool [{:#x}, {:#x}) is outside the window a device address can name",
                start,
                end
            );
            panic!("the kernel's own memory is not addressable by a device");
        }

        if let Some(regions) = &regions {
            let image = kernel_image_range();
            if range_is_in_usable_memory(image, regions) {
                crate::println!(
                    "[mem   ] the kernel's image [{:#x}, {:#x}) is in usable RAM",
                    image.0,
                    image.1
                );
            } else {
                crate::println!(
                    "[mem   ] FATAL: the kernel's image [{:#x}, {:#x}) is in no region the machine calls usable",
                    image.0,
                    image.1
                );
                for (base, length) in regions {
                    crate::println!(
                        "[mem   ]   the machine offered [{:#x}, {:#x})",
                        base,
                        base + length
                    );
                }
                panic!("the kernel was loaded outside the machine's usable memory");
            }
        }
    }
}

/// Invalidate the TLB for every page in `[virtual_address, virtual_address +
/// length)` on all CPUs.
///
/// One request for the whole range rather than one per page: the range is a
/// single edit from the TLB's point of view, and on x86_64 each page-sized
/// request used to make every other CPU flush its entire TLB.  On targets that
/// broadcast their invalidations where the page table is edited, this is a
/// no-op.
pub(crate) fn shootdown_range(virtual_address: usize, length: usize) {
    crate::kernel::smp::tlb_shootdown_range(virtual_address, length);
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
    // SAFETY: the caller owns the mapping it is asking for; every target that
    // implements this checks the address against its own tables.
    unsafe { crate::arch::mmu::install_user_page(virtual_address, physical_address, permissions) }
        .is_some()
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
    let mut offset = 0;
    while offset < byte_len {
        // SAFETY: the frame pool is identity-mapped, so the only question is
        // whether the entry is present, and putting it back is what this asks
        // for.  A target without such a guard answers that there is nothing
        // to restore.
        unsafe { crate::arch::mmu::restore_page(address + offset) };
        offset += super::frame::FRAME_SIZE;
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
    // SAFETY: the stack allocator owns both the address (inside the window it
    // was given) and the frame it is mapping there.
    unsafe { crate::arch::mmu::map_stack_page(virtual_address, physical_address) }
}

/// Remove one frame from the stack window.
///
/// Counterpart of [`map_stack_page_arch`]; a target without a window has
/// nothing to remove, which is also what `false` says.
pub(crate) fn unmap_stack_page_arch(virtual_address: usize) -> bool {
    // SAFETY: as `map_stack_page_arch`: the address is one the allocator owns.
    unsafe { crate::arch::mmu::unmap_stack_page(virtual_address) }
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
    crate::arch::mmu::stack_window()
}

/// Unmap a user page from the live hardware page tables via the arch MMU.
pub(crate) fn unmap_user_page_arch(virtual_address: usize) -> bool {
    // SAFETY: the caller is removing a mapping it owns.
    unsafe { crate::arch::mmu::unmap_page(virtual_address) }
}

pub(crate) fn detect_memory() -> usize {
    let detected = DETECTED_PHYSICAL_MEMORY.load(Ordering::Acquire);
    if detected > 0 {
        detected as usize
    } else {
        frame::physical_pool_size()
    }
}

pub(crate) fn bootstrap_translation(virtual_address: usize) -> Option<BootstrapTranslation> {
    crate::arch::mmu::bootstrap_translation(virtual_address)
}

pub(crate) fn prepared_page_tables_active() -> bool {
    crate::arch::mmu::prepared_page_tables_active()
}

pub(crate) fn prepared_translation(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<PreparedTranslation> {
    crate::arch::mmu::prepared_translation(virtual_address, heap_bounds)
}

pub(crate) fn planned_kernel_region(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<PlannedKernelRegion> {
    crate::arch::mmu::planned_kernel_region(virtual_address, heap_bounds)
}
/// Check that the running kernel tables cover what the kernel's facts describe.
///
/// Arch-neutral entry point so the boot path asks once, the same way on every
/// architecture that can answer; a target whose tables this does not cover
/// says nothing rather than lying.
pub(crate) fn check_kernel_map_coverage() {
    crate::arch::mmu::report_kernel_map_coverage();
}

#[cfg(test)]
mod tests {
    use super::range_is_in_usable_memory;

    /// The check a loader cannot make for itself, in its three shapes: inside a
    /// region the machine called usable, outside every one of them, and a
    /// question with no regions to answer it.
    #[test]
    fn the_placement_check_answers_in_usable_memory_or_not() {
        let regions = [(0x1000_usize, 0x1000_0000_usize)];
        let region_end = 0x1000 + 0x1000_0000;

        assert!(range_is_in_usable_memory((0x2000, 0x3000), &regions));
        assert!(
            range_is_in_usable_memory((0x1000, region_end), &regions),
            "a range that ends exactly where the region does is inside it"
        );
        assert!(
            !range_is_in_usable_memory((0x2000, region_end + 1), &regions),
            "one byte past the region is outside it"
        );
        assert!(!range_is_in_usable_memory((0x500, 0x2000), &regions));
        assert!(!range_is_in_usable_memory((0x2000, 0x2000), &regions));
        assert!(!range_is_in_usable_memory((0x2000, 0x3000), &[]));
    }
}
