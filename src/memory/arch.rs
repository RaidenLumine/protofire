//! src/memory/arch.rs
//!
//! Platform-dispatch functions — TLB shootdown, page alignment, user-page
//! install/unmap, memory detection, and bootstrap/prepared/planned translation
//! probes.  These are thin wrappers around arch-specific MMU primitives.

use crate::arch::boot::MemoryRegion;
use crate::arch::boot::MEMORY_REGION_AVAILABLE;
use crate::arch::boot::MEMORY_REGION_DEFECTIVE;
use crate::arch::boot::MEMORY_REGION_RESERVED;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use super::diagnostics::BootstrapTranslation;
use super::diagnostics::PlannedKernelRegion;
use super::diagnostics::PreparedTranslation;
use super::paging;

/// Detected total physical RAM in bytes, populated during early boot by parsing
/// the bootloader memory map (Multiboot2 / FDT).  Zero means "not yet
/// detected"; callers fall back to the static pool size.
static DETECTED_PHYSICAL_MEMORY: AtomicU64 = AtomicU64::new(0);

/// Where the machine's description of RAM stops being contiguous with the
/// pool's start, populated beside [`DETECTED_PHYSICAL_MEMORY`].
///
/// The frame pool is a fixed span of the kernel's address space now, and on a
/// machine whose RAM ends inside that span the frames past RAM end are memory
/// that is not there: writing one is a fault, not an allocation.  This is the
/// address the allocator may not cross, walked from the pool's start over the
/// regions the machine *describes* (any kind but defective, since a loader's
/// reservation is still RAM).  Zero means the machine described nothing —
/// then there is no answer to clamp with and the span is the bound, which is
/// what a boot with no map had before there was a pool to size.
static POOL_RAM_END: AtomicU64 = AtomicU64::new(0);

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
pub fn record_machine_memory() -> Option<Vec<MemoryRegion>> {
    // Which machine is running, and how it describes its memory, is the
    // architecture's answer rather than this layer's.
    let regions = crate::arch::platform::described_memory_regions()?;
    // The number the boot reports as the machine's is the RAM it calls
    // available; the regions keep every kind, because the checks below need to
    // tell "reserved by the loader that put us here" from "defective".
    let total = regions
        .iter()
        .filter(|region| region.kind == MEMORY_REGION_AVAILABLE)
        .fold(0usize, |total, region| total.saturating_add(region.length));
    store_detected_memory(total);
    store_pool_ram_end(pool_ram_end_from(&regions));
    Some(regions)
}

/// Walk from the pool's start over the regions the machine describes.
///
/// Coverage has to be **contiguous**: a frame the allocator hands out is
/// written as a physical address, so the first address past what the machine
/// has described is the first address the allocator may not cross.  Every
/// kind but defective counts as described — a loader's reservation is still
/// RAM the machine owns, and refusing to cross it would strand the memory
/// behind it.
fn pool_ram_end_from(regions: &[MemoryRegion]) -> usize {
    let (pool_start, pool_end) = crate::memory::frame::pool_range();
    let mut end = pool_start;
    loop {
        let next = regions
            .iter()
            .filter(|region| {
                region.kind != MEMORY_REGION_DEFECTIVE && region.base <= end && end < region.end()
            })
            .map(|region| region.end())
            .max();
        match next {
            Some(region_end) if region_end > end => {
                end = region_end.min(pool_end);
                if end >= pool_end {
                    break;
                }
            }
            _ => break,
        }
    }
    end
}

/// Store the walk's answer (in bytes as an address).
fn store_pool_ram_end(end: usize) {
    POOL_RAM_END.store(end as u64, Ordering::Release);
}

/// How much of the frame pool's span lies in memory the machine has.
///
/// This is the number the frame allocator is sized with, and it is the reason
/// the pool can be a fixed span of the kernel's address space without the
/// kernel writing past the end of RAM on a small machine.  A machine that
/// described nothing answers the whole span, which is the shape a boot with
/// no map has always had.
pub fn managed_pool_bytes() -> usize {
    let (pool_start, pool_end) = crate::memory::frame::pool_range();
    let ram_end = POOL_RAM_END.load(Ordering::Acquire) as usize;
    let end = if ram_end > pool_start {
        ram_end.min(pool_end)
    } else {
        pool_end
    };
    end.saturating_sub(pool_start)
}

// The checks below only run on a machine: a host build's "image" is a test
// binary.  The host tests drive them directly, which is the one place a host
// asks them.

/// Whether the map **describes** where `range` is.
///
/// The question is not "is this memory free" — a loader reserves exactly the
/// memory it loaded the image into, so the answer to that is always no — but
/// "does the map name the address at all".  A map silent about the address the
/// kernel is running from is a map this kernel cannot trust about anything else
/// ([RFC 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)).
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub fn range_is_described(range: (usize, usize), regions: &[MemoryRegion]) -> bool {
    let (start, end) = range;
    if end <= start {
        return false;
    }
    let describes = |address: usize| {
        regions
            .iter()
            .any(|region| region.base <= address && address < region.end())
    };
    // The first byte and the last: what lies between them may be holes, which
    // are the loader's own reservations rather than a failure to describe us.
    describes(start) && describes(end - 1)
}

/// Whether any byte of `range` lands in memory the map calls **defective**.
///
/// This is the one kind that is a refusal rather than a report: the firmware
/// has already said those pages are broken, and a kernel whose `.bss` runs into
/// them is broken in a way no later symptom would name as clearly.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub fn range_touches_defective_memory(range: (usize, usize), regions: &[MemoryRegion]) -> bool {
    let (start, end) = range;
    if end <= start {
        return false;
    }
    regions.iter().any(|region| {
        region.kind == MEMORY_REGION_DEFECTIVE && region.base < end && start < region.end()
    })
}

/// The number of bytes of `range` no region describes, and the number it calls
/// reserved.
///
/// Both are reported rather than refused: a loader reserves the memory it
/// loaded the kernel into, so this is what memory the kernel runs from looks
/// like from outside.
// Called from the check that only runs on a machine; the host tests drive the
// two questions themselves.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
fn undescribed_and_reserved_bytes(
    range: (usize, usize),
    regions: &[MemoryRegion],
) -> (usize, usize) {
    let (start, end) = range;
    let mut undescribed = 0usize;
    let mut reserved = 0usize;
    let mut at = start;
    while at < end {
        let covering = regions
            .iter()
            .filter(|region| region.base <= at && at < region.end())
            .max_by_key(|region| region.end());
        match covering {
            Some(region) => {
                let next = region.end().min(end);
                if region.kind == MEMORY_REGION_RESERVED {
                    reserved = reserved.saturating_add(next - at);
                }
                at = next;
            }
            None => {
                let step = crate::memory::paging::PAGE_SIZE.min(end - at);
                undescribed = undescribed.saturating_add(step);
                at += step;
            }
        }
    }
    (undescribed, reserved)
}

/// The kernel's own image, as the linker placed it.
///
/// Only a bare-metal build has these symbols; a host build's "image" is the
/// test binary, which is not a kernel and is not a kernel's question.
///
/// The range stops at `__image_end` rather than at `__kernel_end`, because
/// the demo slots and the frame pool are **reservations** — the tail of the
/// kernel's address space that nothing is loaded into and the boot does not
/// clear — and a machine is not required to have RAM under a span the kernel
/// reserves but never touches.  What the checks below ask about is the part
/// of the kernel the loader loaded: that is the part that has to be RAM.  How
/// much of the pool the machine actually has is [`managed_pool_bytes`]'s
/// answer.
#[cfg(target_os = "none")]
pub fn kernel_image_range() -> (usize, usize) {
    extern "C" {
        static __kernel_start: u8;
        static __image_end: u8;
    }
    // The addresses of the linker's own symbols for the image this code is
    // running from; neither is dereferenced, and taking one is safe.
    let start = core::ptr::addr_of!(__kernel_start) as usize;
    let end = core::ptr::addr_of!(__image_end) as usize;
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

/// What the boot decides about its own placement, from the machine's answer
/// and the kernel's own ranges.
///
/// The four refusals are the ones [RFC
/// 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md) decided,
/// and they are named here rather than spelled as a `panic!` inside
/// [`report_machine_memory`] so that each branch has a test that drives it
/// with a map built for it: no machine this tree boots produces a map that
/// refuses, so every refusal is a path no boot exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlacementVerdict {
    /// The machine's answer and the kernel agree.
    Accepted,
    /// The pool is outside the window a device address can name.
    PoolNotAddressable,
    /// The machine described its memory and the pool starts past all of it.
    PoolPastMachineMemory,
    /// The kernel's image touches memory the machine calls defective.
    ImageInDefectiveMemory,
    /// The kernel's image is in no region the machine describes.
    ImageUndescribed,
}

/// Judge the kernel's placement against the machine's answer.
///
/// The order is the order the boot checks in, and it is load-bearing: the
/// addressability question is the kernel's own ([`super::mmu::phys_addr_of`])
/// and is asked even when the machine described nothing, while the other
/// three are questions *about* a described map and are skipped when there is
/// none — a protocol that describes nothing is not a machine whose memory is
/// unusable (RFC 0019's third answer).
pub(crate) fn judge_placement(
    pool_addressable: bool,
    managed_pool_bytes: usize,
    frame_size: usize,
    image: (usize, usize),
    regions: Option<&[crate::arch::boot::MemoryRegion]>,
) -> PlacementVerdict {
    if !pool_addressable {
        return PlacementVerdict::PoolNotAddressable;
    }
    let Some(regions) = regions else {
        return PlacementVerdict::Accepted;
    };
    if managed_pool_bytes < frame_size {
        return PlacementVerdict::PoolPastMachineMemory;
    }
    if range_touches_defective_memory(image, regions) {
        return PlacementVerdict::ImageInDefectiveMemory;
    }
    if !range_is_described(image, regions) {
        return PlacementVerdict::ImageUndescribed;
    }
    PlacementVerdict::Accepted
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

    // Where the pool *is*, because that is the address every frame the kernel
    // hands out is measured from — and because a boot that moves it is a boot
    // whose behaviour is worth being able to compare ([RFC
    // 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md) found
    // that moving it stalls the boot, and this line is how the two builds are
    // told apart).
    let (pool_start, pool_end) = crate::memory::frame::pool_range();
    crate::println!("[mem   ] the pool is [{:#x}, {:#x})", pool_start, pool_end);

    // The pool is a *span* the kernel reserves; what it manages is the part of
    // that span the machine has.  The two are the same on every machine this
    // kernel was measured on before a small-RAM boot was asked for, so the
    // line appears only where they differ — which is exactly the boot a
    // reader would otherwise misread as "the kernel has its whole span".
    let managed = managed_pool_bytes();
    if managed < pool_end - pool_start {
        crate::println!(
            "[mem   ] the machine has {} MiB of the pool's span; frames stop at {:#x}",
            managed / (1024 * 1024),
            pool_start + managed
        );
    }

    // The answer is a machine's; a host build asks it and does not enforce it.
    let pool_addressable = pool_is_addressable_by_a_device();

    // The verdict is computed in both configurations and *enforced* only on
    // bare metal, where the questions are a machine's: a host build's "image"
    // is the test binary and its pool is not a machine's memory, so the two
    // are judged with a placeholder range and the answer is dropped.  The
    // verdict is what the four refusals below answer to; `judge_placement`
    // and each of its arms carry the tests (no boot this tree runs produces a
    // refusing map).
    #[cfg(target_os = "none")]
    let image = kernel_image_range();
    #[cfg(not(target_os = "none"))]
    let image = (0usize, 0usize);
    let verdict = judge_placement(
        pool_addressable,
        managed,
        crate::memory::frame::FRAME_SIZE,
        image,
        regions.as_deref(),
    );

    #[cfg(not(target_os = "none"))]
    let _ = verdict;

    #[cfg(target_os = "none")]
    {
        match verdict {
            PlacementVerdict::Accepted => {}
            PlacementVerdict::PoolNotAddressable => {
                let (start, end) = crate::memory::frame::pool_range();
                crate::println!(
                    "[mem   ] FATAL: the pool [{:#x}, {:#x}) is outside the window a device address can name",
                    start,
                    end
                );
                panic!("the kernel's own memory is not addressable by a device");
            }
            PlacementVerdict::PoolPastMachineMemory => {
                crate::println!(
                    "[mem   ] FATAL: the pool starts at {:#x}, past the memory the machine describes",
                    pool_start
                );
                panic!("the frame pool lies outside the machine's memory");
            }
            PlacementVerdict::ImageInDefectiveMemory => {
                crate::println!(
                    "[mem   ] FATAL: the kernel's image [{:#x}, {:#x}) overlaps memory the machine calls defective",
                    image.0,
                    image.1
                );
                panic!("the kernel was loaded into defective memory");
            }
            PlacementVerdict::ImageUndescribed => {
                crate::println!(
                    "[mem   ] FATAL: the kernel's image [{:#x}, {:#x}) is in no region the machine describes",
                    image.0,
                    image.1
                );
                if let Some(regions) = &regions {
                    for region in regions {
                        crate::println!(
                            "[mem   ]   the machine offered [{:#x}, {:#x}) kind {}",
                            region.base,
                            region.end(),
                            region.kind
                        );
                    }
                }
                panic!("the kernel was loaded where the machine describes no memory");
            }
        }

        if let Some(regions) = &regions {
            // Reported rather than refused: a loader reserves the memory it
            // loaded the kernel into, so holes and reserved ranges inside the
            // image are what a *correct* map looks like ([RFC
            // 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)).
            let (undescribed, reserved) = undescribed_and_reserved_bytes(image, regions);
            crate::println!(
                "[mem   ] the kernel's image [{:#x}, {:#x}) is described: {} KiB in no entry, {} KiB reserved",
                image.0,
                image.1,
                undescribed / 1024,
                reserved / 1024
            );
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
        offset += crate::memory::frame::FRAME_SIZE;
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
    use super::range_is_described;
    use super::range_touches_defective_memory;
    use crate::arch::boot::MemoryRegion;
    use crate::arch::boot::MEMORY_REGION_AVAILABLE;
    use crate::arch::boot::MEMORY_REGION_DEFECTIVE;
    use crate::arch::boot::MEMORY_REGION_RESERVED;

    fn region(base: usize, length: usize, kind: u32) -> MemoryRegion {
        MemoryRegion { base, length, kind }
    }

    /// The two questions a boot asks about its own placement, over the map a
    /// real UEFI boot produced ([RFC
    /// 0020](../../docs/rfcs/0020-what-the-memory-map-may-refuse-on.md)): the
    /// image is **described** — the loader reserved the memory it put it in,
    /// which is a correct map rather than a failure — and it is not in
    /// defective memory.
    #[test]
    fn a_loader_reserved_image_is_described_rather_than_refused() {
        // Seven entries, the shape OVMF described: the payload's own range
        // marked reserved, and holes between the firmware's regions.
        let regions = [
            region(0x0, 0xa_0000, MEMORY_REGION_AVAILABLE),
            region(0x10_0000, 0x700000, MEMORY_REGION_RESERVED),
            region(0x80_8000, 0x3000, MEMORY_REGION_RESERVED),
            region(0x90_0000, 0x3e_43f000, MEMORY_REGION_AVAILABLE),
        ];
        let image = (0x20_0000, 0x24_895a10);

        assert!(range_is_described(image, &regions));
        assert!(!range_is_described((0x60_0000, 0x70_0000), &[]));
        assert!(
            !range_is_described((0x81_5000, 0x81_6000), &regions),
            "an address the map says nothing about is not described: 0x814000 to 0x900000 is a hole on this boot"
        );
        assert!(!range_touches_defective_memory(image, &regions));

        // The same image, one of its pages declared broken.
        let mut defective = regions.to_vec();
        defective.push(region(0x20_0000, 0x1000, MEMORY_REGION_DEFECTIVE));
        assert!(range_touches_defective_memory(image, &defective));
        assert!(
            !range_touches_defective_memory((0x20_0000, 0x20_0000), &defective),
            "an empty range touches nothing"
        );
        assert!(
            !range_touches_defective_memory((0x30_0000, 0x40_0000), &defective),
            "a range past the defective page does not touch it"
        );
    }

    /// Every arm of the boot's judgment, driven with a map built for it.
    ///
    /// The four refusals cannot be reached from a boot — no machine this tree
    /// runs produces a map that refuses — so each is driven here instead, and
    /// the verdict enum is what makes that possible: the branch that panics is
    /// a `match` over an answer these tests produce directly.
    #[test]
    fn each_placement_refusal_is_reachable_from_its_own_answer() {
        use super::judge_placement;
        use super::PlacementVerdict;
        use crate::memory::frame::FRAME_SIZE;

        let image = (0x20_0000, 0x24_895a10);
        let good = [
            region(0x10_0000, 0x700000, MEMORY_REGION_RESERVED),
            region(0x90_0000, 0x3e_43f000, MEMORY_REGION_AVAILABLE),
        ];

        // The machine's map and the kernel agree.
        assert_eq!(
            judge_placement(true, 512 * 1024 * 1024, FRAME_SIZE, image, Some(&good)),
            PlacementVerdict::Accepted
        );
        // A machine that describes nothing is booted through: RFC 0019's third
        // answer, and it is the one every refusal below must *not* swallow.
        assert_eq!(
            judge_placement(true, 512 * 1024 * 1024, FRAME_SIZE, image, None),
            PlacementVerdict::Accepted
        );

        // 1. The pool is outside the window a device address can name.
        assert_eq!(
            judge_placement(false, 512 * 1024 * 1024, FRAME_SIZE, image, Some(&good)),
            PlacementVerdict::PoolNotAddressable
        );
        assert_eq!(
            judge_placement(false, 512 * 1024 * 1024, FRAME_SIZE, image, None),
            PlacementVerdict::PoolNotAddressable,
            "the addressability question is the kernel's own and is asked even when the machine described nothing"
        );

        // 2. The pool starts past everything the machine describes.
        assert_eq!(
            judge_placement(true, FRAME_SIZE - 1, FRAME_SIZE, image, Some(&good)),
            PlacementVerdict::PoolPastMachineMemory
        );
        assert_eq!(
            judge_placement(true, FRAME_SIZE, FRAME_SIZE, image, Some(&good)),
            PlacementVerdict::Accepted,
            "one whole frame is the first answer that is a pool at all"
        );

        // 3. The image touches memory the machine calls defective.
        let mut defective = good.to_vec();
        defective.push(region(0x24_0000, 0x1000, MEMORY_REGION_DEFECTIVE));
        assert_eq!(
            judge_placement(true, 512 * 1024 * 1024, FRAME_SIZE, image, Some(&defective)),
            PlacementVerdict::ImageInDefectiveMemory
        );

        // 4. The image is in no region the machine describes.
        let hole = [region(0x0, 0x10_0000, MEMORY_REGION_AVAILABLE)];
        assert_eq!(
            judge_placement(true, 512 * 1024 * 1024, FRAME_SIZE, image, Some(&hole)),
            PlacementVerdict::ImageUndescribed
        );
        assert_eq!(
            judge_placement(true, 512 * 1024 * 1024, FRAME_SIZE, (0, 0), Some(&hole)),
            PlacementVerdict::ImageUndescribed,
            "a range with no bytes is described by nothing: the question asks containment for the first and last byte, and an empty range has neither"
        );
    }
}
