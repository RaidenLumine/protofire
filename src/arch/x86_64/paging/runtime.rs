//! src/arch/x86_64/paging/runtime.rs
//!
//! x86_64 runtime page-table management for device MMIO and user address spaces.

use super::*;
use crate::kernel::memory::paging::PagePermissions;
use crate::user::program::UserImageLoadPlan;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::util::sync_unsafe_cell::SyncUnsafeCell;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::boxed::Box;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::arch::asm;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Runtime device MMIO page-table allocation pool
// ---------------------------------------------------------------------------
// When drivers need to map PCI BARs at physical addresses outside the
// bootstrap identity map, we allocate page-table pages from this pool.
// Each entry is a 4 KiB page-table page (512 × 8-byte entries).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RUNTIME_PT_POOL_SIZE: usize = 64;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static RUNTIME_PT_POOL: SyncUnsafeCell<[RawPageTable; RUNTIME_PT_POOL_SIZE]> =
    SyncUnsafeCell::new([RawPageTable::zeroed(); RUNTIME_PT_POOL_SIZE]);
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static RUNTIME_PT_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Allocate a zeroed 4 KiB page-table page from the runtime pool.
///
/// Returns the physical (≡ virtual, identity-mapped) address of the page,
/// or `None` when the pool is exhausted.
///
/// Emits a diagnostic via `println!` when the pool is near exhaustion
/// (≥56 of 64 pages used) so developers can detect MMIO-heavy workloads
/// before pool depletion causes driver failures.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn alloc_runtime_pt_page() -> Option<usize> {
    let index = RUNTIME_PT_ALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
    if index >= RUNTIME_PT_POOL_SIZE {
        RUNTIME_PT_ALLOC_COUNT.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    // Warn when the pool is near exhaustion (≥56 of 64 pages used).
    if index >= 56 {
        crate::println!(
            "[mmio  ] runtime PT pool near exhaustion: {}/{} pages used",
            index + 1,
            RUNTIME_PT_POOL_SIZE,
        );
    }
    let base = RUNTIME_PT_POOL.get() as *mut u8;
    let page_ptr = base.add(index * X86_PAGE_SIZE);
    core::ptr::write_bytes(page_ptr, 0, X86_PAGE_SIZE);
    Some(page_ptr as usize)
}

/// Check whether a physical address range overlaps the kernel image (text,
/// rodata, data, bss).  Used as a safety net in [`map_device_mmio`] — PCI
/// BAR addresses are in the high MMIO space (>1 GiB) and should never overlap
/// the kernel, but a debug-assertion here catches driver bugs early.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn overlaps_kernel(phys: usize, size: usize) -> bool {
    let ktext_start = core::ptr::addr_of!(__text_start) as usize;
    let kbss_end = core::ptr::addr_of!(__bss_end) as usize;
    let phys_end = phys.saturating_add(size);
    // Two ranges [A, B) and [C, D) overlap if A < D ∧ C < B.
    phys < kbss_end && phys_end > ktext_start
}

/// Identity-map a physical address range as device MMIO in the live kernel
/// page tables.  Uses 2 MiB large pages when the range is 2 MiB aligned and
/// at least 2 MiB long; falls back to 4 KiB pages otherwise.
///
/// Device mappings use uncacheable memory (PCD set) to prevent the CPU from
/// reordering or caching MMIO accesses.
///
/// ## Identity-mapping strategy
///
/// The x86_64 kernel page tables use **identity mapping** for all physical
/// memory: virtual address V maps to physical address V.  This means the raw
/// pointer returned by this function **is** the physical address, and callers
/// can access MMIO registers directly with [`core::ptr::write_volatile`] /
/// [`core::ptr::read_volatile`] without any virtual→physical translation.
///
/// ## Ownership
///
/// The returned pointer is valid for the lifetime of the kernel.  There is
/// no `unmap` — once created, a device mapping persists until the page
/// tables are torn down.
///
/// Returns a virtual pointer to the start of the mapped region, or `None`
/// if the mapping fails (pool exhaustion, invalid arguments, or missing
/// root table).
///
/// # Safety
///
/// The caller must ensure `phys` points to valid device MMIO and that the
/// mapped region does not overlap existing kernel mappings (text, rodata,
/// data, bss).  This function is only available on bare-metal x86_64.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn map_device_mmio(phys: u64, size: usize) -> Option<*mut u8> {
    // 4-level paging supports up to 48-bit physical addresses.  Reject
    // addresses beyond this limit (no current PCI BAR exceeds 48 bits).
    if phys >= (1u64 << 48) {
        return None;
    }
    if size == 0 {
        return None;
    }

    // Sanity check: the MMIO range must not overlap kernel memory.
    debug_assert!(
        !overlaps_kernel(phys as usize, size),
        "map_device_mmio: range [{:#x}, {:#x}) overlaps kernel image",
        phys,
        phys.saturating_add(size as u64),
    );

    let page_start = align_down(phys as usize, X86_PAGE_SIZE);
    let page_end = align_up((phys as usize).saturating_add(size), X86_PAGE_SIZE)?;

    let cr3 = current_root_table_address_impl()?;
    let pml4 = cr3 as *mut u64;

    let mut addr = page_start;
    while addr < page_end {
        // Try 2 MiB large page when the remaining range is at least 2 MiB
        // and both the physical address and virtual address are 2 MiB aligned.
        let remaining = page_end - addr;
        if remaining >= PAGE_DIRECTORY_WINDOW_SIZE && addr & (PAGE_DIRECTORY_WINDOW_SIZE - 1) == 0 {
            map_device_large_page(pml4, addr)?;
            addr = addr.saturating_add(PAGE_DIRECTORY_WINDOW_SIZE);
        } else {
            map_device_4k_page(pml4, addr)?;
            addr = addr.saturating_add(X86_PAGE_SIZE);
        }
    }

    Some(phys as *mut u8)
}

/// Map a single 2 MiB device-MMIO large page.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn map_device_large_page(pml4: *mut u64, phys: usize) -> Option<()> {
    let pml4_idx = pml4_index(phys);
    let pdpt_idx = page_directory_pointer_index(phys);
    let pd_idx = page_directory_slot_index(phys);

    ensure_runtime_pdpt(pml4, pml4_idx)?;
    let pdpt = read_runtime_pdpt(pml4, pml4_idx)?;
    let pd = ensure_runtime_pd(pdpt, pdpt_idx)?;

    // Large-page (2 MiB) entry in the Page Directory.
    let entry = (phys as u64 & LARGE_PAGE_ADDRESS_MASK)
        | PAGE_ENTRY_PRESENT
        | PAGE_ENTRY_WRITABLE
        | PAGE_ENTRY_LARGE
        | PAGE_ENTRY_CACHE_DISABLE
        | PAGE_ENTRY_NO_EXECUTE;

    core::ptr::write_volatile(pd.add(pd_idx), entry);
    invalidate_tlb(phys);
    Some(())
}

/// Map a single 4 KiB device-MMIO page.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn map_device_4k_page(pml4: *mut u64, phys: usize) -> Option<()> {
    let pml4_idx = pml4_index(phys);
    let pdpt_idx = page_directory_pointer_index(phys);
    let pd_idx = page_directory_slot_index(phys);
    let pt_idx = page_table_index(phys);

    ensure_runtime_pdpt(pml4, pml4_idx)?;
    let pdpt = read_runtime_pdpt(pml4, pml4_idx)?;
    let pd = ensure_runtime_pd(pdpt, pdpt_idx)?;

    // Check if the PD entry is already a 2 MiB large page; if so, skip.
    let pd_entry = core::ptr::read_volatile(pd.add(pd_idx));
    if pd_entry & PAGE_ENTRY_LARGE != 0 {
        return Some(()); // already mapped as large page
    }

    let pt = ensure_runtime_pt(pd, pd_idx)?;

    let entry = (phys as u64 & PAGE_ENTRY_ADDRESS_MASK)
        | PAGE_ENTRY_PRESENT
        | PAGE_ENTRY_WRITABLE
        | PAGE_ENTRY_CACHE_DISABLE
        | PAGE_ENTRY_NO_EXECUTE;

    core::ptr::write_volatile(pt.add(pt_idx), entry);
    invalidate_tlb(phys);
    Some(())
}

/// Ensure a PML4 entry exists for the given index, allocating a PDPT if needed.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn ensure_runtime_pdpt(pml4: *mut u64, pml4_idx: usize) -> Option<()> {
    let entry = core::ptr::read_volatile(pml4.add(pml4_idx));
    if entry & PAGE_ENTRY_PRESENT == 0 {
        let pdpt_phys = alloc_runtime_pt_page()?;
        let new_entry =
            (pdpt_phys as u64 & PAGE_ENTRY_ADDRESS_MASK) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        core::ptr::write_volatile(pml4.add(pml4_idx), new_entry);
    }
    Some(())
}

/// Read the physical address of a PDPT from its PML4 entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn read_runtime_pdpt(pml4: *mut u64, pml4_idx: usize) -> Option<*mut u64> {
    let entry = core::ptr::read_volatile(pml4.add(pml4_idx));
    if entry & PAGE_ENTRY_PRESENT == 0 {
        return None;
    }
    Some((entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize) as *mut u64)
}

/// Ensure a PD exists for the given PDPT index, allocating one if needed.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn ensure_runtime_pd(pdpt: *mut u64, pdpt_idx: usize) -> Option<*mut u64> {
    let entry = core::ptr::read_volatile(pdpt.add(pdpt_idx));
    if entry & PAGE_ENTRY_PRESENT == 0 {
        let pd_phys = alloc_runtime_pt_page()?;
        let new_entry =
            (pd_phys as u64 & PAGE_ENTRY_ADDRESS_MASK) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        core::ptr::write_volatile(pdpt.add(pdpt_idx), new_entry);
        return Some(pd_phys as *mut u64);
    }
    Some((entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize) as *mut u64)
}

/// Ensure a PT exists for the given PD index, allocating one if needed.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn ensure_runtime_pt(pd: *mut u64, pd_idx: usize) -> Option<*mut u64> {
    let entry = core::ptr::read_volatile(pd.add(pd_idx));
    if entry & PAGE_ENTRY_PRESENT == 0 {
        let pt_phys = alloc_runtime_pt_page()?;
        let new_entry =
            (pt_phys as u64 & PAGE_ENTRY_ADDRESS_MASK) | PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
        core::ptr::write_volatile(pd.add(pd_idx), new_entry);
        return Some(pt_phys as *mut u64);
    }
    Some((entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize) as *mut u64)
}

/// Invalidate the TLB for a single virtual address on all CPUs.
///
/// On SMP systems this broadcasts an IPI shootdown to all other cores.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn invalidate_tlb(virtual_address: usize) {
    crate::kernel::smp::tlb_shootdown(virtual_address);
}

/// Install or update a user-accessible 4 KiB page mapping in the live
/// kernel page tables.  Creates intermediate page-table structures (PDPT,
/// PD, PT) as needed from the runtime pool.
///
/// The page is mapped with the U/S bit set for user access, NX configured
/// per `permissions`, and Write configured per `permissions`.
///
/// Returns `Some(())` on success, `None` if the pool is exhausted or the
/// address is not in the lower canonical half.
///
/// # Safety
///
/// The caller must ensure that the page tables are not concurrently modified.
/// `virtual_address` must be page-aligned and within the user canonical range.
/// `physical_address` must be a valid, page-aligned physical frame.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn install_user_page(
    virtual_address: usize,
    physical_address: usize,
    permissions: PagePermissions,
) -> Option<()> {
    if virtual_address >= X86_64_USER_CANONICAL_END {
        return None;
    }

    let cr3 = current_root_table_address_impl()?;
    let pml4 = cr3 as *mut u64;

    let pml4_idx = pml4_index(virtual_address);
    let pdpt_idx = page_directory_pointer_index(virtual_address);
    let pd_idx = page_directory_slot_index(virtual_address);
    let pt_idx = page_table_index(virtual_address);

    ensure_runtime_pdpt(pml4, pml4_idx)?;
    let pdpt = read_runtime_pdpt(pml4, pml4_idx)?;
    let pd = ensure_runtime_pd(pdpt, pdpt_idx)?;

    // Don't overwrite a large page.
    let pd_entry = core::ptr::read_volatile(pd.add(pd_idx));
    if pd_entry & PAGE_ENTRY_LARGE != 0 {
        return None;
    }

    let pt = ensure_runtime_pt(pd, pd_idx)?;

    let mut entry = (align_down(physical_address, X86_PAGE_SIZE) as u64) & PAGE_ENTRY_ADDRESS_MASK;
    entry |= PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER;
    if permissions.contains(PagePermissions::WRITE) {
        entry |= PAGE_ENTRY_WRITABLE;
    }
    if !permissions.contains(PagePermissions::EXECUTE) {
        entry |= PAGE_ENTRY_NO_EXECUTE;
    }

    core::ptr::write_volatile(pt.add(pt_idx), entry);
    invalidate_tlb(virtual_address);
    Some(())
}

/// Host-side stub.
///
/// # Safety
///
/// On bare-metal x86_64 this function manipulates live page tables. The caller
/// must ensure `virtual_address` and `physical_address` are valid and
/// page-aligned, and that `permissions` does not violate W^X where enforced.
/// This stub is a no-op on non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn install_user_page(
    _virtual_address: usize,
    _physical_address: usize,
    _permissions: PagePermissions,
) -> Option<()> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const PAGE_ENTRY_CACHE_DISABLE: u64 = 1 << 4; // PCD — uncacheable memory
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const LARGE_PAGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffe0_0000; // 2 MiB aligned

/// Host-side stub: no live hardware page tables.
///
/// # Safety
///
/// On bare-metal x86_64 this function maps device MMIO at page-table level.
/// The caller must ensure `phys` points to valid MMIO space and that no
/// conflicting mapping exists in the target range. This stub returns `None`
/// on non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn map_device_mmio(_phys: u64, _size: usize) -> Option<*mut u8> {
    None
}

pub const fn bootstrap_identity_mapping() -> BootstrapMapping {
    BootstrapMapping {
        virtual_start: BOOTSTRAP_IDENTITY_MAP_START,
        physical_start: BOOTSTRAP_IDENTITY_MAP_START,
        length: BOOTSTRAP_IDENTITY_MAP_LENGTH,
        page_size: BOOTSTRAP_PAGE_SIZE,
        writable: true,
        executable: true,
    }
}

pub fn init() {
    INITIALIZED.store(true, Ordering::Release);

    // Enable native x87/SSE so the context switch can safely save and
    // restore XMM registers via movdqu.  Must run before any user thread
    // is entered because the first context switch will execute SSE.
    super::super::control_regs::enable_sse();

    // Enable SMEP so the kernel cannot execute user-accessible pages.
    // SMAP is enabled separately after copy_from/to_user paths are audited.
    // Both functions CPUID-gate internally (no-op on CPUs without the bits)
    // and `enable_smap` marks SMAP active so the `stac`/`clac` wrappers on
    // the user-memory access paths (UserAccessGuard / with_user_access) are
    // actually emitted.
    super::super::control_regs::enable_smep();
    super::super::control_regs::enable_smap();
}

pub fn bootstrap_translate(address: usize) -> Option<usize> {
    bootstrap_identity_mapping().translate(address)
}

pub fn runtime_kernel_page_plan(heap_bounds: (usize, usize)) -> Option<KernelPagePlan> {
    runtime_kernel_page_plan_impl(heap_bounds)
}

/// The kernel page-table spec depends only on linker symbols and the fixed
/// kernel-heap bounds — it never changes after boot.  We compute it once,
/// store it in a leaked `Box`, and share `&'static` references thereafter.
/// This avoids large Vec allocations on a potentially fragmented heap during
/// process spawn.
///
/// # Safety
///
/// The static is initialised during early boot (single-threaded) and treated
/// as read-only after that.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn cached_kernel_page_table_spec(
    heap_bounds: (usize, usize),
) -> Option<&'static KernelPageTableSpec> {
    static CACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static mut SPEC_PTR: *const KernelPageTableSpec = core::ptr::null();

    if CACHED.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: SPEC_PTR was stored during early boot and is immutable afterwards.
        return Some(unsafe { &*SPEC_PTR });
    }

    let plan = runtime_kernel_page_plan(heap_bounds)?;
    let spec = Box::new(KernelPageTableSpec::from_plan(&plan)?);
    // Leak the Box so the reference stays valid for the kernel's lifetime.
    let ptr: *const KernelPageTableSpec = Box::into_raw(spec);
    unsafe {
        SPEC_PTR = ptr;
    }
    CACHED.store(true, core::sync::atomic::Ordering::Release);
    Some(unsafe { &*ptr })
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn runtime_kernel_page_table_spec(heap_bounds: (usize, usize)) -> Option<KernelPageTableSpec> {
    cached_kernel_page_table_spec(heap_bounds).cloned()
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn runtime_kernel_page_table_spec(heap_bounds: (usize, usize)) -> Option<KernelPageTableSpec> {
    let plan = runtime_kernel_page_plan(heap_bounds)?;
    KernelPageTableSpec::from_plan(&plan)
}

pub fn user_address_space_page_table_spec(
    load_plan: &UserImageLoadPlan,
) -> Option<UserAddressSpacePageTableSpec> {
    UserAddressSpacePageTableSpec::from_load_plan(load_plan)
}

pub fn materialize_user_address_space(
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Option<PreparedUserAddressSpace> {
    PreparedUserAddressSpace::from_load_plan(load_plan, image)
}

pub fn prepare_process_address_space(
    kernel_spec: &KernelPageTableSpec,
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Option<PreparedProcessAddressSpace> {
    let user_address_space = PreparedUserAddressSpace::from_load_plan(load_plan, image)?;
    PreparedProcessAddressSpace::from_kernel_spec_and_user_address_space(
        kernel_spec,
        user_address_space,
    )
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn prepare_runtime_process_address_space(
    heap_bounds: (usize, usize),
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Option<PreparedProcessAddressSpace> {
    // Use the cached kernel spec to avoid a large Vec allocation on a
    // potentially fragmented post-boot heap.  The spec is idempotent.
    let kernel_spec = cached_kernel_page_table_spec(heap_bounds)?;
    prepare_process_address_space(kernel_spec, load_plan, image)
}

// Host-side stub: the host code-path in `prepare_arch_user_address_space`
// uses `materialize_user_address_space` instead, but the compiler still
// needs this symbol to exist.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn prepare_runtime_process_address_space(
    _heap_bounds: (usize, usize),
    _load_plan: &UserImageLoadPlan,
    _image: &[u8],
) -> Option<PreparedProcessAddressSpace> {
    None
}

pub fn runtime_prepared_translation(
    address: usize,
    heap_bounds: (usize, usize),
) -> Option<PreparedTranslation> {
    runtime_kernel_page_table_spec(heap_bounds)?.translate(address)
}

pub fn prepare_runtime_kernel_page_tables(
    heap_bounds: (usize, usize),
) -> Option<PreparedRuntimeKernelPageTables> {
    prepare_runtime_kernel_page_tables_impl(heap_bounds)
}

pub fn prepared_runtime_kernel_page_tables() -> Option<PreparedRuntimeKernelPageTables> {
    let root_table_address = PREPARED_ROOT_TABLE.load(Ordering::Relaxed);
    if root_table_address == 0 {
        return None;
    }

    Some(PreparedRuntimeKernelPageTables {
        root_table_address,
        window_count: PREPARED_WINDOW_COUNT.load(Ordering::Relaxed),
        mapped_page_count: PREPARED_MAPPED_PAGE_COUNT.load(Ordering::Relaxed),
    })
}

pub fn prepared_runtime_kernel_page_tables_active() -> bool {
    prepared_runtime_kernel_page_tables_active_impl()
}

pub fn activate_prepared_runtime_kernel_page_tables() -> Option<ActivatedRuntimeKernelPageTables> {
    activate_prepared_runtime_kernel_page_tables_impl()
}

pub fn active_runtime_kernel_page_table_check(
    heap_bounds: (usize, usize),
) -> Option<ActiveRuntimeKernelPageTableCheck> {
    active_runtime_kernel_page_table_check_impl(heap_bounds)
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn prepare_runtime_kernel_page_tables_impl(
    heap_bounds: (usize, usize),
) -> Option<PreparedRuntimeKernelPageTables> {
    let spec = runtime_kernel_page_table_spec(heap_bounds)?;
    Some(unsafe { install_runtime_kernel_page_tables(&spec) })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn prepare_runtime_kernel_page_tables_impl(
    _heap_bounds: (usize, usize),
) -> Option<PreparedRuntimeKernelPageTables> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn prepared_runtime_kernel_page_tables_active_impl() -> bool {
    let Some(prepared) = prepared_runtime_kernel_page_tables() else {
        return false;
    };

    current_root_table_address_impl() == Some(prepared.root_table_address)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn prepared_runtime_kernel_page_tables_active_impl() -> bool {
    false
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn activate_prepared_runtime_kernel_page_tables_impl(
) -> Option<ActivatedRuntimeKernelPageTables> {
    let prepared = prepared_runtime_kernel_page_tables()?;
    let previous_root_table_address = current_root_table_address_impl()?;
    let already_active = previous_root_table_address == prepared.root_table_address;

    if !already_active {
        install_active_root_table_address_impl(prepared.root_table_address)?;
    }

    Some(ActivatedRuntimeKernelPageTables {
        previous_root_table_address,
        active_root_table_address: current_root_table_address_impl()?,
        window_count: prepared.window_count,
        mapped_page_count: prepared.mapped_page_count,
        already_active,
    })
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn activate_prepared_runtime_kernel_page_tables_impl(
) -> Option<ActivatedRuntimeKernelPageTables> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn active_runtime_kernel_page_table_check_impl(
    heap_bounds: (usize, usize),
) -> Option<ActiveRuntimeKernelPageTableCheck> {
    let root_table_address = current_root_table_address_impl()?;
    let plan = runtime_kernel_page_plan(heap_bounds)?;
    let spec = runtime_kernel_page_table_spec(heap_bounds)?;

    build_active_runtime_kernel_page_table_check(
        root_table_address,
        &plan,
        &spec,
        current_instruction_pointer_impl()?,
        current_stack_pointer_impl()?,
        heap_bounds.0,
    )
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn active_runtime_kernel_page_table_check_impl(
    _heap_bounds: (usize, usize),
) -> Option<ActiveRuntimeKernelPageTableCheck> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn install_runtime_kernel_page_tables(
    spec: &KernelPageTableSpec,
) -> PreparedRuntimeKernelPageTables {
    let pml4 = KERNEL_PML4.get();
    let pdpt = KERNEL_PDPT.get();
    let pd = KERNEL_PD.get();
    let pts = KERNEL_PTS.get();

    *pml4 = RawPageTable::zeroed();
    *pdpt = RawPageTable::zeroed();
    *pd = RawPageTable::zeroed();
    for slot in 0..MAX_KERNEL_PT_WINDOWS {
        (*pts)[slot] = RawPageTable::zeroed();
    }

    (*pml4).0[0] = table_pointer_entry(pdpt as usize);
    (*pdpt).0[0] = table_pointer_entry(pd as usize);

    for (slot, window) in spec.windows.iter().enumerate() {
        if let Some(pde) = spec.huge_pd_entries.get(&window.page_directory_index) {
            // 2 MiB huge page: set the PD entry directly (PS bit set),
            // bypassing the PT level entirely.
            (*pd).0[window.page_directory_index] = *pde;
        } else {
            // Normal 4 KiB window: PD points to a PT filled with PTEs.
            let pt = core::ptr::addr_of_mut!((*pts)[slot]);
            (*pd).0[window.page_directory_index] = table_pointer_entry(pt as usize);
            (*pt).0 = window.entries;
        }
    }

    let summary = PreparedRuntimeKernelPageTables {
        root_table_address: pml4 as usize,
        window_count: spec.window_count(),
        mapped_page_count: spec.mapped_page_count(),
    };

    PREPARED_ROOT_TABLE.store(summary.root_table_address, Ordering::SeqCst);
    PREPARED_WINDOW_COUNT.store(summary.window_count, Ordering::SeqCst);
    PREPARED_MAPPED_PAGE_COUNT.store(summary.mapped_page_count, Ordering::SeqCst);

    summary
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn runtime_kernel_page_plan_impl(heap_bounds: (usize, usize)) -> Option<KernelPagePlan> {
    // Extend the text range to cover the alignment gap between __text_end
    // and __rodata_start.  The linker may place read-only data or literal
    // pools in this gap, and the bootstrap identity map covers it — the
    // runtime page tables must do the same.
    let text_end = core::ptr::addr_of!(__text_end) as usize;
    let rodata_start = core::ptr::addr_of!(__rodata_start) as usize;
    let text_end_covered = if rodata_start > text_end {
        rodata_start
    } else {
        text_end
    };

    KernelPagePlan::from_ranges(
        (core::ptr::addr_of!(__text_start) as usize, text_end_covered),
        linker_symbol_range(
            core::ptr::addr_of!(__rodata_start),
            core::ptr::addr_of!(__rodata_end),
        ),
        linker_symbol_range(
            core::ptr::addr_of!(__data_start),
            core::ptr::addr_of!(__data_end),
        ),
        linker_symbol_range(
            core::ptr::addr_of!(__bss_start),
            core::ptr::addr_of!(__bss_end),
        ),
        heap_bounds,
    )
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn runtime_kernel_page_plan_impl(heap_bounds: (usize, usize)) -> Option<KernelPagePlan> {
    KernelPagePlan::heap_only(heap_bounds)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn linker_symbol_range(start: *const u8, end: *const u8) -> (usize, usize) {
    (start as usize, end as usize)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn install_active_root_table_address_impl(root_table_address: usize) -> Option<()> {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) root_table_address as u64,
            options(nostack, preserves_flags)
        );
    }

    Some(())
}

#[cfg(test)]
pub(crate) fn install_active_root_table_address_impl(root_table_address: usize) -> Option<()> {
    TEST_ACTIVE_ROOT_TABLE.store(
        root_table_address & PAGE_ENTRY_ADDRESS_MASK as usize,
        Ordering::SeqCst,
    );
    Some(())
}

#[cfg(not(any(test, all(target_arch = "x86_64", target_os = "none"))))]
pub(crate) fn install_active_root_table_address_impl(_root_table_address: usize) -> Option<()> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn current_root_table_address_impl() -> Option<usize> {
    let root_table_address: u64;
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) root_table_address,
            options(nostack, preserves_flags)
        );
    }

    Some(root_table_address as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
}

#[cfg(test)]
pub(crate) fn current_root_table_address_impl() -> Option<usize> {
    let root_table_address = TEST_ACTIVE_ROOT_TABLE.load(Ordering::SeqCst);
    if root_table_address == 0 {
        None
    } else {
        Some(root_table_address)
    }
}

#[cfg(not(any(test, all(target_arch = "x86_64", target_os = "none"))))]
pub(crate) fn current_root_table_address_impl() -> Option<usize> {
    None
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn current_instruction_pointer_impl() -> Option<usize> {
    let instruction_pointer: usize;
    unsafe {
        asm!(
            "lea {}, [rip + 0]",
            out(reg) instruction_pointer,
            options(nostack, preserves_flags)
        );
    }

    Some(instruction_pointer)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn current_stack_pointer_impl() -> Option<usize> {
    let stack_pointer: usize;
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) stack_pointer,
            options(nostack, preserves_flags)
        );
    }

    Some(stack_pointer)
}

/// Unmap a single 4 KiB page in the live x86_64 hardware page tables by
/// clearing the Present bit and flushing the TLB for that virtual address.
///
/// Returns `true` when the page was mapped and is now unmapped, `false` when
/// the page was already unmapped or the address could not be resolved.
///
/// # Safety
///
/// The caller must ensure that no code or data it relies on resides at
/// `virtual_address` — the page becomes inaccessible immediately.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn unmap_page(virtual_address: usize) -> bool {
    let va = virtual_address;

    // ── Walk CR3 → PML4 → PDPT → PD → PT ──────────────────────
    let root = match current_root_table_address_impl() {
        Some(r) => r,
        None => return false,
    };

    // PML4
    let pml4 = root as *const u64;
    let pml4_index = (va >> 39) & 0x1FF;
    let pml4_entry = core::ptr::read_volatile(pml4.add(pml4_index));
    if pml4_entry & PAGE_ENTRY_PRESENT == 0 {
        return false;
    }

    // PDPT
    let pdpt_addr = (pml4_entry & PAGE_ENTRY_ADDRESS_MASK) as usize;
    let pdpt = pdpt_addr as *const u64;
    let pdpt_index = (va >> 30) & 0x1FF;
    let pdpt_entry = core::ptr::read_volatile(pdpt.add(pdpt_index));
    if pdpt_entry & PAGE_ENTRY_PRESENT == 0 {
        return false;
    }
    // 1 GiB huge page — can't partially unmap.
    if pdpt_entry & PAGE_ENTRY_LARGE != 0 {
        return false;
    }

    // PD
    let pd_addr = (pdpt_entry & PAGE_ENTRY_ADDRESS_MASK) as usize;
    let pd = pd_addr as *const u64;
    let pd_index = (va >> 21) & 0x1FF;
    let pd_entry = core::ptr::read_volatile(pd.add(pd_index));
    if pd_entry & PAGE_ENTRY_PRESENT == 0 {
        return false;
    }
    // 2 MiB huge page — can't partially unmap.
    if pd_entry & PAGE_ENTRY_LARGE != 0 {
        return false;
    }

    // PT — the leaf 4 KiB PTE
    let pt_addr = (pd_entry & PAGE_ENTRY_ADDRESS_MASK) as usize;
    let pt = pt_addr as *mut u64;
    let pt_index = (va >> 12) & 0x1FF;
    let pte = core::ptr::read_volatile(pt.add(pt_index));
    if pte & PAGE_ENTRY_PRESENT == 0 {
        return false; // already unmapped
    }

    // Clear the Present bit and invalidate the TLB entry on all CPUs.
    core::ptr::write_volatile(pt.add(pt_index), pte & !PAGE_ENTRY_PRESENT);

    // `tlb_shootdown` invalidates the local entry immediately and bumps a
    // global generation counter that remote CPUs observe on their next
    // kernel entry (timer tick / syscall / exception), flushing their TLB.
    // Unlike an IPI → ack shootdown it sends no IPIs, so it is safe to call
    // from an AP during early boot.  A remote CPU that kept a stale valid
    // translation could otherwise still access the unmapped page (TLB hit
    // without a page walk), so the full-coverage flush matters.
    crate::kernel::smp::tlb_shootdown(va);

    true
}

/// Host / test stub: no live hardware page tables to manipulate.
///
/// # Safety
///
/// This stub is always safe to call (it is a no-op), but carries the
/// `unsafe` qualifier to match the bare-metal signature.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub unsafe fn unmap_page(_virtual_address: usize) -> bool {
    false
}
