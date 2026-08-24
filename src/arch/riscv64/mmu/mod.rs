//! src/arch/riscv64/mmu/mod.rs
//!
//! Sv39 4 KiB-granule translation for the runtime kernel page tables and
//! per-process demo user address spaces.
//!
//! The runtime tables use three levels: PGD (L2, 1 GiB blocks) → PMD (L1,
//! 2 MiB blocks) → PTE (L0, 4 KiB pages).  satp points at the PGD root and
//! embeds the process ASID in bits [59:44].
//!
//! Memory map (QEMU `virt`, matching the RISC-V kernel linker script):
//!   [0x0000_0000, 0x8000_0000)  PGD[0..1]  device / MMIO window (UART, PLIC,
//!                                            CLINT, virtio)
//!   [0x8000_0000, 0x8800_0000)  PGD[2]     RAM window (kernel text + demo
//!                                            user slots carved top-down)
//!   [0x8800_0000, ...)                     unused by the runtime tables

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::UserThreadStart;
use crate::util::sync_unsafe_cell::SyncUnsafeCell;

mod asid;

use asid::{allocate_asid, free_asid, satp_with_asid};

// ── Constants ────────────────────────────────────────────────────────────

/// Size of one translation granule (4 KiB).
const TRANSLATION_GRANULE_SIZE: usize = 4096;

/// Number of entries in every Sv39 translation table.
const TABLE_ENTRY_COUNT: usize = 512;

/// RAM window covered by the runtime tables (the kernel image and the demo
/// user slots both live here): 128 MiB at the QEMU `virt` RAM base.
const KERNEL_RAM_BASE: usize = 0x8000_0000;
const KERNEL_RAM_LENGTH: usize = 0x800_0000;

/// Low identity-mapped MMIO window (UART, PLIC, CLINT, virtio, ...).
const DEVICE_MMIO_BASE: usize = 0x0000_0000;
const DEVICE_MMIO_END: usize = 0x8000_0000;

/// Number of preallocated 2 MiB demo user slots.
const USER_DEMO_SLOT_COUNT: usize = 8;

/// Each demo slot occupies one PMD block (2 MiB).
const USER_DEMO_REGION_SIZE: usize = 0x20_0000;
const USER_DEMO_REGION_PAGE_COUNT: usize = USER_DEMO_REGION_SIZE / TRANSLATION_GRANULE_SIZE;

/// Per-slot carve-out sizes.
const USER_DEMO_STACK_SIZE: usize = 0x4_0000; // 256 KiB
const USER_DEMO_STACK_GUARD_SIZE: usize = 0x1_0000; // 64 KiB
const USER_DEMO_EXCEPTION_STACK_SIZE: usize = 0x4_0000; // 256 KiB
const USER_DEMO_EXCEPTION_STACK_GUARD_SIZE: usize = 0x1_0000; // 64 KiB

/// Entry-point offset within the code region of a slot.
const USER_DEMO_CODE_OFFSET: usize = 0x1000;

// ── Sv39 translation descriptor bits ─────────────────────────────────────

/// Valid bit — present in both table and leaf descriptors.
const PTE_VALID: u64 = 1 << 0;
/// Read permission (leaf).
const PTE_READ: u64 = 1 << 1;
/// Write permission (leaf).
const PTE_WRITE: u64 = 1 << 2;
/// Execute permission (leaf).
const PTE_EXECUTE: u64 = 1 << 3;
/// User (U-mode) accessible page.
const PTE_USER: u64 = 1 << 4;
/// Global mapping (not flushed by `sfence.vma` without an rs2).
#[allow(dead_code)]
const PTE_GLOBAL: u64 = 1 << 5;
/// Accessed bit (set by hardware on first access).
const PTE_ACCESSED: u64 = 1 << 6;
/// Dirty bit (set by hardware on first write).
const PTE_DIRTY: u64 = 1 << 7;

/// Physical page number mask within a descriptor: PPN occupies bits [53:10].
const PPN_MASK: u64 = 0x0000_0FFF_FFFF_FFFF;

// ── Types ────────────────────────────────────────────────────────────────

/// A single 512-entry Sv39 translation table (one 4 KiB page).
#[derive(Debug, Clone, Copy)]
pub struct PageTable(pub [u64; TABLE_ENTRY_COUNT]);

impl PageTable {
    /// Create a table whose entries are all invalid.
    pub const fn zeroed() -> Self {
        Self([0; TABLE_ENTRY_COUNT])
    }
}

/// Result of translating one virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
}

/// The runtime kernel page tables, as prepared during early paging bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedRuntimeKernelPageTables {
    pub root_table_address: usize,
    pub window_count: usize,
    pub mapped_page_count: usize,
}

/// Result of switching the active root to the prepared runtime kernel tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivatedRuntimeKernelPageTables {
    pub previous_root_table_address: usize,
    pub active_root_table_address: usize,
    pub window_count: usize,
    pub mapped_page_count: usize,
    pub already_active: bool,
}

/// Result of switching the active root to a process address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivatedProcessAddressSpace {
    pub previous_root_table_address: usize,
    pub active_root_table_address: usize,
    pub mapped_page_count: usize,
    pub kernel_page_count: usize,
    pub user_page_count: usize,
    pub table_page_count: usize,
    pub already_active: bool,
}

/// Kernel region kinds used by the active-table diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedRegionKind {
    KernelText,
    KernelRodata,
    KernelData,
    KernelBss,
    KernelHeap,
}

impl PlannedRegionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelText => "kernel-text",
            Self::KernelRodata => "kernel-rodata",
            Self::KernelData => "kernel-data",
            Self::KernelBss => "kernel-bss",
            Self::KernelHeap => "kernel-heap",
        }
    }
}

/// A single translated address probe for the active-table diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveKernelAddressProbe {
    pub virtual_address: usize,
    pub physical_address: usize,
    pub permissions: PagePermissions,
    pub kind: PlannedRegionKind,
}

/// Verifies that the running instruction/stack/heap pointers are mapped by
/// the currently active tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveRuntimeKernelPageTableCheck {
    pub root_table_address: usize,
    pub instruction_pointer: ActiveKernelAddressProbe,
    pub stack_pointer: ActiveKernelAddressProbe,
    pub heap_pointer: ActiveKernelAddressProbe,
}

/// Fixed layout of one demo user slot (region + stacks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemoUserSlotLayout {
    pub region_start: usize,
    pub region_length: usize,
    pub entry_point: usize,
    pub stack_bottom: usize,
    pub stack_top: usize,
    pub exception_stack_bottom: usize,
    pub exception_stack_top: usize,
    pub stack_pointer: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDemoUserSlot {
    slot_index: usize,
    layout: DemoUserSlotLayout,
    payload_len: usize,
    /// When true, the Drop impl skips `release_demo_user_slot`.  Set on
    /// both parent and child slots during fork — the slot stays allocated
    /// for the kernel's lifetime (it is shared by both processes).
    forked: bool,
}

pub struct PreparedProcessAddressSpace {
    pgd: Box<PageTable>,
    pmd: Box<PageTable>,
    user_pte: Box<PageTable>,
    slot: PreparedDemoUserSlot,
    image_page_count: usize,
    stack_page_count: usize,
    /// Address Space ID for this process, embedded in satp[59:44].
    /// Zero means no ASID assigned (host-mode fallback).
    asid: u64,
}

// ── Kernel translation tables ────────────────────────────────────────────

static KERNEL_PGD: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable::zeroed());
static KERNEL_PMD: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable::zeroed());

static PREPARED_ROOT_TABLE: AtomicUsize = AtomicUsize::new(0);
static PREPARED_WINDOW_COUNT: AtomicUsize = AtomicUsize::new(0);
static PREPARED_MAPPED_PAGE_COUNT: AtomicUsize = AtomicUsize::new(0);

// ── Entry-point helpers ──────────────────────────────────────────────────

/// Sv39 index of a virtual address within the top-level (PGD) table.
fn pgd_index(virtual_address: usize) -> usize {
    (virtual_address >> 30) & 0x1FF
}

/// Sv39 index of a virtual address within a PMD table.
fn pmd_index(virtual_address: usize) -> usize {
    (virtual_address >> 21) & 0x1FF
}

/// Sv39 index of a virtual address within a leaf PTE table.
fn pte_index(virtual_address: usize) -> usize {
    (virtual_address >> 12) & 0x1FF
}

/// Decode the physical page base address from a Sv39 descriptor.
fn page_base_address(entry: u64) -> usize {
    (((entry >> 10) & PPN_MASK) << 12) as usize
}

/// Build a next-level-table descriptor for `address`.
fn table_entry(address: usize) -> u64 {
    (((address as u64) >> 12) << 10) | PTE_VALID
}

/// Build a supervisor-only 2 MiB block descriptor.
fn normal_pmd_block_entry(region_start: usize) -> u64 {
    (((region_start as u64) >> 12) << 10)
        | PTE_VALID
        | PTE_READ
        | PTE_WRITE
        | PTE_EXECUTE
        | PTE_ACCESSED
        | PTE_DIRTY
}

/// Build a supervisor-only 4 KiB leaf descriptor (guard pages / unused slot
/// space inside a user region).
fn normal_pte_page_entry(physical_address: usize) -> u64 {
    (((physical_address as u64) >> 12) << 10)
        | PTE_VALID
        | PTE_READ
        | PTE_WRITE
        | PTE_ACCESSED
        | PTE_DIRTY
}

/// Build a leaf descriptor for a U-mode page with the given permissions.
fn user_page_entry(physical_address: usize, permissions: PagePermissions) -> u64 {
    let mut entry =
        (((physical_address as u64) >> 12) << 10) | PTE_VALID | PTE_USER | PTE_ACCESSED | PTE_DIRTY;
    if permissions.contains(PagePermissions::WRITE) {
        // User-writable: read/write, never executable from U-mode.
        entry |= PTE_READ | PTE_WRITE;
        entry &= !PTE_EXECUTE;
    } else if permissions.contains(PagePermissions::EXECUTE) {
        // Executable: read/execute so user code cannot rewrite itself.
        entry |= PTE_READ | PTE_EXECUTE;
    } else {
        entry |= PTE_READ;
    }
    entry
}

/// Decode the U-mode-facing permissions of a leaf entry.
fn page_permissions_from_entry(entry: u64) -> PagePermissions {
    let mut permissions = PagePermissions::READ;
    if entry & PTE_WRITE != 0 {
        permissions |= PagePermissions::WRITE;
    }
    if entry & PTE_EXECUTE != 0 {
        permissions |= PagePermissions::EXECUTE;
    }
    permissions
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|aligned| aligned & !(align - 1))
}

/// Returns true when `[start, end)` is contained within `[region_start, region_end)`.
fn range_within(start: usize, end: usize, region_start: usize, region_end: usize) -> bool {
    start >= region_start && end <= region_end && start <= end
}

// ── MMU control ──────────────────────────────────────────────────────────

/// Return the address currently programmed into satp (ASID stripped).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) fn current_root_table_address() -> usize {
    let satp: u64;
    unsafe {
        asm!(
            "csrr {satp}, satp",
            satp = out(reg) satp,
            options(nomem, nostack, preserves_flags)
        );
    }
    // PPN occupies satp[43:0]; the root table address is PPN << 12.
    ((satp & PPN_MASK) << 12) as usize
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub(crate) fn current_root_table_address() -> usize {
    0
}

/// Returns true when the MMU is enabled (satp MODE != Bare).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn mmu_enabled() -> bool {
    let satp: u64;
    unsafe {
        asm!(
            "csrr {satp}, satp",
            satp = out(reg) satp,
            options(nomem, nostack, preserves_flags)
        );
    }
    (satp >> 60) != 0
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn mmu_enabled() -> bool {
    false
}

/// Invalidate all cached translations (used after a satp root switch).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn sfence_vma_all() {
    unsafe {
        asm!("sfence.vma", options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn sfence_vma_all() {}

/// Switch satp to a new root table (used when the MMU is already on).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn install_active_root_table_address(satp: u64) {
    unsafe {
        asm!(
            "csrw satp, {satp}",
            satp = in(reg) satp,
            options(nostack, preserves_flags)
        );
    }
    // The root table changed — invalidate all cached translations.
    sfence_vma_all();
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn install_active_root_table_address(_satp: u64) {}

/// Program satp and enable the MMU (cold start).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn install_translation_configuration(satp: u64) {
    unsafe {
        asm!(
            "csrw satp, {satp}",
            satp = in(reg) satp,
            options(nostack, preserves_flags)
        );
    }
    sfence_vma_all();
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn install_translation_configuration(_satp: u64) {}

/// Invalidate cached translations for one virtual address (all ASIDs).
///
/// `sfence.vma rs1, rs2` puts the virtual address in rs1 and the ASID in rs2
/// (x0 for either operand means "all"), so `sfence.vma {va}, zero` invalidates
/// only the target VA across every ASID.  The older `sfence.vma zero, {va}`
/// form was inverted — it placed the VA in the ASID operand and flushed all
/// VAs tagged with that (numeric) ASID, leaving the target page's stale
/// translation behind.  Compare [`asid::sfence_asid`], which correctly uses
/// `sfence.vma zero, {asid}` for an ASID-scoped flush.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn flush_tlb_page(virtual_address: usize) {
    unsafe {
        asm!(
            "sfence.vma {va}, zero",
            va = in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn flush_tlb_page(_virtual_address: usize) {}

// ── Runtime page-table pool ──────────────────────────────────────────────

/// Pages for runtime page tables allocated outside the kernel tables.
const RUNTIME_PT_POOL_PAGES: usize = 32;

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
struct RuntimePtPoolPage([u64; TABLE_ENTRY_COUNT]);

static RUNTIME_PT_POOL_STORE: SyncUnsafeCell<[RuntimePtPoolPage; RUNTIME_PT_POOL_PAGES]> =
    SyncUnsafeCell::new([RuntimePtPoolPage([0; TABLE_ENTRY_COUNT]); RUNTIME_PT_POOL_PAGES]);
static RUNTIME_PT_POOL_BITMAP: AtomicU64 = AtomicU64::new(0);

/// Allocate one zeroed, page-aligned translation-table page.
fn allocate_runtime_pt_page() -> Option<usize> {
    loop {
        let taken = RUNTIME_PT_POOL_BITMAP.load(Ordering::Acquire);
        let mut found = None;
        for page_index in 0..RUNTIME_PT_POOL_PAGES {
            let mask = 1u64 << page_index;
            if taken & mask == 0 {
                found = Some((page_index, mask));
                break;
            }
        }
        let Some((page_index, mask)) = found else {
            return None;
        };
        if RUNTIME_PT_POOL_BITMAP
            .compare_exchange(taken, taken | mask, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let store = RUNTIME_PT_POOL_STORE.get();
            let page = unsafe { &mut (*store)[page_index] };
            page.0 = [0; TABLE_ENTRY_COUNT];
            return Some(page as *mut RuntimePtPoolPage as usize);
        }
        // CAS failed — someone else took a page; retry with a fresh snapshot.
    }
}

/// Split a 1 GiB PGD block into a PMD table of 2 MiB kernel blocks.
fn split_pgd_block(pgd: *mut u64, pgd_index: usize, pgd_entry: u64, pmd_table: usize) {
    let block_base = page_base_address(pgd_entry);
    let pmd = pmd_table as *mut u64;
    for block_index in 0..TABLE_ENTRY_COUNT {
        let address = block_base + block_index * USER_DEMO_REGION_SIZE;
        unsafe {
            ptr::write_volatile(pmd.add(block_index), normal_pmd_block_entry(address));
        }
    }
    unsafe {
        ptr::write_volatile(pgd.add(pgd_index), table_entry(pmd_table));
    }
}

/// Split a 2 MiB PMD block into a PTE table of 4 KiB kernel pages.
fn split_pmd_block(pmd: *mut u64, pmd_index: usize, pmd_entry: u64, pte_table: usize) {
    let block_base = page_base_address(pmd_entry);
    let pte = pte_table as *mut u64;
    for page_index in 0..TABLE_ENTRY_COUNT {
        let address = block_base + page_index * TRANSLATION_GRANULE_SIZE;
        unsafe {
            ptr::write_volatile(pte.add(page_index), normal_pte_page_entry(address));
        }
    }
    unsafe {
        ptr::write_volatile(pmd.add(pmd_index), table_entry(pte_table));
    }
}

/// Walk the live tables and return the PTE table covering `virtual_address`,
/// allocating and splitting intermediate tables as needed.
unsafe fn resolve_pte_table(root: usize, virtual_address: usize) -> Option<*mut u64> {
    let pgd_entry_index = pgd_index(virtual_address);
    let pmd_entry_index = pmd_index(virtual_address);

    let pgd = root as *mut u64;
    let mut pgd_entry = unsafe { ptr::read_volatile(pgd.add(pgd_entry_index)) };
    if pgd_entry & PTE_VALID == 0 {
        let pmd_table = allocate_runtime_pt_page()?;
        unsafe {
            ptr::write_volatile(pgd.add(pgd_entry_index), table_entry(pmd_table));
        }
        pgd_entry = unsafe { ptr::read_volatile(pgd.add(pgd_entry_index)) };
    } else if pgd_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
        // 1 GiB block at PGD — split it before resolving a page inside it.
        let pmd_table = allocate_runtime_pt_page()?;
        split_pgd_block(pgd, pgd_entry_index, pgd_entry, pmd_table);
        pgd_entry = unsafe { ptr::read_volatile(pgd.add(pgd_entry_index)) };
    }

    let pmd = page_base_address(pgd_entry) as *mut u64;
    let mut pmd_entry = unsafe { ptr::read_volatile(pmd.add(pmd_entry_index)) };
    if pmd_entry & PTE_VALID == 0 {
        let pte_table = allocate_runtime_pt_page()?;
        unsafe {
            ptr::write_volatile(pmd.add(pmd_entry_index), table_entry(pte_table));
        }
        pmd_entry = unsafe { ptr::read_volatile(pmd.add(pmd_entry_index)) };
    } else if pmd_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
        // 2 MiB block at PMD — split it before resolving a page inside it.
        let pte_table = allocate_runtime_pt_page()?;
        split_pmd_block(pmd, pmd_entry_index, pmd_entry, pte_table);
        pmd_entry = unsafe { ptr::read_volatile(pmd.add(pmd_entry_index)) };
    }

    Some(page_base_address(pmd_entry) as *mut u64)
}

// ── Install / unmap / device MMIO ────────────────────────────────────────

/// Install (or replace) a U-mode-accessible page in the live tables.
///
/// # Safety
///
/// `physical_address` must be a valid, owned physical frame and
/// `virtual_address` must be a canonical user address.
pub unsafe fn install_user_page(
    virtual_address: usize,
    physical_address: usize,
    permissions: PagePermissions,
) -> Option<()> {
    let root = current_root_table_address();
    if root == 0 {
        return None;
    }
    let pte = unsafe { resolve_pte_table(root, virtual_address)? };
    let pte_entry_index = pte_index(virtual_address);
    unsafe {
        ptr::write_volatile(
            pte.add(pte_entry_index),
            user_page_entry(physical_address, permissions),
        );
    }
    flush_tlb_page(virtual_address);
    Some(())
}

/// Remove a page from the live tables.
///
/// # Safety
///
/// The caller must guarantee the page is not in use by another mapping.
pub unsafe fn unmap_page(virtual_address: usize) -> bool {
    let root = current_root_table_address();
    if root == 0 {
        return false;
    }
    let pgd_entry_index = pgd_index(virtual_address);
    let pmd_entry_index = pmd_index(virtual_address);
    let pte_entry_index = pte_index(virtual_address);

    let pgd = root as *mut u64;
    let pgd_entry = unsafe { ptr::read_volatile(pgd.add(pgd_entry_index)) };
    if pgd_entry & PTE_VALID == 0 {
        return false;
    }
    let pmd = if pgd_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
        // 1 GiB block at PGD — split it before unmapping a page inside it.
        let Some(pmd_table) = allocate_runtime_pt_page() else {
            return false;
        };
        split_pgd_block(pgd, pgd_entry_index, pgd_entry, pmd_table);
        let updated = unsafe { ptr::read_volatile(pgd.add(pgd_entry_index)) };
        page_base_address(updated) as *mut u64
    } else {
        page_base_address(pgd_entry) as *mut u64
    };

    let pmd_entry = unsafe { ptr::read_volatile(pmd.add(pmd_entry_index)) };
    if pmd_entry & PTE_VALID == 0 {
        return false;
    }
    let pte = if pmd_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
        // 2 MiB block at PMD — split it before unmapping a page inside it.
        let Some(pte_table) = allocate_runtime_pt_page() else {
            return false;
        };
        split_pmd_block(pmd, pmd_entry_index, pmd_entry, pte_table);
        let updated = unsafe { ptr::read_volatile(pmd.add(pmd_entry_index)) };
        page_base_address(updated) as *mut u64
    } else {
        page_base_address(pmd_entry) as *mut u64
    };

    if unsafe { ptr::read_volatile(pte.add(pte_entry_index)) } & PTE_VALID == 0 {
        return false;
    }
    unsafe {
        ptr::write_volatile(pte.add(pte_entry_index), 0);
    }
    flush_tlb_page(virtual_address);
    true
}

/// Map a device-MMIO region at a fixed virtual address.
///
/// # Safety
///
/// The caller must guarantee the physical region is a live MMIO range and
/// the virtual address is reserved for device mappings.
pub unsafe fn map_device_mmio_at(
    virtual_address: usize,
    physical_address: u64,
    size: usize,
) -> Option<*mut u8> {
    if size == 0 || virtual_address & (TRANSLATION_GRANULE_SIZE - 1) != 0 {
        return None;
    }
    let root = current_root_table_address();
    if root == 0 {
        return None;
    }
    let page_count = align_up(size, TRANSLATION_GRANULE_SIZE)? / TRANSLATION_GRANULE_SIZE;
    for page_index in 0..page_count {
        let va = virtual_address.checked_add(page_index * TRANSLATION_GRANULE_SIZE)?;
        let pa = physical_address.checked_add((page_index * TRANSLATION_GRANULE_SIZE) as u64)?;
        let pte = unsafe { resolve_pte_table(root, va)? };
        let pte_entry_index = pte_index(va);
        unsafe {
            ptr::write_volatile(pte.add(pte_entry_index), device_page_entry(pa as usize));
        }
        flush_tlb_page(va);
    }
    Some(virtual_address as *mut u8)
}

/// Build a device leaf page descriptor.
fn device_page_entry(physical_address: usize) -> u64 {
    (((physical_address as u64) >> 12) << 10)
        | PTE_VALID
        | PTE_READ
        | PTE_WRITE
        | PTE_ACCESSED
        | PTE_DIRTY
}

/// Build a device 1 GiB block descriptor for the low MMIO window.
fn device_pgd_block_entry(physical_address: usize) -> u64 {
    (((physical_address as u64) >> 12) << 10)
        | PTE_VALID
        | PTE_READ
        | PTE_WRITE
        | PTE_ACCESSED
        | PTE_DIRTY
}

/// Map a device-MMIO region and return its kernel virtual address.
///
/// # Safety
///
/// The caller must guarantee `phys` is a live MMIO range.
pub unsafe fn map_device_mmio(phys: u64, size: usize) -> Option<*mut u8> {
    let end = phys.checked_add(size as u64)?;
    if end <= DEVICE_MMIO_END as u64 {
        // The runtime kernel tables already identity-map the low MMIO window.
        Some(phys as usize as *mut u8)
    } else {
        // High-payload device (e.g. PCI ECAM): map it above the RAM window.
        const HIGH_DEVICE_VA_BASE: usize = 0x2_0000_0000;
        unsafe { map_device_mmio_at(HIGH_DEVICE_VA_BASE, phys, size) }
    }
}

// ── Runtime kernel tables ────────────────────────────────────────────────

/// Validate the heap bounds against the runtime-table memory map.
fn validate_runtime_layout(heap_bounds: (usize, usize)) -> Option<()> {
    let (heap_start, heap_end) = heap_bounds;
    if heap_start > heap_end {
        return None;
    }
    // The kernel heap must live inside the RAM window so the runtime PMD
    // table (and thus the memory manager's physical frames) covers it.
    if heap_start < KERNEL_RAM_BASE || heap_end > KERNEL_RAM_BASE + KERNEL_RAM_LENGTH {
        return None;
    }
    Some(())
}

/// Build the runtime kernel tables (device window + RAM window) into the
/// kernel table statics and record their root address.
unsafe fn install_runtime_kernel_page_tables() -> Option<PreparedRuntimeKernelPageTables> {
    let pgd_ptr = KERNEL_PGD.get();
    let pmd_ptr = KERNEL_PMD.get();

    unsafe {
        *pgd_ptr = PageTable::zeroed();
        *pmd_ptr = PageTable::zeroed();
    }

    let pgd = unsafe { &mut *pgd_ptr };
    // PGD[0..1]: device / MMIO window [0, 2 GiB) as two 1 GiB blocks.
    pgd.0[0] = device_pgd_block_entry(DEVICE_MMIO_BASE);
    pgd.0[1] = device_pgd_block_entry(DEVICE_MMIO_BASE + (1 << 30));
    // PGD[2]: RAM window [0x8000_0000, 0x8800_0000) → PMD table.
    pgd.0[2] = table_entry(pmd_ptr as *mut PageTable as usize);

    let pmd = unsafe { &mut *pmd_ptr };
    // PMD: cover the full RAM window with 2 MiB kernel RWX blocks so the
    // kernel image, stack, and heap are all reachable after the switch.
    let ram_block_count = KERNEL_RAM_LENGTH / USER_DEMO_REGION_SIZE;
    for block_index in 0..ram_block_count {
        let block_address = KERNEL_RAM_BASE + block_index * USER_DEMO_REGION_SIZE;
        pmd.0[block_index] = normal_pmd_block_entry(block_address);
    }

    let window_count = 2usize;
    let mapped_page_count =
        ((DEVICE_MMIO_END - DEVICE_MMIO_BASE) + KERNEL_RAM_LENGTH) / TRANSLATION_GRANULE_SIZE;

    Some(PreparedRuntimeKernelPageTables {
        root_table_address: pgd_ptr as *mut PageTable as usize,
        window_count,
        mapped_page_count,
    })
}

pub fn runtime_prepared_translation(
    address: usize,
    heap_bounds: (usize, usize),
) -> Option<PreparedTranslation> {
    let _ = heap_bounds;

    if (DEVICE_MMIO_BASE..DEVICE_MMIO_END).contains(&address) {
        Some(PreparedTranslation {
            physical_address: address,
            permissions: PagePermissions::READ_WRITE,
        })
    } else if (KERNEL_RAM_BASE..KERNEL_RAM_BASE + KERNEL_RAM_LENGTH).contains(&address) {
        Some(PreparedTranslation {
            physical_address: address,
            permissions: PagePermissions::READ_WRITE_EXECUTE,
        })
    } else {
        None
    }
}

pub fn prepare_runtime_kernel_page_tables(
    heap_bounds: (usize, usize),
) -> Option<PreparedRuntimeKernelPageTables> {
    validate_runtime_layout(heap_bounds)?;

    let prepared = unsafe { install_runtime_kernel_page_tables()? };
    PREPARED_ROOT_TABLE.store(prepared.root_table_address, Ordering::SeqCst);
    PREPARED_WINDOW_COUNT.store(prepared.window_count, Ordering::SeqCst);
    PREPARED_MAPPED_PAGE_COUNT.store(prepared.mapped_page_count, Ordering::SeqCst);
    Some(prepared)
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
    let Some(prepared) = prepared_runtime_kernel_page_tables() else {
        return false;
    };
    current_root_table_address() == prepared.root_table_address
}

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
}

/// Classify a kernel address into a region kind using the linker symbols.
fn classify_kernel_address(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> Option<PlannedRegionKind> {
    let text_start = ptr::addr_of!(__text_start) as usize;
    let text_end = ptr::addr_of!(__text_end) as usize;
    let rodata_start = ptr::addr_of!(__rodata_start) as usize;
    let rodata_end = ptr::addr_of!(__rodata_end) as usize;
    let data_start = ptr::addr_of!(__data_start) as usize;
    let data_end = ptr::addr_of!(__data_end) as usize;
    let bss_start = ptr::addr_of!(__bss_start) as usize;
    let bss_end = ptr::addr_of!(__bss_end) as usize;

    if (text_start..text_end).contains(&virtual_address) {
        Some(PlannedRegionKind::KernelText)
    } else if (rodata_start..rodata_end).contains(&virtual_address) {
        Some(PlannedRegionKind::KernelRodata)
    } else if (data_start..data_end).contains(&virtual_address) {
        Some(PlannedRegionKind::KernelData)
    } else if (bss_start..bss_end).contains(&virtual_address) {
        Some(PlannedRegionKind::KernelBss)
    } else if (heap_bounds.0..heap_bounds.1).contains(&virtual_address) {
        Some(PlannedRegionKind::KernelHeap)
    } else {
        None
    }
}

/// Build one address probe for the active-table diagnostic.
fn probe_kernel_address(
    virtual_address: usize,
    heap_bounds: (usize, usize),
) -> ActiveKernelAddressProbe {
    let translation = runtime_prepared_translation(virtual_address, heap_bounds);
    ActiveKernelAddressProbe {
        virtual_address,
        physical_address: translation
            .map(|translation| translation.physical_address)
            .unwrap_or(0),
        permissions: translation
            .map(|translation| translation.permissions)
            .unwrap_or(PagePermissions::READ),
        kind: classify_kernel_address(virtual_address, heap_bounds)
            .unwrap_or(PlannedRegionKind::KernelText),
    }
}

/// Return the address of the currently executing kernel function as a proxy
/// for the instruction pointer (RISC-V has no architectural PC read).
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn current_instruction_pointer() -> usize {
    // Cast through a raw pointer to avoid the `function-casts-as-integer` lint.
    current_instruction_pointer as *const () as usize
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn current_instruction_pointer() -> usize {
    0
}

/// Read the current stack pointer.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn current_stack_pointer() -> usize {
    let sp: usize;
    unsafe {
        asm!(
            "mv {sp}, sp",
            sp = out(reg) sp,
            options(nomem, nostack, preserves_flags)
        );
    }
    sp
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn current_stack_pointer() -> usize {
    0
}

/// Verify that the running instruction/stack/heap pointers are mapped by the
/// currently active tables.
pub fn active_runtime_kernel_page_table_check(
    heap_bounds: (usize, usize),
) -> Option<ActiveRuntimeKernelPageTableCheck> {
    let root_table_address = current_root_table_address();
    if root_table_address == 0 {
        return None;
    }
    Some(ActiveRuntimeKernelPageTableCheck {
        root_table_address,
        instruction_pointer: probe_kernel_address(current_instruction_pointer(), heap_bounds),
        stack_pointer: probe_kernel_address(current_stack_pointer(), heap_bounds),
        heap_pointer: probe_kernel_address(heap_bounds.0, heap_bounds),
    })
}

// ── Demo user slots ──────────────────────────────────────────────────────

static DEMO_SLOT_TAKEN: AtomicU64 = AtomicU64::new(0);

/// Return the raw pointer to a demo slot region (carved top-down from the
/// end of the RAM window).
fn demo_user_region_ptr(slot_index: usize) -> Option<*mut u8> {
    if slot_index >= USER_DEMO_SLOT_COUNT {
        return None;
    }
    let region = KERNEL_RAM_BASE + KERNEL_RAM_LENGTH - (slot_index + 1) * USER_DEMO_REGION_SIZE;
    Some(region as *mut u8)
}

/// Claim a demo slot index.
fn allocate_demo_user_slot_index() -> Option<usize> {
    loop {
        let taken = DEMO_SLOT_TAKEN.load(Ordering::Acquire);
        let mut found = None;
        for slot_index in 0..USER_DEMO_SLOT_COUNT {
            let mask = 1u64 << slot_index;
            if taken & mask == 0 {
                found = Some((slot_index, mask));
                break;
            }
        }
        let Some((slot_index, mask)) = found else {
            return None;
        };
        if DEMO_SLOT_TAKEN
            .compare_exchange(taken, taken | mask, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(slot_index);
        }
        // CAS failed — someone else took a slot; retry with a fresh snapshot.
    }
}

/// Return a claimed demo slot to the pool.
fn release_demo_user_slot(slot_index: usize) {
    if slot_index < USER_DEMO_SLOT_COUNT {
        DEMO_SLOT_TAKEN.fetch_and(!(1u64 << slot_index), Ordering::AcqRel);
    }
}

/// Make freshly-written user code visible to instruction fetch.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
fn synchronize_user_code(_entry_point: usize, _payload_len: usize) {
    // RISC-V requires an explicit instruction-fence to make stores visible
    // to instruction fetch; sfence.vma covers any stale TLB entries.
    unsafe {
        asm!("fence.i", options(nostack, preserves_flags));
        asm!("sfence.vma", options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
fn synchronize_user_code(_entry_point: usize, _payload_len: usize) {}

pub fn demo_user_slot_layout(slot_index: usize) -> Option<DemoUserSlotLayout> {
    let region_base =
        KERNEL_RAM_BASE + KERNEL_RAM_LENGTH - (slot_index + 1) * USER_DEMO_REGION_SIZE;
    let region = region_base;
    let region_end = region.checked_add(USER_DEMO_REGION_SIZE)?;

    // Verify the region is within kernel RAM.
    if region < KERNEL_RAM_BASE || region_end > KERNEL_RAM_BASE + KERNEL_RAM_LENGTH {
        return None;
    }
    if !region.is_multiple_of(USER_DEMO_REGION_SIZE) {
        return None;
    }

    // Layout: [code/data][regular stack][guard][exception stack][guard]
    let stack_top = region_end & !0xF;
    let stack_bottom = stack_top.checked_sub(USER_DEMO_STACK_SIZE)?;
    let stack_guard_start = stack_bottom.checked_sub(USER_DEMO_STACK_GUARD_SIZE)?;
    let exception_stack_top = stack_guard_start & !0xF;
    let exception_stack_bottom = exception_stack_top.checked_sub(USER_DEMO_EXCEPTION_STACK_SIZE)?;

    Some(DemoUserSlotLayout {
        region_start: region,
        region_length: USER_DEMO_REGION_SIZE,
        entry_point: region + USER_DEMO_CODE_OFFSET,
        stack_bottom,
        stack_top,
        exception_stack_bottom,
        exception_stack_top,
        stack_pointer: stack_top,
    })
}

pub fn allocate_demo_user_slot(
    payload: &[u8],
    entry_offset: usize,
) -> Option<PreparedDemoUserSlot> {
    if payload.is_empty() || entry_offset >= payload.len() {
        return None;
    }
    let code_end = USER_DEMO_CODE_OFFSET.checked_add(payload.len())?;
    if code_end >= USER_DEMO_REGION_SIZE {
        return None;
    }

    let slot_index = allocate_demo_user_slot_index()?;
    let layout = match demo_user_slot_layout(slot_index) {
        Some(layout) => layout,
        None => {
            release_demo_user_slot(slot_index);
            return None;
        }
    };
    let region = match demo_user_region_ptr(slot_index) {
        Some(region) => region,
        None => {
            release_demo_user_slot(slot_index);
            return None;
        }
    };

    unsafe {
        ptr::write_bytes(region.cast::<u8>(), 0, USER_DEMO_REGION_SIZE);
        ptr::copy_nonoverlapping(
            payload.as_ptr(),
            (layout.region_start + USER_DEMO_CODE_OFFSET) as *mut u8,
            payload.len(),
        );
    }
    synchronize_user_code(layout.entry_point, payload.len());

    Some(PreparedDemoUserSlot {
        slot_index,
        layout: DemoUserSlotLayout {
            entry_point: layout.entry_point.checked_add(entry_offset)?,
            ..layout
        },
        payload_len: payload.len(),
        forked: false,
    })
}

pub fn demo_user_slot_count() -> usize {
    USER_DEMO_SLOT_COUNT
}

pub fn prepare_runtime_process_address_space(
    slot: PreparedDemoUserSlot,
) -> Option<PreparedProcessAddressSpace> {
    if PREPARED_ROOT_TABLE.load(Ordering::Relaxed) == 0 {
        return None;
    }

    let mut pgd = Box::new(PageTable::zeroed());
    let mut pmd = Box::new(PageTable::zeroed());
    let mut user_pte = Box::new(PageTable::zeroed());

    unsafe {
        *pgd = *KERNEL_PGD.get();
        *pmd = *KERNEL_PMD.get();
    }

    // Set up the PGD to point to our cloned PMD for the kernel RAM region.
    let kernel_pmd_index = pgd_index(KERNEL_RAM_BASE);
    pgd.0[kernel_pmd_index] = table_entry(pmd.as_ref() as *const PageTable as usize);

    // Reset user slot PMD entries to block mappings, then splice in the
    // active slot's PTE table.
    for slot_index in 0..USER_DEMO_SLOT_COUNT {
        let layout = demo_user_slot_layout(slot_index)?;
        let block_index = pmd_index(layout.region_start);
        pmd.0[block_index] = normal_pmd_block_entry(layout.region_start);
    }
    let active_block_index = pmd_index(slot.region_start());
    pmd.0[active_block_index] = table_entry(user_pte.as_ref() as *const PageTable as usize);

    let image_page_start = align_down(slot.code_start(), TRANSLATION_GRANULE_SIZE);
    let image_page_end = align_up(slot.payload_end(), TRANSLATION_GRANULE_SIZE)?;
    if image_page_start < slot.region_start()
        || image_page_end > slot.exception_stack_guard_start()
        || image_page_end > slot.region_end()
    {
        return None;
    }

    for page_index in 0..USER_DEMO_REGION_PAGE_COUNT {
        let page_address = slot
            .region_start()
            .checked_add(page_index.checked_mul(TRANSLATION_GRANULE_SIZE)?)?;
        user_pte.0[page_index] = if (image_page_start..image_page_end).contains(&page_address) {
            user_page_entry(page_address, PagePermissions::READ_EXECUTE)
        } else if (slot.stack_bottom()..slot.stack_top()).contains(&page_address)
            || (slot.exception_stack_bottom()..slot.exception_stack_top()).contains(&page_address)
        {
            user_page_entry(page_address, PagePermissions::READ_WRITE)
        } else {
            normal_pte_page_entry(page_address)
        };
    }

    let image_page_count = image_page_end
        .checked_sub(image_page_start)?
        .checked_div(TRANSLATION_GRANULE_SIZE)?;
    let stack_page_count = slot
        .stack_top()
        .checked_sub(slot.stack_bottom())?
        .checked_add(
            slot.exception_stack_top()
                .checked_sub(slot.exception_stack_bottom())?,
        )?
        .checked_div(TRANSLATION_GRANULE_SIZE)?;

    let asid = allocate_asid();

    Some(PreparedProcessAddressSpace {
        pgd,
        pmd,
        user_pte,
        slot,
        image_page_count,
        stack_page_count,
        asid,
    })
}

// ── Activation ───────────────────────────────────────────────────────────

pub fn activate_prepared_runtime_kernel_page_tables() -> Option<ActivatedRuntimeKernelPageTables> {
    let prepared = prepared_runtime_kernel_page_tables()?;
    let previous_root_table_address = current_root_table_address();
    let already_active = prepared_runtime_kernel_page_tables_active();

    if !already_active {
        let satp = satp_with_asid((prepared.root_table_address as u64) >> 12, 0); // ASID 0 = kernel
        if mmu_enabled() {
            install_active_root_table_address(satp);
        } else {
            install_translation_configuration(satp);
        }
    }

    Some(ActivatedRuntimeKernelPageTables {
        previous_root_table_address,
        active_root_table_address: current_root_table_address(),
        window_count: prepared.window_count,
        mapped_page_count: prepared.mapped_page_count,
        already_active,
    })
}

fn activate_prepared_process_address_space_impl(
    address_space: &PreparedProcessAddressSpace,
) -> Option<ActivatedProcessAddressSpace> {
    let previous_root_table_address = current_root_table_address();
    let already_active = previous_root_table_address == address_space.root_table_address();

    if !already_active {
        let satp = satp_with_asid(
            (address_space.root_table_address() as u64) >> 12,
            address_space.asid,
        );
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        unsafe {
            asm!(
                "csrw satp, {satp}",
                satp = in(reg) satp,
                options(nomem, nostack, preserves_flags)
            );
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        let _ = satp;
        sfence_vma_all();
    }

    Some(ActivatedProcessAddressSpace {
        previous_root_table_address,
        active_root_table_address: current_root_table_address(),
        mapped_page_count: address_space.mapped_page_count(),
        kernel_page_count: address_space.kernel_page_count(),
        user_page_count: address_space.user_page_count(),
        table_page_count: address_space.table_page_count(),
        already_active,
    })
}

// ── PreparedDemoUserSlot impl ────────────────────────────────────────────

impl PreparedDemoUserSlot {
    pub fn region_start(&self) -> usize {
        self.layout.region_start
    }

    pub fn region_end(&self) -> usize {
        self.layout.region_start + self.layout.region_length
    }

    pub fn region_length(&self) -> usize {
        self.layout.region_length
    }

    pub fn code_start(&self) -> usize {
        self.layout.entry_point - USER_DEMO_CODE_OFFSET
    }

    pub fn entry_point(&self) -> usize {
        self.layout.entry_point
    }

    pub fn stack_pointer(&self) -> usize {
        self.layout.stack_pointer
    }

    pub fn stack_bottom(&self) -> usize {
        self.layout.stack_bottom
    }

    pub fn stack_top(&self) -> usize {
        self.layout.stack_top
    }

    pub fn stack_guard_start(&self) -> usize {
        self.layout.stack_bottom - USER_DEMO_STACK_GUARD_SIZE
    }

    pub fn stack_guard_end(&self) -> usize {
        self.layout.stack_bottom
    }

    pub fn exception_stack_bottom(&self) -> usize {
        self.layout.exception_stack_bottom
    }

    pub fn exception_stack_top(&self) -> usize {
        self.layout.exception_stack_top
    }

    pub fn exception_stack_guard_start(&self) -> usize {
        self.layout.exception_stack_bottom - USER_DEMO_EXCEPTION_STACK_GUARD_SIZE
    }

    pub fn exception_stack_guard_end(&self) -> usize {
        self.layout.exception_stack_bottom
    }

    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub fn payload_end(&self) -> usize {
        self.code_start() + USER_DEMO_CODE_OFFSET + self.payload_len
    }

    /// Write bytes into the user stack or exception stack region.
    pub fn write_bytes(&mut self, address: usize, bytes: &[u8]) -> Option<()> {
        let end = address.checked_add(bytes.len())?;
        if !range_within(address, end, self.stack_bottom(), self.stack_top())
            && !range_within(
                address,
                end,
                self.exception_stack_bottom(),
                self.exception_stack_top(),
            )
        {
            return None;
        }

        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
        }
        Some(())
    }

    pub fn set_stack_pointer(&mut self, stack_pointer: usize) -> Option<()> {
        if stack_pointer < self.stack_bottom() || stack_pointer > self.stack_top() {
            return None;
        }
        if stack_pointer & 0xF != 0 {
            return None;
        }

        self.layout.stack_pointer = stack_pointer;
        Some(())
    }

    pub fn exception_stack_pointer(&self) -> Option<usize> {
        Some(self.exception_stack_top())
    }

    pub fn thread_start(&self) -> UserThreadStart {
        UserThreadStart::new(
            self.entry_point(),
            self.stack_pointer(),
            self.exception_stack_pointer(),
        )
    }
}

impl Drop for PreparedDemoUserSlot {
    fn drop(&mut self) {
        if !self.forked {
            release_demo_user_slot(self.slot_index);
        }
    }
}

// ── PreparedProcessAddressSpace impl ─────────────────────────────────────

impl PreparedProcessAddressSpace {
    pub fn root_table_address(&self) -> usize {
        self.pgd.as_ref() as *const PageTable as usize
    }

    /// The process owns three tables: the cloned PGD, the cloned PMD, and
    /// the active slot's user PTE table.
    pub fn table_page_count(&self) -> usize {
        3
    }

    pub fn mapped_page_count(&self) -> usize {
        self.kernel_page_count() + self.user_page_count()
    }

    /// The runtime tables map the kernel RAM window as 2 MiB blocks; report
    /// the equivalent 4 KiB page count.
    pub fn kernel_page_count(&self) -> usize {
        KERNEL_RAM_LENGTH / TRANSLATION_GRANULE_SIZE
    }

    pub fn user_page_count(&self) -> usize {
        self.image_page_count + self.stack_page_count
    }

    pub fn image_page_count(&self) -> usize {
        self.image_page_count
    }

    pub fn stack_page_count(&self) -> usize {
        self.stack_page_count
    }

    pub fn root_entry_count(&self) -> usize {
        self.pgd
            .0
            .iter()
            .filter(|entry| **entry & PTE_VALID != 0)
            .count()
    }

    pub fn second_level_entry_count(&self) -> usize {
        self.pmd
            .0
            .iter()
            .filter(|entry| **entry & PTE_VALID != 0)
            .count()
    }

    pub fn leaf_table_count(&self) -> usize {
        self.user_pte
            .0
            .iter()
            .filter(|entry| **entry & PTE_VALID != 0)
            .count()
    }

    /// Translate a user virtual address through the process tables.
    pub fn translate_user(&self, address: usize) -> Option<PreparedTranslation> {
        if pgd_index(address) != pgd_index(KERNEL_RAM_BASE) {
            return None;
        }
        let pgd_entry = self.pgd.0[pgd_index(address)];
        if pgd_entry & PTE_VALID == 0 {
            return None;
        }
        let pmd_entry = self.pmd.0[pmd_index(address)];
        if pmd_entry & PTE_VALID == 0 {
            return None;
        }
        if pmd_entry & (PTE_READ | PTE_WRITE | PTE_EXECUTE) != 0 {
            // Block mapping (kernel) — not a user leaf page.
            return None;
        }
        let pte_table = page_base_address(pmd_entry) as *const u64;
        let pte_entry = unsafe { ptr::read_volatile(pte_table.add(pte_index(address))) };
        if pte_entry & PTE_VALID == 0 {
            return None;
        }
        let physical_address = page_base_address(pte_entry) + (address & 0xFFF);
        Some(PreparedTranslation {
            physical_address,
            permissions: page_permissions_from_entry(pte_entry),
        })
    }

    pub fn user_page_va_range(&self) -> Option<(usize, usize)> {
        Some((self.slot.region_start(), self.slot.region_end()))
    }

    pub fn user_thread_start(&self) -> UserThreadStart {
        self.slot.thread_start()
    }

    pub fn activate(&self) -> Option<ActivatedProcessAddressSpace> {
        activate_prepared_process_address_space_impl(self)
    }

    /// Report every present user page as `(virtual_address, physical_address, permissions)`.
    pub fn user_page_entries(&self) -> Vec<(usize, usize, PagePermissions)> {
        let mut entries = Vec::new();
        for page_index in 0..USER_DEMO_REGION_PAGE_COUNT {
            let entry = self.user_pte.0[page_index];
            if entry & PTE_VALID == 0 {
                continue;
            }
            let va = self.slot.region_start() + page_index * TRANSLATION_GRANULE_SIZE;
            let pa = page_base_address(entry);
            entries.push((va, pa, page_permissions_from_entry(entry)));
        }
        entries
    }

    /// Clone the address space for `fork`, returning the child plus the
    /// shared (copy-on-write) and child page lists.
    pub fn fork_clone(
        &mut self,
    ) -> Option<(
        PreparedProcessAddressSpace,
        Vec<(usize, usize, PagePermissions)>,
        Vec<(usize, usize, PagePermissions)>,
    )> {
        // Clone the full table hierarchy.
        let mut child_pgd = Box::new(PageTable::zeroed());
        let mut child_pmd = Box::new(PageTable::zeroed());
        let mut child_pte = Box::new(PageTable::zeroed());
        *child_pgd = *self.pgd;
        *child_pmd = *self.pmd;
        *child_pte = *self.user_pte;

        // User-writable pages become copy-on-write in the parent; the child
        // keeps write access.  Shared read-only (code) pages map into both.
        let mut shared_pages = Vec::new();
        let mut all_child_pages = Vec::new();
        for page_index in 0..USER_DEMO_REGION_PAGE_COUNT {
            let entry = self.user_pte.0[page_index];
            if entry & PTE_VALID == 0 {
                continue;
            }
            let va = self.slot.region_start() + page_index * TRANSLATION_GRANULE_SIZE;
            let pa = page_base_address(entry);
            let permissions = page_permissions_from_entry(entry);
            if permissions.contains(PagePermissions::WRITE) {
                // Parent loses write access (copy-on-write).  Child keeps RW.
                let read_only = if permissions.contains(PagePermissions::EXECUTE) {
                    PagePermissions::READ_EXECUTE
                } else {
                    PagePermissions::READ
                };
                self.user_pte.0[page_index] = user_page_entry(pa, read_only);
                // The parent's live page table is active while fork runs;
                // flush the stale (previously writable) TLB entry so the
                // read-only CoW mapping takes effect immediately — otherwise
                // the parent keeps writing the shared frame through a stale
                // RW TLB entry.
                flush_tlb_page(va);
                shared_pages.push((va, pa, read_only));
                all_child_pages.push((va, pa, permissions));
            } else {
                all_child_pages.push((va, pa, permissions));
            }
        }

        let child_asid = allocate_asid();

        // Both parent and child keep the slot allocated for the kernel's
        // lifetime (they share the underlying region).
        let mut child_slot = self.slot.clone();
        child_slot.forked = true;
        self.slot.forked = true;

        let child = PreparedProcessAddressSpace {
            pgd: child_pgd,
            pmd: child_pmd,
            user_pte: child_pte,
            slot: child_slot,
            image_page_count: self.image_page_count,
            stack_page_count: self.stack_page_count,
            asid: child_asid,
        };

        Some((child, shared_pages, all_child_pages))
    }

    /// Report the physical frame backing a user page in the active slot's PTE
    /// table WITHOUT modifying the live hardware page-table entry.
    ///
    /// During fork the parent's shared pages keep their present read-only
    /// (copy-on-write) mapping in the live table; this function only reports
    /// the referenced frame so callers can transfer refcount ownership.
    /// Unlike the x86_64 variant there is no separate software page list to
    /// prune, so the hardware PTE is left untouched — zeroing it would make
    /// the parent's own mapping not-present and break the CoW contract.
    pub fn remove_user_page_frame(&mut self, virtual_address: usize) -> Option<usize> {
        if virtual_address < self.slot.region_start() || virtual_address >= self.slot.region_end() {
            return None;
        }
        let page_index = (virtual_address - self.slot.region_start()) / TRANSLATION_GRANULE_SIZE;
        if page_index >= USER_DEMO_REGION_PAGE_COUNT {
            return None;
        }
        let entry = self.user_pte.0[page_index];
        if entry & PTE_VALID == 0 {
            return None;
        }
        Some(page_base_address(entry))
    }
}

impl Drop for PreparedProcessAddressSpace {
    fn drop(&mut self) {
        free_asid(self.asid);
    }
}
