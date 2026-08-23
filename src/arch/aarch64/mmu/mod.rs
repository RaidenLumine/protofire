//! src/arch/aarch64/mmu/mod.rs
//! AArch64 4 KiB-granule translation for the runtime kernel page tables and
//! per-process demo user address spaces.
//!
//! The runtime tables use three levels: L1 (1 GiB blocks) → L2 (2 MiB blocks)
//! → L3 (4 KiB pages).  TTBR0_EL1 points at the L1 table and embeds the
//! process ASID in bits [63:48].
//!
//! Memory map (QEMU `virt`, matching the AArch64 kernel linker script):
//!   [0x0000_0000, 0x4000_0000)  L1[0]  device / MMIO window (GIC, PL011, virtio)
//!   [0x4000_0000, 0x8000_0000)  L1[1]  RAM window (kernel text + demo user slots)
//!   [0x8000_0000, ...)                 unused by the runtime tables

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::UserThreadStart;
use crate::util::sync_unsafe_cell::SyncUnsafeCell;

mod asid;

use asid::{allocate_asid, free_asid, ttbr0_with_asid};

// ── Constants ────────────────────────────────────────────────────────────

/// When true, SCTLR_EL1.SPAN is programmed during translation configuration
/// and the kernel auto-sets PSTATE.PAN on EL0→EL1 entry.  See
/// [`crate::arch::aarch64::user_access`].
pub const SPAN_ENABLED: bool = true;

/// Size of one translation granule (4 KiB).
const TRANSLATION_GRANULE_SIZE: usize = 4096;

/// Number of entries in every translation table.
const TABLE_ENTRY_COUNT: usize = 512;

/// RAM window covered by the runtime tables (the kernel image and the demo
/// user slots both live here).
const KERNEL_TEXT_BASE: usize = 0x4000_0000;
const KERNEL_TEXT_END: usize = 0x8000_0000;

/// Low identity-mapped MMIO window (GIC, PL011, virtio, ...).
const DEVICE_MMIO_BASE: usize = 0x0000_0000;
const DEVICE_MMIO_END: usize = 0x4000_0000;

/// Number of preallocated 2 MiB demo user slots.
const USER_DEMO_SLOT_COUNT: usize = 8;

/// Each demo slot occupies one L2 block (2 MiB).
const USER_DEMO_REGION_SIZE: usize = 0x20_0000;
const USER_DEMO_REGION_PAGE_COUNT: usize = USER_DEMO_REGION_SIZE / TRANSLATION_GRANULE_SIZE;

/// Per-slot carve-out sizes.
const USER_DEMO_STACK_SIZE: usize = 0x4_0000; // 256 KiB
const USER_DEMO_STACK_GUARD_SIZE: usize = 0x1_0000; // 64 KiB
const USER_DEMO_EXCEPTION_STACK_SIZE: usize = 0x4_0000; // 256 KiB
const USER_DEMO_EXCEPTION_STACK_GUARD_SIZE: usize = 0x1_0000; // 64 KiB

/// Entry-point offset within the code region of a slot.
const USER_DEMO_CODE_OFFSET: usize = 0x1000;

// ── Translation descriptor bits ──────────────────────────────────────────

/// Table descriptor: bit 0 valid, bit 1 = 0 (next-level table).
const DESCRIPTOR_TABLE: u64 = 0x1;
/// Block / page descriptor: bit 0 valid, bit 1 = 1 (leaf).
const DESCRIPTOR_BLOCK_PAGE: u64 = 0x3;

/// AP[2:1] encodings (EL1&0 translation regime).
const AP_EL1_RW: u64 = 0b01 << 6; // EL1 read/write, EL0 no access
const AP_EL1_EL0_RW: u64 = 0b00 << 6; // EL1 & EL0 read/write
const AP_EL1_EL0_RO: u64 = 0b10 << 6; // EL1 & EL0 read-only

/// Shareability, access flag, non-global.
const SH_OUTER: u64 = 0b11 << 8;
const AF_ACCESS: u64 = 1 << 10;
const NG_NOT_GLOBAL: u64 = 1 << 11;

/// Execute-never bits.
const PXN_EXECUTE_NEVER: u64 = 1 << 53;
const UXN_EXECUTE_NEVER: u64 = 1 << 54;

/// MAIR_EL1 attribute indices (see MAIR_EL1_CONFIG).
const MAIR_ATTR_NORMAL: u64 = 0 << 2;
const MAIR_ATTR_DEVICE: u64 = 1 << 2;

/// TCR_EL1: 4 KiB granules, three-level walk starting at L1, 512 GiB VA
/// space (T0SZ = 25), 48-bit physical addresses (IPS = 0b101), inner
/// shareable, WBWA cache policy, TTBR1 disabled.
const TCR_EL1_CONFIG: u64 =
    (0b101 << 32) | (1 << 23) | (0b011001) | (0b11 << 12) | (0b01 << 10) | (0b01 << 8);

/// MAIR_EL1: attr 0 = Normal Write-Back Read-Allocate Write-Allocate,
/// attr 1 = Device-nGnRnE.
const MAIR_EL1_CONFIG: u64 = 0x0000_00FF;

// ── Types ────────────────────────────────────────────────────────────────

/// A single 512-entry translation table (one 4 KiB page).
#[derive(Debug, Clone, Copy)]
pub struct TranslationTable(pub [u64; TABLE_ENTRY_COUNT]);

impl TranslationTable {
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
    l1: Box<TranslationTable>,
    l2: Box<TranslationTable>,
    user_l3: Box<TranslationTable>,
    slot: PreparedDemoUserSlot,
    image_page_count: usize,
    stack_page_count: usize,
    /// Address Space ID for this process, embedded in TTBR0_EL1[63:48].
    /// Zero means no ASID assigned (host-mode fallback).
    asid: u64,
}

// ── Kernel translation tables ────────────────────────────────────────────

static KERNEL_L1_TABLE: SyncUnsafeCell<TranslationTable> =
    SyncUnsafeCell::new(TranslationTable::zeroed());
static KERNEL_L2_TABLE: SyncUnsafeCell<TranslationTable> =
    SyncUnsafeCell::new(TranslationTable::zeroed());

static PREPARED_ROOT_TABLE: AtomicUsize = AtomicUsize::new(0);
static PREPARED_WINDOW_COUNT: AtomicUsize = AtomicUsize::new(0);
static PREPARED_MAPPED_PAGE_COUNT: AtomicUsize = AtomicUsize::new(0);

// ── Entry-point helpers ──────────────────────────────────────────────────

/// Build a next-level-table descriptor for `address`.
fn table_entry(address: usize) -> u64 {
    ((address as u64) & 0x0000_FFFF_FFFF_F000) | DESCRIPTOR_TABLE
}

/// Convert a virtual address to its L2 block index within the RAM window.
fn user_block_index(virtual_address: usize) -> Option<usize> {
    if virtual_address < KERNEL_TEXT_BASE || virtual_address >= KERNEL_TEXT_END {
        return None;
    }
    let block_index =
        (virtual_address - KERNEL_TEXT_BASE) / (TRANSLATION_GRANULE_SIZE * TABLE_ENTRY_COUNT);
    if block_index >= TABLE_ENTRY_COUNT {
        return None;
    }
    Some(block_index)
}

/// Build a leaf page descriptor for an EL0-accessible page with the given
/// permissions.  The physical address is the virtual address (the demo
/// model maps user pages identity-mapped).
fn user_l3_page_entry(virtual_address: usize, permissions: PagePermissions) -> u64 {
    user_page_entry(virtual_address, permissions)
}

/// Build a leaf page descriptor for an EL0-accessible page at `physical_address`.
fn user_page_entry(physical_address: usize, permissions: PagePermissions) -> u64 {
    let address = (physical_address as u64) & 0x0000_FFFF_FFFF_F000;
    let (ap, uxn) = if permissions.contains(PagePermissions::WRITE) {
        // User-writable: EL1 & EL0 read/write, never executable from EL0.
        (AP_EL1_EL0_RW, UXN_EXECUTE_NEVER)
    } else if permissions.contains(PagePermissions::EXECUTE) {
        // Executable: read-only at both EL1 and EL0 so user code cannot
        // rewrite itself.
        (AP_EL1_EL0_RO, 0)
    } else {
        (AP_EL1_EL0_RO, UXN_EXECUTE_NEVER)
    };
    address
        | DESCRIPTOR_BLOCK_PAGE
        | ap
        | SH_OUTER
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | uxn
        | MAIR_ATTR_NORMAL
}

/// Build a leaf page descriptor for a kernel-only (EL1) page.
fn normal_l3_page_entry(virtual_address: usize) -> u64 {
    let address = (virtual_address as u64) & 0x0000_FFFF_FFFF_F000;
    address
        | DESCRIPTOR_BLOCK_PAGE
        | AP_EL1_RW
        | SH_OUTER
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | PXN_EXECUTE_NEVER
        | UXN_EXECUTE_NEVER
        | MAIR_ATTR_NORMAL
}

/// Build a kernel-only 2 MiB block descriptor used for non-active slots in a
/// process address space.
fn normal_l2_block_entry(virtual_address: usize) -> u64 {
    let address = (virtual_address as u64) & 0x0000_FFFF_FFE0_0000;
    address
        | DESCRIPTOR_BLOCK_PAGE
        | AP_EL1_RW
        | SH_OUTER
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | PXN_EXECUTE_NEVER
        | UXN_EXECUTE_NEVER
        | MAIR_ATTR_NORMAL
}

/// Build a kernel RWX 2 MiB block descriptor (runtime kernel tables).
fn kernel_l2_block_entry(physical_address: usize) -> u64 {
    let address = (physical_address as u64) & 0x0000_FFFF_FFE0_0000;
    address
        | DESCRIPTOR_BLOCK_PAGE
        | AP_EL1_RW
        | SH_OUTER
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | MAIR_ATTR_NORMAL
}

/// Build a device 1 GiB block descriptor for the low MMIO window.
fn device_l1_block_entry(physical_address: usize) -> u64 {
    let address = (physical_address as u64) & 0x0000_FFFF_C000_0000;
    address
        | DESCRIPTOR_BLOCK_PAGE
        | AP_EL1_RW
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | PXN_EXECUTE_NEVER
        | UXN_EXECUTE_NEVER
        | MAIR_ATTR_DEVICE
}

/// Build a device leaf page descriptor.
fn device_page_entry(physical_address: usize) -> u64 {
    let address = (physical_address as u64) & 0x0000_FFFF_FFFF_F000;
    address
        | DESCRIPTOR_BLOCK_PAGE
        | AP_EL1_RW
        | AF_ACCESS
        | NG_NOT_GLOBAL
        | PXN_EXECUTE_NEVER
        | UXN_EXECUTE_NEVER
        | MAIR_ATTR_DEVICE
}

/// Decode the EL0-facing permissions of a leaf entry.
fn page_permissions_from_entry(entry: u64) -> PagePermissions {
    let ap = (entry >> 6) & 0x3;
    let uxn = (entry >> 54) & 0x1;
    let mut permissions = PagePermissions::READ;
    if ap == 0b00 {
        permissions |= PagePermissions::WRITE;
    }
    if uxn == 0 {
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

/// Return the address currently programmed into TTBR0_EL1 (ASID stripped).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) fn current_root_table_address() -> usize {
    let ttbr0: u64;
    unsafe {
        asm!(
            "mrs {ttbr0}, TTBR0_EL1",
            ttbr0 = out(reg) ttbr0,
            options(nomem, nostack, preserves_flags)
        );
    }
    (ttbr0 & 0x0000_FFFF_FFFF_FFFE) as usize
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(crate) fn current_root_table_address() -> usize {
    0
}

/// Returns true when the MMU is enabled (SCTLR_EL1.M).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn mmu_enabled() -> bool {
    let sctlr: u64;
    unsafe {
        asm!(
            "mrs {sctlr}, SCTLR_EL1",
            sctlr = out(reg) sctlr,
            options(nomem, nostack, preserves_flags)
        );
    }
    sctlr & 1 != 0
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn mmu_enabled() -> bool {
    false
}

/// Switch TTBR0_EL1 to a new root table (used when the MMU is already on).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn install_active_root_table_address(ttbr0: u64) {
    unsafe {
        asm!(
            "msr TTBR0_EL1, {ttbr0}",
            "isb",
            ttbr0 = in(reg) ttbr0,
            options(nostack, preserves_flags)
        );
        // The root table changed — invalidate all cached translations.
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn install_active_root_table_address(_ttbr0: u64) {}

/// Program TCR_EL1 / MAIR_EL1 / TTBR0_EL1 and enable the MMU (cold start).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn install_translation_configuration(ttbr0: u64) {
    unsafe {
        asm!(
            "msr TCR_EL1, {tcr}",
            tcr = in(reg) TCR_EL1_CONFIG,
            options(nostack, preserves_flags)
        );
        asm!(
            "msr MAIR_EL1, {mair}",
            mair = in(reg) MAIR_EL1_CONFIG,
            options(nostack, preserves_flags)
        );
        asm!(
            "msr TTBR0_EL1, {ttbr0}",
            ttbr0 = in(reg) ttbr0,
            options(nostack, preserves_flags)
        );
        asm!("isb", options(nostack, preserves_flags));

        let sctlr: u64;
        asm!(
            "mrs {sctlr}, SCTLR_EL1",
            sctlr = out(reg) sctlr,
            options(nomem, nostack, preserves_flags)
        );
        let mut next = sctlr | 1; // M: enable the MMU
        if SPAN_ENABLED {
            next |= 1 << 23; // SPAN: set PSTATE.PAN on EL0→EL1 entry
        }
        asm!(
            "msr SCTLR_EL1, {sctlr}",
            sctlr = in(reg) next,
            options(nostack, preserves_flags)
        );
        asm!("isb", options(nostack, preserves_flags));
        asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn install_translation_configuration(_ttbr0: u64) {}

/// Invalidate cached translations for one virtual address (all ASIDs).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn flush_tlb_page(virtual_address: usize) {
    unsafe {
        asm!(
            "tlbi vaale1is, {va}",
            va = in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
        asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
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

/// Split a 1 GiB L1 block into an L2 table of 2 MiB kernel blocks.
fn split_l1_block(l1: *mut u64, l1_index: usize, l1_entry: u64, l2_table: usize) {
    let block_base = (l1_entry & 0x0000_FFFF_C000_0000) as usize;
    let l2 = l2_table as *mut u64;
    for block_index in 0..TABLE_ENTRY_COUNT {
        let address = block_base + block_index * USER_DEMO_REGION_SIZE;
        unsafe {
            ptr::write_volatile(l2.add(block_index), kernel_l2_block_entry(address));
        }
    }
    unsafe {
        ptr::write_volatile(l1.add(l1_index), table_entry(l2_table));
    }
}

/// Split a 2 MiB L2 block into an L3 table of 4 KiB kernel pages.
fn split_l2_block(l2: *mut u64, l2_index: usize, l2_entry: u64, l3_table: usize) {
    let block_base = (l2_entry & 0x0000_FFFF_FFE0_0000) as usize;
    let l3 = l3_table as *mut u64;
    for page_index in 0..TABLE_ENTRY_COUNT {
        let address = block_base + page_index * TRANSLATION_GRANULE_SIZE;
        unsafe {
            ptr::write_volatile(l3.add(page_index), normal_l3_page_entry(address));
        }
    }
    unsafe {
        ptr::write_volatile(l2.add(l2_index), table_entry(l3_table));
    }
}

/// Walk the live tables and return the L3 table covering `virtual_address`,
/// allocating and splitting intermediate tables as needed.
unsafe fn resolve_l3_table(root: usize, virtual_address: usize) -> Option<*mut u64> {
    let l1_index = (virtual_address >> 30) & 0x1FF;
    let l2_index = (virtual_address >> 21) & 0x1FF;

    let l1 = root as *mut u64;
    let mut l1_entry = unsafe { ptr::read_volatile(l1.add(l1_index)) };
    if l1_entry & 0x1 == 0 {
        let l2_table = allocate_runtime_pt_page()?;
        unsafe {
            ptr::write_volatile(l1.add(l1_index), table_entry(l2_table));
        }
        l1_entry = unsafe { ptr::read_volatile(l1.add(l1_index)) };
    } else if l1_entry & 0x3 == 0x3 {
        let l2_table = allocate_runtime_pt_page()?;
        split_l1_block(l1, l1_index, l1_entry, l2_table);
        l1_entry = unsafe { ptr::read_volatile(l1.add(l1_index)) };
    }

    let l2 = (l1_entry & 0x0000_FFFF_FFFF_F000) as *mut u64;
    let mut l2_entry = unsafe { ptr::read_volatile(l2.add(l2_index)) };
    if l2_entry & 0x1 == 0 {
        let l3_table = allocate_runtime_pt_page()?;
        unsafe {
            ptr::write_volatile(l2.add(l2_index), table_entry(l3_table));
        }
        l2_entry = unsafe { ptr::read_volatile(l2.add(l2_index)) };
    } else if l2_entry & 0x3 == 0x3 {
        let l3_table = allocate_runtime_pt_page()?;
        split_l2_block(l2, l2_index, l2_entry, l3_table);
        l2_entry = unsafe { ptr::read_volatile(l2.add(l2_index)) };
    }

    Some((l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64)
}

// ── Install / unmap / device MMIO ────────────────────────────────────────

/// Install (or replace) an EL0-accessible page in the live tables.
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
    let l3 = unsafe { resolve_l3_table(root, virtual_address)? };
    let l3_index = (virtual_address >> 12) & 0x1FF;
    unsafe {
        ptr::write_volatile(
            l3.add(l3_index),
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
    let l1_index = (virtual_address >> 30) & 0x1FF;
    let l2_index = (virtual_address >> 21) & 0x1FF;
    let l3_index = (virtual_address >> 12) & 0x1FF;

    let l1 = root as *mut u64;
    let l1_entry = unsafe { ptr::read_volatile(l1.add(l1_index)) };
    if l1_entry & 0x1 == 0 {
        return false;
    }
    let l2 = if l1_entry & 0x3 == 0x3 {
        // 1 GiB block at L1 — split it before unmapping a page inside it.
        let Some(l2_table) = allocate_runtime_pt_page() else {
            return false;
        };
        split_l1_block(l1, l1_index, l1_entry, l2_table);
        let updated = unsafe { ptr::read_volatile(l1.add(l1_index)) };
        (updated & 0x0000_FFFF_FFFF_F000) as *mut u64
    } else {
        (l1_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
    };

    let l2_entry = unsafe { ptr::read_volatile(l2.add(l2_index)) };
    if l2_entry & 0x1 == 0 {
        return false;
    }
    let l3 = if l2_entry & 0x3 == 0x3 {
        // 2 MiB block at L2 — split it before unmapping a page inside it.
        let Some(l3_table) = allocate_runtime_pt_page() else {
            return false;
        };
        split_l2_block(l2, l2_index, l2_entry, l3_table);
        let updated = unsafe { ptr::read_volatile(l2.add(l2_index)) };
        (updated & 0x0000_FFFF_FFFF_F000) as *mut u64
    } else {
        (l2_entry & 0x0000_FFFF_FFFF_F000) as *mut u64
    };

    if unsafe { ptr::read_volatile(l3.add(l3_index)) } & 0x1 == 0 {
        return false;
    }
    unsafe {
        ptr::write_volatile(l3.add(l3_index), 0);
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
        let l3 = unsafe { resolve_l3_table(root, va)? };
        let l3_index = (va >> 12) & 0x1FF;
        unsafe {
            ptr::write_volatile(l3.add(l3_index), device_page_entry(pa as usize));
        }
        flush_tlb_page(va);
    }
    Some(virtual_address as *mut u8)
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
    // The kernel heap must live inside the RAM window so the runtime L2
    // table (and thus the memory manager's physical frames) covers it.
    if heap_start < KERNEL_TEXT_BASE || heap_end > KERNEL_TEXT_END {
        return None;
    }
    Some(())
}

/// Build the runtime kernel tables (device window + RAM window) into the
/// kernel table statics and record their root address.
unsafe fn install_runtime_kernel_page_tables() -> Option<PreparedRuntimeKernelPageTables> {
    let l1_ptr = KERNEL_L1_TABLE.get();
    let l2_ptr = KERNEL_L2_TABLE.get();

    unsafe {
        *l1_ptr = TranslationTable::zeroed();
        *l2_ptr = TranslationTable::zeroed();
    }

    let l1 = unsafe { &mut *l1_ptr };
    // L1[0]: device / MMIO window [0, 1 GiB) as a single 1 GiB block.
    l1.0[0] = device_l1_block_entry(DEVICE_MMIO_BASE);
    // L1[1]: RAM window [1 GiB, 2 GiB) → L2 table.
    l1.0[1] = table_entry(l2_ptr as *mut TranslationTable as usize);

    let l2 = unsafe { &mut *l2_ptr };
    // L2: cover the full RAM window with 2 MiB kernel RWX blocks so the
    // kernel image, stack, and heap are all reachable after the switch.
    for block_index in 0..TABLE_ENTRY_COUNT {
        let block_address = KERNEL_TEXT_BASE + block_index * USER_DEMO_REGION_SIZE;
        l2.0[block_index] = kernel_l2_block_entry(block_address);
    }

    let window_count = 2usize;
    let mapped_page_count = 2 * (KERNEL_TEXT_END - KERNEL_TEXT_BASE) / TRANSLATION_GRANULE_SIZE;

    Some(PreparedRuntimeKernelPageTables {
        root_table_address: l1_ptr as *mut TranslationTable as usize,
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
    } else if (KERNEL_TEXT_BASE..KERNEL_TEXT_END).contains(&address) {
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
/// for the instruction pointer (AArch64 has no architectural PC read).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_instruction_pointer() -> usize {
    current_instruction_pointer as usize
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn current_instruction_pointer() -> usize {
    0
}

/// Read the current stack pointer.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_stack_pointer() -> usize {
    let sp: u64;
    unsafe {
        asm!(
            "mov {sp}, sp",
            sp = out(reg) sp,
            options(nomem, nostack, preserves_flags)
        );
    }
    sp as usize
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
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
    let region = KERNEL_TEXT_END - (slot_index + 1) * USER_DEMO_REGION_SIZE;
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
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn synchronize_user_code(entry_point: usize, payload_len: usize) {
    // Clean the D-cache lines covering the code, then invalidate the
    // matching I-cache lines so the payload is visible to fetch.
    let start = align_down(entry_point, 64);
    let end = align_up(entry_point + payload_len, 64).unwrap_or(entry_point + payload_len);
    unsafe {
        let mut address = start;
        while address < end {
            asm!(
                "dc cvau, {address}",
                address = in(reg) address,
                options(nostack, preserves_flags)
            );
            address += 64;
        }
        asm!("dsb ish", options(nostack, preserves_flags));
        asm!(
            "ic ivau, {start}",
            start = in(reg) start,
            options(nostack, preserves_flags)
        );
        asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn synchronize_user_code(_entry_point: usize, _payload_len: usize) {}

/// Minimal ASLR: randomize the code offset within the slot region by a
/// page-aligned amount to vary user process virtual addresses.
///
/// Uses a simple LFSR seeded from the static slot index and a boot-time
/// constant to produce deterministic-but-varied offsets per slot.
fn aslr_offset(slot_index: usize) -> usize {
    // Mix the slot index with a fixed seed to produce a pseudo-random
    // offset in the range [0, ASLR_MAX_PAGES) × 4 KiB.
    const ASLR_MAX_PAGES: usize = 32; // 128 KiB max shift
    let seed = (slot_index
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(0x517C_C1B7)) as u32;
    let page_offset = (seed as usize) % ASLR_MAX_PAGES;
    page_offset * TRANSLATION_GRANULE_SIZE
}

pub fn demo_user_slot_layout(slot_index: usize) -> Option<DemoUserSlotLayout> {
    let region = demo_user_region_ptr(slot_index)? as usize;
    let region_end = region.checked_add(USER_DEMO_REGION_SIZE)?;
    if region < KERNEL_TEXT_BASE || region_end > KERNEL_TEXT_END {
        return None;
    }
    if !region.is_multiple_of(USER_DEMO_REGION_SIZE) {
        return None;
    }

    // ASLR: shift the code/data area upward within the slot.
    let aslr_shift = aslr_offset(slot_index);

    // Each slot is carved as:
    // [aslr pad][code/data][regular stack][guard][exception stack][guard]
    // The stack tops stay 16-byte aligned for the AArch64 ABI.
    let code_region_start = region.checked_add(aslr_shift)?;
    let stack_top = region_end & !0xF;
    let stack_bottom = stack_top.checked_sub(USER_DEMO_STACK_SIZE)?;
    let stack_guard_start = stack_bottom.checked_sub(USER_DEMO_STACK_GUARD_SIZE)?;
    let exception_stack_top = stack_guard_start & !0xF;
    let exception_stack_bottom = exception_stack_top.checked_sub(USER_DEMO_EXCEPTION_STACK_SIZE)?;
    let _exception_stack_guard_start =
        exception_stack_bottom.checked_sub(USER_DEMO_EXCEPTION_STACK_GUARD_SIZE)?;

    // Verify the code area doesn't overlap with the exception stack guard.
    if code_region_start >= _exception_stack_guard_start {
        return None;
    }

    Some(DemoUserSlotLayout {
        region_start: region,
        region_length: USER_DEMO_REGION_SIZE,
        entry_point: code_region_start + USER_DEMO_CODE_OFFSET,
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

    let slot_index = allocate_demo_user_slot_index()?;
    let layout = match demo_user_slot_layout(slot_index) {
        Some(layout) => layout,
        None => {
            release_demo_user_slot(slot_index);
            return None;
        }
    };

    // Verify the payload fits in the code/data area (from ASLR-shifted base
    // to the start of the exception stack guard).
    let code_start = layout.entry_point - USER_DEMO_CODE_OFFSET;
    let payload_end = code_start
        .checked_add(USER_DEMO_CODE_OFFSET)?
        .checked_add(payload.len())?;
    if payload_end > layout.stack_bottom {
        // Payload would overlap the stack — abort.
        release_demo_user_slot(slot_index);
        return None;
    }

    let region = match demo_user_region_ptr(slot_index) {
        Some(region) => region,
        None => {
            release_demo_user_slot(slot_index);
            return None;
        }
    };

    unsafe {
        // Zero the full slot so guard pages and unused stack bytes start from a
        // deterministic state before the payload is copied in.
        ptr::write_bytes(region.cast::<u8>(), 0, USER_DEMO_REGION_SIZE);
        ptr::copy_nonoverlapping(
            payload.as_ptr(),
            layout.entry_point as *mut u8,
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

    let mut l1 = Box::new(TranslationTable::zeroed());
    let mut l2 = Box::new(TranslationTable::zeroed());
    let mut user_l3 = Box::new(TranslationTable::zeroed());

    unsafe {
        // Start from the already prepared kernel layout, then splice one user
        // L3 table into the slot's 2 MiB window.
        *l1 = *KERNEL_L1_TABLE.get();
        *l2 = *KERNEL_L2_TABLE.get();
    }

    l1.0[1] = table_entry(l2.as_ref() as *const TranslationTable as usize);

    for slot_index in 0..USER_DEMO_SLOT_COUNT {
        let layout = demo_user_slot_layout(slot_index)?;
        let block_index = user_block_index(layout.region_start)?;
        l2.0[block_index] = normal_l2_block_entry(layout.region_start);
    }

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
        user_l3.0[page_index] = if (image_page_start..image_page_end).contains(&page_address) {
            user_l3_page_entry(page_address, PagePermissions::READ_EXECUTE)
        } else if (slot.stack_bottom()..slot.stack_top()).contains(&page_address)
            || (slot.exception_stack_bottom()..slot.exception_stack_top()).contains(&page_address)
        {
            user_l3_page_entry(page_address, PagePermissions::READ_WRITE)
        } else {
            normal_l3_page_entry(page_address)
        };
    }

    let active_block_index = user_block_index(slot.region_start())?;
    l2.0[active_block_index] = table_entry(user_l3.as_ref() as *const TranslationTable as usize);

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

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    let asid = allocate_asid();
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    let asid = 0;

    Some(PreparedProcessAddressSpace {
        l1,
        l2,
        user_l3,
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
        let kernel_ttbr0 = prepared.root_table_address as u64; // ASID = 0 for kernel
        if mmu_enabled() {
            install_active_root_table_address(kernel_ttbr0);
        } else {
            install_translation_configuration(kernel_ttbr0);
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
        let ttbr0 = ttbr0_with_asid(address_space.root_table_address(), address_space.asid);
        if mmu_enabled() {
            install_active_root_table_address(ttbr0);
        } else {
            install_translation_configuration(ttbr0);
        }
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
        // With ASLR, the code area starts at entry_point - CODE_OFFSET
        // (which may differ from region_start due to aslr_offset).
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
    ///
    /// ## Cache-maintenance boundary
    ///
    /// This function writes *data* (stack contents), never *code*.  On AArch64
    /// the data and instruction caches are not coherent, but stack data is
    /// accessed via normal loads (D-cache) — the I-cache is never involved.
    /// Therefore no D-cache clean or I-cache invalidation is required here.
    ///
    /// The only code-load path is [`allocate_demo_user_slot`], which calls
    /// [`synchronize_user_code`] after copying the payload.
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
        self.l1.as_ref() as *const TranslationTable as usize
    }

    /// The process owns three tables: the cloned L1, the cloned L2, and the
    /// active slot's user L3.
    pub fn table_page_count(&self) -> usize {
        3
    }

    pub fn mapped_page_count(&self) -> usize {
        self.kernel_page_count() + self.user_page_count()
    }

    /// The runtime tables map the 1 GiB device window and the 1 GiB RAM
    /// window as blocks; report the equivalent 4 KiB page count.
    pub fn kernel_page_count(&self) -> usize {
        2 * (KERNEL_TEXT_END - KERNEL_TEXT_BASE) / TRANSLATION_GRANULE_SIZE
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
        self.l1.0.iter().filter(|entry| **entry & 0x1 != 0).count()
    }

    pub fn second_level_entry_count(&self) -> usize {
        self.l2.0.iter().filter(|entry| **entry & 0x1 != 0).count()
    }

    pub fn leaf_table_count(&self) -> usize {
        self.user_l3
            .0
            .iter()
            .filter(|entry| **entry & 0x1 != 0)
            .count()
    }

    /// Translate a user virtual address through the process tables.
    pub fn translate_user(&self, address: usize) -> Option<PreparedTranslation> {
        let l1_index = (address >> 30) & 0x1FF;
        let l2_index = (address >> 21) & 0x1FF;
        let l3_index = (address >> 12) & 0x1FF;

        let l1_entry = self.l1.0[l1_index];
        if l1_entry & 0x1 == 0 || l1_index != 1 {
            return None;
        }
        let l2_entry = self.l2.0[l2_index];
        if l2_entry & 0x3 != DESCRIPTOR_TABLE {
            return None; // invalid or a block mapping — not a leaf page
        }
        let l3_table = (l2_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
        let l3_entry = unsafe { ptr::read_volatile(l3_table.add(l3_index)) };
        if l3_entry & 0x1 == 0 {
            return None;
        }
        let physical_address = ((l3_entry & 0x0000_FFFF_FFFF_F000) as usize) + (address & 0xFFF);
        Some(PreparedTranslation {
            physical_address,
            permissions: page_permissions_from_entry(l3_entry),
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
            let entry = self.user_l3.0[page_index];
            if entry & 0x1 == 0 {
                continue;
            }
            let va = self.slot.region_start() + page_index * TRANSLATION_GRANULE_SIZE;
            let pa = (entry & 0x0000_FFFF_FFFF_F000) as usize;
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
        let mut child_l1 = Box::new(TranslationTable::zeroed());
        let mut child_l2 = Box::new(TranslationTable::zeroed());
        let mut child_l3 = Box::new(TranslationTable::zeroed());
        *child_l1 = *self.l1;
        *child_l2 = *self.l2;
        *child_l3 = *self.user_l3;

        // User-writable pages become copy-on-write in the parent; the child
        // keeps write access.  Shared read-only (code) pages map into both.
        let mut shared_pages = Vec::new();
        let mut all_child_pages = Vec::new();
        for page_index in 0..USER_DEMO_REGION_PAGE_COUNT {
            let entry = self.user_l3.0[page_index];
            if entry & 0x1 == 0 {
                continue;
            }
            let va = self.slot.region_start() + page_index * TRANSLATION_GRANULE_SIZE;
            let pa = (entry & 0x0000_FFFF_FFFF_F000) as usize;
            let permissions = page_permissions_from_entry(entry);
            if permissions.contains(PagePermissions::WRITE) {
                // Parent loses write access (copy-on-write).  Child keeps RW.
                let read_only = if permissions.contains(PagePermissions::EXECUTE) {
                    PagePermissions::READ_EXECUTE
                } else {
                    PagePermissions::READ
                };
                self.user_l3.0[page_index] = user_page_entry(pa, read_only);
                // The parent's live L3 is active while fork runs; flush the
                // stale (previously writable) TLB entry so the read-only CoW
                // mapping takes effect immediately — otherwise the parent
                // keeps writing the shared frame through a stale RW TLB.
                flush_tlb_page(va);
                shared_pages.push((va, pa, read_only));
                all_child_pages.push((va, pa, permissions));
            } else {
                all_child_pages.push((va, pa, permissions));
            }
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        let child_asid = allocate_asid();
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        let child_asid = 0;

        // Both parent and child keep the slot allocated for the kernel's
        // lifetime (they share the underlying region).
        let mut child_slot = self.slot.clone();
        child_slot.forked = true;
        self.slot.forked = true;

        let child = PreparedProcessAddressSpace {
            l1: child_l1,
            l2: child_l2,
            user_l3: child_l3,
            slot: child_slot,
            image_page_count: self.image_page_count,
            stack_page_count: self.stack_page_count,
            asid: child_asid,
        };

        Some((child, shared_pages, all_child_pages))
    }

    /// Report the physical frame backing a user page in the active slot's L3
    /// table WITHOUT modifying the live hardware page-table entry.
    ///
    /// During fork the parent's shared pages keep their present read-only
    /// (copy-on-write) mapping in the live L3; this function only reports the
    /// referenced frame so callers can transfer refcount ownership.  Unlike
    /// the x86_64 variant there is no separate software page list to prune,
    /// so the hardware PTE is left untouched — zeroing it would make the
    /// parent's own mapping not-present and break the CoW contract.
    pub fn remove_user_page_frame(&mut self, virtual_address: usize) -> Option<usize> {
        if virtual_address < self.slot.region_start() || virtual_address >= self.slot.region_end() {
            return None;
        }
        let page_index = (virtual_address - self.slot.region_start()) / TRANSLATION_GRANULE_SIZE;
        if page_index >= USER_DEMO_REGION_PAGE_COUNT {
            return None;
        }
        let entry = self.user_l3.0[page_index];
        if entry & 0x1 == 0 {
            return None;
        }
        Some((entry & 0x0000_FFFF_FFFF_F000) as usize)
    }
}

impl Drop for PreparedProcessAddressSpace {
    fn drop(&mut self) {
        free_asid(self.asid);
    }
}
