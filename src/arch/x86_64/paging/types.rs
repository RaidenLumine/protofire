//! src/arch/x86_64/paging/types.rs
//!
//! src/arch/x86_64/paging.rs
//!
//! x86_64 bootstrap and runtime page-table planning plus per-process address-space assembly.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicUsize};

use super::*;
use crate::kernel::memory::paging::PagePermissions;

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
// These atomics publish the most recently prepared runtime kernel page-table
// summary so activation and diagnostics can inspect it without holding a heap
// allocation alive globally.
pub(crate) static PREPARED_ROOT_TABLE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PREPARED_WINDOW_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PREPARED_MAPPED_PAGE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static TEST_ACTIVE_ROOT_TABLE: AtomicUsize = AtomicUsize::new(0);
pub(crate) const KERNEL_IMAGE_REGION_COUNT: usize = 4;
pub(crate) const PAGE_TABLE_ENTRY_COUNT: usize = 512;
pub(crate) const X86_PAGE_SIZE: usize = 4096;
/// 2 MiB large / huge page size (PS bit in Page Directory entries).
pub(crate) const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
/// 1 GiB gigantic page size (PS bit in PDPT entries).
pub(crate) const GIGANTIC_PAGE_SIZE: usize = 1024 * 1024 * 1024;
pub(crate) const PAGE_DIRECTORY_WINDOW_SIZE: usize = HUGE_PAGE_SIZE;
pub(crate) const MAX_KERNEL_PT_WINDOWS: usize = 512;
pub(crate) const MAX_USER_PT_WINDOWS: usize = 64;

/// Physical address ranges that must be identity-mapped as device MMIO
/// (read-write, non-executable, supervisor) so drivers can access hardware
/// registers after the runtime page tables replace the bootstrap identity
/// mapping.  Each tuple is (base_address, size_in_bytes).
///
/// NOTE: addresses above BOOTSTRAP_IDENTITY_MAP_END (1 GiB) cannot be
/// statically pre-mapped here; they must be dynamically mapped at runtime
/// via `map_device_mmio` or `map_device_mmio_page`.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) const DEVICE_MMIO_IDENTITY_REGIONS: &[(usize, usize)] = &[
    // VirtIO MMIO transport window (8 slots × 0x200 stride).
    // This sits at 0x0A00_0000 (160 MiB), well within the 1 GiB identity map.
    (0x0A00_0000, 0x200 * 8),
];

/// Physical address ranges that must be identity-mapped with read-write
/// (non-NX) permissions for firmware/boot data: Multiboot2 info, ACPI tables,
/// AP trampoline code and data page, BIOS data area, etc.
///
/// On non-bare-metal (host/test) targets this list is empty — there are no
/// firmware regions to identity-map in a userspace test environment.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) const LOW_MEMORY_IDENTITY_REGIONS: &[(usize, usize)] = &[
    // First 1 MiB: covers IVT (0x0), BDA (0x400), Multiboot2 info,
    // trampoline (0x8000-0xA000), EBDA, and BIOS ROM (0xE0000-0xFFFFF).
    (0x0, 0x10_0000),
];
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) const LOW_MEMORY_IDENTITY_REGIONS: &[(usize, usize)] = &[];

// On non-bare-metal targets the host-side mkimage tool uses this module
// for disk-image layout only — no actual MMIO devices exist.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) const DEVICE_MMIO_IDENTITY_REGIONS: &[(usize, usize)] = &[];
pub(crate) const PAGE_ENTRY_PRESENT: u64 = 1 << 0;
pub(crate) const PAGE_ENTRY_WRITABLE: u64 = 1 << 1;
pub(crate) const PAGE_ENTRY_USER: u64 = 1 << 2;
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
pub(crate) const PAGE_ENTRY_LARGE: u64 = 1 << 7; // PS bit — indicates huge page (1 GiB in PDPT, 2 MiB in PD)
pub(crate) const PAGE_ENTRY_GLOBAL: u64 = 1 << 8;
pub(crate) const PAGE_ENTRY_NO_EXECUTE: u64 = 1 << 63;
pub(crate) const PAGE_ENTRY_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
pub(crate) const HUGE_PAGE_ENTRY_ADDRESS_MASK: u64 = 0x000f_ffff_ffe0_0000;
/// Physical-address field of a 1 GiB gigantic page entry: bits [51:30] hold
/// the 1 GiB-aligned base (the PS bit is bit 7, identical to 2 MiB pages).
pub(crate) const GIGANTIC_PAGE_ENTRY_ADDRESS_MASK: u64 = 0x000f_ffff_c000_0000;
pub(crate) const USER_PAGE_ENTRY_STACK: u64 = 1 << 9;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) const TABLE_ENTRY_FLAGS: u64 = PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;
pub(crate) const USER_TABLE_ENTRY_FLAGS: u64 =
    PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE | PAGE_ENTRY_USER;

// Early boot keeps a 1 GiB identity map using 2 MiB pages until the runtime
// page tables are fully prepared and activated.
pub const BOOTSTRAP_PAGE_SIZE: usize = 2 * 1024 * 1024;
pub const BOOTSTRAP_IDENTITY_MAP_START: usize = 0;
pub const BOOTSTRAP_IDENTITY_MAP_LENGTH: usize = 512 * BOOTSTRAP_PAGE_SIZE;
pub const BOOTSTRAP_IDENTITY_MAP_END: usize =
    BOOTSTRAP_IDENTITY_MAP_START + BOOTSTRAP_IDENTITY_MAP_LENGTH;
pub const X86_64_USER_CANONICAL_END: usize = 0x0000_8000_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapMapping {
    pub virtual_start: usize,
    pub physical_start: usize,
    pub length: usize,
    pub page_size: usize,
    pub writable: bool,
    pub executable: bool,
}

impl BootstrapMapping {
    pub const fn contains(self, address: usize) -> bool {
        address >= self.virtual_start && address < self.virtual_start + self.length
    }

    pub const fn translate(self, address: usize) -> Option<usize> {
        if self.contains(address) {
            Some(self.physical_start + (address - self.virtual_start))
        } else {
            None
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedRegion {
    pub start: usize,
    pub end: usize,
    pub permissions: PagePermissions,
    pub kind: PlannedRegionKind,
}

impl PlannedRegion {
    pub const fn contains(self, address: usize) -> bool {
        address >= self.start && address < self.end
    }

    pub const fn len(self) -> usize {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPagePlan {
    pub(crate) image_regions: [Option<PlannedRegion>; KERNEL_IMAGE_REGION_COUNT],
    pub(crate) heap_region: Option<PlannedRegion>,
}

impl KernelPagePlan {
    pub const fn empty() -> Self {
        Self {
            image_regions: [None; KERNEL_IMAGE_REGION_COUNT],
            heap_region: None,
        }
    }

    pub fn from_ranges(
        text: (usize, usize),
        rodata: (usize, usize),
        data: (usize, usize),
        bss: (usize, usize),
        heap: (usize, usize),
    ) -> Option<Self> {
        let image_regions = [
            Some(required_region(
                text,
                PagePermissions::READ_EXECUTE,
                PlannedRegionKind::KernelText,
            )?),
            Some(required_region(
                rodata,
                PagePermissions::READ,
                PlannedRegionKind::KernelRodata,
            )?),
            Some(required_region(
                data,
                PagePermissions::READ_WRITE,
                PlannedRegionKind::KernelData,
            )?),
            Some(required_region(
                bss,
                PagePermissions::READ_WRITE,
                PlannedRegionKind::KernelBss,
            )?),
        ];
        let heap_region = Some(required_region(
            heap,
            PagePermissions::READ_WRITE,
            PlannedRegionKind::KernelHeap,
        )?);

        Self::new(image_regions, heap_region)
    }

    pub fn heap_only(heap: (usize, usize)) -> Option<Self> {
        Self::new(
            [None; KERNEL_IMAGE_REGION_COUNT],
            Some(required_region(
                heap,
                PagePermissions::READ_WRITE,
                PlannedRegionKind::KernelHeap,
            )?),
        )
    }

    pub fn classify(&self, address: usize) -> Option<PlannedRegion> {
        if let Some(region) = self.heap_region {
            if region.contains(address) {
                return Some(region);
            }
        }

        self.image_regions
            .iter()
            .flatten()
            .copied()
            .find(|region| region.contains(address))
    }

    pub(crate) fn classify_page(&self, page_start: usize) -> Option<PlannedRegion> {
        let page_end = page_start.checked_add(X86_PAGE_SIZE)?;

        if let Some(region) = self.heap_region {
            if page_start < region.end && region.start < page_end {
                return Some(region);
            }
        }

        self.image_regions
            .iter()
            .flatten()
            .copied()
            .find(|region| page_start < region.end && region.start < page_end)
    }

    pub fn region_count(&self) -> usize {
        self.image_regions.iter().flatten().count() + usize::from(self.heap_region.is_some())
    }

    pub(crate) fn new(
        image_regions: [Option<PlannedRegion>; KERNEL_IMAGE_REGION_COUNT],
        heap_region: Option<PlannedRegion>,
    ) -> Option<Self> {
        validate_image_regions(&image_regions)?;
        validate_heap_region(&image_regions, heap_region)?;

        Some(Self {
            image_regions,
            heap_region,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedRuntimeKernelPageTables {
    pub root_table_address: usize,
    pub window_count: usize,
    pub mapped_page_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivatedRuntimeKernelPageTables {
    pub previous_root_table_address: usize,
    pub active_root_table_address: usize,
    pub window_count: usize,
    pub mapped_page_count: usize,
    pub already_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveKernelAddressProbe {
    pub virtual_address: usize,
    pub physical_address: usize,
    pub permissions: PagePermissions,
    pub kind: PlannedRegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveRuntimeKernelPageTableCheck {
    pub root_table_address: usize,
    pub instruction_pointer: ActiveKernelAddressProbe,
    pub stack_pointer: ActiveKernelAddressProbe,
    pub heap_pointer: ActiveKernelAddressProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRegionKind {
    Image,
    Stack,
}

impl UserRegionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "user-image",
            Self::Stack => "user-stack",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPageMapping {
    pub permissions: PagePermissions,
    pub kind: UserRegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedUserTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
    pub kind: UserRegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRegionKind {
    Kernel,
    UserImage,
    UserStack,
}

impl ProcessRegionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::UserImage => "user-image",
            Self::UserStack => "user-stack",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedProcessTranslation {
    pub physical_address: usize,
    pub permissions: PagePermissions,
    pub kind: ProcessRegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedUserAddressSpaceSummary {
    pub root_table_address: usize,
    pub mapped_page_count: usize,
    pub image_page_count: usize,
    pub stack_page_count: usize,
    pub table_page_count: usize,
    pub pml4_entry_count: usize,
    pub pdpt_count: usize,
    pub page_directory_count: usize,
    pub page_table_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedProcessAddressSpaceSummary {
    pub root_table_address: usize,
    pub mapped_page_count: usize,
    pub kernel_page_count: usize,
    pub user_page_count: usize,
    pub table_page_count: usize,
    pub pml4_entry_count: usize,
    pub pdpt_count: usize,
    pub page_directory_count: usize,
    pub page_table_count: usize,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PageTableWindowSpec {
    pub(crate) page_directory_index: usize,
    pub(crate) base_address: usize,
    pub(crate) entries: [u64; PAGE_TABLE_ENTRY_COUNT],
}

impl PageTableWindowSpec {
    pub(crate) const fn new(page_directory_index: usize, base_address: usize) -> Self {
        Self {
            page_directory_index,
            base_address,
            entries: [0; PAGE_TABLE_ENTRY_COUNT],
        }
    }
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub(crate) struct RawPageTable(pub(crate) [u64; PAGE_TABLE_ENTRY_COUNT]);

impl RawPageTable {
    /// Zero-initialised value used for static initialisers and non‑heap
    /// contexts.  For heap allocations prefer [`RawPageTable::new_boxed_zeroed`]
    /// to avoid a 4096‑byte stack temporary.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) const fn zeroed() -> Self {
        Self([0; PAGE_TABLE_ENTRY_COUNT])
    }

    /// Allocate a zeroed `RawPageTable` directly on the heap, avoiding a
    /// 4096‑byte stack temporary that risks overflowing the 32 KiB kernel
    /// stack when several page‑table levels are materialised in a single call
    /// chain.
    pub(crate) fn new_boxed_zeroed() -> Box<Self> {
        unsafe {
            let layout = core::alloc::Layout::new::<Self>();
            let ptr = alloc::alloc::alloc(layout);
            if ptr.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            core::ptr::write_bytes(ptr, 0, layout.size());
            Box::from_raw(ptr as *mut Self)
        }
    }
}

#[repr(C, align(4096))]
pub(crate) struct RawPageFrame(pub(crate) [u8; X86_PAGE_SIZE]);

impl RawPageFrame {
    /// Zero-initialised value for non‑heap contexts.  For heap allocations
    /// prefer [`RawPageFrame::new_boxed_zeroed`] to avoid a 4096‑byte stack
    /// temporary.
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self([0; X86_PAGE_SIZE])
    }

    /// Allocate a zeroed `RawPageFrame` directly on the heap, avoiding a
    /// 4096‑byte stack temporary.  See [`RawPageTable::new_boxed_zeroed`].
    pub(crate) fn new_boxed_zeroed() -> Box<Self> {
        unsafe {
            let layout = core::alloc::Layout::new::<Self>();
            let ptr = alloc::alloc::alloc(layout);
            if ptr.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            core::ptr::write_bytes(ptr, 0, layout.size());
            Box::from_raw(ptr as *mut Self)
        }
    }
}
