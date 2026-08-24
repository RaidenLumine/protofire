//! src/arch/x86_64/paging/kernel_address_space.rs
//!
//! x86_64 kernel address-space layout, page-table windows, and huge-page detection.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::*;
use crate::kernel::memory::paging::PagePermissions;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::util::sync_unsafe_cell::SyncUnsafeCell;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPageTableSpec {
    pub(crate) windows: Vec<PageTableWindowSpec>,
    /// PD indices whose entries should be 2 MiB huge pages (PS bit set).
    /// Maps PD index → PDE value (physical address + flags + PS bit).
    pub(crate) huge_pd_entries: BTreeMap<usize, u64>,
    /// PDPT indices whose entries should be 1 GiB gigantic pages (PS bit
    /// set).  Maps PDPT index → PDPTE value.  Windows inside a gigantic
    /// block are not backed by PD/PT levels.
    pub(crate) huge_pdpt_entries: BTreeMap<usize, u64>,
    pub(crate) window_count: usize,
    pub(crate) mapped_page_count: usize,
}

impl KernelPageTableSpec {
    pub fn empty() -> Self {
        Self {
            windows: Vec::new(),
            huge_pd_entries: BTreeMap::new(),
            huge_pdpt_entries: BTreeMap::new(),
            window_count: 0,
            mapped_page_count: 0,
        }
    }

    pub fn from_plan(plan: &KernelPagePlan) -> Option<Self> {
        // Pre-allocate the Windows Vec to its maximum possible size so that
        // `ensure_window` never needs to grow the buffer on a fragmented
        // post-boot heap.
        let mut spec = Self {
            windows: Vec::with_capacity(MAX_KERNEL_PT_WINDOWS),
            huge_pd_entries: BTreeMap::new(),
            huge_pdpt_entries: BTreeMap::new(),
            window_count: 0,
            mapped_page_count: 0,
        };
        let mut mapped_page_count = 0;

        for region in plan.image_regions.iter().flatten().copied() {
            spec.add_region_windows(region)?;
        }
        if let Some(region) = plan.heap_region {
            spec.add_region_windows(region)?;
        }

        // Map device MMIO regions as identity-mapped, supervisor, read-write,
        // non-executable pages so drivers can access hardware registers after
        // the runtime page tables replace the bootstrap identity mapping.
        for &(base, size) in DEVICE_MMIO_IDENTITY_REGIONS {
            spec.add_device_mmio_pages(base, size)?;
        }

        // Map low-memory firmware regions (Multiboot2 info, ACPI tables,
        // AP trampoline, BIOS data) with read-write (no NX) so SMP bring-up
        // can parse the MADT and execute trampoline code at physical 0x8000.
        for &(base, size) in LOW_MEMORY_IDENTITY_REGIONS {
            spec.add_firmware_identity_pages(base, size)?;
        }

        // ── Detect 1 GiB gigantic-page candidates (PDPT level) ──
        // A 1 GiB block is eligible when a single contiguous region covers
        // its entire range with uniform permissions.  The PDPTE is stored
        // with the PS bit (1 << 7), letting the CPU skip both the PD and PT
        // levels.
        let mut huge_pdpt_entries: BTreeMap<usize, u64> = BTreeMap::new();
        for pdpt_index in 0..PAGE_TABLE_ENTRY_COUNT {
            let base = pdpt_index * GIGANTIC_PAGE_SIZE;
            if base >= BOOTSTRAP_IDENTITY_MAP_END {
                break; // Runtime kernel tables only cover the identity map.
            }
            if let Some(region) = plan.classify(base) {
                if region.start <= base && region.end >= base.checked_add(GIGANTIC_PAGE_SIZE)? {
                    huge_pdpt_entries
                        .insert(pdpt_index, gigantic_page_entry(base, region.permissions));
                }
            }
        }

        // ── Detect 2 MiB huge-page candidates ──
        // A window is eligible when a single contiguous region covers its
        // entire 2 MiB range with uniform permissions and it is not already
        // backed by a 1 GiB gigantic page.  The PDE is stored with the PS
        // bit (1 << 7), allowing the CPU to skip the PT level.
        let mut huge_pd_entries: BTreeMap<usize, u64> = BTreeMap::new();
        for window in &spec.windows {
            if huge_pdpt_entries.contains_key(&page_directory_pointer_index(window.base_address)) {
                continue;
            }
            let base = window.base_address;
            if let Some(region) = plan.classify(base) {
                if region.start <= base && region.end >= base.checked_add(HUGE_PAGE_SIZE)? {
                    huge_pd_entries.insert(
                        window.page_directory_index,
                        huge_page_entry(base, region.permissions),
                    );
                }
            }
        }

        // ── Fill normal (4 KiB) PT entries, skipping huge-page windows ──
        for window in &mut spec.windows {
            if huge_pdpt_entries.contains_key(&page_directory_pointer_index(window.base_address)) {
                // Backed by a 1 GiB gigantic page — no PD/PT levels needed.
                continue;
            }
            if huge_pd_entries.contains_key(&window.page_directory_index) {
                // Backed by a 2 MiB huge page — no 4 KiB PTEs needed.
                continue;
            }

            let mut address = window.base_address;
            for entry in &mut window.entries {
                if let Some(region) = plan.classify_page(address) {
                    *entry = page_entry(address, region.permissions);
                    mapped_page_count += 1;
                } else if *entry != 0 {
                    // Entry was already populated by add_device_mmio_pages;
                    // count it but don't overwrite it.
                    mapped_page_count += 1;
                }
                address = address.checked_add(X86_PAGE_SIZE)?;
            }
        }

        // Each huge page counts as one mapped unit in the summary.
        mapped_page_count += huge_pd_entries.len() + huge_pdpt_entries.len();
        spec.huge_pd_entries = huge_pd_entries;
        spec.huge_pdpt_entries = huge_pdpt_entries;
        spec.mapped_page_count = mapped_page_count;
        Some(spec)
    }

    pub fn translate(&self, address: usize) -> Option<PreparedTranslation> {
        // Check 1 GiB gigantic pages first — the PDPTE holds the physical
        // address directly (no PD/PT levels), with an extra offset within
        // the 1 GiB block.
        let pdpt_index = page_directory_pointer_index(address);
        if let Some(pdpte) = self.huge_pdpt_entries.get(&pdpt_index) {
            return Some(PreparedTranslation {
                physical_address: (*pdpte as usize & GIGANTIC_PAGE_ENTRY_ADDRESS_MASK as usize)
                    + (address & (GIGANTIC_PAGE_SIZE - 1)),
                permissions: permissions_from_page_entry(*pdpte),
            });
        }

        let pd_index = page_directory_index(address);

        // Check 2 MiB huge pages — the PDE holds the physical address
        // directly (no PT level), with an extra offset within the 2 MiB block.
        if let Some(pde) = self.huge_pd_entries.get(&pd_index) {
            return Some(PreparedTranslation {
                physical_address: (*pde as usize & HUGE_PAGE_ENTRY_ADDRESS_MASK as usize)
                    + (address & (HUGE_PAGE_SIZE - 1)),
                permissions: permissions_from_page_entry(*pde),
            });
        }

        // Fall back to 4 KiB PT entries.
        let window = self
            .windows
            .iter()
            .find(|window| window.page_directory_index == pd_index)?;
        let entry = window.entries[page_table_index(address)];

        if entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }

        Some(PreparedTranslation {
            physical_address: (entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
                + page_offset(address),
            permissions: permissions_from_page_entry(entry),
        })
    }

    pub const fn window_count(&self) -> usize {
        self.window_count
    }

    pub const fn mapped_page_count(&self) -> usize {
        self.mapped_page_count
    }

    fn add_region_windows(&mut self, region: PlannedRegion) -> Option<()> {
        let mut base_address = align_down(region.start, PAGE_DIRECTORY_WINDOW_SIZE);
        let end = align_up(region.end, PAGE_DIRECTORY_WINDOW_SIZE)?;

        while base_address < end {
            self.ensure_window(base_address)?;
            base_address = base_address.checked_add(PAGE_DIRECTORY_WINDOW_SIZE)?;
        }

        Some(())
    }

    /// Identity-map a physical address range as device MMIO pages
    /// (supervisor, read-write, non-executable).  Ensures that the
    /// necessary page-table windows exist so the entries can be written.
    fn add_device_mmio_pages(&mut self, base: usize, size: usize) -> Option<()> {
        let end = base.checked_add(size)?;
        let page_start = align_down(base, X86_PAGE_SIZE);
        let page_end = align_up(end, X86_PAGE_SIZE)?;

        // Device pages: present, writable, supervisor (U/S=0), NX set.
        let entry_flags = PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE | PAGE_ENTRY_NO_EXECUTE;

        let mut addr = page_start;
        while addr < page_end {
            // Ensure the 2 MiB window that contains this page exists.
            let window_base = align_down(addr, PAGE_DIRECTORY_WINDOW_SIZE);
            self.ensure_window(window_base)?;

            // Find the window and set the entry.
            let pd_index = page_directory_index(window_base);
            if let Some(window) = self
                .windows
                .iter_mut()
                .find(|w| w.page_directory_index == pd_index)
            {
                let pt_index = page_table_index(addr);
                let phys = align_down(addr, X86_PAGE_SIZE);
                window.entries[pt_index] = (phys as u64) | entry_flags;
            }

            addr = addr.checked_add(X86_PAGE_SIZE)?;
        }

        Some(())
    }

    /// Map physical address ranges as identity-mapped, supervisor,
    /// read-write (NO NX — code in these regions, e.g. the AP trampoline,
    /// must be executable).
    fn add_firmware_identity_pages(&mut self, base: usize, size: usize) -> Option<()> {
        let end = base.checked_add(size)?;
        let page_start = align_down(base, X86_PAGE_SIZE);
        let page_end = align_up(end, X86_PAGE_SIZE)?;

        // Firmware pages: present, writable, supervisor (U/S=0), NO NX.
        let entry_flags = PAGE_ENTRY_PRESENT | PAGE_ENTRY_WRITABLE;

        let mut addr = page_start;
        while addr < page_end {
            let window_base = align_down(addr, PAGE_DIRECTORY_WINDOW_SIZE);
            self.ensure_window(window_base)?;

            let pd_index = page_directory_index(window_base);
            if let Some(window) = self
                .windows
                .iter_mut()
                .find(|w| w.page_directory_index == pd_index)
            {
                let pt_index = page_table_index(addr);
                let phys = align_down(addr, X86_PAGE_SIZE);
                window.entries[pt_index] = (phys as u64) | entry_flags;
            }

            addr = addr.checked_add(X86_PAGE_SIZE)?;
        }

        Some(())
    }

    fn ensure_window(&mut self, base_address: usize) -> Option<()> {
        if base_address >= BOOTSTRAP_IDENTITY_MAP_END
            || base_address & (PAGE_DIRECTORY_WINDOW_SIZE - 1) != 0
        {
            return None;
        }

        let page_directory_index = page_directory_index(base_address);
        for window in &self.windows {
            if window.page_directory_index == page_directory_index {
                return Some(());
            }
        }

        if self.windows.len() >= MAX_KERNEL_PT_WINDOWS {
            return None;
        }

        self.windows
            .push(PageTableWindowSpec::new(page_directory_index, base_address));
        self.window_count += 1;
        Some(())
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static KERNEL_PML4: SyncUnsafeCell<RawPageTable> =
    SyncUnsafeCell::new(RawPageTable::zeroed());
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static KERNEL_PDPT: SyncUnsafeCell<RawPageTable> =
    SyncUnsafeCell::new(RawPageTable::zeroed());
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static KERNEL_PD: SyncUnsafeCell<RawPageTable> =
    SyncUnsafeCell::new(RawPageTable::zeroed());
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) static KERNEL_PTS: SyncUnsafeCell<[RawPageTable; MAX_KERNEL_PT_WINDOWS]> =
    SyncUnsafeCell::new([RawPageTable::zeroed(); MAX_KERNEL_PT_WINDOWS]);
pub(crate) fn required_region(
    range: (usize, usize),
    permissions: PagePermissions,
    kind: PlannedRegionKind,
) -> Option<PlannedRegion> {
    let (start, end) = range;
    if start >= end {
        return None;
    }

    Some(PlannedRegion {
        start,
        end,
        permissions,
        kind,
    })
}

pub(crate) fn validate_image_regions(
    image_regions: &[Option<PlannedRegion>; KERNEL_IMAGE_REGION_COUNT],
) -> Option<()> {
    for region in image_regions.iter().flatten().copied() {
        if region.start >= region.end {
            return None;
        }
    }

    for (left, left_region) in image_regions.iter().copied().enumerate() {
        let Some(left_region) = left_region else {
            continue;
        };

        for right_region in image_regions.iter().skip(left + 1).flatten().copied() {
            if ranges_overlap(
                left_region.start,
                left_region.end,
                right_region.start,
                right_region.end,
            ) {
                return None;
            }
        }
    }

    Some(())
}

pub(crate) fn validate_heap_region(
    image_regions: &[Option<PlannedRegion>; KERNEL_IMAGE_REGION_COUNT],
    heap_region: Option<PlannedRegion>,
) -> Option<()> {
    let Some(heap_region) = heap_region else {
        return Some(());
    };

    if heap_region.start >= heap_region.end {
        return None;
    }

    for region in image_regions.iter().flatten().copied() {
        if !ranges_overlap(heap_region.start, heap_region.end, region.start, region.end) {
            continue;
        }

        if region.kind == PlannedRegionKind::KernelBss
            && heap_region.start >= region.start
            && heap_region.end <= region.end
        {
            continue;
        }

        return None;
    }

    Some(())
}

pub(crate) const fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

pub(crate) const fn is_page_aligned(address: usize) -> bool {
    address & (X86_PAGE_SIZE - 1) == 0
}

pub(crate) const fn is_lower_canonical_user_address(address: usize) -> bool {
    address >= X86_PAGE_SIZE && address < X86_64_USER_CANONICAL_END
}

pub(crate) const fn is_lower_canonical_user_range(start: usize, end: usize) -> bool {
    start < end && is_lower_canonical_user_address(start) && end <= X86_64_USER_CANONICAL_END
}

pub(crate) const fn page_directory_index(address: usize) -> usize {
    address / PAGE_DIRECTORY_WINDOW_SIZE
}

pub(crate) const fn pml4_index(address: usize) -> usize {
    (address >> 39) & (PAGE_TABLE_ENTRY_COUNT - 1)
}

pub(crate) const fn page_directory_pointer_index(address: usize) -> usize {
    (address >> 30) & (PAGE_TABLE_ENTRY_COUNT - 1)
}

pub(crate) const fn page_directory_slot_index(address: usize) -> usize {
    (address >> 21) & (PAGE_TABLE_ENTRY_COUNT - 1)
}

pub(crate) const fn page_table_index(address: usize) -> usize {
    (address / X86_PAGE_SIZE) & (PAGE_TABLE_ENTRY_COUNT - 1)
}

pub(crate) const fn page_offset(address: usize) -> usize {
    address & (X86_PAGE_SIZE - 1)
}

pub(crate) fn page_entry(address: usize, permissions: PagePermissions) -> u64 {
    let mut entry = (align_down(address, X86_PAGE_SIZE) as u64) & PAGE_ENTRY_ADDRESS_MASK;
    entry |= PAGE_ENTRY_PRESENT;

    if permissions.contains(PagePermissions::WRITE) {
        entry |= PAGE_ENTRY_WRITABLE;
    }
    if !permissions.contains(PagePermissions::EXECUTE) {
        entry |= PAGE_ENTRY_NO_EXECUTE;
    }

    entry
}

/// Build a 2 MiB huge-page Page-Directory entry (PDE) with the PS bit set.
///
/// The PDE directly encodes the 2 MiB-aligned physical address, permission
/// flags, and the `PAGE_ENTRY_LARGE` (PS) bit, allowing the MMU to skip
/// the Page-Table (PT) level during translation.
pub(crate) fn huge_page_entry(address: usize, permissions: PagePermissions) -> u64 {
    let mut entry = (align_down(address, HUGE_PAGE_SIZE) as u64) & HUGE_PAGE_ENTRY_ADDRESS_MASK;
    entry |= PAGE_ENTRY_PRESENT | PAGE_ENTRY_LARGE;

    if permissions.contains(PagePermissions::WRITE) {
        entry |= PAGE_ENTRY_WRITABLE;
    }
    if !permissions.contains(PagePermissions::EXECUTE) {
        entry |= PAGE_ENTRY_NO_EXECUTE;
    }

    entry
}

/// Build a 1 GiB gigantic-page Page-Directory-Pointer entry (PDPTE) with the
/// PS bit set.
///
/// The PDPTE directly encodes the 1 GiB-aligned physical address and
/// permission flags with `PAGE_ENTRY_LARGE` (PS) set, allowing the MMU to
/// skip both the Page-Directory and Page-Table levels during translation.
pub(crate) fn gigantic_page_entry(address: usize, permissions: PagePermissions) -> u64 {
    let mut entry =
        (align_down(address, GIGANTIC_PAGE_SIZE) as u64) & GIGANTIC_PAGE_ENTRY_ADDRESS_MASK;
    entry |= PAGE_ENTRY_PRESENT | PAGE_ENTRY_LARGE;

    if permissions.contains(PagePermissions::WRITE) {
        entry |= PAGE_ENTRY_WRITABLE;
    }
    if !permissions.contains(PagePermissions::EXECUTE) {
        entry |= PAGE_ENTRY_NO_EXECUTE;
    }

    entry
}

pub(crate) fn permissions_from_page_entry(entry: u64) -> PagePermissions {
    let writable = entry & PAGE_ENTRY_WRITABLE != 0;
    let executable = entry & PAGE_ENTRY_NO_EXECUTE == 0;

    match (writable, executable) {
        (false, false) => PagePermissions::READ,
        (true, false) => PagePermissions::READ_WRITE,
        (false, true) => PagePermissions::READ_EXECUTE,
        (true, true) => PagePermissions::READ_WRITE_EXECUTE,
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) const fn table_pointer_entry(address: usize) -> u64 {
    (address as u64 & PAGE_ENTRY_ADDRESS_MASK) | TABLE_ENTRY_FLAGS
}

pub(crate) const fn user_table_pointer_entry(address: usize) -> u64 {
    (address as u64 & PAGE_ENTRY_ADDRESS_MASK) | USER_TABLE_ENTRY_FLAGS
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
