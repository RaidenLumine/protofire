//! src/arch/x86_64/paging/user_address_space.rs
//!
//! x86_64 user address-space page-table planning and assembly for
//! ELF image loading and runtime translation.

use super::*;
use crate::kernel::memory::paging::PagePermissions;
use crate::user::program::UserImageLoadPlan;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;

pub(crate) struct PreparedUserPdpt {
    pub(crate) pml4_index: usize,
    pub(crate) table: Box<RawPageTable>,
}

impl PreparedUserPdpt {
    pub(crate) fn address(&self) -> usize {
        self.table.as_ref() as *const RawPageTable as usize
    }
}

pub(crate) struct PreparedUserPd {
    pub(crate) pml4_index: usize,
    pub(crate) pdpt_index: usize,
    pub(crate) table: Box<RawPageTable>,
}

impl PreparedUserPd {
    pub(crate) fn address(&self) -> usize {
        self.table.as_ref() as *const RawPageTable as usize
    }
}

pub(crate) struct PreparedUserPt {
    pub(crate) pml4_index: usize,
    pub(crate) pdpt_index: usize,
    pub(crate) page_directory_index: usize,
    pub(crate) table: Box<RawPageTable>,
}

impl PreparedUserPt {
    pub(crate) fn address(&self) -> usize {
        self.table.as_ref() as *const RawPageTable as usize
    }
}

pub(crate) struct PreparedUserPage {
    pub(crate) virtual_address: usize,
    pub(crate) permissions: PagePermissions,
    pub(crate) kind: UserRegionKind,
    pub(crate) frame: Box<RawPageFrame>,
}

impl PreparedUserPage {
    pub(crate) fn physical_address(&self) -> usize {
        self.frame.as_ref() as *const RawPageFrame as usize
    }

    fn contains(&self, address: usize) -> bool {
        (self.virtual_address..self.virtual_address + X86_PAGE_SIZE).contains(&address)
    }

    fn read_byte(&self, address: usize) -> Option<u8> {
        if !self.contains(address) {
            return None;
        }

        Some(self.frame.0[address - self.virtual_address])
    }
}

pub struct PreparedUserAddressSpace {
    pub(crate) spec: Box<UserAddressSpacePageTableSpec>,
    pub(crate) summary: PreparedUserAddressSpaceSummary,
    pub(crate) pml4: Box<RawPageTable>,
    pub(crate) pdpts: Vec<PreparedUserPdpt>,
    pub(crate) pds: Vec<PreparedUserPd>,
    pub(crate) pts: Vec<PreparedUserPt>,
    pub(crate) pages: Vec<PreparedUserPage>,
}

impl PreparedUserAddressSpace {
    pub(crate) fn from_load_plan(load_plan: &UserImageLoadPlan, image: &[u8]) -> Option<Self> {
        let spec = UserAddressSpacePageTableSpec::from_load_plan(load_plan)?;
        let mut pages = materialize_user_pages(&spec, load_plan, image)?;
        // Keep page order deterministic so translation and byte helpers can
        // scan a stable address-sorted list.
        pages.sort_by_key(|page| page.virtual_address);

        let mut pml4 = RawPageTable::new_boxed_zeroed();
        let mut pdpts = Vec::with_capacity(spec.pml4_count());
        let mut pds = Vec::with_capacity(spec.pdpt_count());
        let mut pts = Vec::with_capacity(spec.window_count());

        // Materialize the user PT hierarchy directly from the logical window
        // spec, then point each present PTE at the prepared backing frames.
        for window in &spec.windows {
            ensure_prepared_pdpt(&mut pdpts, window.pml4_index);
            ensure_prepared_pd(&mut pds, window.pml4_index, window.pdpt_index);

            let mut pt = PreparedUserPt {
                pml4_index: window.pml4_index,
                pdpt_index: window.pdpt_index,
                page_directory_index: window.page_directory_index,
                table: RawPageTable::new_boxed_zeroed(),
            };

            let mut address = window.base_address;
            for (index, entry) in window.entries.iter().enumerate() {
                if let Some(mapping) = user_page_mapping_from_entry(*entry) {
                    let page = find_prepared_user_page(&pages, address)?;
                    pt.table.0[index] = user_page_frame_entry(
                        page.physical_address(),
                        mapping.permissions,
                        mapping.kind,
                    );
                }
                address = address.checked_add(X86_PAGE_SIZE)?;
            }

            let pd = find_prepared_pd_mut(&mut pds, window.pml4_index, window.pdpt_index)?;
            pd.table.0[window.page_directory_index] = user_table_pointer_entry(pt.address());
            pts.push(pt);
        }

        for pd in &pds {
            let pdpt = find_prepared_pdpt_mut(&mut pdpts, pd.pml4_index)?;
            pdpt.table.0[pd.pdpt_index] = user_table_pointer_entry(pd.address());
        }

        for pdpt in &pdpts {
            pml4.0[pdpt.pml4_index] = user_table_pointer_entry(pdpt.address());
        }

        let summary = PreparedUserAddressSpaceSummary {
            root_table_address: pml4.as_ref() as *const RawPageTable as usize,
            mapped_page_count: pages.len(),
            image_page_count: pages
                .iter()
                .filter(|page| page.kind == UserRegionKind::Image)
                .count(),
            stack_page_count: pages
                .iter()
                .filter(|page| page.kind == UserRegionKind::Stack)
                .count(),
            table_page_count: 1 + pdpts.len() + pds.len() + pts.len(),
            pml4_entry_count: spec.pml4_count(),
            pdpt_count: spec.pdpt_count(),
            page_directory_count: spec.page_directory_count(),
            page_table_count: spec.window_count(),
        };

        Some(Self {
            spec: Box::new(spec),
            summary,
            pml4,
            pdpts,
            pds,
            pts,
            pages,
        })
    }

    pub fn summary(&self) -> PreparedUserAddressSpaceSummary {
        self.summary
    }

    pub fn root_table_address(&self) -> usize {
        self.summary.root_table_address
    }

    pub fn translate(&self, address: usize) -> Option<PreparedUserTranslation> {
        let page = self.find_page(address)?;
        Some(PreparedUserTranslation {
            physical_address: page.physical_address() + (address - page.virtual_address),
            permissions: page.permissions,
            kind: page.kind,
        })
    }

    pub fn read_byte(&self, address: usize) -> Option<u8> {
        self.find_page(address)?.read_byte(address)
    }

    pub fn write_bytes(&mut self, address: usize, bytes: &[u8]) -> Option<()> {
        let mut remaining = bytes;
        let mut cursor = address;

        while !remaining.is_empty() {
            let page = self.find_page_mut(cursor)?;
            let page_offset = cursor - page.virtual_address;
            let available = X86_PAGE_SIZE - page_offset;
            let chunk = remaining.len().min(available);

            page.frame.0[page_offset..page_offset + chunk].copy_from_slice(&remaining[..chunk]);

            cursor += chunk;
            remaining = &remaining[chunk..];
        }

        Some(())
    }

    /// Binary-search the sorted `pages` vector for the page covering `address`.
    ///
    /// Pages are sorted by `virtual_address` at construction time and never
    /// overlap, so a `binary_search_by_key` with a fallback to the preceding
    /// slot gives O(log n) lookup instead of the previous O(n) linear scan.
    fn find_page(&self, address: usize) -> Option<&PreparedUserPage> {
        let index = match self
            .pages
            .binary_search_by_key(&address, |page| page.virtual_address)
        {
            Ok(index) => index,
            Err(0) => return None, // before the first page
            Err(index) => index.saturating_sub(1),
        };

        self.pages.get(index).filter(|page| page.contains(address))
    }

    fn find_page_mut(&mut self, address: usize) -> Option<&mut PreparedUserPage> {
        let index = match self
            .pages
            .binary_search_by_key(&address, |page| page.virtual_address)
        {
            Ok(index) => index,
            Err(0) => return None,
            Err(index) => index.saturating_sub(1),
        };

        self.pages
            .get_mut(index)
            .filter(|page| page.contains(address))
    }

    pub fn table_page_count(&self) -> usize {
        1 + self.pdpts.len() + self.pds.len() + self.pts.len()
    }

    pub fn mapped_page_count(&self) -> usize {
        self.pages.len()
    }

    /// Return `(virtual_address, physical_address, permissions)` for every
    /// user page, suitable for registering in the software page table.
    pub fn user_page_entries(&self) -> Vec<(usize, usize, PagePermissions)> {
        self.pages
            .iter()
            .map(|page| {
                (
                    page.virtual_address,
                    page.physical_address(),
                    page.permissions,
                )
            })
            .collect()
    }

    /// Return the virtual address range `(start, end_exclusive)` that covers
    /// all user pages, or `None` when there are no pages.
    pub fn user_page_va_range(&self) -> Option<(usize, usize)> {
        let min = self.pages.iter().map(|p| p.virtual_address).min()?;
        let max = self
            .pages
            .iter()
            .map(|p| p.virtual_address.saturating_add(X86_PAGE_SIZE))
            .max()?;
        Some((min, max))
    }

    pub fn root_entry_count(&self) -> usize {
        self.pml4
            .0
            .iter()
            .filter(|entry| **entry & PAGE_ENTRY_PRESENT != 0)
            .count()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserPageTableWindowSpec {
    pub(crate) pml4_index: usize,
    pub(crate) pdpt_index: usize,
    pub(crate) page_directory_index: usize,
    pub(crate) base_address: usize,
    pub(crate) entries: Box<[u64; PAGE_TABLE_ENTRY_COUNT]>,
}

impl UserPageTableWindowSpec {
    pub(crate) fn new(base_address: usize) -> Option<Self> {
        // Allocate the 4 KiB entries array on the heap to avoid stack
        // overflow in deep call chains (kernel stack is only 32 KiB).
        let layout = Layout::new::<[u64; PAGE_TABLE_ENTRY_COUNT]>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }
        let entries = unsafe { Box::from_raw(ptr as *mut [u64; PAGE_TABLE_ENTRY_COUNT]) };
        Some(Self {
            pml4_index: pml4_index(base_address),
            pdpt_index: page_directory_pointer_index(base_address),
            page_directory_index: page_directory_slot_index(base_address),
            base_address,
            entries,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAddressSpacePageTableSpec {
    pub(crate) windows: Vec<UserPageTableWindowSpec>,
    pub(crate) window_count: usize,
    pub(crate) mapped_page_count: usize,
    pub(crate) pml4_count: usize,
    pub(crate) pdpt_count: usize,
    pub(crate) page_directory_count: usize,
    pub(crate) stack_page_count: usize,
}

impl UserAddressSpacePageTableSpec {
    pub fn empty() -> Self {
        Self {
            windows: Vec::with_capacity(8),
            window_count: 0,
            mapped_page_count: 0,
            pml4_count: 0,
            pdpt_count: 0,
            page_directory_count: 0,
            stack_page_count: 0,
        }
    }

    pub fn from_load_plan(load_plan: &UserImageLoadPlan) -> Option<Self> {
        let mut spec = Self::empty();

        // Enforce the loader contract up front: image, normal stack, exception
        // stack, and both guard gaps must stay in the lower canonical range and
        // follow the fixed adjacency/alignment layout expected by user mode.
        if !is_lower_canonical_user_range(load_plan.image_start, load_plan.image_end)
            || !is_lower_canonical_user_range(
                load_plan.stack_guard_start,
                load_plan.stack_guard_end,
            )
            || !is_lower_canonical_user_range(load_plan.stack_bottom, load_plan.stack_top)
            || !is_lower_canonical_user_range(
                load_plan.exception_stack_guard_start,
                load_plan.exception_stack_guard_end,
            )
            || !is_lower_canonical_user_range(
                load_plan.exception_stack_bottom,
                load_plan.exception_stack_top,
            )
        {
            return None;
        }

        if !load_plan.has_consistent_runtime_layout() {
            return None;
        }

        for segment in &load_plan.segments {
            if !is_lower_canonical_user_range(segment.page_start, segment.page_end) {
                return None;
            }

            spec.map_region(
                segment.page_start,
                segment.page_end,
                segment.permissions,
                UserRegionKind::Image,
            )?;
        }

        // Guard pages stay intentionally unmapped; only the usable stack spans
        // become writable user-stack mappings.
        spec.map_region(
            load_plan.stack_bottom,
            load_plan.stack_top,
            PagePermissions::READ_WRITE,
            UserRegionKind::Stack,
        )?;
        spec.map_region(
            load_plan.exception_stack_bottom,
            load_plan.exception_stack_top,
            PagePermissions::READ_WRITE,
            UserRegionKind::Stack,
        )?;

        spec.pml4_count = count_unique_usize_values(spec.windows.iter().map(|w| w.pml4_index));
        spec.pdpt_count =
            count_unique_pair_values(spec.windows.iter().map(|w| (w.pml4_index, w.pdpt_index)));
        spec.page_directory_count = count_unique_triple_values(
            spec.windows
                .iter()
                .map(|w| (w.pml4_index, w.pdpt_index, w.page_directory_index)),
        );

        Some(spec)
    }

    pub fn lookup(&self, address: usize) -> Option<UserPageMapping> {
        let base_address = align_down(address, PAGE_DIRECTORY_WINDOW_SIZE);
        let window = self
            .windows
            .iter()
            .find(|window| window.base_address == base_address)?;
        user_page_mapping_from_entry(window.entries[page_table_index(address)])
    }

    pub const fn window_count(&self) -> usize {
        self.window_count
    }

    pub const fn mapped_page_count(&self) -> usize {
        self.mapped_page_count
    }

    pub const fn pml4_count(&self) -> usize {
        self.pml4_count
    }

    pub const fn pdpt_count(&self) -> usize {
        self.pdpt_count
    }

    pub const fn page_directory_count(&self) -> usize {
        self.page_directory_count
    }

    pub const fn stack_page_count(&self) -> usize {
        self.stack_page_count
    }

    fn map_region(
        &mut self,
        start: usize,
        end: usize,
        permissions: PagePermissions,
        kind: UserRegionKind,
    ) -> Option<()> {
        if start >= end || !is_page_aligned(start) || !is_page_aligned(end) {
            return None;
        }

        let mut address = start;
        while address < end {
            self.map_page(address, permissions, kind)?;
            address = address.checked_add(X86_PAGE_SIZE)?;
        }

        Some(())
    }

    fn map_page(
        &mut self,
        address: usize,
        permissions: PagePermissions,
        kind: UserRegionKind,
    ) -> Option<()> {
        let entry = user_page_entry(permissions, kind);
        let window = self.ensure_window(address)?;
        let slot = &mut window.entries[page_table_index(address)];

        if *slot & PAGE_ENTRY_PRESENT != 0 {
            // Multi-segment ELFs may place different LOAD segments on the same
            // page (e.g. an R+X text segment and a trailing R rodata segment
            // that starts mid-page).  Merge the permissions upward and keep
            // the first-assigned region kind; the page-table mapper already
            // uses the union of flags for shared pages.
            let existing = user_page_mapping_from_entry(*slot)?;
            let mut merged = existing.permissions;
            if permissions.contains(PagePermissions::WRITE) {
                merged = if merged.contains(PagePermissions::EXECUTE) {
                    PagePermissions::READ_WRITE_EXECUTE
                } else {
                    PagePermissions::READ_WRITE
                };
            }
            if permissions.contains(PagePermissions::EXECUTE)
                && !merged.contains(PagePermissions::EXECUTE)
            {
                merged = if merged.contains(PagePermissions::WRITE) {
                    PagePermissions::READ_WRITE_EXECUTE
                } else {
                    PagePermissions::READ_EXECUTE
                };
            }
            // READ is always implied for user pages.
            if merged != existing.permissions {
                *slot = user_page_entry(merged, existing.kind);
            }
            return Some(());
        }

        *slot = entry;
        self.mapped_page_count += 1;
        if kind == UserRegionKind::Stack {
            self.stack_page_count += 1;
        }

        Some(())
    }

    fn ensure_window(&mut self, address: usize) -> Option<&mut UserPageTableWindowSpec> {
        if !is_lower_canonical_user_address(address) {
            return None;
        }

        // One window tracks one 2 MiB PT slice. The counts derived from these
        // windows feed the later address-space summary and table allocation.
        let base_address = align_down(address, PAGE_DIRECTORY_WINDOW_SIZE);
        if let Some(index) = self
            .windows
            .iter()
            .position(|window| window.base_address == base_address)
        {
            return self.windows.get_mut(index);
        }

        if self.windows.len() >= MAX_USER_PT_WINDOWS {
            return None;
        }

        let spec = UserPageTableWindowSpec::new(base_address)?;
        self.windows.push(spec);
        self.window_count += 1;
        self.windows.last_mut()
    }
}
pub(crate) fn materialize_user_pages(
    spec: &UserAddressSpacePageTableSpec,
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Option<Vec<PreparedUserPage>> {
    let mut pages = Vec::with_capacity(spec.mapped_page_count());

    for window in &spec.windows {
        let mut address = window.base_address;
        for entry in window.entries.iter() {
            if let Some(mapping) = user_page_mapping_from_entry(*entry) {
                let mut frame = RawPageFrame::new_boxed_zeroed();
                if mapping.kind == UserRegionKind::Image {
                    populate_user_image_page(frame.as_mut(), address, load_plan, image)?;
                }

                pages.push(PreparedUserPage {
                    virtual_address: address,
                    permissions: mapping.permissions,
                    kind: mapping.kind,
                    frame,
                });
            }

            address = address.checked_add(X86_PAGE_SIZE)?;
        }
    }

    Some(pages)
}

pub(crate) fn populate_user_image_page(
    frame: &mut RawPageFrame,
    page_start: usize,
    load_plan: &UserImageLoadPlan,
    image: &[u8],
) -> Option<()> {
    let segment = load_plan
        .segments
        .iter()
        .find(|segment| page_start >= segment.page_start && page_start < segment.page_end)?;
    let page_end = page_start.checked_add(X86_PAGE_SIZE)?;
    let copy_start = segment.virtual_start.max(page_start);
    let copy_end = page_end.min(segment.zero_start);

    if copy_start < copy_end {
        let copy_offset = copy_start.checked_sub(segment.virtual_start)?;
        let src_start = segment.file_offset.checked_add(copy_offset)?;
        let copy_len = copy_end.checked_sub(copy_start)?;
        let src_end = src_start.checked_add(copy_len)?;
        let source = image.get(src_start..src_end)?;
        let dst_start = copy_start.checked_sub(page_start)?;
        let dst_end = dst_start.checked_add(copy_len)?;
        frame.0.get_mut(dst_start..dst_end)?.copy_from_slice(source);
    }

    Some(())
}

pub(crate) fn user_page_entry(permissions: PagePermissions, kind: UserRegionKind) -> u64 {
    let mut entry = PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER;

    if permissions.contains(PagePermissions::WRITE) {
        entry |= PAGE_ENTRY_WRITABLE;
    }
    if !permissions.contains(PagePermissions::EXECUTE) {
        entry |= PAGE_ENTRY_NO_EXECUTE;
    }
    if kind == UserRegionKind::Stack {
        entry |= USER_PAGE_ENTRY_STACK;
    }

    entry
}

pub(crate) fn user_page_frame_entry(
    physical_address: usize,
    permissions: PagePermissions,
    kind: UserRegionKind,
) -> u64 {
    let mut entry = (align_down(physical_address, X86_PAGE_SIZE) as u64) & PAGE_ENTRY_ADDRESS_MASK;
    entry |= user_page_entry(permissions, kind);
    entry
}

pub(crate) fn user_page_mapping_from_entry(entry: u64) -> Option<UserPageMapping> {
    if entry & PAGE_ENTRY_PRESENT == 0 {
        return None;
    }

    Some(UserPageMapping {
        permissions: permissions_from_page_entry(entry),
        kind: if entry & USER_PAGE_ENTRY_STACK != 0 {
            UserRegionKind::Stack
        } else {
            UserRegionKind::Image
        },
    })
}

pub(crate) fn process_region_kind_from_entry(entry: u64) -> ProcessRegionKind {
    if entry & PAGE_ENTRY_USER == 0 {
        ProcessRegionKind::Kernel
    } else if entry & USER_PAGE_ENTRY_STACK != 0 {
        ProcessRegionKind::UserStack
    } else {
        ProcessRegionKind::UserImage
    }
}

pub(crate) fn ensure_prepared_pdpt(pdpts: &mut Vec<PreparedUserPdpt>, pml4_index: usize) {
    if pdpts.iter().any(|pdpt| pdpt.pml4_index == pml4_index) {
        return;
    }

    pdpts.push(PreparedUserPdpt {
        pml4_index,
        table: RawPageTable::new_boxed_zeroed(),
    });
}

pub(crate) fn ensure_prepared_pd(
    pds: &mut Vec<PreparedUserPd>,
    pml4_index: usize,
    pdpt_index: usize,
) {
    if pds
        .iter()
        .any(|pd| pd.pml4_index == pml4_index && pd.pdpt_index == pdpt_index)
    {
        return;
    }

    pds.push(PreparedUserPd {
        pml4_index,
        pdpt_index,
        table: RawPageTable::new_boxed_zeroed(),
    });
}

pub(crate) fn find_prepared_pdpt_mut(
    pdpts: &mut [PreparedUserPdpt],
    pml4_index: usize,
) -> Option<&mut PreparedUserPdpt> {
    pdpts.iter_mut().find(|pdpt| pdpt.pml4_index == pml4_index)
}

pub(crate) fn find_prepared_pd_mut(
    pds: &mut [PreparedUserPd],
    pml4_index: usize,
    pdpt_index: usize,
) -> Option<&mut PreparedUserPd> {
    pds.iter_mut()
        .find(|pd| pd.pml4_index == pml4_index && pd.pdpt_index == pdpt_index)
}

pub(crate) fn ensure_prepared_pt(
    pts: &mut Vec<PreparedUserPt>,
    pml4_index: usize,
    pdpt_index: usize,
    page_directory_index: usize,
) {
    if pts.iter().any(|pt| {
        pt.pml4_index == pml4_index
            && pt.pdpt_index == pdpt_index
            && pt.page_directory_index == page_directory_index
    }) {
        return;
    }

    pts.push(PreparedUserPt {
        pml4_index,
        pdpt_index,
        page_directory_index,
        table: RawPageTable::new_boxed_zeroed(),
    });
}

pub(crate) fn find_prepared_pt_mut(
    pts: &mut [PreparedUserPt],
    pml4_index: usize,
    pdpt_index: usize,
    page_directory_index: usize,
) -> Option<&mut PreparedUserPt> {
    pts.iter_mut().find(|pt| {
        pt.pml4_index == pml4_index
            && pt.pdpt_index == pdpt_index
            && pt.page_directory_index == page_directory_index
    })
}

pub(crate) fn find_prepared_user_page(
    pages: &[PreparedUserPage],
    virtual_address: usize,
) -> Option<&PreparedUserPage> {
    pages
        .iter()
        .find(|page| page.virtual_address == virtual_address)
}

pub(crate) fn count_unique_usize_values(values: impl Iterator<Item = usize>) -> usize {
    let mut seen = [None; MAX_USER_PT_WINDOWS];
    let mut count = 0;

    for value in values {
        if seen.iter().flatten().any(|existing| *existing == value) {
            continue;
        }

        if let Some(slot) = seen.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(value);
            count += 1;
        }
    }

    count
}

pub(crate) fn count_unique_pair_values(values: impl Iterator<Item = (usize, usize)>) -> usize {
    let mut seen = [None; MAX_USER_PT_WINDOWS];
    let mut count = 0;

    for value in values {
        if seen.iter().flatten().any(|existing| *existing == value) {
            continue;
        }

        if let Some(slot) = seen.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(value);
            count += 1;
        }
    }

    count
}

pub(crate) fn count_unique_triple_values(
    values: impl Iterator<Item = (usize, usize, usize)>,
) -> usize {
    let mut seen = [None; MAX_USER_PT_WINDOWS];
    let mut count = 0;

    for value in values {
        if seen.iter().flatten().any(|existing| *existing == value) {
            continue;
        }

        if let Some(slot) = seen.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(value);
            count += 1;
        }
    }

    count
}
