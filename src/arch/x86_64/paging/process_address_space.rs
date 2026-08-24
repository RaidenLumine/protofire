//! src/arch/x86_64/paging/process_address_space.rs
//!
//! x86_64 process address-space assembly: merge kernel and user
//! page tables into a single hierarchy for CR3 load.

use super::*;
use crate::kernel::memory::paging::PagePermissions;
use crate::println;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct PreparedProcessAddressSpace {
    pub(crate) summary: PreparedProcessAddressSpaceSummary,
    pub(crate) pml4: Box<RawPageTable>,
    pub(crate) pdpts: Vec<PreparedUserPdpt>,
    pub(crate) pds: Vec<PreparedUserPd>,
    pub(crate) pts: Vec<PreparedUserPt>,
    pub(crate) user_address_space: PreparedUserAddressSpace,
}

impl PreparedProcessAddressSpace {
    pub(crate) fn from_kernel_spec_and_user_address_space(
        kernel_spec: &KernelPageTableSpec,
        user_address_space: PreparedUserAddressSpace,
    ) -> Option<Self> {
        let mut pml4 = RawPageTable::new_boxed_zeroed();
        let mut pdpts = Vec::new();
        let mut pds = Vec::new();
        let mut pts = Vec::new();

        // A process address space is the runtime kernel mapping plus the
        // per-process user image/stack mappings in one merged hierarchy.
        for window in &kernel_spec.windows {
            install_process_kernel_window(&mut pdpts, &mut pds, &mut pts, window)?;
        }

        for window in &user_address_space.spec.windows {
            install_process_user_window(
                &mut pdpts,
                &mut pds,
                &mut pts,
                &user_address_space.pages,
                window,
            )?;
        }

        for pt in &pts {
            let pd = find_prepared_pd_mut(&mut pds, pt.pml4_index, pt.pdpt_index)?;
            pd.table.0[pt.page_directory_index] = user_table_pointer_entry(pt.address());
        }

        for pd in &pds {
            let pdpt = find_prepared_pdpt_mut(&mut pdpts, pd.pml4_index)?;
            pdpt.table.0[pd.pdpt_index] = user_table_pointer_entry(pd.address());
        }

        for pdpt in &pdpts {
            pml4.0[pdpt.pml4_index] = user_table_pointer_entry(pdpt.address());
        }

        let summary = PreparedProcessAddressSpaceSummary {
            root_table_address: pml4.as_ref() as *const RawPageTable as usize,
            mapped_page_count: kernel_spec.mapped_page_count()
                + user_address_space.mapped_page_count(),
            kernel_page_count: kernel_spec.mapped_page_count(),
            user_page_count: user_address_space.mapped_page_count(),
            table_page_count: 1 + pdpts.len() + pds.len() + pts.len(),
            pml4_entry_count: pml4
                .0
                .iter()
                .filter(|entry| **entry & PAGE_ENTRY_PRESENT != 0)
                .count(),
            pdpt_count: pdpts.len(),
            page_directory_count: pds.len(),
            page_table_count: pts.len(),
        };

        // Validate kernel/user page-table boundary invariants before
        // returning the prepared address space.  Catches bugs where a
        // kernel PTE accidentally gains the USER bit or a user PTE
        // accidentally gains the GLOBAL bit.
        validate_prepared_process_address_space(&pts, &user_address_space)?;

        Some(Self {
            summary,
            pml4,
            pdpts,
            pds,
            pts,
            user_address_space,
        })
    }

    pub fn summary(&self) -> PreparedProcessAddressSpaceSummary {
        self.summary
    }

    pub fn root_table_address(&self) -> usize {
        self.summary.root_table_address
    }

    pub fn user_address_space_summary(&self) -> PreparedUserAddressSpaceSummary {
        self.user_address_space.summary()
    }

    pub fn user_root_table_address(&self) -> usize {
        self.user_address_space.root_table_address()
    }

    /// Return `(virtual_address, physical_address, permissions)` for every
    /// user page in this address space.
    pub fn user_page_entries(&self) -> Vec<(usize, usize, PagePermissions)> {
        self.user_address_space.user_page_entries()
    }

    /// Return the virtual address range `(start, end_exclusive)` covering all
    /// user pages in this address space, or `None` when there are no pages.
    pub fn user_page_va_range(&self) -> Option<(usize, usize)> {
        self.user_address_space.user_page_va_range()
    }

    /// Mark a single user page as NOT PRESENT in the prepared page tables
    /// and release its backing physical frame.
    ///
    /// Returns the physical address that was previously mapped, or `None` if
    /// the virtual address does not resolve to a present user page.
    pub fn mark_user_page_not_present(&mut self, virtual_address: usize) -> Option<usize> {
        let page_addr = align_down(virtual_address, X86_PAGE_SIZE);

        // Walk the combined page-table hierarchy to find the PTE.
        let pml4_entry = self.pml4.0[pml4_index(page_addr)];
        if pml4_entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }
        let pdpt_addr = (pml4_entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);
        let pdpt = self.pdpts.iter().find(|t| t.address() == pdpt_addr)?;
        let pdpt_entry = pdpt.table.0[page_directory_pointer_index(page_addr)];
        if pdpt_entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }
        let pd_addr = (pdpt_entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);
        let pd = self.pds.iter().find(|t| t.address() == pd_addr)?;
        let pd_entry = pd.table.0[page_directory_slot_index(page_addr)];
        if pd_entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }
        let pt_addr = (pd_entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);
        let pt = self.pts.iter().find(|t| t.address() == pt_addr)?;
        let pte_index = page_table_index(page_addr);
        let entry = pt.table.0[pte_index];
        if entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }
        // Only operate on user pages (USER bit set).
        if entry & PAGE_ENTRY_USER == 0 {
            return None;
        }

        let old_phys = (entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);

        // Clear the PRESENT bit (and the physical address for cleanliness).
        // We need mutable access to the pt – re-find it mutably.
        let pt_mut = self.pts.iter_mut().find(|t| t.address() == pt_addr)?;
        pt_mut.table.0[pte_index] = entry & !PAGE_ENTRY_PRESENT & !PAGE_ENTRY_ADDRESS_MASK;

        // Release the backing frame by removing it from the user address space.
        let page_idx = self
            .user_address_space
            .pages
            .iter()
            .position(|p| p.virtual_address == page_addr)?;
        self.user_address_space.pages.remove(page_idx);

        // Also clear the PTE in the user-only hierarchy so translation
        // helpers stay consistent.
        if let Some(user_pt_mut) = self.user_address_space.pts.iter_mut().find(|t| {
            t.pml4_index == pt_mut.pml4_index
                && t.pdpt_index == pt_mut.pdpt_index
                && t.page_directory_index == pt_mut.page_directory_index
        }) {
            user_pt_mut.table.0[pte_index] =
                user_pt_mut.table.0[pte_index] & !PAGE_ENTRY_PRESENT & !PAGE_ENTRY_ADDRESS_MASK;
        }

        // Update summary counts.
        self.summary.user_page_count = self.summary.user_page_count.saturating_sub(1);
        self.summary.mapped_page_count = self.summary.mapped_page_count.saturating_sub(1);

        Some(old_phys)
    }

    /// Clone this address space for fork(), marking writable user pages as
    /// read-only in both the parent (`self`) and the returned child clone.
    ///
    /// Returns `(child_address_space, shared_cow_pages, all_child_pages)`
    /// where:
    /// - `shared_cow_pages` lists `(va, pa, perms)` for pages now shared CoW
    /// - `all_child_pages` lists `(va, pa, perms)` for every user page in
    ///   the child's address space (for software page-table registration)
    #[allow(clippy::type_complexity)]
    pub fn fork_clone(
        &mut self,
    ) -> Option<(
        PreparedProcessAddressSpace,
        Vec<(usize, usize, PagePermissions)>,
        Vec<(usize, usize, PagePermissions)>,
    )> {
        use alloc::collections::BTreeMap;

        // ── First pass: collect user PTE groups and record shared pages ──
        let mut user_windows: BTreeMap<(usize, usize, usize), Vec<(usize, u64)>> = BTreeMap::new();
        let mut shared_pages: Vec<(usize, usize, PagePermissions)> = Vec::new();
        let mut all_child_pages: Vec<(usize, usize, PagePermissions)> = Vec::new();
        let mut user_page_count = 0usize;
        let mut image_page_count = 0usize;
        let mut stack_page_count = 0usize;

        // Collect unique (pml4, pdpt, pd) keys for summary stats.
        let mut pml4_indices: [Option<usize>; 64] = [None; 64];
        let mut pml4_count = 0usize;
        let mut pdpt_pairs: [Option<(usize, usize)>; 64] = [None; 64];
        let mut pdpt_count = 0usize;
        let mut pd_triples: [Option<(usize, usize, usize)>; 64] = [None; 64];
        let mut pd_count = 0usize;

        for pt in &self.pts {
            let key = (pt.pml4_index, pt.pdpt_index, pt.page_directory_index);

            // Track unique indices for summary.
            if !pml4_indices.iter().flatten().any(|&i| i == pt.pml4_index) {
                if let Some(slot) = pml4_indices.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(pt.pml4_index);
                    pml4_count += 1;
                }
            }
            let pair = (pt.pml4_index, pt.pdpt_index);
            if !pdpt_pairs.iter().flatten().any(|&p| p == pair) {
                if let Some(slot) = pdpt_pairs.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(pair);
                    pdpt_count += 1;
                }
            }
            let triple = (pt.pml4_index, pt.pdpt_index, pt.page_directory_index);
            if !pd_triples.iter().flatten().any(|&t| t == triple) {
                if let Some(slot) = pd_triples.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(triple);
                    pd_count += 1;
                }
            }

            for (pte_index, &entry) in pt.table.0.iter().enumerate() {
                if entry & (PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER)
                    != PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER
                {
                    continue;
                }

                user_page_count += 1;
                if entry & USER_PAGE_ENTRY_STACK != 0 {
                    stack_page_count += 1;
                } else {
                    image_page_count += 1;
                }

                let is_writable = entry & PAGE_ENTRY_WRITABLE != 0;
                // Compute virtual address from page-table indices.
                let va = (pt.pml4_index << 39)
                    | (pt.pdpt_index << 30)
                    | (pt.page_directory_index << 21)
                    | (pte_index << 12);

                let child_entry = if is_writable {
                    let phys = (entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);
                    shared_pages.push((va, phys, PagePermissions::READ));
                    entry & !PAGE_ENTRY_WRITABLE
                } else {
                    entry
                };

                // Record for child software page-table registration.
                let child_perms = permissions_from_page_entry(child_entry);
                let child_phys = (child_entry as usize) & (PAGE_ENTRY_ADDRESS_MASK as usize);
                all_child_pages.push((va, child_phys, child_perms));

                user_windows
                    .entry(key)
                    .or_default()
                    .push((pte_index, child_entry));
            }
        }

        // ── Second pass: clear WRITE bit in parent's combined hierarchy ──
        for pt in &mut self.pts {
            for pte_index in 0..PAGE_TABLE_ENTRY_COUNT {
                let entry = pt.table.0[pte_index];
                if entry & (PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER | PAGE_ENTRY_WRITABLE)
                    == PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER | PAGE_ENTRY_WRITABLE
                {
                    pt.table.0[pte_index] = entry & !PAGE_ENTRY_WRITABLE;
                }
            }
        }

        // ── Third pass: clear WRITE bit in parent's user-only hierarchy ──
        for pt in &mut self.user_address_space.pts {
            for pte_index in 0..PAGE_TABLE_ENTRY_COUNT {
                let entry = pt.table.0[pte_index];
                if entry & (PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER | PAGE_ENTRY_WRITABLE)
                    == PAGE_ENTRY_PRESENT | PAGE_ENTRY_USER | PAGE_ENTRY_WRITABLE
                {
                    pt.table.0[pte_index] = entry & !PAGE_ENTRY_WRITABLE;
                }
            }
        }

        // Update parent PreparedUserPage permissions to reflect read-only.
        for page in &mut self.user_address_space.pages {
            if page.permissions.contains(PagePermissions::WRITE) {
                page.permissions = PagePermissions::READ;
            }
        }

        // ── Build child address space ────────────────────────────────────

        // --- Child combined hierarchy ---
        let mut child_pml4 = RawPageTable::new_boxed_zeroed();
        let mut child_pdpts: Vec<PreparedUserPdpt> = Vec::new();
        let mut child_pds: Vec<PreparedUserPd> = Vec::new();
        let mut child_pts: Vec<PreparedUserPt> = Vec::new();

        // Deep-copy the ENTIRE merged hierarchy (kernel windows and user
        // windows share one set of tables — in the current layout the kernel
        // identity map at PML4[0]/PDPT[0] and the user image at PML4[0]/PDPT[4]
        // both live under PML4 index 0, so no USER-bit or PML4-index filter can
        // separate them).  The child gets its own table pages so it can be
        // freed independently, while the entries keep the kernel mappings
        // (interrupt and syscall entry run with the child's CR3 active) and
        // the CoW-marked user mappings (pass 2 above already cleared the WRITE
        // bit in `self.pts`, so the copied user PTEs are read-only, matching
        // the per-window rebuild this replaces).  Mirrors aarch64's
        // fork_clone, which clones the whole l1/l2/l3 hierarchy.
        for t in &self.pdpts {
            let mut table = RawPageTable::new_boxed_zeroed();
            table.0.copy_from_slice(&t.table.0);
            child_pdpts.push(PreparedUserPdpt {
                pml4_index: t.pml4_index,
                table,
            });
        }
        for t in &self.pds {
            let mut table = RawPageTable::new_boxed_zeroed();
            table.0.copy_from_slice(&t.table.0);
            child_pds.push(PreparedUserPd {
                pml4_index: t.pml4_index,
                pdpt_index: t.pdpt_index,
                table,
            });
        }
        for t in &self.pts {
            let mut table = RawPageTable::new_boxed_zeroed();
            table.0.copy_from_slice(&t.table.0);
            child_pts.push(PreparedUserPt {
                pml4_index: t.pml4_index,
                pdpt_index: t.pdpt_index,
                page_directory_index: t.page_directory_index,
                table,
            });
        }

        // Copy the parent's PML4 entries (kernel + user) so the child's
        // top-level table keeps every mapping.  The wiring loops below
        // re-point each child pdpt/pd/pt to its own copied table address.
        child_pml4.0.copy_from_slice(&self.pml4.0);

        // Wire PD → PT pointers.
        for pt in &child_pts {
            let pd = find_prepared_pd_mut(&mut child_pds, pt.pml4_index, pt.pdpt_index)?;
            pd.table.0[pt.page_directory_index] = user_table_pointer_entry(pt.address());
        }

        // Wire PDPT → PD pointers.
        for pd in &child_pds {
            let pdpt = find_prepared_pdpt_mut(&mut child_pdpts, pd.pml4_index)?;
            pdpt.table.0[pd.pdpt_index] = user_table_pointer_entry(pd.address());
        }

        // Wire PML4 → PDPT pointers.
        for pdpt in &child_pdpts {
            child_pml4.0[pdpt.pml4_index] = user_table_pointer_entry(pdpt.address());
        }

        let table_page_count = 1 + child_pdpts.len() + child_pds.len() + child_pts.len();

        let child_summary = PreparedProcessAddressSpaceSummary {
            root_table_address: child_pml4.as_ref() as *const RawPageTable as usize,
            mapped_page_count: self.summary.kernel_page_count + user_page_count,
            kernel_page_count: self.summary.kernel_page_count,
            user_page_count,
            table_page_count,
            pml4_entry_count: child_pml4
                .0
                .iter()
                .filter(|entry| **entry & PAGE_ENTRY_PRESENT != 0)
                .count(),
            pdpt_count: child_pdpts.len(),
            page_directory_count: child_pds.len(),
            page_table_count: child_pts.len(),
        };

        // --- Child user-only hierarchy (mirror of combined user portion) ---
        let mut child_user_pml4 = RawPageTable::new_boxed_zeroed();
        let mut child_user_pdpts: Vec<PreparedUserPdpt> = Vec::new();
        let mut child_user_pds: Vec<PreparedUserPd> = Vec::new();
        let mut child_user_pts: Vec<PreparedUserPt> = Vec::new();

        for ((pml4_idx, pdpt_idx, pd_idx), ptes) in &user_windows {
            // The user-only hierarchy uses its own pdpts/pds/pts.
            ensure_prepared_pdpt(&mut child_user_pdpts, *pml4_idx);
            ensure_prepared_pd(&mut child_user_pds, *pml4_idx, *pdpt_idx);

            let pd = find_prepared_pd_mut(&mut child_user_pds, *pml4_idx, *pdpt_idx)?;

            let mut user_pt = PreparedUserPt {
                pml4_index: *pml4_idx,
                pdpt_index: *pdpt_idx,
                page_directory_index: *pd_idx,
                table: RawPageTable::new_boxed_zeroed(),
            };

            for &(pte_index, entry) in ptes {
                user_pt.table.0[pte_index] = entry;
            }

            pd.table.0[*pd_idx] = user_table_pointer_entry(user_pt.address());
            child_user_pts.push(user_pt);
        }

        // Wire user-only PDPTs → PDs.
        for pd in &child_user_pds {
            let pdpt = child_user_pdpts
                .iter_mut()
                .find(|p| p.pml4_index == pd.pml4_index)?;
            pdpt.table.0[pd.pdpt_index] = user_table_pointer_entry(pd.address());
        }

        // Wire user-only PML4 → PDPTs.
        for pdpt in &child_user_pdpts {
            child_user_pml4.0[pdpt.pml4_index] = user_table_pointer_entry(pdpt.address());
        }

        let child_user_summary = PreparedUserAddressSpaceSummary {
            root_table_address: child_user_pml4.as_ref() as *const RawPageTable as usize,
            mapped_page_count: user_page_count,
            image_page_count,
            stack_page_count,
            table_page_count: 1
                + child_user_pdpts.len()
                + child_user_pds.len()
                + child_user_pts.len(),
            pml4_entry_count: pml4_count,
            pdpt_count,
            page_directory_count: pd_count,
            page_table_count: child_user_pts.len(),
        };

        // Build a minimal spec for the child user address space (used only
        // for construction — the spec is never consulted after build).
        let child_user_spec = UserAddressSpacePageTableSpec {
            windows: Vec::new(),
            window_count: 0,
            mapped_page_count: user_page_count,
            pml4_count,
            pdpt_count,
            page_directory_count: pd_count,
            stack_page_count,
        };

        let child_user_address_space = PreparedUserAddressSpace {
            spec: Box::new(child_user_spec),
            summary: child_user_summary,
            pml4: child_user_pml4,
            pdpts: child_user_pdpts,
            pds: child_user_pds,
            pts: child_user_pts,
            pages: Vec::new(), // frames are shared — child owns no frames
        };

        let child = PreparedProcessAddressSpace {
            summary: child_summary,
            pml4: child_pml4,
            pdpts: child_pdpts,
            pds: child_pds,
            pts: child_pts,
            user_address_space: child_user_address_space,
        };

        Some((child, shared_pages, all_child_pages))
    }

    /// Remove a user page frame from the page list, leaking the underlying
    /// `Box<RawPageFrame>` so ownership can transfer to the frame refcount
    /// table for Copy-on-Write sharing.
    ///
    /// Returns the physical address of the removed frame, or `None` if no
    /// page at the given virtual address exists.
    pub fn remove_user_page_frame(&mut self, virtual_address: usize) -> Option<usize> {
        let page_addr = align_down(virtual_address, X86_PAGE_SIZE);
        let idx = self
            .user_address_space
            .pages
            .iter()
            .position(|p| p.virtual_address == page_addr)?;
        let page = self.user_address_space.pages.remove(idx);
        let phys = page.physical_address();
        // Leak the Box so the refcount table in MemoryManager owns the frame.
        let _ = core::mem::ManuallyDrop::new(page.frame);
        Some(phys)
    }

    pub fn translate(&self, address: usize) -> Option<PreparedProcessTranslation> {
        let pml4 = self.pml4.0[pml4_index(address)];
        if pml4 & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }

        let pdpt = self
            .pdpts
            .iter()
            .find(|table| table.address() == (pml4 as usize & PAGE_ENTRY_ADDRESS_MASK as usize))?;
        let pdpt_entry = pdpt.table.0[page_directory_pointer_index(address)];
        if pdpt_entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }

        let pd = self.pds.iter().find(|table| {
            table.address() == (pdpt_entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
        })?;
        let pd_entry = pd.table.0[page_directory_slot_index(address)];
        if pd_entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }

        let pt = self.pts.iter().find(|table| {
            table.address() == (pd_entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
        })?;
        let entry = pt.table.0[page_table_index(address)];
        if entry & PAGE_ENTRY_PRESENT == 0 {
            return None;
        }

        Some(PreparedProcessTranslation {
            physical_address: (entry as usize & PAGE_ENTRY_ADDRESS_MASK as usize)
                + page_offset(address),
            permissions: permissions_from_page_entry(entry),
            kind: process_region_kind_from_entry(entry),
        })
    }

    pub fn translate_user(&self, address: usize) -> Option<PreparedUserTranslation> {
        let translation = self.translate(address)?;
        let kind = match translation.kind {
            ProcessRegionKind::Kernel => return None,
            ProcessRegionKind::UserImage => UserRegionKind::Image,
            ProcessRegionKind::UserStack => UserRegionKind::Stack,
        };

        Some(PreparedUserTranslation {
            physical_address: translation.physical_address,
            permissions: translation.permissions,
            kind,
        })
    }

    pub fn read_byte(&self, address: usize) -> Option<u8> {
        match self.translate(address)?.kind {
            ProcessRegionKind::Kernel => None,
            ProcessRegionKind::UserImage | ProcessRegionKind::UserStack => {
                self.user_address_space.read_byte(address)
            }
        }
    }

    pub fn write_user_bytes(&mut self, address: usize, bytes: &[u8]) -> Option<()> {
        self.user_address_space.write_bytes(address, bytes)
    }

    pub fn table_page_count(&self) -> usize {
        1 + self.pdpts.len() + self.pds.len() + self.pts.len()
    }

    pub fn mapped_page_count(&self) -> usize {
        self.summary.mapped_page_count
    }

    pub fn root_entry_count(&self) -> usize {
        self.pml4
            .0
            .iter()
            .filter(|entry| **entry & PAGE_ENTRY_PRESENT != 0)
            .count()
    }

    pub fn activate(&self) -> Option<ActivatedProcessAddressSpace> {
        activate_prepared_process_address_space_impl(self)
    }
}

impl Drop for PreparedProcessAddressSpace {
    fn drop(&mut self) {
        println!(
            "[MMU   ] dropping prepared process address space root={:#018x} mapped={} kernel={} user={} tables={}",
            self.summary.root_table_address,
            self.summary.mapped_page_count,
            self.summary.kernel_page_count,
            self.summary.user_page_count,
            self.summary.table_page_count,
        );
        // Switch CR3 back to the kernel page tables *before* the
        // Box<RawPageTable> fields (pml4, pdpts, pds, pts) are dropped,
        // so that no TLB walk can encounter freed page-table memory.
        // See the aarch64 mmu.rs counterpart for a detailed explanation
        // of why this early switch is necessary.
        //
        // Only switch when the dying tables are the currently active ones
        // (self-termination).  When a parent process reaps a child via
        // wait(2), the parent's page tables are active and must not be
        // disturbed.
        let self_root = self.summary.root_table_address;
        if current_root_table_address_impl() == Some(self_root) {
            let _ = activate_prepared_runtime_kernel_page_tables();
        }
        // Fields are dropped automatically in reverse declaration order by the
        // compiler: user_address_space, pts, pds, pdpts, pml4, summary.
        // Box<RawPageTable> and Vec<PreparedUser*> heap allocations are
        // freed by their own Drop impls.
    }
}

/// Validate kernel/user page-table boundary invariants.
///
/// Returns `None` (causing address-space construction to fail) if any
/// invariant is violated:
///
/// 1. No user-accessible PTE may carry the GLOBAL bit — GLOBAL pages
///    survive CR3 switches and would leak data between address spaces.
/// 2. Every user-mapped virtual address must reside in the lower
///    canonical half (`< X86_64_USER_CANONICAL_END`).
pub(crate) fn validate_prepared_process_address_space(
    pts: &[PreparedUserPt],
    user_address_space: &PreparedUserAddressSpace,
) -> Option<()> {
    // ── 1. Global-bit check across all merged PT entries ──────────────
    for pt in pts {
        for &entry in &pt.table.0 {
            if entry & PAGE_ENTRY_PRESENT == 0 {
                continue;
            }
            if entry & PAGE_ENTRY_USER != 0 && entry & PAGE_ENTRY_GLOBAL != 0 {
                return None;
            }
        }
    }

    // ── 2. User virtual-address canonical-range check ────────────────
    for page in &user_address_space.pages {
        if page.virtual_address >= X86_64_USER_CANONICAL_END {
            return None;
        }
    }

    Some(())
}
pub(crate) fn install_process_kernel_window(
    pdpts: &mut Vec<PreparedUserPdpt>,
    pds: &mut Vec<PreparedUserPd>,
    pts: &mut Vec<PreparedUserPt>,
    window: &PageTableWindowSpec,
) -> Option<()> {
    let pml4_index = pml4_index(window.base_address);
    let pdpt_index = page_directory_pointer_index(window.base_address);

    ensure_prepared_pdpt(pdpts, pml4_index);
    ensure_prepared_pd(pds, pml4_index, pdpt_index);
    ensure_prepared_pt(pts, pml4_index, pdpt_index, window.page_directory_index);

    let pt = find_prepared_pt_mut(pts, pml4_index, pdpt_index, window.page_directory_index)?;
    for (index, entry) in window.entries.iter().enumerate() {
        if *entry & PAGE_ENTRY_PRESENT == 0 {
            continue;
        }

        if pt.table.0[index] & PAGE_ENTRY_PRESENT != 0 {
            return None;
        }

        pt.table.0[index] = *entry;
    }

    Some(())
}

pub(crate) fn install_process_user_window(
    pdpts: &mut Vec<PreparedUserPdpt>,
    pds: &mut Vec<PreparedUserPd>,
    pts: &mut Vec<PreparedUserPt>,
    pages: &[PreparedUserPage],
    window: &UserPageTableWindowSpec,
) -> Option<()> {
    ensure_prepared_pdpt(pdpts, window.pml4_index);
    ensure_prepared_pd(pds, window.pml4_index, window.pdpt_index);
    ensure_prepared_pt(
        pts,
        window.pml4_index,
        window.pdpt_index,
        window.page_directory_index,
    );

    let pt = find_prepared_pt_mut(
        pts,
        window.pml4_index,
        window.pdpt_index,
        window.page_directory_index,
    )?;
    let mut address = window.base_address;

    for (index, entry) in window.entries.iter().enumerate() {
        if let Some(mapping) = user_page_mapping_from_entry(*entry) {
            if pt.table.0[index] & PAGE_ENTRY_PRESENT != 0 {
                return None;
            }

            let page = find_prepared_user_page(pages, address)?;
            pt.table.0[index] =
                user_page_frame_entry(page.physical_address(), mapping.permissions, mapping.kind);
        }

        address = address.checked_add(X86_PAGE_SIZE)?;
    }

    Some(())
}
pub(crate) fn activate_prepared_process_address_space_impl(
    address_space: &PreparedProcessAddressSpace,
) -> Option<ActivatedProcessAddressSpace> {
    let previous_root_table_address = current_root_table_address_impl()?;
    let already_active = previous_root_table_address == address_space.root_table_address();

    if !already_active {
        install_active_root_table_address_impl(address_space.root_table_address())?;
    }

    Some(ActivatedProcessAddressSpace {
        previous_root_table_address,
        active_root_table_address: current_root_table_address_impl()?,
        mapped_page_count: address_space.summary.mapped_page_count,
        kernel_page_count: address_space.summary.kernel_page_count,
        user_page_count: address_space.summary.user_page_count,
        table_page_count: address_space.summary.table_page_count,
        already_active,
    })
}
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn build_active_runtime_kernel_page_table_check(
    root_table_address: usize,
    plan: &KernelPagePlan,
    spec: &KernelPageTableSpec,
    instruction_pointer: usize,
    stack_pointer: usize,
    heap_pointer: usize,
) -> Option<ActiveRuntimeKernelPageTableCheck> {
    Some(ActiveRuntimeKernelPageTableCheck {
        root_table_address,
        instruction_pointer: validate_instruction_pointer_probe(plan, spec, instruction_pointer)?,
        stack_pointer: validate_stack_pointer_probe(plan, spec, stack_pointer)?,
        heap_pointer: validate_heap_pointer_probe(plan, spec, heap_pointer)?,
    })
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn validate_instruction_pointer_probe(
    plan: &KernelPagePlan,
    spec: &KernelPageTableSpec,
    address: usize,
) -> Option<ActiveKernelAddressProbe> {
    let probe = validate_identity_probe(plan, spec, address)?;
    if probe.kind != PlannedRegionKind::KernelText {
        return None;
    }
    if probe.permissions != PagePermissions::READ_EXECUTE {
        return None;
    }

    Some(probe)
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn validate_stack_pointer_probe(
    plan: &KernelPagePlan,
    spec: &KernelPageTableSpec,
    address: usize,
) -> Option<ActiveKernelAddressProbe> {
    let probe = validate_identity_probe(plan, spec, address)?;
    if !probe.permissions.contains(PagePermissions::WRITE) {
        return None;
    }
    if matches!(
        probe.kind,
        PlannedRegionKind::KernelText | PlannedRegionKind::KernelRodata
    ) {
        return None;
    }

    Some(probe)
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn validate_heap_pointer_probe(
    plan: &KernelPagePlan,
    spec: &KernelPageTableSpec,
    address: usize,
) -> Option<ActiveKernelAddressProbe> {
    let probe = validate_identity_probe(plan, spec, address)?;
    if probe.kind != PlannedRegionKind::KernelHeap {
        return None;
    }
    if !probe.permissions.contains(PagePermissions::WRITE) {
        return None;
    }

    Some(probe)
}

#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn validate_identity_probe(
    plan: &KernelPagePlan,
    spec: &KernelPageTableSpec,
    address: usize,
) -> Option<ActiveKernelAddressProbe> {
    let translation = spec.translate(address)?;
    let region = plan.classify(address)?;

    if translation.physical_address != address {
        return None;
    }

    Some(ActiveKernelAddressProbe {
        virtual_address: address,
        physical_address: translation.physical_address,
        permissions: translation.permissions,
        kind: region.kind,
    })
}

pub(crate) const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

pub(crate) fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|aligned| align_down(aligned, align))
}
