//! src/memory/manager/mapping.rs
//!
//! Address-space mapping operations, diagnostics, user page registration,
//! page table access, and content store.

use alloc::vec::Vec;

use crate::memory::alloc_profiler::AllocProfilerSnapshot;
use crate::memory::fault_profiler::FaultProfilerSnapshot;
use crate::memory::heap;
use crate::memory::paging;
use crate::memory::paging::MappingKind;
use crate::memory::paging::PagePermissions;
use crate::memory::paging::PageTable;
use crate::memory::swap::SwapSlot;
use crate::Result;

use super::super::arch::align_down_page;
use super::super::arch::bootstrap_translation;
use super::super::arch::planned_kernel_region;
use super::super::arch::prepared_page_tables_active;
use super::super::arch::prepared_translation;
use super::super::arch::shootdown_range;
use super::super::diagnostics::AddressTranslation;
use super::super::diagnostics::PageFaultInsight;
use super::MemoryManager;

impl MemoryManager {
    pub fn map_region(
        &mut self,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        self.map_region_with_kind(virtual_address, length, permissions, MappingKind::Anonymous)
    }

    pub fn map_region_with_kind(
        &mut self,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        self.page_table
            .map_region_with_kind(virtual_address, length, permissions, kind)
    }

    /// Map an identity region on behalf of `owner`.
    pub fn map_region_with_kind_owned(
        &mut self,
        owner_root_table: usize,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        self.page_table.map_to_owned(
            owner,
            virtual_address,
            virtual_address,
            length,
            permissions,
            kind,
        )?;
        shootdown_range(virtual_address, length);
        Ok(())
    }

    pub fn map_to(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        length: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        self.map_to_with_kind(
            virtual_address,
            physical_address,
            length,
            permissions,
            MappingKind::Anonymous,
        )
    }

    pub fn map_to_with_kind(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        self.page_table.map_to_with_kind(
            virtual_address,
            physical_address,
            length,
            permissions,
            kind,
        )?;
        // After modifying the virtual address space, invalidate stale TLB
        // entries on all CPUs that may have cached the old mapping.
        shootdown_range(virtual_address, length);
        Ok(())
    }

    pub fn unmap(&mut self, virtual_address: usize, length: usize) -> Result<()> {
        self.page_table.unmap(virtual_address, length)?;
        // After removing a mapping, invalidate stale TLB entries on all CPUs.
        shootdown_range(virtual_address, length);
        Ok(())
    }

    /// Remove `owner`'s mappings in a range, leaving every other address
    /// space's alone.
    pub fn unmap_owned(
        &mut self,
        owner_root_table: usize,
        virtual_address: usize,
        length: usize,
    ) -> Result<()> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        self.page_table
            .unmap_owned(owner, virtual_address, length)?;
        shootdown_range(virtual_address, length);
        Ok(())
    }

    pub fn translate(&self, virtual_address: usize) -> Option<(usize, PagePermissions)> {
        self.page_table.lookup(virtual_address)
    }

    pub fn page_fault_insight(&self, virtual_address: usize) -> PageFaultInsight {
        let (heap_start, heap_end) = self.heap_bounds();
        // Build a layered diagnostic snapshot (runtime table + bootstrap + prepared
        // plans).
        let translation = self.page_table.lookup_mapping(virtual_address).map(
            |(physical_address, permissions, kind)| AddressTranslation {
                physical_address,
                permissions,
                kind,
            },
        );
        let bootstrap_translation = bootstrap_translation(virtual_address);
        let prepared_active = prepared_page_tables_active();
        let prepared_translation = prepared_translation(virtual_address, (heap_start, heap_end));
        let planned_region = planned_kernel_region(virtual_address, (heap_start, heap_end));

        PageFaultInsight {
            in_kernel_heap: (heap_start..heap_end).contains(&virtual_address),
            translation,
            bootstrap_translation,
            prepared_active,
            prepared_translation,
            planned_region,
        }
    }

    pub fn heap_bounds(&self) -> (usize, usize) {
        (self.kernel_heap_start, self.kernel_heap_end)
    }

    /// Return a point-in-time snapshot of all allocator profiler counters
    /// (heap, frame, page table).  When the `alloc_profiler` feature is
    /// disabled this returns all zeros.
    pub fn alloc_profiler_snapshot(&self) -> AllocProfilerSnapshot {
        let mut snapshot = self.frame_allocators[0].profiler.snapshot();
        let page_snap = self.page_table.profiler.snapshot();
        let heap_snap = heap::heap_model().profiler.snapshot();

        // Merge: frame and page-table counters come from the fields on
        // MemoryManager; heap counters come from the global model.
        snapshot.heap_allocs = heap_snap.heap_allocs;
        snapshot.heap_frees = heap_snap.heap_frees;
        snapshot.heap_alloc_scan_steps = heap_snap.heap_alloc_scan_steps;
        snapshot.heap_bytes_allocated = heap_snap.heap_bytes_allocated;
        snapshot.heap_bytes_freed = heap_snap.heap_bytes_freed;
        snapshot.page_table_maps = page_snap.page_table_maps;
        snapshot.page_table_unmaps = page_snap.page_table_unmaps;
        snapshot.page_table_lookups = page_snap.page_table_lookups;
        // frame counters already set from frame_allocators[0].profiler.snapshot()

        snapshot
    }

    /// Return a point-in-time snapshot of the fault profiler counters.
    pub fn fault_profiler_snapshot(&self) -> FaultProfilerSnapshot {
        self.fault_profiler.snapshot()
    }

    // ── register / unregister user pages ─────────────────────────────────
    /// Register a process's user pages in the software page table.
    ///
    /// Each entry is `(virtual_address, physical_address, permissions, kind)`.
    /// The pages must not overlap with mappings *visible to `owner`*: the
    /// kernel's own are visible to every address space, and another process's
    /// are not visible at all.  Existing user mappings that `owner` can see at
    /// the same virtual address are silently replaced (the old one is unmapped
    /// first).
    ///
    /// `owner` is the address space the pages belong to — the root table
    /// address of the hierarchy they were loaded into, which is the number the
    /// hardware will translate through.  Registration happens before that
    /// hierarchy is activated, so the caller passes it in rather than letting
    /// this read the current root, which still names the *previous* process.
    ///
    /// Returns the number of pages successfully registered.
    pub fn register_user_pages(
        &mut self,
        owner_root_table: usize,
        pages: &[(usize, usize, PagePermissions, MappingKind)],
    ) -> usize {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        let mut count = 0;
        for &(va, pa, perms, kind) in pages {
            let page_addr = align_down_page(va);
            // Skip if this would conflict with a kernel mapping, and replace
            // only what this owner can see.
            if let Some((_, _, existing_kind)) =
                self.page_table.lookup_mapping_owned(owner, page_addr)
            {
                match existing_kind {
                    // Kernel state: a user registration must not touch it.
                    // `KernelStack` belongs here for the same reason it is
                    // excluded from the reclaim paths — the kernel writes to a
                    // stack while handling the fault a missing mapping would
                    // raise.
                    MappingKind::KernelHeap
                    | MappingKind::KernelStack
                    | MappingKind::Identity
                    | MappingKind::DeviceMemory => continue,
                    // User-space kinds visible to this owner: unmap the old
                    // entry first.  Scoped to `owner`, so a process replacing
                    // its own mapping leaves every other process's alone.
                    MappingKind::Anonymous
                    | MappingKind::DemandPaged
                    | MappingKind::Cow
                    | MappingKind::Shared
                    | MappingKind::Locked => {
                        let _ = self
                            .page_table
                            .unmap_owned(owner, page_addr, paging::PAGE_SIZE);
                    }
                }
            }
            if self
                .page_table
                .map_to_owned(owner, page_addr, pa, paging::PAGE_SIZE, perms, kind)
                .is_ok()
            {
                count += 1;
            }
        }
        count
    }

    /// Register a single shared-memory page in the software page table.
    ///
    /// Shared pages belong to the address space that attaches the segment, so
    /// an attach in one process cannot collide with another process mapping
    /// the same virtual address.
    pub fn register_shared_page(
        &mut self,
        owner_root_table: usize,
        virtual_address: usize,
        physical_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        let page_addr = align_down_page(virtual_address);
        self.page_table
            .map_to_owned(
                owner,
                page_addr,
                physical_address,
                paging::PAGE_SIZE,
                permissions,
                MappingKind::Shared,
            )
            .map_err(|_| crate::Error::AlreadyExists)
    }

    /// Unregister user pages in a virtual address range from the software page
    /// table, as seen by `owner`.
    ///
    /// Kernel mappings (KernelHeap, KernelStack, Identity, DeviceMemory) are
    /// left untouched, and so is every mapping belonging to another address
    /// space — they may name the same virtual addresses, because every process
    /// maps its image and stack at the same ones.
    ///
    /// For CoW pages this also decrements the shared-frame refcount so
    /// frames are freed when the last owner terminates.
    ///
    /// Returns the number of pages actually removed.
    pub fn unregister_user_page_range(
        &mut self,
        owner_root_table: usize,
        start: usize,
        len: usize,
    ) -> usize {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        let page_start = align_down_page(start);
        let page_end = align_down_page(
            start
                .saturating_add(len)
                .saturating_add(paging::PAGE_SIZE - 1),
        );
        let mut count = 0;

        // The requested range may span an enormous gap: an x86_64 process's
        // image is mapped near the bottom of the 128 TiB user half while its
        // stack sits at `X86_64_USER_STACK_TOP` (~128 TiB), so the range
        // derived from the address space's lowest and highest page covers
        // hundreds of GiB of empty space.  Walking every 4 KiB virtual
        // address in that span — each step doing a linear mapping scan —
        // never finishes, which froze exec/exit mid teardown.  Snapshot the
        // software table instead and operate only on pages that are actually
        // present in the range, preserving the per-page CoW / swap /
        // compressed-page bookkeeping of the previous implementation.
        for mapping in self.page_table.mappings_snapshot() {
            // Another address space's user page is not this process's to
            // release: every process maps its image and stack at the same
            // virtual addresses, so without this check one process's exit
            // would tear down another's mappings.
            if mapping.owner != owner {
                continue;
            }
            let mapping_start = mapping.virtual_address;
            let mapping_end = mapping_start.saturating_add(mapping.length);
            let lo = mapping_start.max(page_start);
            let hi = mapping_end.min(page_end);
            if lo >= hi {
                continue;
            }
            match mapping.kind {
                MappingKind::Anonymous
                | MappingKind::DemandPaged
                | MappingKind::Cow
                | MappingKind::Shared => {}
                _ => continue,
            }
            let mut addr = align_down_page(lo);
            while addr < hi {
                // Physical frame backing `addr` within this (possibly
                // multi-page) mapping.
                let phys = mapping
                    .physical_address
                    .saturating_add(addr - mapping_start);
                // For CoW pages, release the reference to the shared frame.
                if mapping.kind == MappingKind::Cow {
                    self.dec_frame_refcount(phys);
                }
                // Free any swap slot associated with this page.
                if let Some(slot_idx) = self.swap_map.remove(&(owner, addr)) {
                    if let Some(ref mut area) = self.swap_area {
                        area.free_slot(SwapSlot(slot_idx));
                    }
                }
                // Drop any compressed copy of this page.
                self.remove_compressed_page(owner, addr);
                if self
                    .page_table
                    .unmap_owned(owner, addr, paging::PAGE_SIZE)
                    .is_ok()
                {
                    count += 1;
                }
                addr = addr.saturating_add(paging::PAGE_SIZE);
            }
        }
        count
    }

    /// Register the running process's user pages.
    ///
    /// The caller is a process acting on its own memory, so it names no address
    /// space; this asks the machine which root the CPU is on and registers
    /// under that.  Callers that act on *another* process's memory — fork,
    /// which registers the child while the parent is running — use
    /// [`register_user_pages`](Self::register_user_pages) and say whose the
    /// pages are.
    pub fn register_user_pages_current(
        &mut self,
        pages: &[(usize, usize, PagePermissions, MappingKind)],
    ) -> usize {
        let owner = crate::memory::arch::current_owner();
        self.register_user_pages(owner.root_table(), pages)
    }

    /// Unregister the running process's user pages in a range.
    pub fn unregister_user_page_range_current(&mut self, start: usize, len: usize) -> usize {
        let owner = crate::memory::arch::current_owner();
        self.unregister_user_page_range(owner.root_table(), start, len)
    }

    /// Register a single shared-memory page in the running process's address
    /// space.
    pub fn register_shared_page_current(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let owner = crate::memory::arch::current_owner();
        self.register_shared_page(
            owner.root_table(),
            virtual_address,
            physical_address,
            permissions,
        )
    }

    /// Replace the kind of the running process's mapping at `virtual_address`.
    pub fn replace_mapping_kind_current(
        &mut self,
        virtual_address: usize,
        kind: MappingKind,
    ) -> Result<()> {
        let owner = crate::memory::arch::current_owner();
        self.page_table
            .replace_mapping_kind_owned(owner, virtual_address, kind)
    }

    /// Replace the kind of `owner`'s mapping, named by root table address.
    pub fn replace_mapping_kind_for(
        &mut self,
        owner_root_table: usize,
        virtual_address: usize,
        kind: MappingKind,
    ) -> Result<()> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        self.page_table
            .replace_mapping_kind_owned(owner, virtual_address, kind)
    }

    /// Replace the permissions of `owner`'s mapping, named by root table
    /// address.
    pub fn replace_mapping_permissions_for(
        &mut self,
        owner_root_table: usize,
        virtual_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        self.page_table
            .replace_mapping_permissions_owned(owner, virtual_address, permissions)
    }

    /// Look up an address as the address space rooted at `owner_root_table`
    /// sees it.
    pub fn lookup_mapping_for(
        &self,
        owner_root_table: usize,
        virtual_address: usize,
    ) -> Option<(usize, PagePermissions, MappingKind)> {
        let owner = paging::AddressSpaceId::from_root_table(owner_root_table);
        self.page_table.lookup_mapping_owned(owner, virtual_address)
    }

    /// Replace the advice of the running process's mapping at
    /// `virtual_address`.
    pub fn replace_mapping_advice_current(
        &mut self,
        virtual_address: usize,
        advice: paging::AdviceHint,
    ) -> Result<()> {
        let owner = crate::memory::arch::current_owner();
        self.page_table
            .replace_mapping_advice_owned(owner, virtual_address, advice)
    }

    /// Remove the running process's mappings in a range, leaving every other
    /// address space's alone.
    pub fn unmap_current(&mut self, virtual_address: usize, length: usize) -> Result<()> {
        let owner = crate::memory::arch::current_owner();
        self.unmap_owned(owner.root_table(), virtual_address, length)
    }
    /// Map an identity region in the running process's address space.
    pub fn map_region_with_kind_current(
        &mut self,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        let owner = crate::memory::arch::current_owner();
        self.map_region_with_kind_owned(
            owner.root_table(),
            virtual_address,
            length,
            permissions,
            kind,
        )
    }

    /// Is the running process's mapping at `virtual_address` still
    /// demand-paged?
    pub fn is_demand_paged_current(&self, virtual_address: usize) -> bool {
        let owner = crate::memory::arch::current_owner();
        let page_addr = align_down_page(virtual_address);
        self.page_table.mappings_snapshot().iter().any(|mapping| {
            mapping.owner == owner
                && mapping.virtual_address == page_addr
                && mapping.kind == MappingKind::DemandPaged
        })
    }

    /// Return a reference to the software page table for diagnostics.
    pub fn page_table(&self) -> &PageTable {
        &self.page_table
    }

    /// Return a mutable reference to the software page table.
    pub fn page_table_mut(&mut self) -> &mut PageTable {
        &mut self.page_table
    }

    /// Store page content for later backfill on DemandPaged faults.
    ///
    /// The content is keyed by address space and virtual page address.  Every
    /// process maps its image at the same virtual addresses, so keying by the
    /// address alone would let one process's saved bytes be handed back to
    /// another — which is the same defect the page table itself had, one layer
    /// up.
    ///
    /// If content already exists for this key it is replaced silently.
    pub fn store_page_content(
        &mut self,
        owner: paging::AddressSpaceId,
        va: usize,
        content: Vec<u8>,
    ) {
        let page_addr = align_down_page(va);
        // Replace existing entry if present, otherwise append.
        if let Some(existing) = self
            .page_content
            .iter_mut()
            .find(|(key, _)| *key == (owner, page_addr))
        {
            existing.1 = content;
        } else {
            self.page_content.push(((owner, page_addr), content));
        }
    }

    // ── compressed page cache (zswap-style) ─────────────────────────────

    /// Store a compressed page in the cache, evicting oldest entries to the
    /// raw content store when the byte budget is exceeded.
    pub(crate) fn add_compressed_page(
        &mut self,
        owner: paging::AddressSpaceId,
        va: usize,
        page: crate::memory::compressed::CompressedPage,
    ) {
        let page_addr = align_down_page(va);
        // Replace any previous entry for this address.
        self.remove_compressed_page(owner, page_addr);
        let encoded = page.encoded_len();
        self.compressed_cache_bytes += encoded;
        self.compressed_pages_saved += paging::PAGE_SIZE.saturating_sub(encoded);

        // Evict while over budget.  Evicted pages are decompressed into the
        // raw content store so their data is never lost.
        let budget = crate::memory::compressed::MAX_COMPRESSED_CACHE_BYTES;
        while self.compressed_cache_bytes > budget {
            let Some(((evict_owner, evict_va), evict_page)) = self.compressed_pages.pop_first()
            else {
                break;
            };
            self.compressed_cache_bytes = self
                .compressed_cache_bytes
                .saturating_sub(evict_page.encoded_len());
            self.compressed_pages_saved = self
                .compressed_pages_saved
                .saturating_sub(paging::PAGE_SIZE.saturating_sub(evict_page.encoded_len()));
            let mut raw = alloc::vec![0u8; paging::PAGE_SIZE];
            if evict_page.decompress(&mut raw) {
                self.store_page_content(evict_owner, evict_va, raw);
            }
            self.compressed_evictions += 1;
        }

        self.compressed_pages.insert((owner, page_addr), page);
    }

    /// Remove the compressed entry for `va` (if any), returning it to the
    /// raw content store is *not* performed here — callers choose whether to
    /// re-store the raw content (faults drop it, eviction re-stores it).
    pub(crate) fn remove_compressed_page(&mut self, owner: paging::AddressSpaceId, va: usize) {
        let page_addr = align_down_page(va);
        if let Some(page) = self.compressed_pages.remove(&(owner, page_addr)) {
            self.compressed_cache_bytes = self
                .compressed_cache_bytes
                .saturating_sub(page.encoded_len());
            self.compressed_pages_saved = self
                .compressed_pages_saved
                .saturating_sub(paging::PAGE_SIZE.saturating_sub(page.encoded_len()));
        }
    }

    /// Return compressed-cache statistics:
    /// `(compressed_pages, cache_bytes, bytes_saved_vs_raw, evictions)`.
    pub fn compressed_stats(&self) -> (usize, usize, usize, usize) {
        (
            self.compressed_pages.len(),
            self.compressed_cache_bytes,
            self.compressed_pages_saved,
            self.compressed_evictions,
        )
    }

    /// Look up stored page content without removing it.
    ///
    /// Returns a reference to the content slice, or `None` if no content
    /// is stored for this address in this address space.
    pub fn get_page_content(&self, owner: paging::AddressSpaceId, va: usize) -> Option<&[u8]> {
        let page_addr = align_down_page(va);
        self.page_content
            .iter()
            .find(|(key, _)| *key == (owner, page_addr))
            .map(|(_, content)| content.as_slice())
    }

    /// Drop all stored page content (used on process teardown).
    pub fn clear_page_content(&mut self) {
        self.page_content.clear();
        self.compressed_pages.clear();
        self.compressed_cache_bytes = 0;
        self.compressed_pages_saved = 0;
    }
}
