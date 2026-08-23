//! src/kernel/memory/manager/mapping.rs
//! Address-space mapping operations, diagnostics, user page registration,
//! page table access, and content store.

use alloc::vec::Vec;

use crate::kernel::memory::alloc_profiler::AllocProfilerSnapshot;
use crate::kernel::memory::fault_profiler::FaultProfilerSnapshot;
use crate::kernel::memory::heap;
use crate::kernel::memory::paging;
use crate::kernel::memory::paging::{MappingKind, PagePermissions, PageTable};
use crate::kernel::memory::swap::SwapSlot;
use crate::Result;

use super::super::arch::{
    align_down_page, bootstrap_translation, planned_kernel_region, prepared_page_tables_active,
    prepared_translation, shootdown_range,
};
use super::super::diagnostics::{AddressTranslation, PageFaultInsight};
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

    pub fn translate(&self, virtual_address: usize) -> Option<(usize, PagePermissions)> {
        self.page_table.lookup(virtual_address)
    }

    pub fn page_fault_insight(&self, virtual_address: usize) -> PageFaultInsight {
        let (heap_start, heap_end) = self.heap_bounds();
        // Build a layered diagnostic snapshot (runtime table + bootstrap + prepared plans).
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
    ///
    /// Each entry is `(virtual_address, physical_address, permissions, kind)`.
    /// The pages must not overlap with existing kernel mappings.  Existing
    /// user mappings at the same virtual address are silently replaced (the
    /// old mapping is unmapped first).
    ///
    /// Returns the number of pages successfully registered.
    pub fn register_user_pages(
        &mut self,
        pages: &[(usize, usize, PagePermissions, MappingKind)],
    ) -> usize {
        let mut count = 0;
        for &(va, pa, perms, kind) in pages {
            let page_addr = align_down_page(va);
            // Skip if this would conflict with a kernel mapping.
            if let Some((_, _, existing_kind)) = self.page_table.lookup_mapping(page_addr) {
                match existing_kind {
                    MappingKind::KernelHeap | MappingKind::Identity | MappingKind::DeviceMemory => {
                        continue
                    }
                    // User-space kinds: silently unmap the old entry first.
                    MappingKind::Anonymous
                    | MappingKind::DemandPaged
                    | MappingKind::Cow
                    | MappingKind::Shared
                    | MappingKind::Locked => {
                        let _ = self.page_table.unmap(page_addr, paging::PAGE_SIZE);
                    }
                }
            }
            if self
                .page_table
                .map_to_with_kind(page_addr, pa, paging::PAGE_SIZE, perms, kind)
                .is_ok()
            {
                count += 1;
            }
        }
        count
    }

    /// Register a single shared-memory page in the software page table.
    pub fn register_shared_page(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let page_addr = align_down_page(virtual_address);
        self.page_table
            .map_to_with_kind(
                page_addr,
                physical_address,
                paging::PAGE_SIZE,
                permissions,
                MappingKind::Shared,
            )
            .map_err(|_| crate::Error::AlreadyExists)
    }

    /// Unregister user pages in a virtual address range from the software
    /// page table.  Kernel mappings (KernelHeap, Identity, DeviceMemory) are
    /// left untouched.
    ///
    /// For CoW pages this also decrements the shared-frame refcount so
    /// frames are freed when the last owner terminates.
    ///
    /// Returns the number of pages actually removed.
    pub fn unregister_user_page_range(&mut self, start: usize, len: usize) -> usize {
        let page_start = align_down_page(start);
        let page_end = align_down_page(
            start
                .saturating_add(len)
                .saturating_add(paging::PAGE_SIZE - 1),
        );
        let mut count = 0;
        let mut addr = page_start;
        while addr < page_end {
            if let Some((phys, _, kind)) = self.page_table.lookup_mapping(addr) {
                match kind {
                    MappingKind::Anonymous
                    | MappingKind::DemandPaged
                    | MappingKind::Cow
                    | MappingKind::Shared => {}
                    _ => {
                        addr = addr.saturating_add(paging::PAGE_SIZE);
                        continue;
                    }
                }
                // For CoW pages, release the reference to the shared frame.
                if kind == MappingKind::Cow {
                    self.dec_frame_refcount(phys);
                }
                // Free any swap slot associated with this page.
                if let Some(slot_idx) = self.swap_map.remove(&addr) {
                    if let Some(ref mut area) = self.swap_area {
                        area.free_slot(SwapSlot(slot_idx));
                    }
                }
                // Drop any compressed copy of this page.
                self.remove_compressed_page(addr);
                if self.page_table.unmap(addr, paging::PAGE_SIZE).is_ok() {
                    count += 1;
                }
            }
            addr = addr.saturating_add(paging::PAGE_SIZE);
        }
        count
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
    /// The content is keyed by virtual page address.  If content already
    /// exists for this address it is replaced silently.
    pub fn store_page_content(&mut self, va: usize, content: Vec<u8>) {
        let page_addr = align_down_page(va);
        // Replace existing entry if present, otherwise append.
        if let Some(existing) = self
            .page_content
            .iter_mut()
            .find(|(addr, _)| *addr == page_addr)
        {
            existing.1 = content;
        } else {
            self.page_content.push((page_addr, content));
        }
    }

    // ── compressed page cache (zswap-style) ─────────────────────────────

    /// Store a compressed page in the cache, evicting oldest entries to the
    /// raw content store when the byte budget is exceeded.
    pub(crate) fn add_compressed_page(
        &mut self,
        va: usize,
        page: crate::kernel::memory::compressed::CompressedPage,
    ) {
        let page_addr = align_down_page(va);
        // Replace any previous entry for this address.
        self.remove_compressed_page(page_addr);
        let encoded = page.encoded_len();
        self.compressed_cache_bytes += encoded;
        self.compressed_pages_saved += paging::PAGE_SIZE.saturating_sub(encoded);

        // Evict while over budget.  Evicted pages are decompressed into the
        // raw content store so their data is never lost.
        let budget = crate::kernel::memory::compressed::MAX_COMPRESSED_CACHE_BYTES;
        while self.compressed_cache_bytes > budget {
            let Some((evict_va, evict_page)) = self.compressed_pages.pop_first() else {
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
                self.store_page_content(evict_va, raw);
            }
            self.compressed_evictions += 1;
        }

        self.compressed_pages.insert(page_addr, page);
    }

    /// Remove the compressed entry for `va` (if any), returning it to the
    /// raw content store is *not* performed here — callers choose whether to
    /// re-store the raw content (faults drop it, eviction re-stores it).
    pub(crate) fn remove_compressed_page(&mut self, va: usize) {
        let page_addr = align_down_page(va);
        if let Some(page) = self.compressed_pages.remove(&page_addr) {
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
    /// is stored for this address.
    pub fn get_page_content(&self, va: usize) -> Option<&[u8]> {
        let page_addr = align_down_page(va);
        self.page_content
            .iter()
            .find(|(addr, _)| *addr == page_addr)
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
