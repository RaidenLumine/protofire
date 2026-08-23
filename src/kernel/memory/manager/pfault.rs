//! src/kernel/memory/manager/pfault.rs
//! Page-fault resolution: demand-paging backfill (with swap-in and fault-around
//! prefetching) and Copy-on-Write private copy.

use crate::kernel::memory::paging::{self, MappingKind, PagePermissions};

use super::super::arch::{align_down_page, install_user_page_arch};
use super::MemoryManager;

impl MemoryManager {
    /// Attempt to resolve a page fault at `virtual_address`.
    ///
    /// Returns `true` if the fault was resolved (the page is now mapped and
    /// accessible), `false` if it's a genuine fault that should be delivered
    /// to the user exception handler or terminate the process.
    ///
    /// `is_write` indicates whether the fault was caused by a write access.
    pub fn resolve_page_fault(&mut self, virtual_address: usize, is_write: bool) -> bool {
        // Align to page boundary.
        let page_addr = align_down_page(virtual_address);

        // Look up in the software page table.
        let (phys, perms, kind) = match self.page_table.lookup_mapping(page_addr) {
            Some((phys, perms, kind)) => (phys, perms, kind),
            None => return false,
        };

        match kind {
            MappingKind::DemandPaged => {
                // Allocate a frame and populate it.
                let frame = match self.allocate_frames(1) {
                    Some(ptr) => ptr,
                    None => {
                        // Out of physical frames — invoke the OOM killer and
                        // retry once before giving up.
                        if crate::kernel::oom::oom_kill() {
                            match self.allocate_frames(1) {
                                Some(ptr) => ptr,
                                None => return false,
                            }
                        } else {
                            return false;
                        }
                    }
                };
                let frame_phys = frame as usize;

                // Check the swap map first: if this page was swapped to
                // disk, read it back from the swap device.  Otherwise try
                // the in-memory content store, and fall back to zero-fill.
                let swap_slot = self.swap_map.remove(&page_addr);
                if let Some(slot_idx) = swap_slot {
                    let page_buf =
                        unsafe { core::slice::from_raw_parts_mut(frame, paging::PAGE_SIZE) };
                    match &self.swap_area {
                        Some(area) => {
                            if area
                                .read_page(
                                    crate::kernel::memory::swap::SwapSlot(slot_idx),
                                    page_buf,
                                )
                                .is_err()
                            {
                                self.deallocate_frames(frame, 1);
                                return false;
                            }
                        }
                        None => {
                            // swap_map entry without swap_area: shouldn't happen,
                            // but handle it gracefully.
                            self.deallocate_frames(frame, 1);
                            return false;
                        }
                    }
                    // Free the swap slot now that the page is back in memory.
                    if let Some(ref mut area) = self.swap_area {
                        area.free_slot(crate::kernel::memory::swap::SwapSlot(slot_idx));
                    }
                } else if let Some(page) = self.compressed_pages.remove(&page_addr) {
                    // Compressed in-memory copy (zswap-style): decompress it
                    // straight into the fresh frame.
                    self.compressed_cache_bytes = self
                        .compressed_cache_bytes
                        .saturating_sub(page.encoded_len());
                    self.compressed_pages_saved = self
                        .compressed_pages_saved
                        .saturating_sub(paging::PAGE_SIZE.saturating_sub(page.encoded_len()));
                    let page_buf =
                        unsafe { core::slice::from_raw_parts_mut(frame, paging::PAGE_SIZE) };
                    if !page.decompress(page_buf) {
                        self.deallocate_frames(frame, 1);
                        return false;
                    }
                } else if let Some(content) = self.get_page_content(page_addr) {
                    unsafe {
                        let copy_len = core::cmp::min(content.len(), paging::PAGE_SIZE);
                        core::ptr::copy_nonoverlapping(content.as_ptr(), frame, copy_len);
                    }
                } else {
                    unsafe { core::ptr::write_bytes(frame, 0, paging::PAGE_SIZE) };
                }

                // Install in hardware page tables.
                if !install_user_page_arch(page_addr, frame_phys, perms) {
                    self.deallocate_frames(frame, 1);
                    return false;
                }

                // Keep the software mapping as DemandPaged so that other
                // processes sharing the same virtual address (different CR3
                // trees) can also fault and get their own private frame.
                // The global software page table does not track per-process
                // ownership, so converting to Anonymous would block
                // demand-paging for every other process.
                //
                // Mark the resolved page as accessed so the clock
                // reclamation algorithm skips it on the next sweep.
                self.page_table.mark_accessed_va(page_addr);
                self.fault_profiler.inc_page_faults_demand_paged();

                // ── Fault-around: speculatively pre-map adjacent DemandPaged
                //     pages to reduce future page faults.  Pages are pre-mapped
                //     only if they are DemandPaged, have stored content, and
                //     frames are available.  Limited to FAULT_AROUND_PAGES per
                //     direction (8 pages / 32 KiB).
                const FAULT_AROUND_PAGES: usize = 8;
                for direction in [-1isize, 1isize] {
                    for offset in 1..=FAULT_AROUND_PAGES {
                        let adj_va = page_addr.wrapping_add(
                            offset
                                .wrapping_mul(paging::PAGE_SIZE)
                                .wrapping_mul(direction as usize),
                        );
                        // Only prefetch if direction is forward, or backward
                        // after checking for underflow.
                        if direction < 0 && adj_va > page_addr {
                            break; // underflow wrap
                        }

                        // Check if adjacent page is DemandPaged.
                        let (_adj_phys, adj_perms, adj_kind) =
                            match self.page_table.lookup_mapping(adj_va) {
                                Some(t) => t,
                                None => break, // end of mapped region
                            };
                        if adj_kind != MappingKind::DemandPaged {
                            break; // not a DemandPaged page, stop this direction
                        }

                        // Must have stored content to backfill.  Get the content
                        // (immutable borrow) before allocating a frame (mutable
                        // borrow) to avoid borrow conflicts.
                        let adj_content_len = match self.get_page_content(adj_va) {
                            Some(c) => {
                                let len = core::cmp::min(c.len(), paging::PAGE_SIZE);
                                let content_ptr = c.as_ptr();
                                Some((content_ptr, len))
                            }
                            None => break, // reclaimed page without content, skip
                        };

                        // Allocate a frame for the adjacent page.
                        let adj_frame = match self.allocate_frames(1) {
                            Some(ptr) => ptr,
                            None => break, // out of frames, stop prefetching
                        };
                        let adj_frame_phys = adj_frame as usize;

                        if let Some((content_ptr, copy_len)) = adj_content_len {
                            unsafe {
                                core::ptr::copy_nonoverlapping(content_ptr, adj_frame, copy_len);
                            }
                        }

                        if !install_user_page_arch(adj_va, adj_frame_phys, adj_perms) {
                            self.deallocate_frames(adj_frame, 1);
                            break;
                        }

                        // Keep as DemandPaged — see note above about
                        // global software page table and multi-process
                        // demand-paging correctness.

                        // Mark prefetched page as accessed.
                        self.page_table.mark_accessed_va(adj_va);
                        self.fault_profiler.inc_page_faults_demand_paged();
                    }
                }

                true
            }
            MappingKind::Cow => {
                // CoW pages are mapped read-only in hardware; only a write
                // fault should reach here (read faults on read-only pages
                // succeed without trapping).  Allocate a private copy.
                if !is_write {
                    // Read-fault on CoW: should not happen in normal operation
                    // since the page is already mapped read-only.  Let it fall
                    // through to the user exception handler.
                    return false;
                }

                // Write fault on CoW page — allocate a private copy.
                let new_frame = match self.allocate_frames(1) {
                    Some(ptr) => ptr,
                    None => {
                        // Out of physical frames — invoke the OOM killer and
                        // retry once before giving up.
                        if crate::kernel::oom::oom_kill() {
                            match self.allocate_frames(1) {
                                Some(ptr) => ptr,
                                None => return false,
                            }
                        } else {
                            return false;
                        }
                    }
                };
                // Copy the original page contents.
                unsafe {
                    core::ptr::copy_nonoverlapping(phys as *const u8, new_frame, paging::PAGE_SIZE);
                }
                let new_phys = new_frame as usize;

                // Decrement the refcount of the old shared frame.  If it
                // drops to 0 the frame is freed (this process was the last
                // owner).
                self.dec_frame_refcount(phys);

                // Install the new writable page in hardware.
                if !install_user_page_arch(page_addr, new_phys, PagePermissions::READ_WRITE) {
                    self.deallocate_frames(new_frame, 1);
                    return false;
                }

                // Split the software mapping: remove the single page from
                // the CoW region (unmap splits it into prefix + suffix),
                // then insert the new Anonymous page.
                let _ = self.page_table.unmap(page_addr, paging::PAGE_SIZE);
                if self
                    .page_table
                    .map_to_with_kind(
                        page_addr,
                        new_phys,
                        paging::PAGE_SIZE,
                        PagePermissions::READ_WRITE,
                        MappingKind::Anonymous,
                    )
                    .is_err()
                {
                    self.deallocate_frames(new_frame, 1);
                    return false;
                }

                self.fault_profiler.inc_page_faults_cow();
                // Mark the new private page as accessed.
                self.page_table.mark_accessed_va(page_addr);
                true
            }
            _ => {
                // Other mapping kinds: genuine fault.
                false
            }
        }
    }
}
