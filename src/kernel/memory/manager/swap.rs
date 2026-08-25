//! src/kernel/memory/manager/swap.rs
//!
//! Page reclamation (clock algorithm with second-chance), swap I/O,
//! and Copy-on-Write frame reference counting.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::memory::paging::MappingKind;
use crate::kernel::memory::paging::{self};
use crate::kernel::memory::swap::SwapArea;
use crate::kernel::memory::swap::SwapSlot;
use crate::Result;

use super::super::arch::align_down_page;
use super::super::arch::unmap_user_page_arch;
use super::MemoryManager;

impl MemoryManager {
    /// Lightweight page reclamation using a second-chance (clock) algorithm.
    ///
    /// The clock hand sweeps across the page-table mappings looking for
    /// anonymous user pages whose frames are not CoW-shared.  If a page has
    /// been accessed since the last sweep (`accessed == true`), it gets a
    /// second chance: the accessed bit is cleared and the hand moves on.
    /// If a page is unaccessed, it is reclaimed: content is saved for later
    /// backfill, the frame is unmapped from hardware and freed, and the
    /// software mapping is marked as DemandPaged.
    ///
    /// Pages with a frame reference count > 1 (CoW-shared frames) are skipped:
    /// reclaiming a shared frame would either corrupt the other process's data
    /// or require complex partial-reclamation logic that is out of scope for
    /// the prototype.
    ///
    /// The clock hand wraps around when it reaches the end of the mapping
    /// vector.  If a full revolution finds no reclaimable pages (all pages
    /// were accessed), the function returns early.
    ///
    /// Returns the number of pages actually reclaimed.
    pub fn reclaim_pages(&mut self, target: usize) -> usize {
        let mut reclaimed = 0;
        let mapping_count = self.page_table.mapping_count();

        if mapping_count == 0 {
            return 0;
        }

        // Collect anonymous mapping indices for efficient clock-hand
        // progression.  We scan the raw mappings vector directly via
        // get_mapping_mut so we can test-and-clear the accessed bit
        // atomically without taking a full snapshot.
        let anonymous_indices: alloc::vec::Vec<usize> = {
            let snapshot = self.page_table.mappings_snapshot();
            snapshot
                .iter()
                .enumerate()
                .filter(|(_, m)| m.kind == MappingKind::Anonymous)
                .map(|(i, _)| i)
                .collect()
        };

        if anonymous_indices.is_empty() {
            return 0;
        }

        // Advance the clock hand through anonymous mappings.  We scan up to
        // two full revolutions: one to give every page a second chance, and
        // a second to reclaim unaccessed pages.  The `reclaim_hand` cursor
        // is an index into the full mapping vector; we jump between
        // anonymous pages using the pre-collected index list.
        let mut scanned = 0;
        let max_scan = (anonymous_indices.len() * 2)
            .min(target * 4)
            .max(anonymous_indices.len());

        while reclaimed < target && scanned < max_scan {
            let anon_pos = self.reclaim_hand % anonymous_indices.len();
            let mapping_idx = anonymous_indices[anon_pos];

            // Access the mapping directly to test-and-clear the accessed bit.
            let (page_addr, phys, was_accessed, advice) = {
                let snapshot = self.page_table.mappings_snapshot();
                let m = &snapshot[mapping_idx];
                // Verify the mapping is still anonymous (it could have been
                // changed by a concurrent CoW fault or DemandPaged backfill).
                if m.kind != MappingKind::Anonymous {
                    self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
                    scanned += 1;
                    continue;
                }
                (m.virtual_address, m.physical_address, m.accessed, m.advice)
            };

            // Advice hint based reclamation priority:
            //   Sequential — even recently accessed pages are reclaimed
            //                on first unaccessed pass (no second chance).
            //   Random     — never reclaim, always give second chance.
            //   Normal     — default clock algorithm behavior.
            if advice == crate::kernel::memory::paging::AdviceHint::Random {
                // Random pages: always give second chance.
                self.page_table.mark_accessed_va(page_addr);
                self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
                scanned += 1;
                continue;
            }

            if was_accessed && advice != crate::kernel::memory::paging::AdviceHint::Sequential {
                // Page was accessed recently — give it a second chance.
                // Clear the accessed bit and move on.
                // Sequential pages skip this: they're reclaimed eagerly.
                self.page_table.clear_accessed_va(page_addr);
                self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
                scanned += 1;
                continue;
            }

            // Page was NOT accessed — candidate for reclamation.
            // Skip CoW-shared frames.
            if self.get_frame_refcount(phys) > 1 {
                self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
                scanned += 1;
                continue;
            }

            // Save page content before unmapping.
            let mut content = alloc::vec![0u8; paging::PAGE_SIZE];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys as *const u8,
                    content.as_mut_ptr(),
                    paging::PAGE_SIZE,
                );
            }

            // Try swap-out first: write the page to the swap device so the
            // frame can be genuinely freed without keeping a copy in the
            // in-memory content store.  If swap is not configured, the
            // slot pool is exhausted, or the write fails, fall back to
            // the in-memory content store.
            let mut swapped = false;
            if let Some(ref mut area) = self.swap_area {
                if let Some(slot) = area.allocate_slot() {
                    if area.write_page(slot, &content).is_ok() {
                        self.swap_map.insert(page_addr, slot.0);
                        swapped = true;
                    } else {
                        // Write failed — return the slot.
                        area.free_slot(slot);
                    }
                }
            }

            if !swapped {
                // Memory compression (zswap-style): keep a compressed copy in
                // RAM when it is smaller than the raw 4 KiB content store.
                // Incompressible pages fall back to the raw store.
                if let Some(page) = crate::kernel::memory::compressed::compress_page(&content) {
                    self.add_compressed_page(page_addr, page);
                } else {
                    self.store_page_content(page_addr, content);
                }
            }

            // Unmap from hardware page tables.
            if !unmap_user_page_arch(page_addr) {
                self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
                scanned += 1;
                continue;
            }

            // Free the physical frame.
            self.deallocate_frames(phys as *mut u8, 1);

            // Mark as demand-paged so it can be faulted back in.
            let _ = self
                .page_table
                .replace_mapping_kind(page_addr, MappingKind::DemandPaged);

            reclaimed += 1;
            self.reclaim_hand = self.reclaim_hand.wrapping_add(1);
            scanned += 1;
        }

        // If the hand wrapped past the mapping count, wrap it back.
        if self.reclaim_hand >= mapping_count {
            self.reclaim_hand = 0;
        }

        if reclaimed > 0 {
            crate::println!(
                "[vm    ] clock-reclaimed {} pages ({} frames freed)",
                reclaimed,
                reclaimed
            );
        }
        reclaimed
    }

    /// Return the number of reclaimable (anonymous) pages.
    ///
    /// CoW-shared frames (frame refcount > 1) are excluded from the count
    /// because they are managed by the CoW lifecycle and should not be
    /// reclaimed independently.
    pub fn reclaimable_page_count(&self) -> usize {
        self.page_table
            .mappings_snapshot()
            .into_iter()
            .filter(|m| {
                m.kind == MappingKind::Anonymous && self.get_frame_refcount(m.physical_address) <= 1
            })
            .count()
    }

    // ── swap support ─────────────────────────────────────────────────────

    /// Initialise a swap area on `device` starting at `start_lba` with
    /// capacity for `page_count` page slots (each 4096 bytes / 8 blocks).
    ///
    /// After this call, [`reclaim_pages`] will try to write reclaimed
    /// pages to the swap device before falling back to the in-memory
    /// content store.  [`resolve_page_fault`] will check the swap map
    /// and read pages back from the device when a swapped-out page is
    /// faulted.
    ///
    /// Only one swap area is supported at a time; calling this method
    /// again replaces the previous area (any pages still in the old
    /// area become orphaned — callers should drain the swap map first).
    pub fn init_swap(
        &mut self,
        device: Arc<dyn BlockDevice>,
        start_lba: u64,
        page_count: u64,
    ) -> Result<()> {
        let area = SwapArea::new(device, start_lba, page_count)?;
        self.swap_area = Some(area);
        crate::println!("[vm    ] swap initialised: {} pages on device", page_count);
        Ok(())
    }

    /// Return swap area statistics: `(total_pages, used_pages, free_pages)`.
    /// Returns `(0, 0, 0)` when swap is not configured.
    pub fn swap_stats(&self) -> (u64, u64, u64) {
        match &self.swap_area {
            Some(area) => (area.total_pages(), area.used_pages(), area.free_pages()),
            None => (0, 0, 0),
        }
    }

    /// Free all swap slots and compressed copies for the given list of
    /// virtual page addresses (typically called on process termination).
    ///
    /// Pages that are not in the swap map are silently skipped.
    pub fn free_user_swap_slots(&mut self, pages: &[usize]) {
        for &va in pages {
            let page_addr = align_down_page(va);
            if let Some(slot_idx) = self.swap_map.remove(&page_addr) {
                if let Some(ref mut area) = self.swap_area {
                    area.free_slot(SwapSlot(slot_idx));
                }
            }
            self.remove_compressed_page(page_addr);
        }
    }

    // ── CoW frame reference counting ─────────────────────────────────────

    /// Increment the reference count for a shared CoW frame.
    ///
    /// Each call adds one reference.  For a fork, call twice per shared
    /// frame — once for the parent's reference, once for the child's —
    /// so the count starts at 2.  When every holder has CoW-faulted (or
    /// exited), the count reaches 0 and the frame is freed.
    pub fn inc_frame_refcount(&mut self, phys: usize) {
        let count = self.frame_refcounts.entry(phys).or_insert(0);
        *count += 1;
    }

    /// Decrement the reference count for a shared CoW frame.
    ///
    /// Returns the new reference count.  When the count reaches 0 the
    /// frame is freed via `Box::from_raw` (CoW-shared frames are
    /// heap-allocated `RawPageFrame` instances, not frame-pool pages).
    ///
    /// If `phys` is not in the refcount table this is a no-op and
    /// returns 0.
    pub fn dec_frame_refcount(&mut self, phys: usize) -> usize {
        if let Some(count) = self.frame_refcounts.get_mut(&phys) {
            *count -= 1;
            if *count == 0 {
                self.frame_refcounts.remove(&phys);
                // The frame was originally a Box<RawPageFrame> that was
                // leaked via into_raw.  Reconstruct and drop to free
                // the heap allocation.
                unsafe {
                    let _ = Box::from_raw(phys as *mut u8);
                }
                return 0;
            }
            *count
        } else {
            0
        }
    }

    /// Return the current reference count for a shared CoW frame.
    ///
    /// Returns 0 if the frame is not in the refcount table.
    pub fn get_frame_refcount(&self, phys: usize) -> usize {
        self.frame_refcounts.get(&phys).copied().unwrap_or(0)
    }

    /// Decrement reference counts for all shared frames listed, and unmap
    /// their corresponding entries from the software page table.
    ///
    /// Used on process termination to release CoW-shared pages.
    pub fn release_cow_pages(&mut self, pages: &[(usize, usize)]) {
        for &(va, phys) in pages {
            self.dec_frame_refcount(phys);
            let _ = self.page_table.unmap(va, paging::PAGE_SIZE);
        }
    }
}
