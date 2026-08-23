//! src/kernel/memory/manager/compact.rs
//! Memory defragmentation (compaction): relocate movable user frames so the
//! free ranges of the physical frame pool coalesce into one contiguous block.
//!
//! The frame allocator compacts by moving live frames down into holes.  Only
//! frames that appear in the software page table as single-page, movable user
//! mappings (Anonymous / Locked) are relocated; every other live frame
//! (kernel heap, page-table pages, CoW/Shared frames, multi-page regions) is
//! treated as an immovable barrier and compaction stops at the first one.
//!
//! On bare-metal targets the hardware page tables are re-mapped as frames
//! move.  On host-side targets the arch helpers are no-ops and only the
//! software page table is updated — which is exactly what the unit tests
//! exercise.

use crate::kernel::memory::arch::{install_user_page_arch, unmap_user_page_arch};
use crate::kernel::memory::paging::{self, MappingKind, PagePermissions, PageTable};

use super::MemoryManager;

/// True on bare-metal kernel targets, where the arch MMU helpers actually
/// touch live hardware page tables (as opposed to host-side stubs).
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
const BARE_METAL: bool = true;
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
const BARE_METAL: bool = false;

impl MemoryManager {
    /// Compact the physical frame pool on every NUMA node.
    ///
    /// Returns the total number of frames relocated.  Prints a summary line
    /// when any frame moved.
    pub fn compact_memory(&mut self) -> usize {
        let num_nodes = self.num_nodes;
        let Self {
            frame_allocators,
            page_table,
            ..
        } = self;
        let mut moved = 0usize;
        #[allow(clippy::needless_range_loop)]
        for node in 0..num_nodes {
            moved += frame_allocators[node]
                .compact(|old_addr, new_addr| relocate_user_frame(page_table, old_addr, new_addr));
        }

        if moved > 0 {
            let mut largest = 0usize;
            #[allow(clippy::needless_range_loop)]
            for node in 0..num_nodes {
                largest = largest.max(frame_allocators[node].largest_free_contiguous_frames());
            }
            crate::println!(
                "[vm    ] compacted {} frames, largest contiguous free block now {} frames",
                moved,
                largest
            );
        }
        moved
    }

    /// Return fragmentation diagnostics: `(free_range_count, largest_block)`.
    pub fn fragmentation_stats(&self) -> (usize, usize) {
        let mut ranges = 0usize;
        let mut largest = 0usize;
        for node in 0..self.num_nodes {
            ranges += self.frame_allocators[node].free_range_count();
            largest = largest.max(self.frame_allocators[node].largest_free_contiguous_frames());
        }
        (ranges, largest)
    }
}

/// Relocate a single-page user mapping whose frame currently sits at
/// `old_addr` to `new_addr`.  Returns `false` when the frame is not a
/// uniquely-mapped, movable user page.
fn relocate_user_frame(page_table: &mut PageTable, old_addr: usize, new_addr: usize) -> bool {
    // Find software mappings whose frame is exactly `old_addr`.
    let snapshot = page_table.mappings_snapshot();
    let mut target: Option<(usize, PagePermissions)> = None;
    let mut refs = 0usize;
    for m in &snapshot {
        if m.length != paging::PAGE_SIZE || m.physical_address != old_addr {
            continue;
        }
        refs += 1;
        if matches!(m.kind, MappingKind::Anonymous | MappingKind::Locked) {
            target = Some((m.virtual_address, m.permissions));
        }
    }
    // Only relocate a frame referenced by exactly one movable user mapping.
    let Some((va, perms)) = target else {
        return false;
    };
    if refs != 1 {
        return false;
    }

    // Re-map in hardware: unmap the old physical frame, install the new one.
    let _ = unmap_user_page_arch(va);
    if BARE_METAL && !install_user_page_arch(va, new_addr, perms) {
        return false;
    }

    // Update the software page table so translation follows the moved frame.
    page_table.replace_mapping_phys(va, new_addr).is_ok()
}
