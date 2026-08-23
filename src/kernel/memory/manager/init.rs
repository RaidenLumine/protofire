//! src/kernel/memory/manager/init.rs
//! MemoryManager construction, initialisation, and frame allocation/deallocation.

use crate::kernel::memory::frame::MAX_NODES;
use crate::kernel::memory::paging::{MappingKind, PagePermissions};
use crate::{println, Result};

use super::super::arch::detect_memory;
use super::MemoryManager;
use crate::kernel::topology::NUMA_NODE_NONE;

impl MemoryManager {
    pub const fn new() -> Self {
        Self {
            frame_allocators: [const { crate::kernel::memory::frame::FrameAllocator::new() };
                MAX_NODES],
            num_nodes: 0,
            heap_allocator: crate::kernel::memory::heap::HeapAllocator::new(),
            page_table: crate::kernel::memory::paging::PageTable::new(),
            fault_profiler: crate::kernel::memory::fault_profiler::FaultProfiler::new(),
            kernel_heap_start: 0,
            kernel_heap_end: 0,
            initialized: false,
            page_content: alloc::vec::Vec::new(),
            frame_refcounts: alloc::collections::BTreeMap::new(),
            reclaim_hand: 0,
            locked_pages: 0,
            swap_area: None,
            swap_map: alloc::collections::BTreeMap::new(),
            compressed_pages: alloc::collections::BTreeMap::new(),
            compressed_cache_bytes: 0,
            compressed_pages_saved: 0,
            compressed_evictions: 0,
        }
    }

    pub fn init(&mut self) {
        if self.initialized {
            // Idempotent init: keep prior allocator/page-table state untouched.
            return;
        }

        let memory_size = detect_memory();
        // Initialise node 0 with the full detected memory (default single-node
        // configuration; callers may later subdivide with set_node_range).
        self.frame_allocators[0].init(memory_size);
        self.num_nodes = 1;
        self.page_table.init();
        self.init_kernel_heap();

        if let Err(error) = self.map_kernel_heap_bootstrap() {
            // Fail closed: keep manager uninitialized when heap bootstrap mapping fails.
            println!(
                "Memory manager init aborted: failed to bootstrap heap mapping ({})",
                error.as_str()
            );
            return;
        }

        self.initialized = true;

        println!(
            "Memory manager initialized: {} MiB physical, {} KiB heap free",
            memory_size / 1024 / 1024,
            self.heap_allocator.remaining() / 1024
        );
    }

    pub(crate) fn init_kernel_heap(&mut self) {
        self.heap_allocator.init();
        let (raw_start, raw_end) = self.heap_allocator.bounds();
        // Page-align the heap bounds.  The heap backing static's address is
        // chosen by the linker and is not guaranteed to land on a page
        // boundary; mapping or unmapping an unaligned base would produce
        // partial-page mappings that corrupt the page-table model.
        let page_mask = crate::kernel::memory::paging::PAGE_SIZE - 1;
        self.kernel_heap_start = raw_start & !page_mask;
        self.kernel_heap_end = (raw_end + page_mask) & !page_mask;
    }

    pub(crate) fn map_kernel_heap_bootstrap(&mut self) -> Result<()> {
        let heap_size = self.kernel_heap_end.saturating_sub(self.kernel_heap_start);
        // Seed early heap range as kernel-heap mapping before runtime allocations depend on it.
        self.page_table.map_region_with_kind(
            self.kernel_heap_start,
            heap_size,
            PagePermissions::READ_WRITE,
            MappingKind::KernelHeap,
        )
    }

    /// Allocate `count` physical frames, preferring the local NUMA node.
    ///
    /// Tries the local node (read from the current CPU's PerCpuData) first;
    /// on failure falls back to any available node.
    pub fn allocate_frames(&mut self, count: usize) -> Option<*mut u8> {
        let node_id = crate::kernel::percpu::get().numa_node_id;

        // Try local node first.
        if node_id != NUMA_NODE_NONE && (node_id as usize) < self.num_nodes {
            if let Some(addr) = self.frame_allocators[node_id as usize].allocate(count) {
                return Some(addr);
            }
        }

        // Fall back to any node.
        for i in 0..self.num_nodes {
            if let Some(addr) = self.frame_allocators[i].allocate(count) {
                return Some(addr);
            }
        }

        None
    }

    /// Allocate `count` physical frames from the specified NUMA node.
    pub fn allocate_frame_on_node(&mut self, node_id: u8, count: usize) -> Option<*mut u8> {
        if (node_id as usize) < self.num_nodes {
            self.frame_allocators[node_id as usize].allocate(count)
        } else {
            None
        }
    }

    pub fn deallocate_frames(&mut self, ptr: *mut u8, count: usize) -> bool {
        for i in 0..self.num_nodes {
            if self.frame_allocators[i].deallocate(ptr, count) {
                return true;
            }
        }
        false
    }

    /// Return the total number of physical frames across all NUMA nodes.
    pub fn total_frames(&self) -> usize {
        let mut total = 0;
        for i in 0..self.num_nodes {
            total += self.frame_allocators[i].total_frames();
        }
        total
    }

    /// Return the number of frames currently available for allocation.
    pub fn available_frames(&self) -> usize {
        let mut total = 0;
        for i in 0..self.num_nodes {
            total += self.frame_allocators[i].available_frames();
        }
        total
    }
}
