//! src/kernel/memory/manager/mod.rs
//!
//! Core memory manager — struct definition and sub-module organisation.
//!
//! Sub-module organisation:
//! - `init`     — Construction, initialisation, frame allocation/deallocation
//! - `mapping`  — Address-space mapping, diagnostics, user page registration,
//!   content store
//! - `pfault`   — Page-fault resolution (demand-paging + CoW)
//! - `swap`     — Page reclamation, swap I/O, CoW frame reference counting

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::Ordering;

use crate::kernel::memory::compressed::CompressedPage;
use crate::kernel::memory::fault_profiler::FaultProfiler;
use crate::kernel::memory::frame::{FrameAllocator, MAX_NODES};
use crate::kernel::memory::heap::HeapAllocator;
use crate::kernel::memory::paging::PageTable;
use crate::kernel::memory::swap::SwapArea;

use super::global::GLOBAL_MEMORY_MANAGER;

pub(crate) mod compact;
pub(crate) mod init;
pub(crate) mod mapping;
pub(crate) mod pfault;
pub(crate) mod swap;

pub struct MemoryManager {
    pub(crate) frame_allocators: [FrameAllocator; MAX_NODES],
    pub(crate) num_nodes: usize,
    pub(crate) heap_allocator: HeapAllocator,
    pub(crate) page_table: PageTable,
    pub(crate) fault_profiler: FaultProfiler,
    pub(crate) kernel_heap_start: usize,
    pub(crate) kernel_heap_end: usize,
    pub(crate) initialized: bool,
    /// VA → page content for DemandPaged backfill (code pages whose frames
    /// were freed at spawn).  Content is retained after backfill so the
    /// reclamation→fault cycle can repeat without data loss.
    pub(crate) page_content: Vec<(usize, Vec<u8>)>,
    /// Physical address → reference count for CoW-shared frames.
    /// When count drops to 0 the frame is freed via Box<RawPageFrame> drop.
    pub(crate) frame_refcounts: BTreeMap<usize, usize>,
    /// Clock hand cursor for page reclamation.  Points to the index in the
    /// page-table mapping vector where the next sweep will start.  Wraps
    /// around when it reaches the end.
    pub(crate) reclaim_hand: usize,
    /// Number of pages locked via mlock (never swapped out).
    pub(crate) locked_pages: usize,
    /// Swap area for writing reclaimed pages to a block device.
    /// `None` when swap is not configured (reclamation falls back to
    /// the in-memory content store).
    pub(crate) swap_area: Option<SwapArea>,
    /// Virtual page address → swap slot index for pages currently
    /// stored in the swap area.  Looked up during demand-page faults
    /// so the page can be read back from the device.
    pub(crate) swap_map: BTreeMap<usize, u64>,
    /// Compressed-page cache (zswap-style): virtual page address → encoded
    /// content for reclaimed pages retained in memory.  Checked during
    /// demand-page faults before the raw content store.
    pub(crate) compressed_pages: BTreeMap<usize, CompressedPage>,
    /// Total encoded size (in bytes) of every entry in `compressed_pages`,
    /// used to enforce `MAX_COMPRESSED_CACHE_BYTES`.
    pub(crate) compressed_cache_bytes: usize,
    /// Cumulative `PAGE_SIZE - encoded_len` across cached pages — how much
    /// RAM the compressed cache saves versus the raw content store.
    pub(crate) compressed_pages_saved: usize,
    /// Number of compressed pages evicted to the raw content store because
    /// the cache exceeded its byte budget.
    pub(crate) compressed_evictions: usize,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MemoryManager {
    fn drop(&mut self) {
        let self_ptr = self as *mut Self;
        let _ = GLOBAL_MEMORY_MANAGER.compare_exchange(
            self_ptr,
            ptr::null_mut(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}
