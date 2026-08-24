//! src/kernel/memory/heap/allocator.rs
//!
//! `KernelGlobalAllocator` — the core TLSF-based kernel heap allocator with
//! exponential-backoff spinlock and `GlobalAlloc` trait implementation.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;
use crate::kernel::memory::alloc_profiler::AllocProfiler;

#[cfg(debug_assertions)]
use super::tlsf::scan_free_lists;
use super::tlsf::{
    align_up, block_clear_used, block_is_used, block_set_prev_phys, block_set_prev_phys_of_next,
    block_set_size, block_set_used, block_size, coalesce, find_suitable_block, insert_free_block,
    mapping, remove_free_block, AllocatorState, HEADER_SIZE, HEAP_BLOCK_ALIGNMENT, KERNEL_HEAP,
    KERNEL_HEAP_SIZE, MIN_FREE_BLOCK, SL_COUNT, SL_INDEX_LOG2,
};

pub struct KernelGlobalAllocator {
    pub(crate) state: UnsafeCell<AllocatorState>,
    locked: AtomicBool,
    pub profiler: AllocProfiler,
}

unsafe impl Sync for KernelGlobalAllocator {}

impl Default for KernelGlobalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelGlobalAllocator {
    pub const fn new() -> Self {
        Self {
            state: UnsafeCell::new(AllocatorState::new()),
            locked: AtomicBool::new(false),
            profiler: AllocProfiler::new(),
        }
    }

    pub(crate) fn with_state<R>(&self, callback: impl FnOnce(&mut AllocatorState) -> R) -> R {
        let _guard = self.acquire_lock();
        let state = unsafe { &mut *self.state.get() };

        if !state.initialized {
            self.initialize(state);
        }

        callback(state)
    }

    pub(crate) fn ensure_init(&self) {
        self.with_state(|_| ());
    }

    pub(crate) fn acquire_lock(&self) -> KernelGlobalAllocatorGuard<'_> {
        // Disable interrupts while spinning to prevent local re-entrancy
        // deadlocks and preemption during heap operations.  Without this,
        // a timer interrupt on CPU0 can preempt a thread holding the lock,
        // schedule another thread which then tries to allocate → deadlock.
        // On SMP this also prevents a CPU from observing an intermediate
        // heap state during a cross-CPU TLB shootdown.
        let interrupts_were_enabled = arch::interrupts::save_and_disable();

        // Exponential backoff test-and-test-and-set spinlock — the same pattern
        // used by SpinLock.  Without backoff, two CPUs hammering CAS in a tight
        // loop cause cache-line ping-pong and can livelock under QEMU TCG.
        let mut backoff: u32 = 1;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Wait until observed unlocked, then retry.
            while self.locked.load(Ordering::Relaxed) {
                for _ in 0..backoff.min(64) {
                    spin_loop();
                }
                backoff = backoff.saturating_mul(2).min(1024);
            }
            // Lock just became free — reset backoff so all contenders get a
            // fair shot at the CAS.  Without this a long-waiting CPU would
            // have a large backoff and lose every race, leading to starvation.
            backoff = 1;
        }

        KernelGlobalAllocatorGuard {
            allocator: self,
            interrupts_were_enabled,
        }
    }

    pub(crate) fn initialize(&self, state: &mut AllocatorState) {
        let start = KERNEL_HEAP.get() as *mut u8 as usize;
        let end = start + KERNEL_HEAP_SIZE;

        debug_assert_eq!(start % HEAP_BLOCK_ALIGNMENT, 0);

        state.start = start;
        state.end = end;
        state.available = KERNEL_HEAP_SIZE;
        state.initialized = true;

        // Register the entire heap as one free block.
        unsafe {
            block_set_size(start, KERNEL_HEAP_SIZE);
            block_clear_used(start);
            block_set_prev_phys(start, 0);

            insert_free_block(state, start);
        }
    }

    /// Allocate a block of memory matching the given `layout`.
    ///
    /// Searches the TLSF free lists for a suitable block, splits it if
    /// necessary, and returns a pointer to the payload (past the block
    /// header).  Returns a null pointer on allocation failure.
    ///
    /// # Parameters
    ///
    /// * `state` — mutable reference to the allocator state containing
    ///   the free lists and bitmaps.
    /// * `layout` — the requested size and alignment.
    /// * `profiler` — profiler for tracking allocated byte counts.
    pub(crate) fn allocate_locked(
        state: &mut AllocatorState,
        layout: Layout,
        profiler: &AllocProfiler,
    ) -> *mut u8 {
        let requested_size = layout.size().max(1);
        let requested_align = layout.align().max(HEAP_BLOCK_ALIGNMENT);

        // The block we request from the free lists must be large enough for
        // the header, the payload, and worst‑case alignment padding.
        // Tail-rounding to HEAP_BLOCK_ALIGNMENT is deterministic, so we
        // fold it in exactly:
        let end_round = HEAP_BLOCK_ALIGNMENT.wrapping_sub(HEADER_SIZE.wrapping_add(requested_size))
            % HEAP_BLOCK_ALIGNMENT;
        let mut min_block_size = HEADER_SIZE
            .saturating_add(requested_size)
            .saturating_add(requested_align.saturating_sub(HEAP_BLOCK_ALIGNMENT))
            .saturating_add(end_round);

        // Find a suitable free block via the TLSF bitmaps.
        // If alignment padding makes the chosen block too tight (rare —
        // happens when there is a gap smaller than MIN_FREE_BLOCK that
        // cannot be carved into a prefix), we re-insert it and search
        // for a larger one instead of giving up.
        let block = 'search: loop {
            let candidate = find_suitable_block(state, min_block_size);
            if candidate == 0 {
                crate::println!(
                    "[heap] ALLOC FAIL: requested {} bytes (align {}), min_block {} bytes, available {} KiB, fl_bitmap=0x{:x}",
                    requested_size,
                    requested_align,
                    min_block_size,
                    state.available / 1024,
                    state.fl_bitmap
                );
                return null_mut();
            }

            unsafe {
                remove_free_block(state, candidate);

                let block_end = candidate.saturating_add(block_size(candidate));
                let payload_start = match align_up(candidate + HEADER_SIZE, requested_align) {
                    Some(addr) => addr,
                    None => {
                        crate::println!(
                            "[heap] ALLOC FAIL (align_up overflow): block=0x{:x} size={} align={}",
                            candidate,
                            block_size(candidate),
                            requested_align,
                        );
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };
                let alloc_header_start = match payload_start.checked_sub(HEADER_SIZE) {
                    Some(addr) => addr,
                    None => {
                        crate::println!(
                            "[heap] ALLOC FAIL (header underflow): block=0x{:x} payload=0x{:x}",
                            candidate,
                            payload_start,
                        );
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };

                let mut alloc_end = match alloc_header_start
                    .checked_add(HEADER_SIZE)
                    .and_then(|a| a.checked_add(requested_size))
                {
                    Some(addr) => addr,
                    None => {
                        crate::println!(
                            "[heap] ALLOC FAIL (size overflow): block=0x{:x} header=0x{:x} requested={}",
                            candidate,
                            alloc_header_start,
                            requested_size,
                        );
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };
                alloc_end = match align_up(alloc_end, HEAP_BLOCK_ALIGNMENT) {
                    Some(addr) => addr,
                    None => {
                        crate::println!(
                            "[heap] ALLOC FAIL (end align overflow): block=0x{:x} alloc_end=0x{:x}",
                            candidate,
                            alloc_end,
                        );
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };

                if alloc_end > block_end {
                    // Alignment gap made this block too tight.
                    // Re-insert it and search for a larger one.
                    insert_free_block(state, candidate);
                    // Advance past the rejected block's entire SL class.
                    // Simply adding 1 to candidate_size can land in the same
                    // SL bucket, which would cause find_suitable_block to
                    // return the same block (now re-inserted at the list head)
                    // and create an infinite loop.
                    let candidate_size = block_size(candidate);
                    let (fl, sl) = mapping(candidate_size);
                    let sl_step = 1usize << fl.saturating_sub(SL_INDEX_LOG2);
                    let next_class_min = if sl + 1 < SL_COUNT {
                        // Start of the next SL class within the same FL.
                        (1usize << fl) + (sl + 1) * sl_step
                    } else {
                        // Start of the next FL class.
                        1usize << (fl + 1)
                    };
                    min_block_size = next_class_min;
                    continue 'search;
                }

                // ── Prefix (before aligned payload) ──
                let prefix_size = alloc_header_start.wrapping_sub(candidate);
                let prefix_created = prefix_size >= MIN_FREE_BLOCK;

                // ── Suffix (after the allocation) ──
                let suffix_size = block_end.wrapping_sub(alloc_end);
                let suffix_created = suffix_size >= MIN_FREE_BLOCK;

                // ── Mark the allocated block as used ──
                // A sub-minimum prefix (smaller than MIN_FREE_BLOCK) is too
                // small to be inserted as a free block.  Absorb it into the
                // allocated block by placing the block header at the free
                // block start, so the gap is reclaimed on free instead of
                // being orphaned forever.  A forwarding pointer to that start
                // is stored in the padding slot at `alloc_header_start` so
                // deallocate_locked can locate the real header.
                let (alloc_start, allocated_size) = if prefix_created {
                    block_set_size(candidate, prefix_size);
                    block_clear_used(candidate);
                    insert_free_block(state, candidate);

                    let allocated_size = alloc_end.wrapping_sub(alloc_header_start);
                    block_set_size(alloc_header_start, allocated_size);
                    block_set_used(alloc_header_start);
                    (alloc_header_start, allocated_size)
                } else if prefix_size > 0 {
                    let allocated_size = alloc_end.wrapping_sub(candidate);
                    block_set_size(candidate, allocated_size);
                    block_set_used(candidate);
                    // Already inside the enclosing `unsafe` block above.
                    core::ptr::write(alloc_header_start as *mut usize, candidate);
                    (candidate, allocated_size)
                } else {
                    let allocated_size = alloc_end.wrapping_sub(alloc_header_start);
                    block_set_size(alloc_header_start, allocated_size);
                    block_set_used(alloc_header_start);
                    (alloc_header_start, allocated_size)
                };

                // ── Suffix (after the allocation) ──
                if suffix_created {
                    block_set_size(alloc_end, suffix_size);
                    block_clear_used(alloc_end);
                    block_set_prev_phys(alloc_end, alloc_start);
                    insert_free_block(state, alloc_end);
                }

                // ── Fix up prev_phys chain ──
                if prefix_created {
                    block_set_prev_phys(alloc_header_start, candidate);
                }
                if suffix_created {
                    block_set_prev_phys_of_next(alloc_end, alloc_end);
                }

                // ── Accounting: only the bytes that become unavailable are
                //    removed.  The allocated block (which may include an
                //    absorbed alignment prefix) is subtracted here and added
                //    back on free; re-inserted prefix/suffix free blocks are
                //    not double-counted.
                state.available = state.available.saturating_sub(allocated_size);

                profiler.add_heap_bytes_allocated(allocated_size as u64);
                break 'search payload_start as *mut u8;
            }
        };
        block
    }

    /// Deallocate a block previously returned by [`allocate_locked`].
    ///
    /// Coalesces the freed block with its physical neighbours and
    /// inserts the result into the appropriate free list.
    ///
    /// Returns `true` if the block was successfully freed, `false` if
    /// `ptr` is null, outside the heap, or already free (double-free).
    ///
    /// # Parameters
    ///
    /// * `state` — mutable reference to the allocator state.
    /// * `ptr` — pointer to the payload (must have been returned by
    ///   a prior call to [`allocate_locked`]).
    /// * `profiler` — profiler for tracking freed byte counts.
    pub(crate) fn deallocate_locked(
        state: &mut AllocatorState,
        ptr: *mut u8,
        profiler: &AllocProfiler,
    ) -> bool {
        if ptr.is_null() {
            return false;
        }

        let payload_start = ptr as usize;
        let nominal = match payload_start.checked_sub(HEADER_SIZE) {
            Some(addr) => addr,
            None => return false,
        };

        // A block whose allocation absorbed a sub-minimum (16-byte) alignment
        // prefix keeps its true header at the free-block start, one
        // HEAP_BLOCK_ALIGNMENT below `nominal`, and stores a forwarding
        // pointer to that start in the padding slot at `nominal`.  A used
        // block's size word at `nominal` is always odd (bit 0 is the used
        // flag), so a 16-aligned value there unambiguously marks a forwarded
        // block.
        let header_start = if nominal >= state.start && nominal < state.end {
            let fwd = unsafe { *(nominal as *const usize) };
            if fwd >= state.start
                && fwd < nominal
                && fwd.is_multiple_of(HEAP_BLOCK_ALIGNMENT)
                && nominal == fwd.wrapping_add(HEAP_BLOCK_ALIGNMENT)
            {
                let size = unsafe { block_size(fwd) };
                let end = fwd.wrapping_add(size);
                if unsafe { block_is_used(fwd) }
                    && size >= HEADER_SIZE
                    && fwd <= payload_start
                    && payload_start < end
                    && end <= state.end
                {
                    fwd
                } else {
                    nominal
                }
            } else {
                nominal
            }
        } else {
            nominal
        };

        if !(state.start..state.end).contains(&header_start) {
            return false;
        }

        let size = unsafe { block_size(header_start) };
        if size == 0 || size < HEADER_SIZE {
            return false;
        }
        if !unsafe { block_is_used(header_start) } {
            // Already free — double‑free is a no‑op.
            return false;
        }

        state.available = state.available.saturating_add(size);

        // Mark the block as free.
        unsafe {
            block_clear_used(header_start);
        }

        // Coalesce with physical neighbours, then insert.
        let block = unsafe { coalesce(state, header_start) };

        unsafe {
            insert_free_block(state, block);
        }

        profiler.add_heap_bytes_freed(size as u64);
        true
    }

    /// Return the `(start, end)` physical addresses of the kernel heap.
    pub fn bounds(&self) -> (usize, usize) {
        self.with_state(|state| (state.start, state.end))
    }

    /// Return the number of free bytes remaining in the kernel heap.
    pub fn remaining(&self) -> usize {
        self.with_state(|state| state.available)
    }

    /// Debug-only: walk all free lists and verify every block is well-formed.
    /// Panics with diagnostic information on the first invalid block found.
    #[cfg(debug_assertions)]
    pub fn verify_heap_integrity(&self) {
        self.with_state(|state| unsafe {
            scan_free_lists(state);
        });
    }

    #[cfg(not(debug_assertions))]
    pub fn verify_heap_integrity(&self) {}
}

// ─── GlobalAlloc impl ─────────────────────────────────────────────────────

unsafe impl GlobalAlloc for KernelGlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = self.with_state(|state| Self::allocate_locked(state, layout, &self.profiler));
        if !result.is_null() {
            self.profiler.inc_heap_allocs();
        }
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let had_bytes =
            self.with_state(|state| Self::deallocate_locked(state, ptr, &self.profiler));
        if had_bytes {
            self.profiler.inc_heap_frees();
        }
    }
}

// ─── Spinlock guard ───────────────────────────────────────────────────────

pub(crate) struct KernelGlobalAllocatorGuard<'a> {
    allocator: &'a KernelGlobalAllocator,
    interrupts_were_enabled: bool,
}

impl Drop for KernelGlobalAllocatorGuard<'_> {
    fn drop(&mut self) {
        // Release lock first, then restore caller interrupt state.
        self.allocator.locked.store(false, Ordering::Release);
        arch::interrupts::restore(self.interrupts_were_enabled);
    }
}
