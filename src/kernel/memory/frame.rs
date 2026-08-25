//! src/kernel/memory/frame.rs
//!
//! Physical frame allocator with free-range tracking, reuse, and coalescing.
//!
//! Free ranges are tracked in a `BTreeMap<start_frame, count>` for O(log n)
//! insertion and removal, replacing the previous `Vec<FrameRange>` which
//! required O(n) element shifting on every insert/remove.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;
use alloc::collections::BTreeMap;

use crate::kernel::memory::alloc_profiler::AllocProfiler;

pub const FRAME_SIZE: usize = 4096;
pub const MAX_NODES: usize = 8;
// Backing pool for host/bare-metal frame simulation; allocation is
// frame-granular.
const PHYSICAL_POOL_SIZE: usize = 512 * 1024 * 1024;

#[repr(C, align(4096))]
struct PhysicalPool([u8; PHYSICAL_POOL_SIZE]);

static PHYSICAL_POOL: SyncUnsafeCell<PhysicalPool> =
    SyncUnsafeCell::new(PhysicalPool([0; PHYSICAL_POOL_SIZE]));

pub const fn physical_pool_size() -> usize {
    PHYSICAL_POOL_SIZE
}

pub struct FrameAllocator {
    // `next_frame` is the bump-allocation high-water mark; anything below it is
    // either live or tracked explicitly in `free_ranges`.
    base: usize,
    total_frames: usize,
    next_frame: usize,
    // Sorted (by BTreeMap key order), non-overlapping free segments recycled
    // after deallocation.  Key = start_frame, value = count.
    free_ranges: BTreeMap<usize, usize>,
    /// Frame allocator profiler (zero-cost when `alloc_profiler` feature is
    /// disabled).
    pub profiler: AllocProfiler,
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self {
            base: 0,
            total_frames: 0,
            next_frame: 0,
            free_ranges: BTreeMap::new(),
            profiler: AllocProfiler::new(),
        }
    }

    pub fn init(&mut self, total_size: usize) {
        self.base = PHYSICAL_POOL.get() as *mut u8 as usize;
        // Clamp callers to the simulated pool and ignore any tail smaller than
        // one frame so raw byte counts remain acceptable.
        self.total_frames = total_size.min(PHYSICAL_POOL_SIZE) / FRAME_SIZE;
        self.next_frame = 0;
        self.free_ranges.clear();
    }

    /// Configure this allocator to manage a sub-range of the physical pool.
    ///
    /// `start_frame` and `end_frame` are frame indices relative to the start of
    /// the physical pool.  The range is `[start_frame, end_frame)`.
    /// `node_id` is stored for diagnostic / profiling use.
    pub fn set_node_range(&mut self, node_id: u8, start_frame: usize, end_frame: usize) {
        let pool_base = PHYSICAL_POOL.get() as *mut u8 as usize;
        self.base = pool_base + start_frame * FRAME_SIZE;
        self.total_frames = end_frame.saturating_sub(start_frame);
        self.next_frame = 0;
        self.free_ranges.clear();
        let _ = node_id; // Reserved for future per-node profiling.
    }

    pub fn allocate(&mut self, count: usize) -> Option<*mut u8> {
        if self.base == 0 || count == 0 {
            return None;
        }

        // Reuse holes first so long-lived churn does not force the bump tail forward.
        if let Some(frame_start) = self.allocate_from_free_ranges(count) {
            let address = self.frame_address(frame_start)?;
            let zero_bytes = (count * FRAME_SIZE) as u64;
            self.zero_frame_range(frame_start, count)?;
            self.profiler.inc_frame_allocs();
            self.profiler.inc_frame_recycled();
            self.profiler.add_frame_zero_bytes(zero_bytes);
            return Some(address as *mut u8);
        }

        let frame_start = self.next_frame;
        let end_frame = frame_start.checked_add(count)?;
        if end_frame > self.total_frames {
            return None;
        }

        let address = self.frame_address(frame_start)?;
        self.next_frame = end_frame;
        let zero_bytes = (count * FRAME_SIZE) as u64;
        self.zero_frame_range(frame_start, count)?;
        self.profiler.inc_frame_allocs();
        self.profiler.inc_frame_bump_allocs();
        self.profiler.add_frame_zero_bytes(zero_bytes);
        Some(address as *mut u8)
    }

    /// Return the total number of physical frames managed by this allocator.
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Return the number of currently free/allocation frames.
    ///
    /// This is the bump tail (`next_frame`) minus allocated frames currently
    /// tracked as live.  Free ranges (holes returned via deallocate) are
    /// included because the bump tail already covers past them.
    pub fn available_frames(&self) -> usize {
        self.total_frames.saturating_sub(self.next_frame)
    }

    pub fn deallocate(&mut self, ptr: *mut u8, count: usize) -> bool {
        if self.base == 0 || ptr.is_null() || count == 0 {
            return false;
        }

        let address = ptr as usize;
        if address < self.base {
            return false;
        }

        let offset = address - self.base;
        // The allocator only speaks in whole frames; partial-frame frees would
        // corrupt the free list.
        if !offset.is_multiple_of(FRAME_SIZE) {
            return false;
        }

        let start_frame = offset / FRAME_SIZE;
        let end_frame = match start_frame.checked_add(count) {
            Some(end) => end,
            None => return false,
        };

        if end_frame > self.total_frames || end_frame > self.next_frame {
            return false;
        }

        if !self.insert_free_range(start_frame, count) {
            return false;
        }

        self.rewind_tail_high_water_mark();
        self.profiler.inc_frame_frees();
        true
    }

    fn rewind_tail_high_water_mark(&mut self) {
        // If the highest free range touches the allocation tail, shrink tail
        // eagerly so future allocations reuse the reclaimed region.
        loop {
            let tail = self.free_ranges.last_key_value().map(|(&s, &c)| (s, c));
            match tail {
                Some((start, count)) if start + count == self.next_frame => {
                    self.next_frame = start;
                    self.free_ranges.remove(&start);
                }
                _ => break,
            }
        }
    }

    fn frame_address(&self, frame_start: usize) -> Option<usize> {
        self.base.checked_add(frame_start.checked_mul(FRAME_SIZE)?)
    }

    /// Return the number of frames in the largest contiguous free region.
    ///
    /// This includes the untracked bump tail: every frame at or above
    /// `next_frame` is free and contiguous, so a fully-compacted pool
    /// reports its whole tail here.  A value of `0` means the pool is fully
    /// allocated.
    pub fn largest_free_contiguous_frames(&self) -> usize {
        let tail_free = self.total_frames.saturating_sub(self.next_frame);
        self.free_ranges
            .values()
            .copied()
            .max()
            .unwrap_or(0)
            .max(tail_free)
    }

    /// Number of distinct free ranges — a fragmentation metric.  Fragmented
    /// pools have many small ranges; a compacted pool has at most one.
    pub fn free_range_count(&self) -> usize {
        self.free_ranges.len()
    }

    /// Compact the physical pool by moving live frames down into holes,
    /// consolidating all free space into a single contiguous block at the
    /// tail.
    ///
    /// `fixup` is invoked as `(old_address, new_address)` for each live frame
    /// that is relocated, *before* its contents are copied; it must update
    /// any external references (page-table mappings) to the frame's new
    /// address and return `true`.  When it returns `false` the frame is left
    /// in place and compaction stops — unmovable frames act as barriers.  Any
    /// frames already moved before the barrier are preserved.
    ///
    /// Returns the number of frames successfully moved.
    pub fn compact<F>(&mut self, mut fixup: F) -> usize
    where
        F: FnMut(usize, usize) -> bool,
    {
        let n = self.next_frame;
        // `free_bit[i]` is true when frame `i` is free.  We compact against a
        // bitmap so that an early stop (unmovable barrier) rebuilds the free
        // list without clobbering live frames that were never relocated.
        let mut free_bit: alloc::vec::Vec<bool> = alloc::vec![false; n];
        for (&start, &count) in &self.free_ranges {
            for bit in free_bit.iter_mut().skip(start).take(count) {
                *bit = true;
            }
        }

        let mut moved = 0usize;
        let mut fill = 0usize;
        let mut f = 0usize;
        while f < n {
            if free_bit[f] {
                f += 1;
                continue;
            }
            if fill < f {
                // Invariant: position `fill` is free — every position below
                // `fill` has been finalized live, and everything in
                // [`fill`, `f`) is a hole or a vacated source.
                let (Some(old_addr), Some(new_addr)) =
                    (self.frame_address(f), self.frame_address(fill))
                else {
                    break;
                };
                if !fixup(old_addr, new_addr) {
                    // Unmovable frame — everything below it is now final.
                    break;
                }
                // Move the frame contents into the hole.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        old_addr as *const u8,
                        new_addr as *mut u8,
                        FRAME_SIZE,
                    );
                }
                free_bit[fill] = false;
                free_bit[f] = true;
                moved += 1;
            }
            fill += 1;
            f += 1;
        }

        // Rebuild the free list from the bitmap, coalescing adjacent runs.
        self.free_ranges.clear();
        let mut run_start: Option<usize> = None;
        for (i, is_free) in free_bit.iter().copied().enumerate() {
            if is_free {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(s) = run_start.take() {
                self.free_ranges.insert(s, i - s);
            }
        }
        if let Some(s) = run_start {
            self.free_ranges.insert(s, n - s);
        }
        moved
    }

    fn zero_frame_range(&self, frame_start: usize, count: usize) -> Option<()> {
        let address = self.frame_address(frame_start)?;
        let byte_len = count.checked_mul(FRAME_SIZE)?;
        unsafe {
            core::ptr::write_bytes(address as *mut u8, 0, byte_len);
        }
        Some(())
    }

    /// First-fit search over address-ordered free ranges.
    /// Iteration order is ascending by key (start_frame), which matches the
    /// sorted-address order previously maintained by the Vec.
    fn allocate_from_free_ranges(&mut self, count: usize) -> Option<usize> {
        // Find the first range whose count is sufficient.
        let found_key = {
            let mut key = None;
            for (&start, &cnt) in self.free_ranges.iter() {
                if cnt >= count {
                    key = Some(start);
                    break;
                }
            }
            key
        };

        let start = found_key?;
        let range_count = self.free_ranges.remove(&start)?;

        if range_count > count {
            self.free_ranges.insert(start + count, range_count - count);
        }

        Some(start)
    }

    /// Insert a freed frame range, coalescing with adjacent ranges.
    ///
    /// Returns `false` if the range overlaps with an existing free range
    /// (indicating a double-free or corruption).
    fn insert_free_range(&mut self, start_frame: usize, count: usize) -> bool {
        if count == 0 {
            return false;
        }

        let mut new_start = start_frame;
        let mut new_count = count;

        // Check the previous range (largest start_frame < start_frame) for
        // overlap or adjacency.
        let merge_prev = self
            .free_ranges
            .range(..start_frame)
            .next_back()
            .map(|(&s, &c)| (s, c));

        if let Some((prev_start, prev_count)) = merge_prev {
            let prev_end = prev_start + prev_count;
            if start_frame < prev_end {
                return false; // Overlap with previous range
            }
            if start_frame == prev_end {
                // Coalesce with previous
                self.free_ranges.remove(&prev_start);
                new_start = prev_start;
                new_count += prev_count;
            }
        }

        // Merge with following adjacent ranges.  We collect keys first to
        // avoid borrowing conflicts between range() and remove().
        loop {
            let next = self
                .free_ranges
                .range(new_start + new_count..)
                .next()
                .map(|(&s, &c)| (s, c));

            match next {
                Some((next_start, next_count)) => {
                    let new_end = new_start + new_count;
                    if new_end < next_start {
                        break; // Gap before next range — done coalescing
                    }
                    if new_end > next_start {
                        return false; // Overlap (should be unreachable with
                                      // well-formed free_ranges)
                    }
                    // Adjacent: coalesce
                    self.free_ranges.remove(&next_start);
                    new_count += next_count;
                }
                None => break,
            }
        }

        self.free_ranges.insert(new_start, new_count);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::physical_pool_size;
    use super::FrameAllocator;
    use super::FRAME_SIZE;
    use alloc::vec::Vec;

    #[test]
    fn allocator_reuses_a_freed_frame_range() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 16);

        let first = allocator.allocate(1).expect("allocate first frame") as usize;
        let second = allocator.allocate(1).expect("allocate second frame") as usize;

        assert!(allocator.deallocate(first as *mut u8, 1));
        let recycled = allocator.allocate(1).expect("reuse freed frame") as usize;

        assert_eq!(recycled, first);
        assert_ne!(recycled, second);
    }

    #[test]
    fn allocator_coalesces_adjacent_freed_ranges() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 16);

        let head = allocator.allocate(3).expect("allocate head") as usize;
        let tail = allocator.allocate(3).expect("allocate tail") as usize;

        assert_eq!(tail, head + 3 * FRAME_SIZE);
        assert!(allocator.deallocate(head as *mut u8, 3));
        assert!(allocator.deallocate(tail as *mut u8, 3));

        let merged = allocator.allocate(6).expect("allocate merged range") as usize;
        assert_eq!(merged, head);
    }

    #[test]
    fn allocator_rejects_invalid_or_overlapping_deallocations() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let first = allocator.allocate(2).expect("allocate test range");
        assert!(!allocator.deallocate(core::ptr::null_mut(), 1));
        assert!(!allocator.deallocate((first as usize + 1) as *mut u8, 1));
        assert!(!allocator.deallocate(first, 0));
        assert!(!allocator.deallocate((first as usize + 4 * FRAME_SIZE) as *mut u8, 1));

        assert!(allocator.deallocate(first, 2));
        assert!(!allocator.deallocate(first, 1));
    }

    #[test]
    fn allocator_rewinds_high_water_mark_after_tail_free() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let _head = allocator.allocate(2).expect("allocate head range") as usize;
        let tail = allocator.allocate(2).expect("allocate tail range") as usize;

        assert!(allocator.deallocate(tail as *mut u8, 2));
        let rewound = allocator.allocate(4).expect("allocate after tail rewind") as usize;

        assert_eq!(rewound, tail);
    }

    #[test]
    fn allocator_zeroes_recycled_frames_before_reuse() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let frame = allocator.allocate(1).expect("allocate test frame");
        unsafe {
            core::ptr::write_bytes(frame, 0xA5, FRAME_SIZE);
        }

        assert!(allocator.deallocate(frame, 1));
        let recycled = allocator.allocate(1).expect("reallocate test frame");
        assert_eq!(recycled as usize, frame as usize);

        let bytes = unsafe { core::slice::from_raw_parts(recycled as *const u8, FRAME_SIZE) };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn allocator_tracks_more_than_legacy_free_range_capacity() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 256);

        let mut frames = Vec::new();
        for _ in 0..140 {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }

        for index in (0..frames.len()).step_by(2) {
            assert!(allocator.deallocate(frames[index], 1));
        }

        for _ in 0..70 {
            assert!(allocator.allocate(1).is_some());
        }
    }

    #[test]
    fn allocator_init_clamps_capacity_to_backing_pool_size() {
        let mut allocator = FrameAllocator::new();
        allocator.init(physical_pool_size() + FRAME_SIZE * 8);

        let max_frames = physical_pool_size() / FRAME_SIZE;
        for _ in 0..max_frames {
            assert!(allocator.allocate(1).is_some());
        }
        assert!(allocator.allocate(1).is_none());
    }

    // ── compaction / defragmentation ──────────────────────────────────────

    /// Helper: build a fragmented pool with `total` single frames, then free
    /// every even-indexed frame so the free ranges interleave with live
    /// frames.
    fn fragmented_pool(total: usize) -> (FrameAllocator, Vec<*mut u8>) {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * total);
        let mut frames = Vec::new();
        for _ in 0..total {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }
        for &frame in frames.iter().step_by(2) {
            assert!(allocator.deallocate(frame, 1));
        }
        (allocator, frames)
    }

    #[test]
    fn compact_consolidates_fragmented_free_ranges_into_one_block() {
        let (mut allocator, frames) = fragmented_pool(10);

        // Before: 5 interleaved single-frame holes.
        assert_eq!(allocator.free_range_count(), 5);
        assert_eq!(allocator.largest_free_contiguous_frames(), 1);

        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 5); // the 5 live frames moved into the 5 holes

        // After: a single contiguous 5-frame free block at the tail.
        assert_eq!(allocator.free_range_count(), 1);
        assert_eq!(allocator.largest_free_contiguous_frames(), 5);

        // The freed tail now satisfies a 5-frame allocation.
        assert!(allocator.allocate(5).is_some());
        // Keep `frames` alive for the duration of the test (borrow semantics).
        let _ = &frames;
    }

    #[test]
    fn compact_moves_contents_and_reports_address_pairs() {
        let (mut allocator, _frames) = fragmented_pool(6);
        // Fragmented: live at {1,3,5}, holes at {0,2,4}.
        let mut moves: Vec<(usize, usize)> = Vec::new();
        let moved = allocator.compact(|old_addr, new_addr| {
            moves.push((old_addr, new_addr));
            true
        });
        assert_eq!(moved, 3); // frames 1, 3, 5 move down into holes 0, 1, 2
                              // Every move relocates a frame strictly downward.
        assert!(moves.iter().all(|(old, new)| old > new));
        assert_eq!(allocator.largest_free_contiguous_frames(), 3);
    }

    #[test]
    fn compact_preserves_content_of_moved_frames() {
        // Use a high sub-range of the shared backing pool (64 MiB in) so
        // parallel frame tests allocating from the front of the pool cannot
        // clobber the patterns written here.
        const BASE_FRAME: usize = 1 << 14;
        let mut allocator = FrameAllocator::new();
        allocator.set_node_range(0, BASE_FRAME, BASE_FRAME + 16);
        let mut frames = Vec::new();
        for _ in 0..16 {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }
        for &frame in frames.iter().step_by(2) {
            assert!(allocator.deallocate(frame, 1));
        }

        // Write a distinctive pattern into every frame so we can verify the
        // live frames' contents survive the move.  Frames 1, 3, .., 15 are
        // live (evens were freed); each holds value (index + 1).
        let base = allocator.base;
        for (i, &_frame) in frames.iter().enumerate() {
            unsafe {
                core::ptr::write_bytes(
                    (base + i * FRAME_SIZE) as *mut u8,
                    (i + 1) as u8,
                    FRAME_SIZE,
                );
            }
        }
        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 8);

        // After compaction the live frames occupy slots 0..8 — contents must
        // match the original frames 1, 3, .., 15 (values 2, 4, .., 16).
        let expected: Vec<u8> = (0..8).map(|k| ((k * 2) + 2) as u8).collect();
        for (slot, &value) in expected.iter().enumerate() {
            let frame_base = base + slot * FRAME_SIZE;
            let bytes = unsafe { core::slice::from_raw_parts(frame_base as *const u8, FRAME_SIZE) };
            assert!(
                bytes.iter().all(|&b| b == value),
                "compacted frame {slot} should hold original value {value}"
            );
        }
    }

    #[test]
    fn compact_stops_at_immovable_frame() {
        let (mut allocator, _frames) = fragmented_pool(6);
        // Refuse the very first move: nothing should be relocated and the
        // free ranges must stay untouched.
        let moved = allocator.compact(|_, _| false);
        assert_eq!(moved, 0);
        assert_eq!(allocator.free_range_count(), 3);
    }

    #[test]
    fn compact_is_idempotent_on_already_compacted_pool() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);
        let head = allocator.allocate(2).expect("allocate head");
        let tail = allocator.allocate(3).expect("allocate tail");
        assert!(allocator.deallocate(tail, 3));

        // Freeing the exact tail rewinds the high-water mark, so the whole
        // remaining pool is one contiguous free block above `next_frame`.
        assert_eq!(allocator.free_range_count(), 0);
        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 0);
        assert_eq!(allocator.largest_free_contiguous_frames(), 6);
        // head/tail handles keep their allocations valid for this test scope.
        let _ = (head, tail);
    }
}
