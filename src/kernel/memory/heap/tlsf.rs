//! src/kernel/memory/heap/tlsf.rs
//!
//! TLSF (Two-Level Segregated Fit) internals: constants, block header layout,
//! raw block accessors, free-list management, bit-scanning search, and
//! physical coalescing.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;

// ─── Constants ────────────────────────────────────────────────────────────

pub(crate) const KERNEL_HEAP_SIZE: usize = 16 * 1024 * 1024;

/// Minimum alignment of any block returned by the allocator.
pub(crate) const HEAP_BLOCK_ALIGNMENT: usize = 16;

// TLSF class constants.
//
// The allocator classifies free blocks by size:
//   fl = ⌊log₂(size)⌋         first-level index  (exponent)
//   sl = fractional part        second-level index (0 … SL_COUNT-1)
//
// With FL_MIN = 5 the smallest block class covers 2⁵ = 32 bytes
// (header + 16‑byte payload).  FL_MAX = 24 covers up to 2²⁴ = 16 MiB,
// which is the entire heap.
pub(crate) const FL_MIN: usize = 5;
pub(crate) const FL_MAX: usize = 24;
pub(crate) const FL_COUNT: usize = FL_MAX - FL_MIN + 1; // 20
pub(crate) const SL_COUNT: usize = 32;
pub(crate) const SL_INDEX_LOG2: usize = 5; // log₂(SL_COUNT)

pub(crate) const FREE_LISTS_COUNT: usize = FL_COUNT * SL_COUNT; // 640

// ─── Block header — 16 bytes on 64‑bit ────────────────────────────────────

/// `size` uses the least-significant bit as the free/used flag:
///   bit 0 = 0 → block is free
///   bit 0 = 1 → block is in use
pub(crate) const BLOCK_USED_FLAG: usize = 1;

pub(crate) const HEADER_SIZE: usize = 16; // size: usize + prev_phys_block: usize

/// Offsets (in bytes) for free-block metadata stored *inside* the payload
/// area of a free block.  Singly-linked lists use only `next_free`.
pub(crate) const FREE_NEXT_OFFSET: usize = HEADER_SIZE; // next_free: usize

/// Minimum size a block must have to be insertable into a free list.
/// Must accommodate header (16) + next_free pointer (8) = 24, then rounded
/// up to the next 16‑byte alignment boundary.
pub(crate) const MIN_FREE_BLOCK: usize = 32;

#[repr(C, align(16))]
pub(crate) struct KernelHeap([u8; KERNEL_HEAP_SIZE]);

pub(crate) static KERNEL_HEAP: SyncUnsafeCell<KernelHeap> =
    SyncUnsafeCell::new(KernelHeap([0; KERNEL_HEAP_SIZE]));

// ─── Allocator state ──────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct AllocatorState {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) available: usize,
    pub(crate) initialized: bool,

    /// Each bit N (N = fl - FL_MIN) is set when at least one free list in
    /// first-level class `fl` is non‑empty.
    pub(crate) fl_bitmap: u32,

    /// `sl_bitmaps[fl - FL_MIN]` — one bit per second-level subclass.
    pub(crate) sl_bitmaps: [u32; FL_COUNT],

    /// Heads of the 640 singly‑linked free lists.  `0` means empty.
    pub(crate) free_lists: [usize; FREE_LISTS_COUNT],
}

impl AllocatorState {
    pub(crate) const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            available: 0,
            initialized: false,
            fl_bitmap: 0,
            sl_bitmaps: [0; FL_COUNT],
            free_lists: [0; FREE_LISTS_COUNT],
        }
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────

pub(crate) fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|aligned| aligned & !(align - 1))
}

// ─── Raw block accessors ──────────────────────────────────────────────────
//
// All functions in this section operate on raw block addresses and are
// inherently unsafe — the caller must ensure the address points to a valid
// block within the heap bounds.

/// Read the full `size` field (includes the used/free flag in bit 0).
#[inline(always)]
pub(crate) unsafe fn block_raw_size(block: usize) -> usize {
    (block as *const usize).read()
}

/// Read the block size *without* the used/free flag.
#[inline(always)]
pub(crate) unsafe fn block_size(block: usize) -> usize {
    block_raw_size(block) & !BLOCK_USED_FLAG
}

/// Write the block size, preserving the used/free flag.
#[inline(always)]
pub(crate) unsafe fn block_set_size(block: usize, size: usize) {
    let flag = block_raw_size(block) & BLOCK_USED_FLAG;
    (block as *mut usize).write(size | flag);
}

#[inline(always)]
pub(crate) unsafe fn block_is_used(block: usize) -> bool {
    block_raw_size(block) & BLOCK_USED_FLAG != 0
}

#[inline(always)]
pub(crate) unsafe fn block_set_used(block: usize) {
    let raw = block_raw_size(block);
    (block as *mut usize).write(raw | BLOCK_USED_FLAG);
}

#[inline(always)]
pub(crate) unsafe fn block_clear_used(block: usize) {
    let raw = block_raw_size(block);
    (block as *mut usize).write(raw & !BLOCK_USED_FLAG);
}

#[inline(always)]
pub(crate) unsafe fn block_prev_phys(block: usize) -> usize {
    (block as *const usize).add(1).read()
}

#[inline(always)]
pub(crate) unsafe fn block_set_prev_phys(block: usize, prev: usize) {
    (block as *mut usize).add(1).write(prev);
}

/// Update the `prev_phys` pointer of the block that physically follows
/// `block` to point to `new_prev`.
///
/// The `prev_phys` field lives in the block header (offset 8) and is valid
/// for **every** block — free or used.  When the block is later freed,
/// `coalesce` reads `prev_phys` to locate the physical predecessor.
pub(crate) unsafe fn block_set_prev_phys_of_next(block: usize, new_prev: usize) {
    let size = block_size(block);
    let next = block.wrapping_add(size);
    let heap = KERNEL_HEAP.get() as *mut u8 as usize;
    let heap_end = heap.wrapping_add(KERNEL_HEAP_SIZE);
    if next < heap_end {
        #[cfg(debug_assertions)]
        {
            debug_assert!(
                next.is_multiple_of(HEAP_BLOCK_ALIGNMENT),
                "block_set_prev_phys_of_next: next=0x{next:x} not aligned; block=0x{block:x} size={size}"
            );
            let write_addr = next.checked_add(8).expect("prev_phys write overflow");
            debug_assert!(
                write_addr <= heap_end,
                "block_set_prev_phys_of_next: write at 0x{write_addr:x} beyond heap_end 0x{heap_end:x}; block=0x{block:x} size={size}"
            );
        }
        block_set_prev_phys(next, new_prev);
    }
}

// Free-block specific accessors — only valid when the block is free.

#[inline(always)]
pub(crate) unsafe fn block_next_free(block: usize) -> usize {
    (block as *const usize).add(FREE_NEXT_OFFSET / 8).read()
}

#[inline(always)]
pub(crate) unsafe fn block_set_next_free(block: usize, next: usize) {
    (block as *mut usize).add(FREE_NEXT_OFFSET / 8).write(next);
}

// ─── TLSF mapping ─────────────────────────────────────────────────────────

/// Map a block `size` to its (first‑level, second‑level) class.
///
/// The returned `fl` is the position of the most-significant set bit
/// (0‑based from LSB).  `sl` extracts the next 5 bits below the MSB.
pub(crate) fn mapping(size: usize) -> (usize, usize) {
    debug_assert!(
        size >= (1 << FL_MIN),
        "size {size} too small for TLSF mapping"
    );
    let leading = size.leading_zeros();
    let fl = (usize::BITS as usize - 1) - leading as usize;
    // Extract the next SL_INDEX_LOG2 bits below the MSB.
    let shift = fl.saturating_sub(SL_INDEX_LOG2);
    let sl = ((size >> shift) ^ (1 << SL_INDEX_LOG2)) & (SL_COUNT - 1);
    (fl, sl)
}

/// Compute the list index for a given (fl, sl) pair.
#[inline(always)]
pub(crate) fn list_index(fl: usize, sl: usize) -> usize {
    debug_assert!((FL_MIN..=FL_MAX).contains(&fl));
    debug_assert!(sl < SL_COUNT);
    (fl - FL_MIN) * SL_COUNT + sl
}

/// Debug-only validation: check that a block looks sane before touching its
/// free-list linkage.  Returns the (fl, sl) mapping if valid.
#[cfg(debug_assertions)]
pub(crate) unsafe fn validate_block(
    state: &AllocatorState,
    block: usize,
    caller: &str,
) -> (usize, usize) {
    if block == 0 {
        panic!("{caller}: null block");
    }
    if block < state.start || block >= state.end {
        panic!(
            "{caller}: block 0x{block:x} outside heap [0x{:x}, 0x{:x})",
            state.start, state.end
        );
    }
    if !block.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
        panic!("{caller}: block 0x{block:x} misaligned");
    }
    let size = block_size(block);
    if size < MIN_FREE_BLOCK {
        panic!("{caller}: block 0x{block:x} size {size} below MIN_FREE_BLOCK");
    }
    let end = block.wrapping_add(size);
    if end > state.end {
        panic!(
            "{caller}: block 0x{block:x} size {size} overflows heap end 0x{:x}",
            state.end
        );
    }
    let (fl, sl) = mapping(size);
    if !(FL_MIN..=FL_MAX).contains(&fl) {
        panic!(
            "{caller}: block 0x{block:x} size {size} maps to fl={fl} (FL_MAX={FL_MAX}); \
             first 16 bytes: {:02x?}",
            core::slice::from_raw_parts(block as *const u8, 16)
        );
    }
    (fl, sl)
}

// ─── Free‑list management ─────────────────────────────────────────────────

/// Insert `block` into the appropriate free list.
pub(crate) unsafe fn insert_free_block(state: &mut AllocatorState, block: usize) {
    debug_assert!(!block_is_used(block));
    let size = block_size(block);

    if size < MIN_FREE_BLOCK {
        // Block is too small to be on a free list — this can happen when a
        // remainder after splitting is tiny.  It will be absorbed by the
        // next coalesce.
        return;
    }

    #[cfg(debug_assertions)]
    let (fl, sl) = validate_block(state, block, "insert_free_block");
    #[cfg(not(debug_assertions))]
    let (fl, sl) = mapping(size);
    let idx = list_index(fl, sl);

    // Singly‑linked list insertion at head.
    let head = state.free_lists[idx];
    block_set_next_free(block, head);
    // Zero the first MIN_FREE_BLOCK bytes of the payload (past next_free) so
    // that a future split that places a new block header here won't see stale
    // application data as block metadata.
    zero_fresh_header_region(block);
    state.free_lists[idx] = block;

    // Update bitmaps.
    let fl_bit = 1u32 << (fl - FL_MIN);
    state.fl_bitmap |= fl_bit;
    state.sl_bitmaps[fl - FL_MIN] |= 1u32 << sl;
}

/// Zero a generous prefix of the free block's payload (past `next_free`)
/// so that stale application data cannot be misread as a block header when
/// the block is later split at typical alignment offsets.
///
/// 2048 bytes is large enough to cover the `Context` struct (including its
/// `flags` field at offset 16, whose value 0x2 matches the RFLAGS reserved
/// bit and would otherwise be misread as a block size when a split boundary
/// aligns with the field).
const FRESH_ZERO_BYTES: usize = 2048;

unsafe fn zero_fresh_header_region(block: usize) {
    let size = block_size(block);
    let zero_start = block + HEADER_SIZE + 8; // past next_free
    let zero_end = (block + FRESH_ZERO_BYTES).min(block + size);
    if zero_start < zero_end {
        core::ptr::write_bytes(zero_start as *mut u8, 0, zero_end - zero_start);
    }
}

/// Remove `block` from whatever free list it currently resides on.
/// For singly‑linked lists, this scans the appropriate list to find the
/// block's predecessor.
pub(crate) unsafe fn remove_free_block(state: &mut AllocatorState, block: usize) {
    let size = block_size(block);
    if size < MIN_FREE_BLOCK {
        return;
    }

    #[cfg(debug_assertions)]
    let (fl, sl) = validate_block(state, block, "remove_free_block(target)");
    #[cfg(not(debug_assertions))]
    let (fl, sl) = mapping(size);
    let idx = list_index(fl, sl);

    let mut prev: usize = 0;
    let mut current = state.free_lists[idx];

    while current != 0 {
        #[cfg(debug_assertions)]
        validate_block(state, current, "remove_free_block(traverse)");

        if current == block {
            // Found it — unlink.
            let next = block_next_free(current);
            if prev == 0 {
                state.free_lists[idx] = next;
            } else {
                block_set_next_free(prev, next);
            }
            break;
        }
        prev = current;
        current = block_next_free(current);
    }

    // If the list is now empty, clear the bitmap bits.
    if state.free_lists[idx] == 0 {
        state.sl_bitmaps[fl - FL_MIN] &= !(1u32 << sl);
        if state.sl_bitmaps[fl - FL_MIN] == 0 {
            state.fl_bitmap &= !(1u32 << (fl - FL_MIN));
        }
    }
}

/// Debug-only: walk every free list and verify every block in every chain
/// has a well-formed header.  Catches corruption before the allocator acts on
/// a poisoned pointer.
#[cfg(debug_assertions)]
pub(crate) unsafe fn scan_free_lists(state: &AllocatorState) {
    let mut fl_bits = state.fl_bitmap;
    while fl_bits != 0 {
        let fl_bit = fl_bits.trailing_zeros() as usize;
        fl_bits &= fl_bits - 1;
        // Corrupted fl_bitmap may have bits beyond FL_COUNT; skip them.
        if fl_bit >= FL_COUNT {
            continue;
        }
        let fl = fl_bit + FL_MIN;
        let mut sl_bits = state.sl_bitmaps[fl_bit];
        while sl_bits != 0 {
            let sl = sl_bits.trailing_zeros() as usize;
            sl_bits &= sl_bits - 1;
            if sl >= SL_COUNT {
                continue;
            }
            let idx = list_index(fl, sl);
            let mut current = state.free_lists[idx];
            let mut depth = 0;
            while current != 0 {
                depth += 1;
                // Cycle detection only fires in debug builds; in release
                // the loop is bounded by the block count (worst-case: O(N)
                // walk of every free block, still finite).
                if depth > 10_000 {
                    if cfg!(debug_assertions) {
                        panic!(
                            "scan_free_lists: cycle or runaway chain at fl={fl} sl={sl} idx={idx}"
                        );
                    }
                    // In release mode, abort the walk for this list to
                    // prevent a livelock.  An undetected cycle would leak
                    // the affected blocks but won't hang the allocator.
                    break;
                }
                validate_block(state, current, "scan_free_lists");
                current = block_next_free(current);
            }
        }
    }
}

/// Find a free block that can satisfy a request of at least `min_size` bytes.
/// Returns the block address, or 0 if no suitable block exists.
pub(crate) fn find_suitable_block(state: &AllocatorState, min_size: usize) -> usize {
    let (fl, sl) = if min_size < (1 << FL_MIN) {
        (FL_MIN, 0)
    } else {
        mapping(min_size)
    };

    // Clamp fl to our range.
    let start_fl = fl.clamp(FL_MIN, FL_MAX);

    // ── Search within the same first‑level class ──
    let fl_idx = start_fl - FL_MIN; // safely in 0..FL_COUNT-1
    let sl_mask = state.sl_bitmaps[fl_idx] & !((1u32 << sl) - 1);
    if sl_mask != 0 {
        let first_sl = sl_mask.trailing_zeros() as usize;
        debug_assert!(first_sl < SL_COUNT);
        let idx = list_index(start_fl, first_sl);
        return state.free_lists[idx];
    }

    // ── Search higher first‑level classes ──
    // Mask out all bits at or below the current FL class, then scan upwards.
    // We only consider bits 0..FL_COUNT-1; any bits beyond FL_COUNT are stale
    // and must be ignored to avoid out-of-bounds accesses.
    let valid_bits_mask: u32 = (1u32 << FL_COUNT) - 1;
    let search_mask = !((1u32 << (fl_idx + 1)) - 1);
    let fl_mask = state.fl_bitmap & valid_bits_mask & search_mask;
    if fl_mask != 0 {
        let next_fl_bit = fl_mask.trailing_zeros() as usize;
        // next_fl_bit is guaranteed < FL_COUNT because of valid_bits_mask.
        let next_fl = next_fl_bit + FL_MIN;
        let sl_mask = state.sl_bitmaps[next_fl_bit];
        if sl_mask != 0 {
            let first_sl = sl_mask.trailing_zeros() as usize;
            debug_assert!(first_sl < SL_COUNT);
            let idx = list_index(next_fl, first_sl);
            return state.free_lists[idx];
        }
    }

    0
}

// ─── Coalescing ──────────────────────────────────────────────────────────

/// Validate that `candidate` looks like a genuine free block that physically
/// follows `predecessor`.  Returns the candidate's size if it passes all
/// sanity checks, or `None` if the header is corrupt, misaligned, or the
/// candidate does not acknowledge `predecessor` as its physical predecessor.
///
/// This prevents stale application data (e.g. freed string buffers) from
/// masquerading as a free block and being coalesced into a garbage-sized
/// monster that corrupts the heap.
pub(crate) unsafe fn validate_coalesce_neighbour(
    candidate: usize,
    predecessor: usize,
    heap_end: usize,
) -> Option<usize> {
    // Must be properly aligned — all real blocks start at 16‑byte boundaries.
    if !candidate.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
        return None;
    }

    // Check that the "free" bit is actually set — the caller already verified
    // this, but a stale word with bit 0 = 0 can fool `block_is_used`.
    let size = block_size(candidate);
    if size < MIN_FREE_BLOCK {
        return None;
    }

    // Must not extend past the end of the heap.
    if candidate.wrapping_add(size) > heap_end {
        return None;
    }

    // The definitive check: a real adjacent block physically follows
    // `predecessor`, so its `prev_phys` field MUST point back to it.
    // Stale data will contain an arbitrary value and fail this check.
    if block_prev_phys(candidate) != predecessor {
        return None;
    }

    Some(size)
}

/// Coalesce the free block at `block` with its physically‑adjacent
/// neighbours and return the (possibly merged) block address.
///
/// The function removes any merged neighbours from their free lists.
pub(crate) unsafe fn coalesce(state: &mut AllocatorState, block: usize) -> usize {
    let mut start = block;
    let mut size = block_size(block);
    let heap_start = state.start;
    let heap_end = state.end;

    // ── Merge with the previous physical block (if free) ──
    if start > heap_start {
        let prev = block_prev_phys(start);
        if prev >= heap_start && prev < start {
            let prev_size = block_size(prev);
            let prev_end = prev.wrapping_add(prev_size);
            if prev_end == start
                && !block_is_used(prev)
                && prev.is_multiple_of(HEAP_BLOCK_ALIGNMENT)
                && prev_size >= MIN_FREE_BLOCK
            {
                remove_free_block(state, prev);
                start = prev;
                size = size.wrapping_add(prev_size);
            }
        }
    }

    // ── Merge with the next physical block (if free) ──
    let end = start.wrapping_add(size);
    if end < heap_end {
        let next = end;
        if !block_is_used(next) {
            if let Some(next_size) = validate_coalesce_neighbour(next, start, heap_end) {
                remove_free_block(state, next);
                size = size.wrapping_add(next_size);
            }
        }
    }

    // Update the merged block's metadata.
    block_set_size(start, size);
    block_clear_used(start);

    // The next physical block (if any) must now point back to us.
    block_set_prev_phys_of_next(start, start);

    start
}
