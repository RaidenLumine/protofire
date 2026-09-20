//! src/kernel/memory/heap/tlsf.rs
//!
//! TLSF (Two-Level Segregated Fit) internals: constants, block header layout,
//! raw block accessors, free-list management, bit-scanning search, and
//! physical coalescing.

use crate::util::sync_unsafe_cell::SyncUnsafeCell;

// ─── Constants ────────────────────────────────────────────────────────────

pub(crate) const KERNEL_HEAP_SIZE: usize = 64 * 1024 * 1024;

/// Minimum alignment of any block returned by the allocator.
pub(crate) const HEAP_BLOCK_ALIGNMENT: usize = 16;

// TLSF class constants.
//
// The allocator classifies free blocks by size:
//   fl = ⌊log₂(size)⌋         first-level index  (exponent)
//   sl = fractional part        second-level index (0 … SL_COUNT-1)
//
// With FL_MIN = 5 the smallest block class covers 2⁵ = 32 bytes
// (header + 16‑byte payload).  FL_MAX covers the whole heap: 2²⁶ = 64 MiB.
pub(crate) const FL_MIN: usize = 5;
pub(crate) const FL_MAX: usize = 26;
pub(crate) const FL_COUNT: usize = FL_MAX - FL_MIN + 1; // 22
pub(crate) const SL_COUNT: usize = 32;
pub(crate) const SL_INDEX_LOG2: usize = 5; // log₂(SL_COUNT)

pub(crate) const FREE_LISTS_COUNT: usize = FL_COUNT * SL_COUNT; // 704

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
            // Report only on failure.  `debug_assert!` cannot run a statement,
            // and this is a hot path — a diagnostic called on every block
            // coalesce would print, and printing allocates, and allocating
            // feeds more heap operations.
            if !next.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
                report_heap_trace();
                panic!(
                    "block_set_prev_phys_of_next: next=0x{next:x} not aligned; \
                     block=0x{block:x} size={size}"
                );
            }
            let write_addr = next.checked_add(8).expect("prev_phys write overflow");
            if write_addr > heap_end {
                report_heap_trace();
                panic!(
                    "block_set_prev_phys_of_next: write at 0x{write_addr:x} beyond \
                     heap_end 0x{heap_end:x}; block=0x{block:x} size={size}"
                );
            }
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

/// Print the blocks the walk passed through on its way to a defect.
///
/// A defect address alone cannot distinguish "this header was overwritten"
/// from "the walk arrived here by the wrong route", and the two have opposite
/// causes: the first is a bad write, the second is a bad size somewhere
/// earlier.  The route makes that decidable.
#[cfg(feature = "heap_audit")]
unsafe fn report_walk_route(state: &AllocatorState, defect_address: usize) {
    // Only the tail of the route is printed.  A heap has thousands of blocks;
    // what matters is the handful just before the walk's step went wrong, not
    // the first sixty from the start.
    const TAIL: usize = 8;
    let mut tail = [(0_usize, 0_usize, false, 0_usize); TAIL];
    let mut seen = 0_usize;
    let mut stopped_early = false;

    let mut block = state.start;
    let mut steps = 0_usize;

    while block < state.end && steps < 1_000_000 {
        let size = block_size(block);
        let used = block_is_used(block);
        tail[seen % TAIL] = (block, size, used, block_prev_phys(block));
        seen += 1;

        if size < MIN_FREE_BLOCK || !size.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
            stopped_early = true;
            break;
        }
        if block >= defect_address {
            break;
        }
        block = block.wrapping_add(size);
        steps += 1;
    }

    crate::println!(
        "[heap  ] walk route into the defect ({} blocks walked{}):",
        steps,
        if stopped_early {
            ", stopped on an invalid size"
        } else {
            ""
        }
    );

    let shown = seen.min(TAIL);
    for offset in 0..shown {
        let (address, size, used, prev) = tail[(seen - shown + offset) % TAIL];
        let marker = if address == defect_address { " <-" } else { "" };
        crate::println!(
            "[heap  ]   0x{:x} size={} {} prev_phys=0x{:x}{}",
            address,
            size,
            if used { "used" } else { "free" },
            prev,
            marker
        );
    }
}

/// Report a detected heap problem: the first damage a full walk finds, then
/// the recent operation history.
///
/// The allocator's own checks fire wherever a free-list traversal happens to
/// land, which is often not where the damage is.  Walking the physical block
/// list first pins the earliest bad block instead, and the trace then says what
/// touched nearby memory last.  Both only run on a path that is already
/// failing, so the cost is irrelevant; neither is worth running per operation,
/// which is why this is not wired into the ordinary allocate/free path.
pub(crate) unsafe fn report_heap_damage(state: &AllocatorState, caller: &str) {
    match check_invariants(state) {
        Ok(()) => {
            crate::println!(
                "[heap  ] {}: block list walks clean; damage is not visible from the start",
                caller
            );
        }
        Err(defect) => {
            crate::println!(
                "[heap  ] {}: first damage at 0x{:x}: {}",
                caller,
                defect.address,
                defect.reason
            );
        }
    }
    report_heap_trace();
}

// ─── Post-operation audit ─────────────────────────────────────────────────

/// Set while a damage report is being printed.
///
/// Printing allocates, and the heap it would allocate from is the one that is
/// damaged — so an unguarded report re-enters the audit, which reports, which
/// allocates, and the output runs away.  While this is set the audit stays
/// quiet so the report can finish and the panic can happen.
#[cfg(feature = "heap_audit")]
static HEAP_AUDIT_REPORTING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Walk the whole heap after one operation, and stop at the operation that
/// damaged it.
///
/// With the walk only running where a free-list traversal happens to pass,
/// damage is reported long after the write that caused it and from an unrelated
/// place.  Auditing after every operation pins it to the operation itself,
/// which — together with [`report_heap_damage`]'s history — names the culprit.
///
/// This is `O(blocks)` per operation and exists only under the `heap_audit`
/// feature: it is a diagnostic build, not something to ship.
#[cfg(feature = "heap_audit")]
pub(crate) unsafe fn audit_after_operation(state: &AllocatorState, operation: &str) {
    use core::sync::atomic::Ordering;

    if HEAP_AUDIT_REPORTING.load(Ordering::Acquire) {
        return;
    }
    let Err(defect) = check_invariants(state) else {
        return;
    };

    HEAP_AUDIT_REPORTING.store(true, Ordering::Release);
    crate::println!(
        "[heap  ] damage first seen after {}: 0x{:x}: {}",
        operation,
        defect.address,
        defect.reason
    );

    report_walk_route(state, defect.address);

    // Raw words around the defect.  With the operation named, the remaining
    // question is what the damaged header actually holds — a stale pointer, a
    // payload value, or zero — and that is only visible in the bytes.
    // Wide enough to include the block *before* the one the walk choked on:
    // the question is whether that block's size word agrees with the boundary
    // its successor records.
    let window_start = defect
        .address
        .saturating_sub(8 * core::mem::size_of::<usize>());
    for offset in 0..14 {
        let address = window_start + offset * core::mem::size_of::<usize>();
        if address < state.start || address + core::mem::size_of::<usize>() > state.end {
            continue;
        }
        let word = (address as *const usize).read();
        let marker = if address == defect.address { " <-" } else { "" };
        crate::println!("[heap  ]   0x{:x}: 0x{:016x}{}", address, word, marker);
    }

    report_heap_trace();
    panic!("heap audit: block list damaged by {}", operation);
}

// ─── Structural invariant checking ────────────────────────────────────────

/// Bytes reserved at the end of every allocation for a canary word.
///
/// A block header sits immediately before the next block's payload, so an
/// allocation that writes past its own bytes damages the *next* block's
/// header — the shape of every corruption this heap has produced.  The canary
/// is the first thing such an overrun meets, and it is checked when the
/// offending allocation is freed, which attributes the damage to a specific
/// pointer instead of leaving a free-list walk to trip over it later.
pub(crate) const CANARY_SIZE: usize = 8;

/// Value written into the canary slot.
///
/// Any fixed value can in principle be reproduced by a wild write, but the
/// point is to catch overruns, which write *data*, not this word.
const CANARY_VALUE: usize = 0xC0DE_C0DE_C0DE_C0DE;

/// Write the canary into the last word of the block starting at `block_start`.
///
/// The request is inflated by `CANARY_SIZE` when the block is carved, so this
/// word is always inside the block and never inside the caller's bytes.  It
/// sits at the block end rather than immediately after the payload: an earlier
/// attempt to place it at `payload + requested_size` broke the allocator's size
/// accounting whenever the payload was pushed forward by an alignment larger
/// than the block alignment, and
/// `tlsf_random_alloc_free_sequence_matches_model` caught it.  See the note on
/// [`canary_check`].
pub(crate) unsafe fn canary_write(block_start: usize) {
    let size = block_size(block_start);
    let canary = block_start.wrapping_add(size).wrapping_sub(CANARY_SIZE);
    (canary as *mut usize).write(CANARY_VALUE);
}

/// Verify the canary of the block starting at `block_start`.
///
/// Returns a defect rather than panicking so callers — and tests — can decide
/// what to do.  The free path treats it as fatal, because continuing with a
/// damaged heap turns a located fault into arbitrary misbehaviour.
///
/// # Coverage
///
/// This catches an overrun that reaches the last word of the block, which is
/// the shape every corruption here has had: the next block's header sits at
/// exactly that address.  It does *not* catch an overrun that stays inside the
/// alignment padding — up to fifteen bytes between the caller's last byte and
/// the block end.  Closing that gap needs the canary placed at
/// `payload + requested_size`, which needs the requested size on the free path;
/// the placement above is what the suite verifies.
pub(crate) unsafe fn canary_check(block_start: usize) -> Result<(), HeapDefect> {
    let size = block_size(block_start);
    if size < CANARY_SIZE {
        return Err(HeapDefect {
            address: block_start,
            reason: "block is smaller than the canary it must hold",
        });
    }

    let canary = block_start.wrapping_add(size).wrapping_sub(CANARY_SIZE);
    let found = (canary as *const usize).read();
    if found != CANARY_VALUE {
        return Err(HeapDefect {
            address: block_start,
            reason: "canary overwritten: an allocation wrote past its own bytes",
        });
    }

    Ok(())
}

/// A structural defect found by [`check_invariants`].
///
/// Carries the address the walk was examining, because the defect often shows
/// up one block *after* the write that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapDefect {
    pub(crate) address: usize,
    pub(crate) reason: &'static str,
}

/// Walk the whole heap and check that the block list is well formed.
///
/// The allocator's existing checks fire when a *free-list walk* happens to
/// reach a damaged block, which makes detection a matter of luck: a corrupt
/// header that no traversal happens to touch goes unnoticed, and one that is
/// touched is reported far from the write that caused it.  This walks the
/// physical block list instead, so the same defect is found by any call and at
/// the earliest block the walk reaches.
///
/// The invariants are the ones the allocator maintains by construction:
///
/// 1. Every block starts on an alignment boundary.
/// 2. Every block is at least [`MIN_FREE_BLOCK`] bytes.
/// 3. Every block ends inside the heap, and the walk lands exactly on `end`.
/// 4. A block's `prev_phys` field points at the block before it, which is the
///    boundary-tag pairing that coalescing depends on.
pub(crate) unsafe fn check_invariants(state: &AllocatorState) -> Result<(), HeapDefect> {
    if state.start == 0 || state.end <= state.start {
        return Err(HeapDefect {
            address: state.start,
            reason: "heap bounds are not initialised",
        });
    }

    let mut block = state.start;
    let mut previous: Option<usize> = None;

    while block < state.end {
        if !block.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
            return Err(HeapDefect {
                address: block,
                reason: "block is not aligned",
            });
        }

        let size = block_size(block);
        if size < MIN_FREE_BLOCK {
            return Err(HeapDefect {
                address: block,
                reason: "block size is below the minimum free block size",
            });
        }
        if !size.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
            return Err(HeapDefect {
                address: block,
                reason: "block size is not a multiple of the block alignment",
            });
        }

        let next = block.wrapping_add(size);
        if next > state.end {
            return Err(HeapDefect {
                address: block,
                reason: "block extends past the end of the heap",
            });
        }

        // The boundary tag: this block's successor records this block as its
        // physical predecessor.  A mismatch means one of the two headers was
        // overwritten.
        if next < state.end {
            let recorded_prev = block_prev_phys(next);
            if recorded_prev != block {
                return Err(HeapDefect {
                    address: next,
                    reason: "prev_phys does not point at the preceding block",
                });
            }
        }

        if let Some(previous) = previous {
            if block_prev_phys(block) != previous {
                return Err(HeapDefect {
                    address: block,
                    reason: "prev_phys does not point at the preceding block",
                });
            }
        }

        previous = Some(block);
        block = next;
    }

    if block != state.end {
        return Err(HeapDefect {
            address: block,
            reason: "block walk did not land on the end of the heap",
        });
    }

    Ok(())
}

// ─── Recent-operation trace ───────────────────────────────────────────────

/// How many recent heap operations are remembered for post-mortem reporting.
pub(crate) const HEAP_TRACE_DEPTH: usize = 32;

/// Recent operations: an address with an operation tag in the low bits.
///
/// Blocks are `HEAP_BLOCK_ALIGNMENT`-aligned, so an address's low bits are
/// always free and the tag needs no packing scheme.
static HEAP_TRACE: [core::sync::atomic::AtomicUsize; HEAP_TRACE_DEPTH] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; HEAP_TRACE_DEPTH];
static HEAP_TRACE_CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Operation tags, small enough for the alignment gap.
pub(crate) const TRACE_ALLOC: usize = 1;
pub(crate) const TRACE_DEALLOC: usize = 2;
const TRACE_TAG_MASK: usize = 0xF;

/// Record a heap operation.
///
/// Called from inside the allocator's own critical section, where interrupts
/// are masked, so relaxed atomics suffice: this cannot race with itself on one
/// CPU, and it must not take a lock of its own.
pub(crate) fn record_heap_trace(tag: usize, address: usize) {
    let slot =
        HEAP_TRACE_CURSOR.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % HEAP_TRACE_DEPTH;
    HEAP_TRACE[slot].store(
        (address & !TRACE_TAG_MASK) | (tag & TRACE_TAG_MASK),
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Print the most recent heap operations, oldest first.
///
/// This answers "who touched this memory last" without a debugger, because the
/// corruption it exists for is a race that does not reproduce on demand.
/// Called from every validation failure, before the panic.
pub(crate) fn report_heap_trace() {
    let cursor = HEAP_TRACE_CURSOR.load(core::sync::atomic::Ordering::Relaxed);
    let depth = cursor.min(HEAP_TRACE_DEPTH);
    crate::println!("[heap  ] last {} heap operations (oldest first):", depth);

    for offset in 0..depth {
        let index = (cursor + HEAP_TRACE_DEPTH - depth + offset) % HEAP_TRACE_DEPTH;
        let entry = HEAP_TRACE[index].load(core::sync::atomic::Ordering::Relaxed);
        if entry == 0 {
            continue;
        }
        let name = match entry & TRACE_TAG_MASK {
            TRACE_ALLOC => "alloc  ",
            TRACE_DEALLOC => "dealloc",
            _ => "unknown",
        };
        crate::println!("[heap  ]   {} 0x{:x}", name, entry & !TRACE_TAG_MASK);
    }
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
        report_heap_damage(state, caller);
        panic!("{caller}: null block");
    }
    if block < state.start || block >= state.end {
        report_heap_damage(state, caller);
        panic!(
            "{caller}: block 0x{block:x} outside heap [0x{:x}, 0x{:x})",
            state.start, state.end
        );
    }
    if !block.is_multiple_of(HEAP_BLOCK_ALIGNMENT) {
        report_heap_damage(state, caller);
        panic!("{caller}: block 0x{block:x} misaligned");
    }
    let size = block_size(block);
    if size < MIN_FREE_BLOCK {
        report_heap_damage(state, caller);
        panic!("{caller}: block 0x{block:x} size {size} below MIN_FREE_BLOCK");
    }
    let end = block.wrapping_add(size);
    if end > state.end {
        report_heap_damage(state, caller);
        panic!(
            "{caller}: block 0x{block:x} size {size} overflows heap end 0x{:x}",
            state.end
        );
    }
    let (fl, sl) = mapping(size);
    if !(FL_MIN..=FL_MAX).contains(&fl) {
        report_heap_damage(state, caller);
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
