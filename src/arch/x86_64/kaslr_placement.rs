//! src/arch/x86_64/kaslr_placement.rs
//!
//! Where the KASLR relocator may put its copy: the candidate search, as a
//! pure function over the machine's region list.
//!
//! The search was written inside [`crate::arch::x86_64::kaslr`], which only
//! compiles on bare metal — so the branch that matters on a real board, *a
//! machine whose usable RAM has holes no candidate avoids*, could not be
//! driven by a test and no gate could boot a machine that describes one.
//! QEMU cannot describe a RAM hole below this kernel's placement ceiling
//! either — a `q35` machine is contiguous available RAM up to just under
//! 2 GiB, and the placement ceiling is 768 MiB — so the note in the
//! relocator's comment, "checked against the map but no gate boots such a
//! machine", was true and staying true for the wrong reason: nothing could
//! drive it *at all*.
//!
//! The search lives here now, over plain [`MemoryRegion`] lists, and the
//! relocator is a thin wrapper that reads its linker symbols and calls it.
//! Every branch is a unit test on a region list: a hole that removes some
//! candidates makes the search step past them, a hole that removes every
//! candidate refuses (the boot then stays at the link address), the pool's
//! first frame is checked alongside the copy, and the two ends of the window
//! are closed.

use crate::arch::boot::MemoryRegion;
use crate::arch::boot::MEMORY_REGION_AVAILABLE;

/// Everything the search needs that is not the machine's region list.
///
/// A struct rather than eight positional arguments because four of them are
/// bare `usize` spans whose order would be a silent defect if a call site
/// swapped two — the copy's span, the whole span, and the pool's offset are
/// the same type and mean different things.
pub(crate) struct PlacementRequest {
    /// The first address a candidate may be placed at (already aligned).
    pub bottom: usize,
    /// The ceiling for the *end* of the whole span.
    pub ceiling: usize,
    /// The alignment of every candidate.
    pub step: usize,
    /// How many bytes the copy covers.
    pub copy_span: usize,
    /// How many bytes the whole kernel span covers (image plus pool).
    pub total_span: usize,
    /// Where the pool's start sits inside the span.
    pub pool_offset: usize,
    /// How many bytes of the pool must be in the machine's memory (its
    /// first frame, for the reasons the allocator has).
    pub pool_check_span: usize,
    /// Where to start the candidate scan, so two boots can differ.
    pub seed: usize,
}

/// Pick the base for the copy from the machine's region list.
///
/// Bounds, in the order they can exclude a candidate:
///
/// * the base is aligned to `step` and starts at `bottom` or later;
/// * `base + total_span` stays at or below `ceiling` (the whole kernel span,
///   not just the copy — the pool and the image after it move with the kernel);
/// * the copy's bytes lie inside a region the machine calls available;
/// * the pool's first frame does too, because the pool's bounds are linker
///   symbols the table patches and the allocator must still have a frame it may
///   manage.
///
/// The candidates are visited from `seed % candidates` onward, wrapping at
/// the end, so two boots of one binary can differ and a hole that removes the
/// first candidates does not stop the search.  `None` is the answer when no
/// candidate survives — a machine too small for the span, or one whose holes
/// leave no room — and the caller boots at the link address.
pub(crate) fn select_placement(
    request: &PlacementRequest,
    regions: &[MemoryRegion],
) -> Option<usize> {
    debug_assert!(
        request.step.is_power_of_two(),
        "the mask below assumes a power of two"
    );
    let top = request.ceiling.checked_sub(request.total_span)? & !(request.step - 1);
    if top < request.bottom {
        return None;
    }
    let candidates = (top - request.bottom) / request.step + 1;

    let inside_available = |start: usize, end: usize| {
        regions.iter().any(|region| {
            region.kind == MEMORY_REGION_AVAILABLE && region.base <= start && end <= region.end()
        })
    };

    for index in 0..candidates {
        // Wrapping so an arbitrary seed — this is a pure function and tests
        // pass their own — cannot overflow the index arithmetic.
        let base = request.bottom + (request.seed.wrapping_add(index) % candidates) * request.step;
        if !inside_available(base, base + request.copy_span) {
            continue;
        }
        if !inside_available(
            base + request.pool_offset,
            base + request.pool_offset + request.pool_check_span,
        ) {
            continue;
        }
        return Some(base);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::boot::MEMORY_REGION_RESERVED;

    fn available(base: usize, end: usize) -> MemoryRegion {
        MemoryRegion {
            base,
            length: end - base,
            kind: MEMORY_REGION_AVAILABLE,
        }
    }

    fn reserved(base: usize, end: usize) -> MemoryRegion {
        MemoryRegion {
            base,
            length: end - base,
            kind: MEMORY_REGION_RESERVED,
        }
    }

    // A small geometry with round numbers so the arithmetic in the expected
    // answers is visible: a 32 MiB ceiling over a 16 MiB span, 2 MiB steps, an
    // 8 MiB copy, and a pool 12 MiB into the span.
    const BOTTOM: usize = 0x4_00000;
    const CEILING: usize = 0x20_00000;
    const STEP: usize = 0x20_0000;
    const COPY: usize = 0x8_00000;
    const SPAN: usize = 0x10_00000;
    const POOL_OFFSET: usize = 0xC_00000;
    const POOL_CHECK: usize = 0x1000;

    /// The small geometry, as a request.
    fn request(seed: usize) -> PlacementRequest {
        PlacementRequest {
            bottom: BOTTOM,
            ceiling: CEILING,
            step: STEP,
            copy_span: COPY,
            total_span: SPAN,
            pool_offset: POOL_OFFSET,
            pool_check_span: POOL_CHECK,
            seed,
        }
    }

    fn place(regions: &[MemoryRegion], seed: usize) -> Option<usize> {
        select_placement(&request(seed), regions)
    }

    /// A machine that describes nothing is not this function's caller: the
    /// relocator answers "no placement" before it gets here (the hand-off
    /// walk has no list), which is the same answer this gives an empty list.
    #[test]
    fn an_empty_region_list_refuses() {
        assert_eq!(place(&[], 0), None);
    }

    /// One contiguous machine: the base is a step-aligned address at or past
    /// the bottom, the whole span fits under the ceiling, and both the copy
    /// and the pool's first frame lie in available memory.
    #[test]
    fn one_available_region_places_inside_it() {
        let regions = [available(0, 0x40_00000)];
        for seed in 0..8 {
            let base = place(&regions, seed).expect("a contiguous 64 MiB machine has room");
            assert!(base >= BOTTOM, "base {base:#x} is below the bottom");
            assert_eq!(base % STEP, 0, "base {base:#x} is not step-aligned");
            assert!(
                base + SPAN <= CEILING,
                "base {base:#x} puts the span past the ceiling"
            );
            assert!(base + COPY <= 0x40_00000, "the copy leaves the region");
            assert!(
                base + POOL_OFFSET + POOL_CHECK <= 0x40_00000,
                "the pool's first frame leaves the region"
            );
        }
    }

    /// A hole the window can cross does not stop the search: candidates whose
    /// copy or pool would land in the hole are stepped past, and the answer
    /// is a candidate on the far side of the scan's starting point rather
    /// than the first address in the window.
    ///
    /// Available [0, 12 MiB) + [20 MiB, 64 MiB), a pool 2 MiB into the span,
    /// seed 3: candidates 10, 12, 14, 16 MiB put their copy or pool in the
    /// hole or past the available side, and the first survivor is the bottom
    /// candidate — the copy 4..12 MiB ends at the hole's edge and the pool
    /// sits at 6 MiB.
    #[test]
    fn a_hole_the_window_can_cross_does_not_stop_the_search() {
        let regions = [available(0, 0xC_00000), available(0x14_00000, 0x40_00000)];
        let mut request = request(3);
        request.pool_offset = 0x2_00000;
        let base =
            select_placement(&request, &regions).expect("the first region holds a candidate");
        assert_eq!(base, BOTTOM, "the first survivor is the bottom candidate");
    }

    /// A hole that removes every candidate refuses, and this is the branch a
    /// board whose RAM is arranged differently would take: with the pool 12
    /// MiB into the span, every candidate's copy ends at or before 12 MiB
    /// while its pool lands in the hole — so the boot stays at the link
    /// address.
    #[test]
    fn a_hole_the_window_cannot_avoid_refuses() {
        let regions = [available(0, 0xC_00000), available(0x14_00000, 0x40_00000)];
        assert_eq!(
            place(&regions, 0),
            None,
            "no candidate keeps both the copy and the pool out of the hole"
        );
    }

    /// The pool's first frame is part of the decision, not an afterthought:
    /// with only the copy checked, this machine has candidates; with the
    /// pool's frame checked, it has none.
    #[test]
    fn the_pools_first_frame_is_checked_with_the_copy() {
        // Available [0, 32 MiB); a pool 25 MiB into the span.  Every
        // candidate's copy fits and every candidate's 8 MiB pool window
        // reaches past the region's end.
        let regions = [available(0, 0x20_00000)];
        let mut request = request(0);
        request.pool_offset = 0x19_00000;
        request.pool_check_span = 0x80_0000;
        assert_eq!(
            select_placement(&request, &regions),
            None,
            "the copy fits but the pool's frame is not in the machine's memory"
        );
        // The same machine with a pool whose first frame fits places.
        request.pool_check_span = POOL_CHECK;
        assert!(
            select_placement(&request, &regions).is_some(),
            "the copy and the pool's first frame both fit"
        );
    }

    /// A machine whose ceiling leaves less than the span below the bottom
    /// refuses before any candidate is considered — the shape the runtime
    /// gate's 128 MiB machine drives at boot.
    #[test]
    fn a_ceiling_too_low_for_the_span_refuses() {
        let regions = [available(0, 0x40_00000)];
        let mut request = request(0);
        request.bottom = 0x1000_0000;
        request.ceiling = 0x10F0_0000;
        assert_eq!(
            select_placement(&request, &regions),
            None,
            "the window between ceiling and bottom cannot hold the span"
        );
    }

    /// Memory the machine calls reserved is not a candidate even though its
    /// extent lies inside a candidate's numbers: the region that carries the
    /// copy has to be the *available* kind.
    #[test]
    fn reserved_memory_is_not_a_candidate() {
        let regions = [reserved(0, 0x8_00000), available(0x8_00000, 0x40_00000)];
        let Some(base) = place(&regions, 0) else {
            panic!("the available region holds a candidate");
        };
        assert_eq!(
            base, 0x80_0000,
            "the first candidate clear of the reserved region carries the copy"
        );
    }

    /// The pool's window is checked against the region it lands in: a pool
    /// whose start is available but whose 4 KiB frame crosses a gap has no
    /// candidate, while the same machine with the pool at the copy's own
    /// address places.
    #[test]
    fn a_pool_crossing_a_region_end_is_refused() {
        // Available [0, 20 MiB) + [30 MiB, 64 MiB).  Copies at 4..12 through
        // 12..20 MiB fit the first region; a pool 16 MiB into the span starts
        // at 20, 22, ... 28 MiB, all inside the gap.
        let regions = [available(0, 0x14_00000), available(0x1E_00000, 0x40_00000)];
        let mut request = request(0);
        request.pool_offset = 0x10_00000;
        assert_eq!(
            select_placement(&request, &regions),
            None,
            "a pool frame in the gap has no candidate"
        );
        // The same machine with the pool at the copy's address places.
        request.pool_offset = 0;
        assert!(
            select_placement(&request, &regions).is_some(),
            "the copy and the pool together fit the first region"
        );
    }
}
