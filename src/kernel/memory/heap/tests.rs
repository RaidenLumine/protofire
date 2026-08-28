//! src/kernel/memory/heap/tests.rs
//!
//! TLSF allocator unit tests.
//!
//! All allocation tests run against the single shared `HOST_HEAP_MODEL`.
//! Its internal spinlock serialises individual operations, and
//! `TEST_MODEL_LOCK` serialises whole tests so no test observes another test's
//! in-flight allocations.  Every test frees everything it allocates, leaving
//! the heap in a consistent, deterministic state.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::allocator::KernelGlobalAllocator;
    use super::super::tlsf::block_next_free;
    use super::super::tlsf::block_size;
    use super::super::tlsf::list_index;
    use super::super::tlsf::mapping;
    use super::super::tlsf::AllocatorState;
    use super::super::tlsf::FL_MAX;
    use super::super::tlsf::FL_MIN;
    use super::super::tlsf::HEADER_SIZE;
    use super::super::tlsf::HEAP_BLOCK_ALIGNMENT;
    use super::super::tlsf::KERNEL_HEAP_SIZE;
    use super::super::tlsf::SL_COUNT;
    use super::super::wrapper::HOST_HEAP_MODEL;
    use crate::kernel::memory::alloc_profiler::AllocProfiler;
    use alloc::vec::Vec;
    use core::alloc::Layout;
    use std::sync::Mutex;

    // ── Deterministic PRNG for property tests ───────────────────────────────
    // Same LCG family as tests/simplefs/property.rs and tests/parsers/fuzz.rs,
    // kept local because the allocator state lives behind `pub(crate)` and is
    // only reachable from in-crate unit tests.

    struct Lcg {
        state: u64,
    }

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next(&mut self) -> u64 {
            self.state = self.state.wrapping_mul(6_364_136_223_846_793_005);
            self.state = self.state.wrapping_add(1_442_695_040_888_963_407);
            self.state
        }

        fn next_usize(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            (self.next() as usize) % bound
        }
    }

    /// Serialises tests that allocate from the shared `HOST_HEAP_MODEL`.
    ///
    /// Cargo runs the tests in this binary on parallel threads.  The property
    /// test snapshots `remaining()` at its start and compares it at its end,
    /// and a concurrent allocating test would hold blocks between those two
    /// points and make the equality check flaky.  Every test that mutates the
    /// model takes this lock for its whole body, so the heap is quiescent
    /// whenever the property test runs and its round-trip check is exact.
    static TEST_MODEL_LOCK: Mutex<()> = Mutex::new(());

    /// Assert the core TLSF placement invariant: every free block lives in
    /// the free list of the size class its actual size maps to.  A block of
    /// size S must sit in `free_lists[list_index(mapping(S))]` — never in a
    /// smaller or larger class.
    unsafe fn verify_size_class_placement(state: &AllocatorState) {
        for fl in FL_MIN..=FL_MAX {
            for sl in 0..SL_COUNT {
                let idx = list_index(fl, sl);
                let mut current = state.free_lists[idx];
                while current != 0 {
                    let size = block_size(current);
                    // Every free-listed block is at least MIN_FREE_BLOCK
                    // (= 1 << FL_MIN), so mapping() is always well-defined.
                    assert!(
                        size >= (1 << FL_MIN),
                        "free block 0x{current:x} has size {size} below the mapping minimum"
                    );
                    assert_eq!(
                        mapping(size),
                        (fl, sl),
                        "free block 0x{current:x} of size {size} placed in class ({fl}, {sl})"
                    );
                    current = block_next_free(current);
                }
            }
        }
    }

    #[test]
    fn fresh_allocator_state_starts_uninitialized() {
        let state = AllocatorState::new();
        assert!(!state.initialized);
        assert_eq!(state.start, 0);
        assert_eq!(state.end, 0);
        assert_eq!(state.available, 0);
    }

    #[test]
    fn tlsf_mapping_places_blocks_in_expected_classes() {
        // Smallest class: 2^FL_MIN = 32 bytes → (FL_MIN, 0).
        assert_eq!(mapping(1 << FL_MIN), (FL_MIN, 0));
        // A 4 KiB block maps to first-level index 12 (log2(4096)).
        assert_eq!(mapping(4096), (12, 0));
        // The full 16 MiB heap maps into the top class.
        let (fl, sl) = mapping(KERNEL_HEAP_SIZE);
        assert!((FL_MIN..=FL_MAX).contains(&fl));
        assert!(sl < SL_COUNT);
    }

    #[test]
    fn profiler_snapshot_starts_at_zero() {
        let snapshot = AllocProfiler::new().snapshot();
        assert_eq!(snapshot, Default::default());
        assert_eq!(snapshot.heap_allocs, 0);
        assert_eq!(snapshot.heap_bytes_allocated, 0);
        assert_eq!(snapshot.heap_frees, 0);
    }

    #[test]
    fn allocate_and_deallocate_round_trip() {
        let _model_guard = TEST_MODEL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        HOST_HEAP_MODEL.ensure_init();

        let (start, end) = HOST_HEAP_MODEL.bounds();
        assert_eq!(end.wrapping_sub(start), KERNEL_HEAP_SIZE);

        let profiler = AllocProfiler::new();
        let layout = Layout::from_size_align(64, 16).unwrap();
        // A block needs room for its header immediately before the payload.
        assert!(HEADER_SIZE + layout.size() <= KERNEL_HEAP_SIZE);
        let mut ptr: *mut u8 = core::ptr::null_mut();

        HOST_HEAP_MODEL.with_state(|state| {
            ptr = KernelGlobalAllocator::allocate_locked(state, layout, &profiler);
        });

        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % HEAP_BLOCK_ALIGNMENT, 0);
        assert!((start..end).contains(&(ptr as usize)));

        // The payload must be writable and readable.
        unsafe {
            ptr.write_bytes(0xAB, layout.size());
        }
        assert_eq!(unsafe { ptr.read() }, 0xAB);

        let mut freed = false;
        HOST_HEAP_MODEL.with_state(|state| {
            freed = KernelGlobalAllocator::deallocate_locked(state, ptr, &profiler);
        });
        assert!(freed);

        // Double-free must be rejected.
        HOST_HEAP_MODEL.with_state(|state| {
            assert!(!KernelGlobalAllocator::deallocate_locked(
                state, ptr, &profiler
            ));
        });

        HOST_HEAP_MODEL.verify_heap_integrity();
    }

    #[test]
    fn multiple_allocations_are_aligned_and_disjoint() {
        let _model_guard = TEST_MODEL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        HOST_HEAP_MODEL.ensure_init();
        let profiler = AllocProfiler::new();
        let layouts = [
            Layout::from_size_align(32, 16).unwrap(),
            Layout::from_size_align(64, 16).unwrap(),
            Layout::from_size_align(256, 8).unwrap(),
            Layout::from_size_align(1024, 4096).unwrap(),
        ];

        let mut ptrs: Vec<(*mut u8, usize)> = Vec::with_capacity(layouts.len());
        for layout in &layouts {
            let mut ptr: *mut u8 = core::ptr::null_mut();
            HOST_HEAP_MODEL.with_state(|state| {
                ptr = KernelGlobalAllocator::allocate_locked(state, *layout, &profiler);
            });
            assert!(
                !ptr.is_null(),
                "allocation of {} bytes failed",
                layout.size()
            );
            assert_eq!(
                ptr as usize % layout.align(),
                0,
                "allocation of {} bytes violates alignment {}",
                layout.size(),
                layout.align()
            );
            ptrs.push((ptr, layout.size()));
        }

        // All blocks must be pairwise disjoint.
        for i in 0..ptrs.len() {
            for j in (i + 1)..ptrs.len() {
                let (a, a_len) = ptrs[i];
                let (b, b_len) = ptrs[j];
                let a_range = (a as usize)..(a as usize + a_len);
                let b_range = (b as usize)..(b as usize + b_len);
                assert!(
                    !a_range.contains(&(b as usize)) && !b_range.contains(&(a as usize)),
                    "allocations {i} and {j} overlap"
                );
            }
        }

        // Write a distinct pattern into every block.
        for (idx, &(ptr, len)) in ptrs.iter().enumerate() {
            unsafe {
                core::slice::from_raw_parts_mut(ptr, len).fill(idx as u8 + 1);
            }
        }

        // Free everything in reverse order.
        for (ptr, _) in ptrs.drain(..).rev() {
            let mut freed = false;
            HOST_HEAP_MODEL.with_state(|state| {
                freed = KernelGlobalAllocator::deallocate_locked(state, ptr, &profiler);
            });
            assert!(freed);
        }

        HOST_HEAP_MODEL.verify_heap_integrity();
    }

    #[test]
    fn deallocate_rejects_null_and_foreign_pointers() {
        HOST_HEAP_MODEL.ensure_init();
        let profiler = AllocProfiler::new();

        let mut null_freed = true;
        HOST_HEAP_MODEL.with_state(|state| {
            null_freed =
                KernelGlobalAllocator::deallocate_locked(state, core::ptr::null_mut(), &profiler);
        });
        assert!(!null_freed);

        // A pointer well outside the heap must be rejected rather than
        // dereferenced as a block header.
        let mut foreign_freed = true;
        HOST_HEAP_MODEL.with_state(|state| {
            foreign_freed = KernelGlobalAllocator::deallocate_locked(
                state,
                0x1000_0000_0000usize as *mut u8,
                &profiler,
            );
        });
        assert!(!foreign_freed);
    }

    /// Random alloc/free sequences against a live-allocations model.
    ///
    /// Invariants checked after every operation:
    ///   - every returned pointer is aligned to its requested alignment;
    ///   - every returned pointer lies inside the heap bounds;
    ///   - no two live allocations overlap;
    ///   - freeing a live pointer always succeeds, and double-freeing is always
    ///     rejected;
    ///   - once everything is freed the heap returns to its initial free byte
    ///     count (coalescing restores the whole pool).
    #[test]
    fn tlsf_random_alloc_free_sequence_matches_model() {
        // Hold the shared-model lock so `initial_remaining` and the final
        // equality check observe a quiescent heap (see TEST_MODEL_LOCK).
        let _model_guard = TEST_MODEL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        HOST_HEAP_MODEL.ensure_init();
        let (start, end) = HOST_HEAP_MODEL.bounds();
        let initial_remaining = HOST_HEAP_MODEL.remaining();
        let profiler = AllocProfiler::new();
        let mut rng = Lcg::new(0xF0F0_5010);

        // Model of live allocations: (payload pointer, payload size, align).
        let mut live: Vec<(*mut u8, usize, usize)> = Vec::new();

        // A broken allocator that always returns null would otherwise make
        // this test pass vacuously (every null is a legal "exhaustion" and
        // the final remaining() check trivially holds).  Track how many
        // attempts actually succeeded and require a meaningful fraction to
        // succeed, so the allocator really is exercised.
        let mut attempted_alloc = 0usize;
        let mut successful_alloc = 0usize;

        for step in 0..4000 {
            if rng.next_usize(2) == 0 {
                // Allocate.
                attempted_alloc += 1;
                let size = match rng.next_usize(4) {
                    0 => 1 + rng.next_usize(64),
                    1 => 65 + rng.next_usize(512),
                    2 => 513 + rng.next_usize(8192),
                    _ => 4096 + rng.next_usize(4096),
                };
                let align = match rng.next_usize(3) {
                    0 => 16,
                    1 => 64,
                    _ => 4096,
                };
                let layout = Layout::from_size_align(size, align).expect("valid layout");
                let mut ptr: *mut u8 = core::ptr::null_mut();
                HOST_HEAP_MODEL.with_state(|state| {
                    ptr = KernelGlobalAllocator::allocate_locked(state, layout, &profiler);
                });
                if ptr.is_null() {
                    // Fragmentation / exhaustion — legal; the model just
                    // records nothing.
                    continue;
                }
                successful_alloc += 1;
                assert_eq!(
                    ptr as usize % align,
                    0,
                    "step {step}: allocation of {size} bytes violates alignment {align}"
                );
                assert!(
                    (start..end).contains(&(ptr as usize)),
                    "step {step}: pointer {ptr:p} outside heap bounds"
                );
                for &(other, other_size, _) in &live {
                    let a_start = other as usize;
                    let a_end = a_start + other_size;
                    let b_start = ptr as usize;
                    let b_end = b_start + size;
                    let overlaps =
                        (a_start..a_end).contains(&b_start) || (b_start..b_end).contains(&a_start);
                    assert!(
                        !overlaps,
                        "step {step}: allocations overlap: {a_start:#x}..{a_end:#x} vs \
                         {b_start:#x}..{b_end:#x}"
                    );
                }
                live.push((ptr, size, align));
            } else {
                // Free a random live allocation (if any), then verify the
                // double-free is rejected.
                if live.is_empty() {
                    continue;
                }
                let idx = rng.next_usize(live.len());
                let (ptr, _, _) = live.swap_remove(idx);
                let mut freed = false;
                HOST_HEAP_MODEL.with_state(|state| {
                    freed = KernelGlobalAllocator::deallocate_locked(state, ptr, &profiler);
                });
                assert!(freed, "step {step}: free of live pointer failed");
                HOST_HEAP_MODEL.with_state(|state| {
                    assert!(
                        !KernelGlobalAllocator::deallocate_locked(state, ptr, &profiler),
                        "step {step}: double-free accepted"
                    );
                });
            }

            if step % 256 == 0 {
                HOST_HEAP_MODEL.verify_heap_integrity();
                HOST_HEAP_MODEL.with_state(|state| unsafe {
                    verify_size_class_placement(state);
                });
            }
        }

        // A meaningful share of allocations must have succeeded, otherwise the
        // invariants above were never really exercised.
        assert!(
            successful_alloc >= attempted_alloc / 4 && successful_alloc >= 128,
            "only {successful_alloc}/{attempted_alloc} allocations succeeded — \
             the allocator appears to be failing outright"
        );

        // Free the remaining live allocations, then verify the whole pool
        // coalesces back to its initial free count.  (With TEST_MODEL_LOCK
        // held, no other test can be holding blocks here, so the equality is
        // exact rather than racy.)
        for (ptr, _, _) in live.drain(..) {
            let mut freed = false;
            HOST_HEAP_MODEL.with_state(|state| {
                freed = KernelGlobalAllocator::deallocate_locked(state, ptr, &profiler);
            });
            assert!(freed, "final free of a live pointer failed");
        }
        HOST_HEAP_MODEL.verify_heap_integrity();
        HOST_HEAP_MODEL.with_state(|state| unsafe {
            verify_size_class_placement(state);
        });
        assert_eq!(
            HOST_HEAP_MODEL.remaining(),
            initial_remaining,
            "heap free count did not return to its initial value"
        );
    }
}
