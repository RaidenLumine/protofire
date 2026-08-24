//! src/kernel/memory/heap/tests.rs
//!
//! TLSF allocator unit tests.
//!
//! All allocation tests run against the single shared `HOST_HEAP_MODEL`
//! (its internal spinlock serialises access so parallel test threads are
//! safe).  Every test frees everything it allocates, leaving the heap in a
//! consistent, deterministic state.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::allocator::KernelGlobalAllocator;
    use super::super::tlsf::{
        mapping, AllocatorState, FL_MAX, FL_MIN, HEADER_SIZE, HEAP_BLOCK_ALIGNMENT,
        KERNEL_HEAP_SIZE, SL_COUNT,
    };
    use super::super::wrapper::HOST_HEAP_MODEL;
    use crate::kernel::memory::alloc_profiler::AllocProfiler;
    use alloc::vec::Vec;
    use core::alloc::Layout;

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
}
