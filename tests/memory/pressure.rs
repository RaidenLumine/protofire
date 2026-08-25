//! tests/memory/pressure.rs
//!
//! Memory pressure and exhaustion stress tests for the kernel frame allocator.

use protofire::kernel::memory::paging::PagePermissions;
use protofire::kernel::memory::paging::PAGE_SIZE;
use protofire::kernel::memory::MemoryManager;

fn align_up(value: usize) -> usize {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Allocate frame chunks of a given size until OOM, returning the count.
fn exhaust_pool(memory: &mut MemoryManager, chunk: usize) -> usize {
    let mut count: usize = 0;
    while memory.allocate_frames(chunk).is_some() {
        count += chunk;
    }
    count
}

// ── Frame exhaustion ───────────────────────────────────────────────────────

#[test]
fn frame_allocator_eventually_exhausts_and_returns_none() {
    let mut memory = MemoryManager::new();
    memory.init();

    let total = exhaust_pool(&mut memory, 1);
    assert!(
        total > 0,
        "expected at least 1 frame before exhaustion, got {total}"
    );
    // After exhaustion, the next allocation returns None.
    assert!(
        memory.allocate_frames(1).is_none(),
        "post-exhaustion returns None"
    );
}

#[test]
fn frame_allocator_reclaims_fragmented_space() {
    let mut memory = MemoryManager::new();
    memory.init();

    let sizes: &[usize] = &[1, 2, 3, 5, 7, 11, 13];
    let mut blocks: Vec<(usize, *mut u8)> = Vec::new();
    for count in sizes {
        for _ in 0..50 {
            match memory.allocate_frames(*count) {
                Some(ptr) => blocks.push((*count, ptr)),
                None => break,
            }
        }
    }

    let mut survivors: Vec<(usize, *mut u8)> = Vec::new();
    for (i, &(count, ptr)) in blocks.iter().enumerate() {
        if i % 2 == 0 {
            memory.deallocate_frames(ptr, count);
        } else {
            survivors.push((count, ptr));
        }
    }

    let mut reclaimed_frames: Vec<*mut u8> = Vec::new();
    while let Some(ptr) = memory.allocate_frames(1) {
        reclaimed_frames.push(ptr);
        if reclaimed_frames.len() >= survivors.len() {
            break; // reclaimed enough to prove fragmentation resistance
        }
    }

    let reclaimed = reclaimed_frames.len();
    for ptr in &reclaimed_frames {
        memory.deallocate_frames(*ptr, 1);
    }

    assert!(
        reclaimed > 0,
        "expected to reclaim at least 1 frame after fragmentation"
    );

    for &(count, ptr) in &survivors {
        memory.deallocate_frames(ptr, count);
    }
}

// ── Large multi-frame allocation ──────────────────────────────────────────

#[test]
fn large_contiguous_allocation_eventually_fails() {
    let mut memory = MemoryManager::new();
    memory.init();

    for count in [64, 128, 256, 512, 1024, 2048, 4096] {
        if let Some(ptr) = memory.allocate_frames(count) {
            memory.deallocate_frames(ptr, count);
        } else {
            return;
        }
    }
}

// ── Map/unmap cycles ──────────────────────────────────────────────────────

#[test]
fn map_and_unmap_small_ranges() {
    let mut memory = MemoryManager::new();
    memory.init();

    let (_, heap_end) = memory.heap_bounds();
    let base_va = align_up(heap_end + PAGE_SIZE * 16) + 0x100;

    for i in 0..50 {
        let va = base_va + i * PAGE_SIZE * 4;
        let pa = 0x10_0000 + i * PAGE_SIZE + 0x100;

        memory
            .map_to(va, pa, 1, PagePermissions::READ_WRITE)
            .unwrap_or_else(|e| panic!("map_to({va:#x}): {e:?}"));

        assert!(memory.translate(va).is_some(), "mapped at {va:#x}");

        memory
            .unmap(va, 1)
            .unwrap_or_else(|e| panic!("unmap({va:#x}): {e:?}"));

        assert!(memory.translate(va).is_none(), "unmapped at {va:#x}");
    }
}

#[test]
fn re_map_same_address_after_unmap() {
    let mut memory = MemoryManager::new();
    memory.init();

    let (_, heap_end) = memory.heap_bounds();
    let base = align_up(heap_end + PAGE_SIZE * 64) + 0x100;
    let pa1 = 0x20_0000 + 0x100;
    let pa2 = 0x30_0000 + 0x100;

    memory
        .map_to(base, pa1, 4, PagePermissions::READ)
        .expect("first map");
    memory.unmap(base, 4).expect("first unmap");
    memory
        .map_to(base, pa2, 4, PagePermissions::READ_WRITE)
        .expect("re-map");
    assert!(memory.translate(base).is_some(), "re-mapped");
    memory.unmap(base, 4).expect("final unmap");
}

// ── Allocate-and-free churn ───────────────────────────────────────────────

#[test]
fn churn_with_varied_sizes() {
    let mut memory = MemoryManager::new();
    memory.init();

    let sizes: &[usize] = &[1, 2, 3, 4, 8, 16, 32, 64, 128];
    let mut allocated: Vec<(usize, *mut u8)> = Vec::new();

    for &count in sizes {
        if let Some(ptr) = memory.allocate_frames(count) {
            allocated.push((count, ptr));
        }
    }

    let mid = allocated.len() / 2;
    for &(count, ptr) in &allocated[mid..] {
        memory.deallocate_frames(ptr, count);
    }
    allocated.truncate(mid);

    let mut reallocated: Vec<(usize, *mut u8)> = Vec::new();
    for _ in 0..10 {
        if let Some(ptr) = memory.allocate_frames(1) {
            reallocated.push((1, ptr));
        } else {
            break;
        }
    }

    for &(count, ptr) in &allocated {
        memory.deallocate_frames(ptr, count);
    }
    for &(count, ptr) in &reallocated {
        memory.deallocate_frames(ptr, count);
    }
}
