//! src/kernel/memory/tests.rs
//! Unit tests for the memory manager and its software page table.

use super::paging::{MappingKind, PagePermissions, PAGE_SIZE};
use super::MemoryManager;

#[test]
fn memory_manager_starts_uninitialized() {
    let memory = MemoryManager::new();
    assert!(!memory.initialized);
    assert_eq!(memory.heap_bounds(), (0, 0));
    assert_eq!(memory.page_table.mapping_count(), 0);
}

#[test]
fn init_succeeds_and_maps_the_kernel_heap() {
    let mut memory = MemoryManager::new();
    memory.init();
    assert!(memory.initialized);
    let (heap_start, heap_end) = memory.heap_bounds();
    assert!(heap_start < heap_end);
    assert!(memory.page_table.lookup(heap_start).is_some());
}

#[test]
fn init_remains_uninitialized_when_heap_bootstrap_mapping_conflicts() {
    let mut memory = MemoryManager::new();
    memory.page_table.init();
    memory.init_kernel_heap();
    let (heap_start, heap_end) = memory.heap_bounds();
    let heap_size = heap_end - heap_start;

    assert_eq!(
        memory.page_table.map_region_with_kind(
            heap_start,
            heap_size,
            PagePermissions::READ_WRITE,
            MappingKind::KernelHeap,
        ),
        Ok(())
    );

    memory.init();

    assert!(!memory.initialized);
    assert!(memory.page_table.lookup(heap_start).is_some());
}

// ── register_user_pages ──────────────────────────────────────────────

#[test]
fn register_user_pages_adds_anonymous_mappings() {
    let mut memory = MemoryManager::new();
    memory.page_table.init();

    let entries = [
        (
            0x1000_0000,
            0x2000_0000,
            PagePermissions::READ_WRITE,
            MappingKind::Anonymous,
        ),
        (
            0x1000_1000,
            0x2000_1000,
            PagePermissions::READ_WRITE,
            MappingKind::Anonymous,
        ),
    ];

    let registered = memory.register_user_pages(&entries);
    assert_eq!(registered, 2);

    let (phys, perms, kind) = memory
        .page_table
        .lookup_mapping(0x1000_0000)
        .expect("first user mapping present");
    assert_eq!(phys, 0x2000_0000);
    assert_eq!(perms, PagePermissions::READ_WRITE);
    assert_eq!(kind, MappingKind::Anonymous);

    let (phys, _, _) = memory
        .page_table
        .lookup_mapping(0x1000_1000)
        .expect("second user mapping present");
    assert_eq!(phys, 0x2000_1000);
}

#[test]
fn register_user_pages_skips_kernel_mapping_conflicts() {
    let mut memory = MemoryManager::new();
    memory.page_table.init();

    memory
        .page_table
        .map_region_with_kind(
            0x8000_0000,
            PAGE_SIZE,
            PagePermissions::READ_WRITE,
            MappingKind::KernelHeap,
        )
        .expect("map kernel heap region");

    let entries = [(
        0x8000_0000,
        0x9000_0000,
        PagePermissions::READ_WRITE,
        MappingKind::Anonymous,
    )];

    // register_user_pages must refuse to overwrite kernel-space mappings.
    let registered = memory.register_user_pages(&entries);
    assert_eq!(registered, 0);

    let (phys, _, kind) = memory
        .page_table
        .lookup_mapping(0x8000_0000)
        .expect("kernel mapping preserved");
    assert_eq!(phys, 0x8000_0000);
    assert_eq!(kind, MappingKind::KernelHeap);
}
