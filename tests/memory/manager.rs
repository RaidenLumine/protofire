//! tests/memory/manager.rs
//! Host-side integration tests for the software memory manager facade.

use protofire::arch::mmu::bootstrap_identity_mapping;
use protofire::kernel::memory::paging::{MappingKind, PagePermissions, PAGE_SIZE};
use protofire::kernel::memory::{
    AddressTranslation, BootstrapTranslation, MemoryManager, PlannedKernelRegion,
    PlannedKernelRegionKind,
};

fn align_up(value: usize) -> usize {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[test]
fn memory_manager_maps_kernel_heap_during_init() {
    let mut memory = MemoryManager::new();
    memory.init();

    let (heap_start, heap_end) = memory.heap_bounds();
    assert!(heap_start < heap_end);
    assert_eq!(
        memory.page_fault_insight(heap_start).translation,
        Some(AddressTranslation {
            physical_address: heap_start,
            permissions: PagePermissions::READ_WRITE,
            kind: MappingKind::KernelHeap,
        })
    );
    assert_eq!(
        memory.page_fault_insight(heap_end - 1).translation,
        Some(AddressTranslation {
            physical_address: heap_end - 1,
            permissions: PagePermissions::READ_WRITE,
            kind: MappingKind::KernelHeap,
        })
    );
    assert_eq!(
        memory.page_fault_insight(heap_start).planned_region,
        Some(PlannedKernelRegion {
            permissions: PagePermissions::READ_WRITE,
            kind: PlannedKernelRegionKind::KernelHeap,
        })
    );

    let heap_insight = memory.page_fault_insight(heap_start);
    assert_eq!(heap_insight.bootstrap_translation, None);
    assert_eq!(heap_insight.bootstrap_state(), "bootstrap-unmapped");
    assert_eq!(heap_insight.prepared_translation, None);
    assert_eq!(heap_insight.prepared_state(), "prepared-unmapped");
}

#[test]
fn memory_manager_reports_kernel_heap_mapping_at_kernel_heap_end() {
    let mut memory = MemoryManager::new();
    memory.init();

    let (_, heap_end) = memory.heap_bounds();

    // heap_end is one byte past the logical heap range.
    // Its translation may or may not be present depending on whether the
    // heap base happens to be page-aligned (the mapping rounds up to page
    // boundaries), so we only assert the deterministic boundary properties.
    let end_insight = memory.page_fault_insight(heap_end);
    assert!(!end_insight.in_kernel_heap);
    assert_eq!(end_insight.bootstrap_translation, None);
    assert_eq!(end_insight.bootstrap_state(), "bootstrap-unmapped");
    assert!(!end_insight.prepared_active);
    assert_eq!(end_insight.prepared_translation, None);
    assert_eq!(end_insight.prepared_state(), "prepared-unmapped");
    assert_eq!(end_insight.planned_region, None);
    assert_eq!(end_insight.planned_state(), "outside-kernel-plan");

    // The last byte inside the heap is always mapped as KernelHeap,
    // regardless of page-alignment of the heap base address.
    let last_byte = heap_end.saturating_sub(1);
    let last_insight = memory.page_fault_insight(last_byte);
    assert!(last_insight.in_kernel_heap);
    assert_eq!(
        last_insight.translation,
        Some(AddressTranslation {
            physical_address: last_byte,
            permissions: PagePermissions::READ_WRITE,
            kind: MappingKind::KernelHeap,
        })
    );
    assert_eq!(last_insight.software_state(), "kernel-heap");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn memory_manager_reports_bootstrap_identity_map_in_page_fault_insight() {
    let mut memory = MemoryManager::new();
    memory.init();

    let bootstrap = bootstrap_identity_mapping();
    let start_address = bootstrap.virtual_start;
    let mapped_address = 0x1234;
    let edge_address = bootstrap.virtual_start + bootstrap.length - 1;
    let outside_address = bootstrap.virtual_start + bootstrap.length;
    let start_insight = memory.page_fault_insight(start_address);
    let insight = memory.page_fault_insight(mapped_address);
    let edge_insight = memory.page_fault_insight(edge_address);
    let outside_insight = memory.page_fault_insight(outside_address);

    assert!(!start_insight.in_kernel_heap);
    assert_eq!(start_insight.translation, None);
    assert_eq!(
        start_insight.bootstrap_translation,
        Some(BootstrapTranslation {
            physical_address: start_address,
            page_size: bootstrap.page_size,
            writable: bootstrap.writable,
            executable: bootstrap.executable,
        })
    );
    assert_eq!(start_insight.bootstrap_state(), "bootstrap-identity-map");
    assert_eq!(start_insight.software_state(), "unmapped");
    assert!(!start_insight.prepared_active);
    assert_eq!(start_insight.prepared_translation, None);
    assert_eq!(start_insight.prepared_state(), "prepared-unmapped");
    assert_eq!(start_insight.planned_region, None);
    assert_eq!(start_insight.planned_state(), "outside-kernel-plan");

    assert!(!insight.in_kernel_heap);
    assert_eq!(insight.translation, None);
    assert_eq!(
        insight.bootstrap_translation,
        Some(BootstrapTranslation {
            physical_address: mapped_address,
            page_size: bootstrap.page_size,
            writable: bootstrap.writable,
            executable: bootstrap.executable,
        })
    );
    assert_eq!(insight.bootstrap_state(), "bootstrap-identity-map");
    assert_eq!(insight.software_state(), "unmapped");
    assert!(!insight.prepared_active);
    assert_eq!(insight.prepared_translation, None);
    assert_eq!(insight.prepared_state(), "prepared-unmapped");
    assert_eq!(insight.planned_region, None);
    assert_eq!(insight.planned_state(), "outside-kernel-plan");

    assert!(!edge_insight.in_kernel_heap);
    assert_eq!(edge_insight.translation, None);
    assert_eq!(
        edge_insight.bootstrap_translation,
        Some(BootstrapTranslation {
            physical_address: edge_address,
            page_size: bootstrap.page_size,
            writable: bootstrap.writable,
            executable: bootstrap.executable,
        })
    );
    assert_eq!(edge_insight.bootstrap_state(), "bootstrap-identity-map");
    assert_eq!(edge_insight.software_state(), "unmapped");
    assert!(!edge_insight.prepared_active);
    assert_eq!(edge_insight.prepared_translation, None);
    assert_eq!(edge_insight.prepared_state(), "prepared-unmapped");
    assert_eq!(edge_insight.planned_region, None);
    assert_eq!(edge_insight.planned_state(), "outside-kernel-plan");

    assert!(!outside_insight.in_kernel_heap);
    assert_eq!(outside_insight.translation, None);
    assert_eq!(outside_insight.bootstrap_translation, None);
    assert_eq!(outside_insight.bootstrap_state(), "bootstrap-unmapped");
    assert_eq!(outside_insight.software_state(), "unmapped");
    assert!(!outside_insight.prepared_active);
    assert_eq!(outside_insight.prepared_translation, None);
    assert_eq!(outside_insight.prepared_state(), "prepared-unmapped");
    assert_eq!(outside_insight.planned_region, None);
    assert_eq!(outside_insight.planned_state(), "outside-kernel-plan");
}

#[test]
fn memory_manager_can_map_translate_and_unmap_explicit_ranges() {
    let mut memory = MemoryManager::new();
    memory.init();

    let (_, heap_end) = memory.heap_bounds();
    let virtual_address = align_up(heap_end + PAGE_SIZE * 8) + 0x120;
    let physical_address = 0x20_000 + 0x120;

    memory
        .map_to(
            virtual_address,
            physical_address,
            256,
            PagePermissions::READ,
        )
        .expect("map explicit range");

    assert_eq!(
        memory.page_fault_insight(virtual_address).translation,
        Some(AddressTranslation {
            physical_address,
            permissions: PagePermissions::READ,
            kind: MappingKind::Anonymous,
        })
    );
    assert_eq!(
        memory.page_fault_insight(virtual_address + 255).translation,
        Some(AddressTranslation {
            physical_address: physical_address + 255,
            permissions: PagePermissions::READ,
            kind: MappingKind::Anonymous,
        })
    );

    memory
        .unmap(virtual_address, 256)
        .expect("unmap explicit range");
    assert_eq!(memory.translate(virtual_address), None);
}

#[test]
fn memory_manager_reuses_frames_after_deallocation() {
    let mut memory = MemoryManager::new();
    memory.init();

    let first = memory.allocate_frames(2).expect("allocate first range");
    let second = memory.allocate_frames(1).expect("allocate second range");

    assert!(memory.deallocate_frames(first, 2));
    let recycled = memory.allocate_frames(2).expect("recycle first range");

    assert_eq!(recycled, first);
    assert_ne!(recycled, second);
}

#[test]
fn memory_manager_init_is_idempotent_and_preserves_runtime_state() {
    let mut memory = MemoryManager::new();
    memory.init();

    let first_frame = memory.allocate_frames(1).expect("allocate first frame");
    let (_, heap_end) = memory.heap_bounds();
    let virtual_address = align_up(heap_end + PAGE_SIZE * 16) + 0x80;
    let physical_address = 0x30_000 + 0x80;

    memory
        .map_to(
            virtual_address,
            physical_address,
            128,
            PagePermissions::READ,
        )
        .expect("map explicit range");

    memory.init();

    let second_frame = memory.allocate_frames(1).expect("allocate second frame");
    assert_ne!(second_frame, first_frame);
    assert_eq!(
        memory.page_fault_insight(virtual_address).translation,
        Some(AddressTranslation {
            physical_address,
            permissions: PagePermissions::READ,
            kind: MappingKind::Anonymous,
        })
    );

    assert!(memory.deallocate_frames(first_frame, 1));
    assert!(memory.deallocate_frames(second_frame, 1));
}
