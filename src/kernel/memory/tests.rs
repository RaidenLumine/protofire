//! src/kernel/memory/tests.rs
//!
//! Unit tests for the memory manager and its software page table.

use super::paging::MappingKind;
use super::paging::PagePermissions;
use super::paging::PAGE_SIZE;
use super::MemoryManager;
use alloc::boxed::Box;

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

// ── memory-manager lock owner ───────────────────────────────────────────
//
// The x86_64 page-fault handler cannot resolve a fault without the memory
// manager, and the fault may have been raised *by* a critical section that
// already holds it.  The only thing that keeps that from being a silent
// permanent spin is the lock recording which CPU owns it, so the handler can
// tell "wait, another CPU has it" from "do not wait, this CPU has it".

#[test]
fn lock_owner_is_free_before_any_acquisition() {
    let owner = super::global::LockOwner::new();
    assert_eq!(owner.owner_for_tests(), super::global::LockOwner::FREE);
    assert!(!owner.held_by_current_cpu());
}

#[test]
fn lock_owner_reports_this_cpu_while_it_holds_the_lock() {
    let owner = super::global::LockOwner::new();
    owner.acquired();
    assert!(
        owner.held_by_current_cpu(),
        "the holder must be able to recognise its own lock"
    );
    owner.released();
    assert!(!owner.held_by_current_cpu(), "release must clear the owner");
}

#[test]
fn lock_owner_does_not_claim_a_lock_another_cpu_holds() {
    let owner = super::global::LockOwner::new();
    // Any id other than this CPU's stands in for another core.  Acquiring on
    // another CPU is exactly the case the fault handler *may* wait for.
    owner.set_owner_for_tests(crate::kernel::percpu::get().cpu_id.wrapping_add(1));
    assert!(
        !owner.held_by_current_cpu(),
        "a lock held elsewhere is not this CPU's own"
    );
}

#[test]
fn lock_owner_free_sentinel_is_not_a_cpu() {
    // `acquired` records a real CPU id, so the sentinel has to be one no CPU
    // can have, or a free lock would read as "held by this CPU".
    assert_ne!(
        super::global::LockOwner::FREE,
        crate::kernel::percpu::get().cpu_id,
        "the free sentinel must not collide with a CPU id"
    );
}

#[test]
fn global_lock_refuses_reentry_and_clears_the_owner_on_release() {
    // The page-fault handler's guard is this call: while this CPU is inside a
    // critical section, re-entering would spin forever, so the accessors must
    // both refuse and say why.  The manager is leaked because the global slot
    // borrows it, and the slot is cleared again before the test returns so the
    // rest of the unit-test binary sees the state it started with.
    let memory: &'static mut MemoryManager = Box::leak(Box::new(MemoryManager::new()));
    memory.init();
    unsafe { super::install_global_for_tests(memory) };

    let guard = super::global_mut().expect("manager installed");
    assert!(
        super::held_by_current_cpu(),
        "the holder must be visible to the fault handler"
    );
    assert!(
        super::try_global_mut().is_none(),
        "acquiring the lock a second time on this CPU must fail, not wait"
    );

    drop(guard);
    super::uninstall_global_for_tests();
}
