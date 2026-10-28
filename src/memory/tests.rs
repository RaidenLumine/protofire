//! src/memory/tests.rs
//!
//! Unit tests for the memory manager and its software page table.

use super::paging::AddressSpaceId;
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

    let owner = 0x1_0000usize;
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

    let registered = memory.register_user_pages(owner, &entries);
    assert_eq!(registered, 2);

    let (phys, perms, kind) = memory
        .lookup_mapping_for(owner, 0x1000_0000)
        .expect("first user mapping present");
    assert_eq!(phys, 0x2000_0000);
    assert_eq!(perms, PagePermissions::READ_WRITE);
    assert_eq!(kind, MappingKind::Anonymous);

    let (phys, _, _) = memory
        .lookup_mapping_for(owner, 0x1000_1000)
        .expect("second user mapping present");
    assert_eq!(phys, 0x2000_1000);
}

/// Two processes may map the same virtual address without disturbing each
/// other.
///
/// This is the defect fork exposed: every process's image and stack live at the
/// same virtual addresses, and the software page table used to key a mapping by
/// the address alone.  Whichever process registered second silently replaced
/// the first one's entry, and the first then faulted on its own stack because
/// the software table described the *other* process's page.
///
/// Both directions are asserted, because a lookup that answers with the wrong
/// owner is as broken as a registration that overwrites: the parent must still
/// see its frame, the child must see its own, and a third address space must
/// see neither.
#[test]
fn two_address_spaces_can_map_the_same_virtual_address() {
    let mut memory = MemoryManager::new();
    memory.page_table.init();

    let parent = 0x2_0000usize;
    let child = 0x3_0000usize;
    let stranger = 0x4_0000usize;
    let va = 0x7fff_ffff_e000;

    memory.register_user_pages(
        parent,
        &[(
            va,
            0x10_0000,
            PagePermissions::READ_WRITE,
            MappingKind::Anonymous,
        )],
    );
    memory.register_user_pages(
        child,
        &[(
            va,
            0x20_0000,
            PagePermissions::READ_WRITE,
            MappingKind::Anonymous,
        )],
    );

    assert_eq!(
        memory
            .lookup_mapping_for(parent, va)
            .map(|(phys, _, _)| phys),
        Some(0x10_0000),
        "the parent's registration must survive the child's"
    );
    assert_eq!(
        memory
            .lookup_mapping_for(child, va)
            .map(|(phys, _, _)| phys),
        Some(0x20_0000),
        "the child must see its own page"
    );
    assert_eq!(
        memory.lookup_mapping_for(stranger, va),
        None,
        "an unrelated address space must not see either"
    );

    // Tearing the child down leaves the parent's mapping in place.
    memory.unregister_user_page_range(child, va, PAGE_SIZE);
    assert_eq!(
        memory
            .lookup_mapping_for(parent, va)
            .map(|(phys, _, _)| phys),
        Some(0x10_0000),
        "the child's teardown must not unmap the parent's page"
    );
    assert_eq!(memory.lookup_mapping_for(child, va), None);
}

/// Page content is per address space too.
///
/// The demand-paging content store is the software page table's neighbour and
/// had the same key: saving one process's page under a bare virtual address
/// would let the next process fault it back in as its own.
#[test]
fn stored_page_content_is_per_address_space() {
    let mut memory = MemoryManager::new();
    let first = AddressSpaceId::from_root_table(0x5_0000);
    let second = AddressSpaceId::from_root_table(0x6_0000);
    let va = 0x1000_0000;

    memory.store_page_content(first, va, alloc::vec![0xAA_u8; PAGE_SIZE]);
    memory.store_page_content(second, va, alloc::vec![0xBB_u8; PAGE_SIZE]);

    assert_eq!(memory.get_page_content(first, va).unwrap()[0], 0xAA);
    assert_eq!(memory.get_page_content(second, va).unwrap()[0], 0xBB);
    assert!(memory
        .get_page_content(AddressSpaceId::from_root_table(0x7_0000), va)
        .is_none());

    memory.clear_page_content();
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
    let owner = 0x8_0000usize;
    let registered = memory.register_user_pages(owner, &entries);
    assert_eq!(registered, 0);

    // The kernel mapping is visible from every address space, so the owner's
    // own lookup finds it too.
    let (phys, _, kind) = memory
        .lookup_mapping_for(owner, 0x8000_0000)
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
    // SAFETY: the manager was leaked on the line above, so it lives for the rest
    // of the test binary; this hook exists only for tests.
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
