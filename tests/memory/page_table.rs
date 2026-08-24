//! tests/memory/page_table.rs
//!
//! Host-side integration tests for the software page-table implementation.

use protofire::kernel::memory::paging::{MappingKind, PagePermissions, PageTable, PAGE_SIZE};
use protofire::Error;

#[test]
fn page_table_rejects_overlapping_virtual_mappings() {
    let mut table = PageTable::new();
    table.init();

    table
        .map_to(0x1000, 0x4000, PAGE_SIZE * 2, PagePermissions::READ)
        .expect("map initial range");

    assert_eq!(
        table.map_to(0x2000, 0x8000, PAGE_SIZE, PagePermissions::READ),
        Err(Error::AlreadyExists)
    );
}

#[test]
fn page_table_preserves_mapping_kind_during_split_unmap() {
    let mut table = PageTable::new();
    table.init();

    table
        .map_to_with_kind(
            0x4000,
            0x9000,
            PAGE_SIZE * 3,
            PagePermissions::READ,
            MappingKind::Identity,
        )
        .expect("map tagged range");

    table.unmap(0x5000, PAGE_SIZE).expect("unmap middle page");

    assert_eq!(
        table.lookup_mapping(0x4000),
        Some((0x9000, PagePermissions::READ, MappingKind::Identity))
    );
    assert_eq!(
        table.lookup_mapping(0x6000),
        Some((0xB000, PagePermissions::READ, MappingKind::Identity))
    );
}

#[test]
fn page_table_requires_matching_page_offsets() {
    let mut table = PageTable::new();
    table.init();

    assert_eq!(
        table.map_to(0x1003, 0x2000, PAGE_SIZE, PagePermissions::READ),
        Err(Error::InvalidArgument)
    );

    table
        .map_to(0x1003, 0x3003, 64, PagePermissions::READ)
        .expect("map matching offsets");

    assert_eq!(table.lookup(0x1003), Some((0x3003, PagePermissions::READ)));
}

#[test]
fn page_table_rounds_unaligned_mappings_to_full_pages() {
    let mut table = PageTable::new();
    table.init();

    table
        .map_to(0x1800, 0x2800, 0x900, PagePermissions::READ)
        .expect("map unaligned range");

    assert_eq!(table.lookup(0x1000), Some((0x2000, PagePermissions::READ)));
    assert_eq!(table.lookup(0x1800), Some((0x2800, PagePermissions::READ)));
    assert_eq!(table.lookup(0x2fff), Some((0x3fff, PagePermissions::READ)));
    assert_eq!(table.lookup(0x3000), None);
}

#[test]
fn page_table_unmap_splits_existing_mapping() {
    let mut table = PageTable::new();
    table.init();

    table
        .map_to(0x1000, 0x4000, PAGE_SIZE * 3, PagePermissions::READ_WRITE)
        .expect("map three pages");

    table.unmap(0x2000, PAGE_SIZE).expect("unmap middle page");

    assert_eq!(table.mapping_count(), 2);
    assert_eq!(
        table.lookup(0x1000),
        Some((0x4000, PagePermissions::READ_WRITE))
    );
    assert_eq!(
        table.lookup(0x1fff),
        Some((0x4fff, PagePermissions::READ_WRITE))
    );
    assert_eq!(table.lookup(0x2000), None);
    assert_eq!(table.lookup(0x2fff), None);
    assert_eq!(
        table.lookup(0x3000),
        Some((0x6000, PagePermissions::READ_WRITE))
    );
}

#[test]
fn page_table_unmap_missing_range_preserves_existing_mappings() {
    let mut table = PageTable::new();
    table.init();

    table
        .map_to(0x1000, 0x4000, PAGE_SIZE, PagePermissions::READ)
        .expect("map first range");
    table
        .map_to(0x4000, 0x9000, PAGE_SIZE, PagePermissions::READ_WRITE)
        .expect("map second range");

    assert_eq!(table.unmap(0x8000, PAGE_SIZE), Err(Error::NotFound));
    assert_eq!(table.mapping_count(), 2);
    assert_eq!(table.lookup(0x1000), Some((0x4000, PagePermissions::READ)));
    assert_eq!(
        table.lookup(0x4000),
        Some((0x9000, PagePermissions::READ_WRITE))
    );
}

#[test]
fn page_table_rejects_virtual_ranges_that_overflow_after_page_rounding() {
    let mut table = PageTable::new();
    table.init();

    assert_eq!(
        table.map_to(
            usize::MAX - 0x7ff,
            usize::MAX - 0x7ff,
            PAGE_SIZE,
            PagePermissions::READ,
        ),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        table.unmap(usize::MAX - 0x7ff, PAGE_SIZE),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn page_table_rejects_physical_ranges_that_overflow_after_page_rounding() {
    let mut table = PageTable::new();
    table.init();

    assert_eq!(
        table.map_to(0x1800, usize::MAX - 0x7ff, PAGE_SIZE, PagePermissions::READ,),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn page_table_allows_more_than_legacy_fixed_mapping_capacity() {
    let mut table = PageTable::new();
    table.init();

    let base_virtual = 0x1000_0000;
    let base_physical = 0x2000_0000;
    let mapping_count = 140;

    for index in 0..mapping_count {
        let offset = index * PAGE_SIZE * 2;
        table
            .map_to(
                base_virtual + offset,
                base_physical + offset,
                PAGE_SIZE,
                PagePermissions::READ,
            )
            .expect("map non-overlapping page");
    }

    assert_eq!(table.mapping_count(), mapping_count);
    assert_eq!(
        table.lookup(base_virtual),
        Some((base_physical, PagePermissions::READ))
    );

    let last_offset = (mapping_count - 1) * PAGE_SIZE * 2;
    assert_eq!(
        table.lookup(base_virtual + last_offset),
        Some((base_physical + last_offset, PagePermissions::READ))
    );
}
