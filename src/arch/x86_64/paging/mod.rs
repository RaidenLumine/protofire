//! src/arch/x86_64/paging/mod.rs
//!
//! x86_64 paging — bootstrap and runtime page-table planning plus per-process
//! address-space assembly.

pub(crate) mod kernel_address_space;
pub(crate) mod process_address_space;
pub(crate) mod runtime;
pub(crate) mod types;
pub(crate) mod user_address_space;

pub use kernel_address_space::*;
pub use process_address_space::*;
pub use runtime::*;
pub use types::*;
pub use user_address_space::*;

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use crate::arch::x86_64::paging::*;
    use crate::kernel::memory::paging::PagePermissions;
    use crate::user::program::UserImageLoadPlan;
    use crate::user::program::UserImageSegmentPlan;
    use crate::user::program::USER_EXCEPTION_STACK_GUARD_SIZE;
    use crate::user::program::USER_EXCEPTION_STACK_SIZE;
    use crate::user::program::USER_STACK_GUARD_SIZE;
    use crate::user::program::USER_STACK_SIZE;
    use crate::user::program::X86_64_USER_STACK_TOP;
    use alloc::vec;
    use core::sync::atomic::Ordering;

    fn test_user_stack_layout() -> (usize, usize, usize, usize, usize, usize, usize, usize) {
        let stack_top = X86_64_USER_STACK_TOP;
        let stack_bottom = stack_top - USER_STACK_SIZE;
        let stack_guard_start = stack_bottom - USER_STACK_GUARD_SIZE;
        let stack_guard_end = stack_bottom;
        let exception_stack_top = stack_guard_start;
        let exception_stack_bottom = exception_stack_top - USER_EXCEPTION_STACK_SIZE;
        let exception_stack_guard_start = exception_stack_bottom - USER_EXCEPTION_STACK_GUARD_SIZE;
        let exception_stack_guard_end = exception_stack_bottom;

        (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        )
    }

    #[test]
    fn page_table_specs_stay_small_enough_for_kernel_stacks() {
        // KernelPageTableSpec carries a window Vec plus two BTreeMaps for
        // huge-page entries; the size increased from 48 to accommodate them
        // (≈136 bytes on x86_64).  The bound keeps it a few cache lines.
        assert!(size_of::<KernelPageTableSpec>() <= 160);
        assert!(size_of::<UserAddressSpacePageTableSpec>() <= 80);
    }

    #[test]
    fn bootstrap_identity_map_covers_first_gib() {
        let mapping = bootstrap_identity_mapping();

        assert_eq!(mapping.page_size, BOOTSTRAP_PAGE_SIZE);
        assert!(mapping.writable);
        assert!(mapping.executable);
        assert!(mapping.contains(0));
        assert!(mapping.contains(BOOTSTRAP_IDENTITY_MAP_END - 1));
        assert!(!mapping.contains(BOOTSTRAP_IDENTITY_MAP_END));
    }

    #[test]
    fn bootstrap_identity_map_translates_identically() {
        assert_eq!(bootstrap_translate(0x1234), Some(0x1234));
        assert_eq!(
            bootstrap_translate(BOOTSTRAP_IDENTITY_MAP_END - 1),
            Some(BOOTSTRAP_IDENTITY_MAP_END - 1)
        );
        assert_eq!(bootstrap_translate(BOOTSTRAP_IDENTITY_MAP_END), None);
    }

    #[test]
    fn kernel_page_plan_prioritizes_heap_inside_bss() {
        let plan = KernelPagePlan::from_ranges(
            (0x200000, 0x210000),
            (0x210000, 0x220000),
            (0x220000, 0x230000),
            (0x230000, 0x260000),
            (0x240000, 0x250000),
        )
        .expect("page plan");

        assert_eq!(plan.region_count(), 5);

        let text = plan.classify(0x200123).expect("text");
        assert_eq!(text.kind, PlannedRegionKind::KernelText);
        assert_eq!(text.permissions, PagePermissions::READ_EXECUTE);

        let bss = plan.classify(0x230123).expect("bss");
        assert_eq!(bss.kind, PlannedRegionKind::KernelBss);

        let heap = plan.classify(0x240123).expect("heap");
        assert_eq!(heap.kind, PlannedRegionKind::KernelHeap);
        assert_eq!(heap.permissions, PagePermissions::READ_WRITE);
    }

    #[test]
    fn kernel_page_plan_rejects_invalid_overlaps() {
        assert!(KernelPagePlan::from_ranges(
            (0x200000, 0x210000),
            (0x208000, 0x220000),
            (0x220000, 0x230000),
            (0x230000, 0x260000),
            (0x240000, 0x250000),
        )
        .is_none());
        assert!(KernelPagePlan::from_ranges(
            (0x200000, 0x210000),
            (0x210000, 0x220000),
            (0x220000, 0x230000),
            (0x230000, 0x260000),
            (0x220000, 0x225000),
        )
        .is_none());
    }

    #[test]
    fn heap_only_plan_tracks_kernel_heap_range() {
        let plan = KernelPagePlan::heap_only((0x800000, 0x810000)).expect("heap-only plan");

        let heap = plan.classify(0x800800).expect("heap");
        assert_eq!(heap.kind, PlannedRegionKind::KernelHeap);
        assert_eq!(heap.permissions, PagePermissions::READ_WRITE);
        assert_eq!(plan.classify(0x7fffff), None);
    }

    #[test]
    fn kernel_page_table_spec_maps_planned_pages_with_expected_permissions() {
        let plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201800),
            (0x202000, 0x203000),
            (0x204000, 0x205000),
            (0x206000, 0x20c000),
            (0x208000, 0x20a000),
        )
        .expect("page plan");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");

        assert_eq!(spec.window_count(), 1);
        assert_eq!(
            spec.translate(0x200123).expect("text mapping").permissions,
            PagePermissions::READ_EXECUTE
        );
        assert_eq!(
            spec.translate(0x202321)
                .expect("rodata mapping")
                .permissions,
            PagePermissions::READ
        );
        assert_eq!(
            spec.translate(0x208456).expect("heap mapping").permissions,
            PagePermissions::READ_WRITE
        );
        assert_eq!(spec.translate(0x203800), None);
    }

    #[test]
    fn kernel_page_table_spec_tracks_multiple_windows() {
        let plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x3ff000, 0x401000),
            (0x600000, 0x601000),
            (0x800000, 0x802000),
            (0x900000, 0x910000),
        )
        .expect("page plan");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");

        assert_eq!(spec.window_count(), 4);
        assert!(spec.mapped_page_count() >= 0x14);
        assert_eq!(
            spec.translate(0x400100)
                .expect("cross-window rodata")
                .permissions,
            PagePermissions::READ
        );
        assert_eq!(
            spec.translate(0x900123).expect("heap").physical_address,
            0x900123
        );
    }

    #[test]
    fn kernel_page_table_spec_rejects_regions_outside_bootstrap_identity_map() {
        let plan = KernelPagePlan::from_ranges(
            (
                BOOTSTRAP_IDENTITY_MAP_END,
                BOOTSTRAP_IDENTITY_MAP_END + 0x1000,
            ),
            (0x210000, 0x220000),
            (0x220000, 0x230000),
            (0x230000, 0x260000),
            (0x240000, 0x250000),
        )
        .expect("page plan");

        assert!(KernelPageTableSpec::from_plan(&plan).is_none());
    }

    #[test]
    fn active_runtime_kernel_page_table_check_validates_text_stack_and_heap() {
        let plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x211000),
            (0x220000, 0x221000),
            (0x230000, 0x240000),
            (0x240000, 0x250000),
        )
        .expect("page plan");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");
        let check = build_active_runtime_kernel_page_table_check(
            0x310000, &plan, &spec, 0x200100, 0x230800, 0x240400,
        )
        .expect("active check");

        assert_eq!(check.root_table_address, 0x310000);
        assert_eq!(
            check.instruction_pointer.kind,
            PlannedRegionKind::KernelText
        );
        assert_eq!(
            check.instruction_pointer.permissions,
            PagePermissions::READ_EXECUTE
        );
        assert_eq!(check.stack_pointer.kind, PlannedRegionKind::KernelBss);
        assert_eq!(check.stack_pointer.permissions, PagePermissions::READ_WRITE);
        assert_eq!(check.heap_pointer.kind, PlannedRegionKind::KernelHeap);
        assert_eq!(check.heap_pointer.virtual_address, 0x240400);
    }

    #[test]
    fn active_runtime_kernel_page_table_check_rejects_non_writable_stack_region() {
        let plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x212000),
            (0x220000, 0x221000),
            (0x230000, 0x240000),
            (0x240000, 0x250000),
        )
        .expect("page plan");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");

        assert!(build_active_runtime_kernel_page_table_check(
            0x310000, &plan, &spec, 0x200100, 0x210100, 0x240400,
        )
        .is_none());
    }

    #[test]
    fn user_address_space_page_table_spec_tracks_image_and_stack_regions() {
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x405000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![
                UserImageSegmentPlan {
                    virtual_start: 0x401000,
                    virtual_end: 0x403000,
                    page_start: 0x401000,
                    page_end: 0x403000,
                    file_offset: 0x1000,
                    file_size: 0x1800,
                    zero_start: 0x402800,
                    zero_end: 0x403000,
                    permissions: PagePermissions::READ_EXECUTE,
                },
                UserImageSegmentPlan {
                    virtual_start: 0x404000,
                    virtual_end: 0x405000,
                    page_start: 0x404000,
                    page_end: 0x405000,
                    file_offset: 0x3000,
                    file_size: 0x800,
                    zero_start: 0x404800,
                    zero_end: 0x405000,
                    permissions: PagePermissions::READ_WRITE,
                },
            ],
        };

        let spec = user_address_space_page_table_spec(&plan).expect("user address space spec");

        assert_eq!(spec.window_count(), 2);
        assert_eq!(
            spec.mapped_page_count(),
            3 + USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096
        );
        assert_eq!(
            spec.stack_page_count(),
            USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096
        );
        assert_eq!(spec.pml4_count(), 2);
        assert_eq!(spec.pdpt_count(), 2);
        assert_eq!(spec.page_directory_count(), 2);
        assert_eq!(
            spec.lookup(0x401123),
            Some(UserPageMapping {
                permissions: PagePermissions::READ_EXECUTE,
                kind: UserRegionKind::Image,
            })
        );
        assert_eq!(
            spec.lookup(0x404456),
            Some(UserPageMapping {
                permissions: PagePermissions::READ_WRITE,
                kind: UserRegionKind::Image,
            })
        );
        assert_eq!(
            spec.lookup(stack_top - 16),
            Some(UserPageMapping {
                permissions: PagePermissions::READ_WRITE,
                kind: UserRegionKind::Stack,
            })
        );
        assert_eq!(spec.lookup(stack_bottom - 1), None);
        assert_eq!(
            spec.lookup(exception_stack_top - 16),
            Some(UserPageMapping {
                permissions: PagePermissions::READ_WRITE,
                kind: UserRegionKind::Stack,
            })
        );
        assert_eq!(spec.lookup(exception_stack_bottom - 1), None);
    }

    #[test]
    fn user_address_space_page_table_spec_rejects_non_canonical_ranges() {
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: X86_64_USER_CANONICAL_END,
            image_start: X86_64_USER_CANONICAL_END,
            image_end: X86_64_USER_CANONICAL_END + 0x2000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: X86_64_USER_CANONICAL_END,
                virtual_end: X86_64_USER_CANONICAL_END + 0x2000,
                page_start: X86_64_USER_CANONICAL_END,
                page_end: X86_64_USER_CANONICAL_END + 0x2000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: X86_64_USER_CANONICAL_END + 0x1000,
                zero_end: X86_64_USER_CANONICAL_END + 0x2000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        assert_eq!(UserAddressSpacePageTableSpec::from_load_plan(&plan), None);
    }

    #[test]
    fn user_address_space_page_table_spec_rejects_image_overlapping_stack_guard() {
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: stack_guard_start,
            image_start: stack_guard_start,
            image_end: stack_bottom,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: stack_guard_start,
                virtual_end: stack_bottom,
                page_start: stack_guard_start,
                page_end: stack_bottom,
                file_offset: 0x1000,
                file_size: 0x800,
                zero_start: stack_guard_start + 0x800,
                zero_end: stack_bottom,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        assert_eq!(user_address_space_page_table_spec(&plan), None);
    }

    #[test]
    fn materialized_user_address_space_copies_image_pages_and_zeroes_tail() {
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x405000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![
                UserImageSegmentPlan {
                    virtual_start: 0x401000,
                    virtual_end: 0x403000,
                    page_start: 0x401000,
                    page_end: 0x403000,
                    file_offset: 0x1000,
                    file_size: 0x1800,
                    zero_start: 0x402800,
                    zero_end: 0x403000,
                    permissions: PagePermissions::READ_EXECUTE,
                },
                UserImageSegmentPlan {
                    virtual_start: 0x404000,
                    virtual_end: 0x405000,
                    page_start: 0x404000,
                    page_end: 0x405000,
                    file_offset: 0x3000,
                    file_size: 0x800,
                    zero_start: 0x404800,
                    zero_end: 0x405000,
                    permissions: PagePermissions::READ_WRITE,
                },
            ],
        };
        let mut image = vec![0_u8; 0x4000];
        for (index, byte) in image[0x1000..0x2800].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        for (index, byte) in image[0x3000..0x3800].iter_mut().enumerate() {
            *byte = (255 - (index % 251)) as u8;
        }

        let prepared =
            materialize_user_address_space(&plan, &image).expect("prepared user address space");
        let summary = prepared.summary();

        assert_eq!(
            summary,
            PreparedUserAddressSpaceSummary {
                root_table_address: prepared.root_table_address(),
                mapped_page_count: 3 + USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096,
                image_page_count: 3,
                stack_page_count: USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096,
                table_page_count: 7,
                pml4_entry_count: 2,
                pdpt_count: 2,
                page_directory_count: 2,
                page_table_count: 2,
            }
        );
        assert_eq!(prepared.table_page_count(), 7);
        assert_eq!(
            prepared.mapped_page_count(),
            3 + USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096
        );
        assert_eq!(prepared.root_entry_count(), 2);
        assert_eq!(
            prepared.translate(0x401123),
            Some(PreparedUserTranslation {
                physical_address: prepared
                    .translate(0x401123)
                    .expect("translation")
                    .physical_address,
                permissions: PagePermissions::READ_EXECUTE,
                kind: UserRegionKind::Image,
            })
        );
        assert_eq!(prepared.read_byte(0x401000), Some(image[0x1000]));
        assert_eq!(prepared.read_byte(0x4027ff), Some(image[0x27ff]));
        assert_eq!(prepared.read_byte(0x402800), Some(0));
        assert_eq!(prepared.read_byte(0x404000), Some(image[0x3000]));
        assert_eq!(prepared.read_byte(0x4047ff), Some(image[0x37ff]));
        assert_eq!(prepared.read_byte(0x404800), Some(0));
        assert_eq!(prepared.read_byte(stack_top - 1), Some(0));
        assert_eq!(prepared.read_byte(exception_stack_top - 1), Some(0));
        assert_eq!(
            prepared.translate(stack_top - 16).map(|entry| entry.kind),
            Some(UserRegionKind::Stack)
        );
        assert_eq!(
            prepared
                .translate(exception_stack_top - 16)
                .map(|entry| entry.kind),
            Some(UserRegionKind::Stack)
        );
    }

    #[test]
    fn materialized_user_address_space_rejects_truncated_image_bytes() {
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401000,
            image_start: 0x401000,
            image_end: 0x402000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: 0x401000,
                virtual_end: 0x402000,
                page_start: 0x401000,
                page_end: 0x402000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: 0x402000,
                zero_end: 0x402000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        assert!(materialize_user_address_space(&plan, &[0_u8; 64]).is_none());
    }

    #[test]
    fn prepared_process_address_space_merges_kernel_and_user_mappings() {
        let kernel_plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x211000),
            (0x220000, 0x221000),
            (0x230000, 0x231000),
            (0x240000, 0x242000),
        )
        .expect("kernel page plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x405000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![
                UserImageSegmentPlan {
                    virtual_start: 0x401000,
                    virtual_end: 0x403000,
                    page_start: 0x401000,
                    page_end: 0x403000,
                    file_offset: 0x1000,
                    file_size: 0x1800,
                    zero_start: 0x402800,
                    zero_end: 0x403000,
                    permissions: PagePermissions::READ_EXECUTE,
                },
                UserImageSegmentPlan {
                    virtual_start: 0x404000,
                    virtual_end: 0x405000,
                    page_start: 0x404000,
                    page_end: 0x405000,
                    file_offset: 0x3000,
                    file_size: 0x800,
                    zero_start: 0x404800,
                    zero_end: 0x405000,
                    permissions: PagePermissions::READ_WRITE,
                },
            ],
        };
        let mut image = vec![0_u8; 0x4000];
        for (index, byte) in image[0x1000..0x2800].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        for (index, byte) in image[0x3000..0x3800].iter_mut().enumerate() {
            *byte = (255 - (index % 251)) as u8;
        }

        let prepared =
            prepare_process_address_space(&kernel_spec, &plan, &image).expect("process root");
        let summary = prepared.summary();

        // The kernel plan above maps 6 pages (four single 4 KiB windows plus
        // one 8 KiB window); the user image contributes 3 pages plus the
        // stack regions.  The merged table shares PML4[0] between the kernel
        // region and the low user image.
        assert_eq!(
            summary,
            PreparedProcessAddressSpaceSummary {
                root_table_address: prepared.root_table_address(),
                mapped_page_count: 6
                    + 3
                    + USER_STACK_SIZE / 4096
                    + USER_EXCEPTION_STACK_SIZE / 4096,
                kernel_page_count: 6,
                user_page_count: 3 + USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096,
                table_page_count: 8,
                pml4_entry_count: 2,
                pdpt_count: 2,
                page_directory_count: 2,
                page_table_count: 3,
            }
        );
        assert_eq!(prepared.table_page_count(), 8);
        assert_eq!(
            prepared.mapped_page_count(),
            6 + 3 + USER_STACK_SIZE / 4096 + USER_EXCEPTION_STACK_SIZE / 4096
        );
        assert_eq!(prepared.root_entry_count(), 2);
        assert_eq!(
            prepared.translate(0x200100),
            Some(PreparedProcessTranslation {
                physical_address: 0x200100,
                permissions: PagePermissions::READ_EXECUTE,
                kind: ProcessRegionKind::Kernel,
            })
        );
        assert_eq!(
            prepared.translate(0x240800),
            Some(PreparedProcessTranslation {
                physical_address: 0x240800,
                permissions: PagePermissions::READ_WRITE,
                kind: ProcessRegionKind::Kernel,
            })
        );
        assert_eq!(
            prepared.translate(0x401123),
            Some(PreparedProcessTranslation {
                physical_address: prepared
                    .translate(0x401123)
                    .expect("user translation")
                    .physical_address,
                permissions: PagePermissions::READ_EXECUTE,
                kind: ProcessRegionKind::UserImage,
            })
        );
        assert_eq!(prepared.read_byte(0x401000), Some(image[0x1000]));
        assert_eq!(prepared.read_byte(0x404800), Some(0));
        assert_eq!(prepared.read_byte(stack_top - 1), Some(0));
        assert_eq!(prepared.read_byte(exception_stack_top - 1), Some(0));
        assert_eq!(prepared.read_byte(0x200000), None);
        assert_eq!(
            prepared.translate(stack_top - 8).map(|entry| entry.kind),
            Some(ProcessRegionKind::UserStack)
        );
        assert_eq!(
            prepared
                .translate(exception_stack_top - 8)
                .map(|entry| entry.kind),
            Some(ProcessRegionKind::UserStack)
        );
    }

    #[test]
    fn fork_clone_keeps_kernel_mappings_and_cows_user_pages() {
        let kernel_plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x211000),
            (0x220000, 0x221000),
            (0x230000, 0x231000),
            (0x240000, 0x242000),
        )
        .expect("kernel page plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x405000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![
                UserImageSegmentPlan {
                    virtual_start: 0x401000,
                    virtual_end: 0x403000,
                    page_start: 0x401000,
                    page_end: 0x403000,
                    file_offset: 0x1000,
                    file_size: 0x1800,
                    zero_start: 0x402800,
                    zero_end: 0x403000,
                    permissions: PagePermissions::READ_EXECUTE,
                },
                UserImageSegmentPlan {
                    virtual_start: 0x404000,
                    virtual_end: 0x405000,
                    page_start: 0x404000,
                    page_end: 0x405000,
                    file_offset: 0x3000,
                    file_size: 0x800,
                    zero_start: 0x404800,
                    zero_end: 0x405000,
                    permissions: PagePermissions::READ_WRITE,
                },
            ],
        };
        let mut image = vec![0_u8; 0x4000];
        for (index, byte) in image[0x1000..0x2800].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        for (index, byte) in image[0x3000..0x3800].iter_mut().enumerate() {
            *byte = (255 - (index % 251)) as u8;
        }

        let mut parent =
            prepare_process_address_space(&kernel_spec, &plan, &image).expect("process root");

        let (child, shared_pages, all_child_pages) = parent
            .fork_clone()
            .expect("fork_clone should succeed on merged hierarchy");

        // Child must keep the kernel mappings — this is the regression the
        // original recovery-era fix missed (it classified PML4[0] as a user
        // window because the low user image shares PML4[0] with the kernel
        // identity map, so the child CR3 lost the whole kernel region).
        assert_eq!(
            child.translate(0x200100).map(|e| e.kind),
            Some(ProcessRegionKind::Kernel)
        );
        assert_eq!(
            child.translate(0x240800).map(|e| e.kind),
            Some(ProcessRegionKind::Kernel)
        );
        assert_eq!(child.root_entry_count(), parent.root_entry_count());
        assert_eq!(child.summary().kernel_page_count, 6);

        // Child user image is present and readable (translate walks the
        // deep-copied child tables; read_byte is not usable here because the
        // child user address space owns no frames — they are CoW-shared).
        assert_eq!(
            child.translate(0x401123).map(|e| e.kind),
            Some(ProcessRegionKind::UserImage)
        );

        // Writable user pages (RW segment at 0x404000) become shared CoW.
        let writable_pa = parent
            .translate(0x404000)
            .expect("writable page")
            .physical_address;
        assert!(
            shared_pages
                .iter()
                .any(|&(va, pa, _)| va == 0x404000 && pa == writable_pa),
            "writable user page must be in shared_pages"
        );
        // CoW share for the writable page.
        let shared = shared_pages
            .iter()
            .find(|&&(va, _, _)| va == 0x404000)
            .expect("shared page");
        assert_eq!(shared.2, PagePermissions::READ);
        // And it is registered in all_child_pages.
        assert!(all_child_pages.iter().any(|&(va, _, _)| va == 0x404000));

        // Executable code pages are shared but not CoW (read-only).
        assert!(
            !shared_pages.iter().any(|&(va, _, _)| va == 0x401000),
            "read-only code page must not be CoW-shared"
        );
        assert!(all_child_pages.iter().any(|&(va, _, _)| va == 0x401000));

        // Parent's writable page lost WRITE (CoW).
        assert!(
            !parent
                .translate(0x404000)
                .expect("parent writable page")
                .permissions
                .contains(PagePermissions::WRITE),
            "parent must lose WRITE on shared page"
        );
        // Child's copy of the same page is also read-only (CoW first-writer).
        assert!(!child
            .translate(0x404000)
            .expect("child writable page")
            .permissions
            .contains(PagePermissions::WRITE));

        // Child summary matches parent's structure.
        assert_eq!(child.table_page_count(), parent.table_page_count());
        assert_eq!(
            child.summary().user_page_count,
            parent.summary().user_page_count
        );
        assert_eq!(
            child.summary().mapped_page_count,
            parent.summary().mapped_page_count
        );
    }

    #[test]
    fn prepared_process_address_space_rejects_kernel_user_overlap() {
        let kernel_plan = KernelPagePlan::heap_only((0x401000, 0x402000)).expect("kernel plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401000,
            image_start: 0x401000,
            image_end: 0x402000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: 0x401000,
                virtual_end: 0x402000,
                page_start: 0x401000,
                page_end: 0x402000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: 0x402000,
                zero_end: 0x402000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        assert!(prepare_process_address_space(&kernel_spec, &plan, &[0_u8; 0x2000]).is_none());
    }

    #[test]
    fn prepared_process_address_space_activation_tracks_previous_root_and_reentry() {
        let kernel_plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x211000),
            (0x220000, 0x221000),
            (0x230000, 0x231000),
            (0x240000, 0x242000),
        )
        .expect("kernel page plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x402000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: 0x401000,
                virtual_end: 0x402000,
                page_start: 0x401000,
                page_end: 0x402000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: 0x402000,
                zero_end: 0x402000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        let prepared =
            prepare_process_address_space(&kernel_spec, &plan, &[0_u8; 0x2000]).expect("root");
        super::TEST_ACTIVE_ROOT_TABLE.store(0x310000, Ordering::SeqCst);

        let activated = prepared.activate().expect("activate");
        assert_eq!(activated.previous_root_table_address, 0x310000);
        assert_eq!(
            activated.active_root_table_address,
            prepared.root_table_address()
        );
        assert_eq!(
            activated.mapped_page_count,
            prepared.summary().mapped_page_count
        );
        assert_eq!(
            activated.kernel_page_count,
            prepared.summary().kernel_page_count
        );
        assert_eq!(
            activated.user_page_count,
            prepared.summary().user_page_count
        );
        assert_eq!(
            activated.table_page_count,
            prepared.summary().table_page_count
        );
        assert!(!activated.already_active);
        assert_eq!(
            super::current_root_table_address_impl(),
            Some(prepared.root_table_address())
        );

        let reactivated = prepared.activate().expect("reactivate");
        assert_eq!(
            reactivated.previous_root_table_address,
            prepared.root_table_address()
        );
        assert_eq!(
            reactivated.active_root_table_address,
            prepared.root_table_address()
        );
        assert!(reactivated.already_active);

        super::TEST_ACTIVE_ROOT_TABLE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn prepared_process_address_space_passes_boundary_validation() {
        let kernel_plan = KernelPagePlan::from_ranges(
            (0x200000, 0x201000),
            (0x210000, 0x211000),
            (0x220000, 0x221000),
            (0x230000, 0x231000),
            (0x240000, 0x242000),
        )
        .expect("kernel page plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        let plan = UserImageLoadPlan {
            entry_point: 0x401020,
            image_start: 0x401000,
            image_end: 0x402000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: 0x401000,
                virtual_end: 0x402000,
                page_start: 0x401000,
                page_end: 0x402000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: 0x402000,
                zero_end: 0x402000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        // Standard kernel + user merge must pass boundary validation
        // (validation runs inside from_kernel_spec_and_user_address_space).
        let prepared =
            prepare_process_address_space(&kernel_spec, &plan, &[0_u8; 0x2000]).expect("root");

        // Kernel pages translate to ProcessRegionKind::Kernel and should
        // never have the USER bit in hardware PTEs.
        assert_eq!(
            prepared.translate(0x200100).map(|t| t.kind),
            Some(ProcessRegionKind::Kernel)
        );
        // User pages translate to UserImage / UserStack and must be
        // canonical.
        assert_eq!(
            prepared.translate(0x401100).map(|t| t.kind),
            Some(ProcessRegionKind::UserImage)
        );
        assert_eq!(
            prepared.translate(stack_top - 8).map(|t| t.kind),
            Some(ProcessRegionKind::UserStack)
        );
    }

    #[test]
    fn prepared_process_address_space_rejects_non_canonical_user_pages() {
        let kernel_plan =
            KernelPagePlan::heap_only((0x240000, 0x242000)).expect("kernel heap-only plan");
        let kernel_spec = KernelPageTableSpec::from_plan(&kernel_plan).expect("kernel page table");
        let (
            stack_top,
            stack_bottom,
            stack_guard_start,
            stack_guard_end,
            exception_stack_top,
            exception_stack_bottom,
            exception_stack_guard_start,
            exception_stack_guard_end,
        ) = test_user_stack_layout();
        // Place the image at the canonical boundary — the user-address-space
        // spec already rejects this, so prepare_process_address_space should
        // return None.
        let plan = UserImageLoadPlan {
            entry_point: X86_64_USER_CANONICAL_END,
            image_start: X86_64_USER_CANONICAL_END,
            image_end: X86_64_USER_CANONICAL_END + 0x1000,
            stack_guard_start,
            stack_guard_end,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end,
            exception_stack_bottom,
            exception_stack_top,
            segments: vec![UserImageSegmentPlan {
                virtual_start: X86_64_USER_CANONICAL_END,
                virtual_end: X86_64_USER_CANONICAL_END + 0x1000,
                page_start: X86_64_USER_CANONICAL_END,
                page_end: X86_64_USER_CANONICAL_END + 0x1000,
                file_offset: 0x1000,
                file_size: 0x1000,
                zero_start: X86_64_USER_CANONICAL_END + 0x1000,
                zero_end: X86_64_USER_CANONICAL_END + 0x1000,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };

        assert!(prepare_process_address_space(&kernel_spec, &plan, &[0_u8; 0x2000]).is_none());
    }

    // ── Huge page tests ────────────────────────────────────────────────────

    #[test]
    fn kernel_page_table_spec_detects_huge_pages_for_2mib_aligned_regions() {
        // A text region that starts at a 2 MiB boundary and spans exactly
        // 2 MiB should be backed by a huge page in the PD.
        let plan = KernelPagePlan::from_ranges(
            (HUGE_PAGE_SIZE, 2 * HUGE_PAGE_SIZE), // 2 MiB – 4 MiB
            (0x2100000, 0x2120000),
            (0x2200000, 0x2210000),
            (0x2300000, 0x2310000),
            (0x2400000, 0x2420000),
        )
        .expect("page plan with 2MiB-aligned text");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");

        // The text region at PD index 1 (0x200000) should be detected as huge.
        assert!(
            spec.huge_pd_entries.contains_key(&1),
            "PD index 1 (0x200000–0x400000) should be a 2 MiB huge page"
        );
        assert!(
            !spec.huge_pd_entries.contains_key(&2),
            "PD index 2 (0x400000–0x600000) should not be huge (partial coverage)"
        );

        // Verify translation through the huge page.
        let tx = spec.translate(0x200000).expect("at start of huge page");
        assert_eq!(tx.physical_address, 0x200000);
        assert!(tx.permissions.contains(PagePermissions::READ));
        assert!(tx.permissions.contains(PagePermissions::EXECUTE));

        let tx_mid = spec.translate(0x201234).expect("mid-huge-page");
        assert_eq!(tx_mid.physical_address, 0x201234);
        assert_eq!(tx_mid.permissions, tx.permissions);
    }

    #[test]
    fn kernel_page_table_spec_uses_4k_entries_for_misaligned_regions() {
        // A region that does NOT start at a 2 MiB boundary must use
        // normal 4 KiB pages — no huge page entries.
        let plan = KernelPagePlan::from_ranges(
            (0x201000, 0x20a000),
            (0x210000, 0x212000),
            (0x220000, 0x221000),
            (0x230000, 0x231000),
            (0x240000, 0x242000),
        )
        .expect("misaligned page plan");
        let spec = KernelPageTableSpec::from_plan(&plan).expect("page table spec");

        assert!(
            spec.huge_pd_entries.is_empty(),
            "misaligned regions should not produce huge page entries"
        );
    }
}
