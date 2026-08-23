//! src/arch/x86_64/idt/mod.rs
//! x86_64 IDT setup, exception dispatch, and page-fault recovery logic.

pub(crate) mod dispatch;
pub(crate) mod exception;
pub(crate) mod types;

// Public API — items that were `pub` in the original single-file module.
pub(crate) use dispatch::init;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) use dispatch::init_ap;
pub use types::{InterruptContext, IPI_RESCHEDULE_VECTOR, IPI_SHOOTDOWN_VECTOR};

// Crate-internal re-exports for exception functions used by tests and dispatch.
#[cfg(test)]
pub(crate) use exception::*;

#[cfg(test)]
mod tests {
    use super::{
        apply_page_fault_recovery_action, diagnose_page_fault,
        evaluate_page_fault_recovery_strategy, exception_log_prefix, exception_name,
        fault_address_from_interrupt_context, sync_user_iret_stack,
        user_exception_termination_reason, InterruptContext,
    };
    use crate::abi::exception::{
        X86_64PageFaultError as PageFaultError, X86_64_EXCEPTION_PAGE_FAULT_VECTOR,
    };
    use crate::arch::exception_recoverability::{
        ExceptionRecoverability, ExceptionRecoveryAction, ExceptionRecoveryActionResult,
    };
    use crate::arch::x86_64::gdt;
    use crate::kernel::memory::paging::{MappingKind, PagePermissions};
    use crate::kernel::memory::MemoryManager;
    use crate::kernel::memory::{
        AddressTranslation, BootstrapTranslation, PageFaultInsight, PlannedKernelRegion,
        PlannedKernelRegionKind, PreparedTranslation,
    };
    use crate::kernel::process::{ExceptionTermination, TerminationReason};

    #[repr(C)]
    struct UserModeInterruptFrame {
        context: InterruptContext,
        iret_stack_pointer: u64,
        iret_stack_segment: u64,
    }

    fn test_page_fault_context(code_selector: u64) -> InterruptContext {
        InterruptContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            saved_stack_pointer: 0,
            saved_stack_segment: if code_selector & 3 == 3 {
                gdt::user_data_selector() as u64
            } else {
                0
            },
            vector: X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64,
            error_code: 0,
            rip: 0xffff_8000_0000_2000,
            cs: code_selector,
            rflags: 0x202,
        }
    }

    #[test]
    fn page_fault_error_decodes_relevant_bits() {
        let error = PageFaultError::from_error_code((1 << 0) | (1 << 1) | (1 << 4) | (1 << 15));

        assert!(error.present);
        assert!(error.write);
        assert!(!error.user);
        assert!(error.instruction_fetch);
        assert!(error.software_guard_ext);
        assert_eq!(error.access_kind(), "instruction-fetch");
        assert_eq!(error.privilege_level(), "kernel");
        assert_eq!(error.reason(), "protection-violation");
    }

    #[test]
    fn exception_name_labels_page_fault() {
        assert_eq!(exception_name(14), "page fault");
        assert_eq!(exception_name(13), "general protection fault");
        assert_eq!(exception_name(255), "exception");
    }

    #[test]
    fn fault_address_helper_returns_none_for_non_page_fault_vectors() {
        let context = InterruptContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            saved_stack_pointer: 0,
            saved_stack_segment: 0,
            vector: 13,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
        };

        assert_eq!(fault_address_from_interrupt_context(&context, 0), None);
    }

    #[test]
    fn fault_address_helper_returns_some_for_page_fault_vector() {
        let context = InterruptContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            saved_stack_pointer: 0,
            saved_stack_segment: 0,
            vector: 14,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
        };

        assert!(fault_address_from_interrupt_context(&context, 0).is_some());
    }

    #[test]
    fn user_exception_reason_is_built_from_ring3_context() {
        let context = InterruptContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            saved_stack_pointer: 0,
            saved_stack_segment: gdt::user_data_selector() as u64,
            vector: 14,
            error_code: 0x6,
            rip: 0x401000,
            cs: gdt::user_code_selector() as u64,
            rflags: 0x202,
        };

        assert_eq!(exception_log_prefix(&context), "user ");
        assert_eq!(
            user_exception_termination_reason(&context, Some(0x7fff_ffff_d000)),
            Some(TerminationReason::Exception(ExceptionTermination {
                vector: 14,
                error_code: 0x6,
                fault_address: Some(0x7fff_ffff_d000),
            }))
        );
    }

    #[test]
    fn kernel_exception_does_not_build_user_termination_reason() {
        let context = InterruptContext {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            saved_stack_pointer: 0,
            saved_stack_segment: 0,
            vector: 13,
            error_code: 0,
            rip: 0xffff_8000_0000_1000,
            cs: gdt::kernel_code_selector() as u64,
            rflags: 0x202,
        };

        assert_eq!(exception_log_prefix(&context), "FATAL");
        assert_eq!(user_exception_termination_reason(&context, None), None);
    }

    #[test]
    fn syncing_user_iret_stack_updates_hardware_return_slots() {
        let mut frame = UserModeInterruptFrame {
            context: InterruptContext {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                saved_stack_pointer: 0x7fff_ffff_e000,
                saved_stack_segment: gdt::user_data_selector() as u64,
                vector: 14,
                error_code: 0,
                rip: 0x401000,
                cs: gdt::user_code_selector() as u64,
                rflags: 0x202,
            },
            iret_stack_pointer: 0,
            iret_stack_segment: 0,
        };

        sync_user_iret_stack(&mut frame.context);

        assert_eq!(frame.iret_stack_pointer, frame.context.saved_stack_pointer);
        assert_eq!(frame.iret_stack_segment, frame.context.saved_stack_segment);
    }

    #[test]
    fn page_fault_insight_matches_software_mappings() {
        let mut memory = MemoryManager::new();
        memory.init();
        let (heap_start, heap_end) = memory.heap_bounds();

        let mapped = memory.page_fault_insight(heap_start);
        assert!(mapped.in_kernel_heap);
        assert_eq!(
            mapped.translation,
            Some(crate::kernel::memory::AddressTranslation {
                physical_address: heap_start,
                permissions: PagePermissions::READ_WRITE,
                kind: MappingKind::KernelHeap,
            })
        );
        assert_eq!(mapped.software_state(), "kernel-heap");
        assert_eq!(mapped.bootstrap_translation, None);
        assert_eq!(mapped.bootstrap_state(), "bootstrap-unmapped");
        assert!(!mapped.prepared_active);
        assert_eq!(mapped.prepared_translation, None);
        assert_eq!(mapped.prepared_state(), "prepared-unmapped");
        assert_eq!(
            mapped.planned_region,
            Some(PlannedKernelRegion {
                permissions: PagePermissions::READ_WRITE,
                kind: PlannedKernelRegionKind::KernelHeap,
            })
        );
        assert_eq!(mapped.planned_state(), "kernel-heap");

        let unmapped = memory.page_fault_insight(heap_end + 4096);
        assert!(!unmapped.in_kernel_heap);
        assert_eq!(unmapped.translation, None);
        assert_eq!(unmapped.software_state(), "unmapped");
        assert!(!unmapped.prepared_active);
        assert_eq!(unmapped.prepared_translation, None);
        assert_eq!(unmapped.prepared_state(), "prepared-unmapped");
        assert_eq!(unmapped.planned_region, None);
        assert_eq!(unmapped.planned_state(), "outside-kernel-plan");
    }

    #[test]
    fn page_fault_insight_reports_bootstrap_identity_mapping() {
        let mut memory = MemoryManager::new();
        memory.init();

        let bootstrap = crate::arch::mmu::bootstrap_identity_mapping();
        let insight = memory.page_fault_insight(bootstrap.virtual_start);

        assert!(!insight.in_kernel_heap);
        assert_eq!(insight.translation, None);
        assert_eq!(insight.software_state(), "unmapped");
        assert_eq!(
            insight.bootstrap_translation,
            Some(BootstrapTranslation {
                physical_address: bootstrap.physical_start,
                page_size: bootstrap.page_size,
                writable: bootstrap.writable,
                executable: bootstrap.executable,
            })
        );
        assert_eq!(insight.bootstrap_state(), "bootstrap-identity-map");
        assert!(!insight.prepared_active);
        assert_eq!(insight.prepared_translation, None);
        assert_eq!(insight.prepared_state(), "prepared-unmapped");
        assert_eq!(insight.planned_region, None);
        assert_eq!(insight.planned_state(), "outside-kernel-plan");
    }

    #[test]
    fn page_fault_diagnosis_distinguishes_missing_and_protection_cases() {
        let missing = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: true,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_WRITE,
                    kind: PlannedKernelRegionKind::KernelHeap,
                }),
            },
        );
        assert_eq!(missing, "missing-kernel-heap-mapping");

        let bootstrap_only = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: Some(BootstrapTranslation {
                    physical_address: 0x2000,
                    page_size: 0x20_0000,
                    writable: true,
                    executable: true,
                }),
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(bootstrap_only, "bootstrap-map-expected-but-not-present");

        let prepared_only = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: Some(PreparedTranslation {
                    physical_address: 0x2800,
                    permissions: PagePermissions::READ_EXECUTE,
                }),
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(prepared_only, "prepared-kernel-page-table-not-active");

        let active_prepared_only = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: true,
                prepared_translation: Some(PreparedTranslation {
                    physical_address: 0x2800,
                    permissions: PagePermissions::READ_EXECUTE,
                }),
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(
            active_prepared_only,
            "active-kernel-page-table-reported-not-present"
        );

        let planned_bootstrap_only = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: Some(BootstrapTranslation {
                    physical_address: 0x3000,
                    page_size: 0x20_0000,
                    writable: true,
                    executable: true,
                }),
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(
            planned_bootstrap_only,
            "planned-kernel-region-still-bootstrap-only"
        );

        let planned_missing = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(planned_missing, "planned-kernel-region-missing");

        let mismatch = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: Some(AddressTranslation {
                    physical_address: 0x4000,
                    permissions: PagePermissions::READ,
                    kind: MappingKind::Anonymous,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(mismatch, "software-mapped-but-hardware-missing");

        let prepared_mismatch = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: Some(AddressTranslation {
                    physical_address: 0x4800,
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: MappingKind::Anonymous,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: Some(PreparedTranslation {
                    physical_address: 0x4800,
                    permissions: PagePermissions::READ_EXECUTE,
                }),
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(
            prepared_mismatch,
            "software-mapped-and-prepared-but-not-active"
        );

        let active_prepared_mismatch = diagnose_page_fault(
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: Some(AddressTranslation {
                    physical_address: 0x4800,
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: MappingKind::Anonymous,
                }),
                bootstrap_translation: None,
                prepared_active: true,
                prepared_translation: Some(PreparedTranslation {
                    physical_address: 0x4800,
                    permissions: PagePermissions::READ_EXECUTE,
                }),
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(
            active_prepared_mismatch,
            "active-kernel-page-table-and-software-reported-present-but-faulted"
        );

        let protection = diagnose_page_fault(
            PageFaultError::from_error_code((1 << 0) | (1 << 1)),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: Some(AddressTranslation {
                    physical_address: 0x5000,
                    permissions: PagePermissions::READ,
                    kind: MappingKind::Anonymous,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(protection, "write-to-read-only-page");

        let execute = diagnose_page_fault(
            PageFaultError::from_error_code((1 << 0) | (1 << 4)),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: Some(AddressTranslation {
                    physical_address: 0x6000,
                    permissions: PagePermissions::READ,
                    kind: MappingKind::Anonymous,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(execute, "execute-on-non-executable-page");

        let active_protection = diagnose_page_fault(
            PageFaultError::from_error_code(1 << 0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: true,
                prepared_translation: Some(PreparedTranslation {
                    physical_address: 0x7000,
                    permissions: PagePermissions::READ_EXECUTE,
                }),
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_EXECUTE,
                    kind: PlannedKernelRegionKind::KernelText,
                }),
            },
        );
        assert_eq!(
            active_protection,
            "active-kernel-page-table-protection-fault"
        );
    }

    #[test]
    fn page_fault_recovery_plan_only_targets_kernel_heap_missing_pages() {
        let kernel_context = test_page_fault_context(gdt::kernel_code_selector() as u64);
        let planned_heap_missing = PageFaultInsight {
            in_kernel_heap: true,
            translation: None,
            bootstrap_translation: None,
            prepared_active: false,
            prepared_translation: None,
            planned_region: Some(PlannedKernelRegion {
                permissions: PagePermissions::READ_WRITE,
                kind: PlannedKernelRegionKind::KernelHeap,
            }),
        };

        let decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code(0),
            planned_heap_missing,
        );
        assert_eq!(decision.recoverability, ExceptionRecoverability::RecoverNow);
        assert_eq!(
            decision.action,
            Some(ExceptionRecoveryAction::MapKernelHeapPage)
        );

        let user_context = test_page_fault_context(gdt::user_code_selector() as u64);
        let user_decision = evaluate_page_fault_recovery_strategy(
            &user_context,
            PageFaultError::from_error_code(0),
            planned_heap_missing,
        );
        assert_eq!(
            user_decision.recoverability,
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(user_decision.action, None);

        let fatal_decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code(1 << 0),
            planned_heap_missing,
        );
        assert_eq!(
            fatal_decision.recoverability,
            ExceptionRecoverability::Fatal
        );
        assert_eq!(fatal_decision.action, None);
    }

    #[test]
    fn apply_page_fault_recovery_plan_maps_missing_kernel_heap_page() {
        let mut memory = MemoryManager::new();
        memory.init();

        let (heap_start, _) = memory.heap_bounds();
        memory
            .unmap(heap_start, crate::kernel::memory::paging::PAGE_SIZE)
            .expect("unmap one heap page");

        let missing = memory.page_fault_insight(heap_start);
        assert_eq!(missing.translation, None);

        let recovered = apply_page_fault_recovery_action(
            &mut memory,
            heap_start,
            ExceptionRecoveryAction::MapKernelHeapPage,
        );
        assert_eq!(recovered, ExceptionRecoveryActionResult::Applied);

        let repaired = memory.page_fault_insight(heap_start);
        assert_eq!(
            repaired.translation,
            Some(AddressTranslation {
                physical_address: heap_start,
                permissions: PagePermissions::READ_WRITE,
                kind: MappingKind::KernelHeap,
            })
        );
    }

    #[test]
    fn page_fault_recoverability_distinguishes_recoverable_user_and_kernel_fatal_paths() {
        let kernel_context = test_page_fault_context(gdt::kernel_code_selector() as u64);
        let recover_decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: true,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_WRITE,
                    kind: PlannedKernelRegionKind::KernelHeap,
                }),
            },
        );
        assert_eq!(
            recover_decision.recoverability,
            ExceptionRecoverability::RecoverNow
        );
        assert_eq!(
            recover_decision.action,
            Some(ExceptionRecoveryAction::MapKernelHeapPage)
        );

        let fatal_decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code(1 << 0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(
            fatal_decision.recoverability,
            ExceptionRecoverability::Fatal
        );
        assert_eq!(fatal_decision.action, None);

        let user_context = test_page_fault_context(gdt::user_code_selector() as u64);
        let user_decision = evaluate_page_fault_recovery_strategy(
            &user_context,
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: false,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: None,
            },
        );
        assert_eq!(
            user_decision.recoverability,
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(user_decision.action, None);
    }

    #[test]
    fn page_fault_recovery_strategy_selects_write_upgrade_action_for_kernel_heap() {
        let kernel_context = test_page_fault_context(gdt::kernel_code_selector() as u64);
        let decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code((1 << 0) | (1 << 1)),
            PageFaultInsight {
                in_kernel_heap: true,
                translation: Some(AddressTranslation {
                    physical_address: 0x1234_5000,
                    permissions: PagePermissions::READ,
                    kind: MappingKind::KernelHeap,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ,
                    kind: PlannedKernelRegionKind::KernelHeap,
                }),
            },
        );

        assert_eq!(decision.recoverability, ExceptionRecoverability::RecoverNow);
        assert_eq!(
            decision.action,
            Some(ExceptionRecoveryAction::UpgradeKernelHeapPageWrite)
        );
    }

    #[test]
    fn page_fault_recovery_strategy_never_upgrades_kernel_heap_for_user_faults() {
        let user_context = test_page_fault_context(gdt::user_code_selector() as u64);

        let decision = evaluate_page_fault_recovery_strategy(
            &user_context,
            PageFaultError::from_error_code((1 << 0) | (1 << 1) | (1 << 2)),
            PageFaultInsight {
                in_kernel_heap: true,
                translation: Some(AddressTranslation {
                    physical_address: 0x1234_5000,
                    permissions: PagePermissions::READ,
                    kind: MappingKind::KernelHeap,
                }),
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ,
                    kind: PlannedKernelRegionKind::KernelHeap,
                }),
            },
        );

        assert_eq!(
            decision.recoverability,
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(decision.action, None);
    }

    #[test]
    fn apply_page_fault_recovery_action_upgrades_kernel_heap_page_to_read_write() {
        let mut memory = MemoryManager::new();
        memory.init();

        let (heap_start, _) = memory.heap_bounds();
        memory
            .unmap(heap_start, crate::kernel::memory::paging::PAGE_SIZE)
            .expect("unmap one heap page for write upgrade");
        memory
            .map_region_with_kind(
                heap_start,
                crate::kernel::memory::paging::PAGE_SIZE,
                PagePermissions::READ,
                MappingKind::KernelHeap,
            )
            .expect("remap heap page as read-only");

        let upgraded = apply_page_fault_recovery_action(
            &mut memory,
            heap_start + 128,
            ExceptionRecoveryAction::UpgradeKernelHeapPageWrite,
        );
        assert_eq!(upgraded, ExceptionRecoveryActionResult::Applied);

        let repaired = memory.page_fault_insight(heap_start);
        assert_eq!(
            repaired.translation,
            Some(AddressTranslation {
                physical_address: heap_start,
                permissions: PagePermissions::READ_WRITE,
                kind: MappingKind::KernelHeap,
            })
        );
    }

    #[test]
    fn page_fault_recovery_effective_recoverability_downgrades_when_action_declines_or_errors() {
        let kernel_context = test_page_fault_context(gdt::kernel_code_selector() as u64);
        let decision = evaluate_page_fault_recovery_strategy(
            &kernel_context,
            PageFaultError::from_error_code(0),
            PageFaultInsight {
                in_kernel_heap: true,
                translation: None,
                bootstrap_translation: None,
                prepared_active: false,
                prepared_translation: None,
                planned_region: Some(PlannedKernelRegion {
                    permissions: PagePermissions::READ_WRITE,
                    kind: PlannedKernelRegionKind::KernelHeap,
                }),
            },
        );

        assert_eq!(decision.recoverability, ExceptionRecoverability::RecoverNow);
        assert_eq!(
            decision.action,
            Some(ExceptionRecoveryAction::MapKernelHeapPage)
        );
        assert_eq!(
            decision.effective_recoverability_after_action(Some(
                ExceptionRecoveryActionResult::Declined,
            )),
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(
            decision
                .effective_recoverability_after_action(Some(ExceptionRecoveryActionResult::Error)),
            ExceptionRecoverability::TerminateCurrent
        );
    }

    #[test]
    fn apply_page_fault_recovery_action_declines_when_upgrade_target_is_missing() {
        let mut memory = MemoryManager::new();
        memory.init();

        let (_, heap_end) = memory.heap_bounds();
        let result = apply_page_fault_recovery_action(
            &mut memory,
            heap_end + crate::kernel::memory::paging::PAGE_SIZE,
            ExceptionRecoveryAction::UpgradeKernelHeapPageWrite,
        );

        assert_eq!(result, ExceptionRecoveryActionResult::Declined);
    }

    #[test]
    fn apply_page_fault_recovery_action_returns_error_for_invalid_mapping_request() {
        let mut memory = MemoryManager::new();
        memory.init();

        let (heap_start, _) = memory.heap_bounds();

        let result = apply_page_fault_recovery_action(
            &mut memory,
            heap_start,
            ExceptionRecoveryAction::MapKernelHeapPage,
        );

        assert_eq!(result, ExceptionRecoveryActionResult::Error);
    }
}
