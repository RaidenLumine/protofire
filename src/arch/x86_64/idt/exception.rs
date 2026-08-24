//! src/arch/x86_64/idt/exception.rs
//!
//! Exception handling, diagnostics, and page-fault recovery.

use core::mem::size_of;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::arch::asm;

use crate::abi::exception::{
    X86_64GeneralProtectionError, X86_64InvalidTssError, X86_64PageFaultError as PageFaultError,
    X86_64SegmentNotPresentError, X86_64StackSegmentError, X86_64_EXCEPTION_DEBUG_VECTOR,
    X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR, X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR,
    X86_64_EXCEPTION_INVALID_OPCODE_VECTOR, X86_64_EXCEPTION_INVALID_TSS_VECTOR,
    X86_64_EXCEPTION_PAGE_FAULT_VECTOR, X86_64_EXCEPTION_SEGMENT_NOT_PRESENT_VECTOR,
    X86_64_EXCEPTION_STACK_SEGMENT_VECTOR,
};
use crate::arch::exception_recoverability::{
    recovery_action_log_line, ExceptionRecoveryAction, ExceptionRecoveryActionResult,
    ExceptionRecoveryDecision, RecoveryActionLogRecord,
};
use crate::kernel::process::TerminationReason;
use crate::println;

use super::types::InterruptContext;

/// RFLAGS bit 8: Trap Flag (single-step).
const X86_64_RFLAGS_TF: u64 = 1 << 8;

pub(crate) fn handle_exception(context: &mut InterruptContext, cr2: u64) {
    let fault_address = fault_address_from_interrupt_context(context, cr2);
    let log_prefix = exception_log_prefix(context);
    let vector = context.vector;

    if vector == X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64 {
        // Page faults get richer diagnostics and a narrow in-kernel recovery
        // path. User faults are still routed through user-exception delivery or
        // termination after the logging/recovery pass completes.
        let fault_address = fault_address.unwrap_or_default();
        let page_fault = PageFaultError::from_error_code(context.error_code);
        if let Some(mut memory) = crate::kernel::memory::global_mut() {
            // ── fault profiler: page fault type counters ──
            memory.fault_profiler.inc_faults_total();
            memory.fault_profiler.inc_page_faults_total();
            if context.entered_from_user_mode() {
                memory.fault_profiler.inc_page_faults_user();
            } else {
                memory.fault_profiler.inc_page_faults_kernel();
            }
            if page_fault.present {
                memory.fault_profiler.inc_page_faults_protection_violation();
            } else {
                memory.fault_profiler.inc_page_faults_not_present();
            }

            // ── demand-paging / CoW resolution ──
            // Attempt to resolve before spending cycles on diagnostics.
            // When the faulting page is registered as DemandPaged or Cow in
            // the software PageTable, this transparently allocates or copies.
            if memory.resolve_page_fault(fault_address, page_fault.write) {
                return;
            }

            let insight = memory.page_fault_insight(fault_address);
            let diagnosis = diagnose_page_fault(page_fault, insight);
            let recovery = evaluate_page_fault_recovery_strategy(context, page_fault, insight);
            let prepared_state = insight.prepared_state();
            let prepared_permissions = insight
                .prepared_translation
                .map(|translation| translation.permissions.as_rwx())
                .unwrap_or("---");
            let planned_state = insight.planned_state();
            let planned_permissions = insight
                .planned_region
                .map(|region| region.permissions.as_rwx())
                .unwrap_or("---");
            if let Some(translation) = insight.translation {
                if let Some(bootstrap) = insight.bootstrap_translation {
                    println!(
                        "[{}] {} addr={:#018x} access={} mode={} reason={} sw={} prepared={} prepared_perms={} plan={} plan_perms={} diagnosis={} phys={:#018x} perms={} boot={} boot_phys={:#018x} boot_page={:#x} boot_w={} boot_x={} reserved={} pk={} ss={} sgx={} error={:#018x} rip={:#018x} cs={:#018x} rflags={:#018x}",
                        log_prefix,
                        exception_name(context.vector),
                        fault_address,
                        page_fault.access_kind(),
                        page_fault.privilege_level(),
                        page_fault.reason(),
                        insight.software_state(),
                        prepared_state,
                        prepared_permissions,
                        planned_state,
                        planned_permissions,
                        diagnosis,
                        translation.physical_address,
                        translation.permissions.as_rwx(),
                        insight.bootstrap_state(),
                        bootstrap.physical_address,
                        bootstrap.page_size,
                        bootstrap.writable,
                        bootstrap.executable,
                        page_fault.reserved_bit_violation,
                        page_fault.protection_key,
                        page_fault.shadow_stack,
                        page_fault.software_guard_ext,
                        context.error_code,
                        context.rip,
                        context.cs,
                        context.rflags
                    );
                } else {
                    println!(
                        "[{}] {} addr={:#018x} access={} mode={} reason={} sw={} prepared={} prepared_perms={} plan={} plan_perms={} diagnosis={} phys={:#018x} perms={} boot={} reserved={} pk={} ss={} sgx={} error={:#018x} rip={:#018x} cs={:#018x} rflags={:#018x}",
                        log_prefix,
                        exception_name(context.vector),
                        fault_address,
                        page_fault.access_kind(),
                        page_fault.privilege_level(),
                        page_fault.reason(),
                        insight.software_state(),
                        prepared_state,
                        prepared_permissions,
                        planned_state,
                        planned_permissions,
                        diagnosis,
                        translation.physical_address,
                        translation.permissions.as_rwx(),
                        insight.bootstrap_state(),
                        page_fault.reserved_bit_violation,
                        page_fault.protection_key,
                        page_fault.shadow_stack,
                        page_fault.software_guard_ext,
                        context.error_code,
                        context.rip,
                        context.cs,
                        context.rflags
                    );
                }
            } else {
                if let Some(bootstrap) = insight.bootstrap_translation {
                    println!(
                        "[{}] {} addr={:#018x} access={} mode={} reason={} sw={} prepared={} prepared_perms={} plan={} plan_perms={} diagnosis={} boot={} boot_phys={:#018x} boot_page={:#x} boot_w={} boot_x={} reserved={} pk={} ss={} sgx={} error={:#018x} rip={:#018x} cs={:#018x} rflags={:#018x}",
                        log_prefix,
                        exception_name(context.vector),
                        fault_address,
                        page_fault.access_kind(),
                        page_fault.privilege_level(),
                        page_fault.reason(),
                        insight.software_state(),
                        prepared_state,
                        prepared_permissions,
                        planned_state,
                        planned_permissions,
                        diagnosis,
                        insight.bootstrap_state(),
                        bootstrap.physical_address,
                        bootstrap.page_size,
                        bootstrap.writable,
                        bootstrap.executable,
                        page_fault.reserved_bit_violation,
                        page_fault.protection_key,
                        page_fault.shadow_stack,
                        page_fault.software_guard_ext,
                        context.error_code,
                        context.rip,
                        context.cs,
                        context.rflags
                    );
                } else {
                    println!(
                        "[{}] {} addr={:#018x} access={} mode={} reason={} sw={} prepared={} prepared_perms={} plan={} plan_perms={} diagnosis={} boot={} reserved={} pk={} ss={} sgx={} error={:#018x} rip={:#018x} cs={:#018x} rflags={:#018x}",
                        log_prefix,
                        exception_name(context.vector),
                        fault_address,
                        page_fault.access_kind(),
                        page_fault.privilege_level(),
                        page_fault.reason(),
                        insight.software_state(),
                        prepared_state,
                        prepared_permissions,
                        planned_state,
                        planned_permissions,
                        diagnosis,
                        insight.bootstrap_state(),
                        page_fault.reserved_bit_violation,
                        page_fault.protection_key,
                        page_fault.shadow_stack,
                        page_fault.software_guard_ext,
                        context.error_code,
                        context.rip,
                        context.cs,
                        context.rflags
                    );
                }
            }

            if let Some(action) = recovery.action {
                // A successful kernel-only recovery resumes immediately without
                // falling through to user delivery or fatal termination.
                let action_result =
                    apply_page_fault_recovery_action(&mut memory, fault_address, action);
                if action_result == ExceptionRecoveryActionResult::Applied {
                    println!(
                        "{}",
                        recovery_action_log_line(RecoveryActionLogRecord {
                            level: "RECOV",
                            exception: exception_name(context.vector),
                            action,
                            result: action_result,
                            recoverability: recovery.recoverability,
                            downgraded: None,
                            addr: Some(fault_address),
                            ip: context.rip,
                            error: None,
                        })
                    );
                    return;
                }

                let effective_recoverability =
                    recovery.effective_recoverability_after_action(Some(action_result));

                println!(
                    "{}",
                    recovery_action_log_line(RecoveryActionLogRecord {
                        level: "WARN",
                        exception: exception_name(context.vector),
                        action,
                        result: action_result,
                        recoverability: recovery.recoverability,
                        downgraded: Some(effective_recoverability),
                        addr: Some(fault_address),
                        ip: context.rip,
                        error: None,
                    })
                );
            }
        } else {
            println!(
                "[{}] {} addr={:#018x} access={} mode={} reason={} sw=memory-manager-unavailable diagnosis=memory-manager-unavailable reserved={} pk={} ss={} sgx={} error={:#018x} rip={:#018x} cs={:#018x} rflags={:#018x}",
                log_prefix,
                exception_name(context.vector),
                fault_address,
                page_fault.access_kind(),
                page_fault.privilege_level(),
                page_fault.reason(),
                page_fault.reserved_bit_violation,
                page_fault.protection_key,
                page_fault.shadow_stack,
                page_fault.software_guard_ext,
                context.error_code,
                context.rip,
                context.cs,
                context.rflags
            );
        }
    } else {
        // ── Ptrace single-step (#DB) from user mode ──
        // Intercept before logging so a traced process being single-stepped
        // does not produce a spurious exception log entry. We check TF in
        // RFLAGS to distinguish single-step #DB from other debug exceptions
        // (e.g. hardware breakpoints, which we don't yet support).
        if vector == X86_64_EXCEPTION_DEBUG_VECTOR as u64
            && context.entered_from_user_mode()
            && (context.rflags & X86_64_RFLAGS_TF) != 0
            && handle_ptrace_singlestop(context)
        {
            // Handled — skip logging, exception delivery, and termination.
            return;
        }

        // ── fault profiler: non-PF exception type counters ──
        if let Some(memory) = crate::kernel::memory::global_mut() {
            memory.fault_profiler.inc_faults_total();
            match vector {
                v if v == X86_64_EXCEPTION_INVALID_OPCODE_VECTOR as u64 => {
                    memory.fault_profiler.inc_invalid_opcode_total();
                }
                7 => memory.fault_profiler.inc_device_not_available_total(),
                v if v == X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR as u64 => {
                    memory.fault_profiler.inc_double_faults_total();
                }
                v if v == X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR as u64 => {
                    memory.fault_profiler.inc_general_protection_total();
                }
                _ => memory.fault_profiler.inc_other_exceptions_total(),
            }
        }

        // Structured diagnostic log for non-page-fault exceptions.
        let diagnosis = diagnose_non_page_fault(vector, context.error_code, context.rip);
        println!(
            "[{}] {} vector={} error={:#018x} diagnosis={} rip={:#018x} cs={:#018x} rflags={:#018x}",
            log_prefix,
            exception_name(vector),
            vector,
            context.error_code,
            diagnosis,
            context.rip,
            context.cs,
            context.rflags
        );
    }

    if let Some(reason) = user_exception_termination_reason(context, fault_address) {
        if let Some(thread) = crate::kernel::process::Scheduler::global()
            .and_then(|scheduler| scheduler.current_thread())
        {
            match thread.deliver_x86_64_user_exception(context, fault_address) {
                Ok(true) => {
                    // ── fault profiler: delivered to user handler ──
                    if let Some(memory) = crate::kernel::memory::global_mut() {
                        memory.fault_profiler.inc_faults_delivered_to_handler();
                    }

                    println!(
                        "[user] delivered {} to handler pid={} tid={} rip={:#018x}",
                        exception_name(context.vector),
                        thread.pid(),
                        thread.tid(),
                        context.rip
                    );
                    return;
                }
                Ok(false) => {
                    // ── fault profiler: no user handler ──
                    if let Some(memory) = crate::kernel::memory::global_mut() {
                        memory.fault_profiler.inc_faults_no_handler();
                    }
                }
                Err(error) => {
                    println!(
                        "[user] {} delivery failed pid={} tid={} error={}",
                        exception_name(context.vector),
                        thread.pid(),
                        thread.tid(),
                        error.as_str()
                    );
                }
            }
        }
        log_user_exception_termination(context, fault_address);
        // ── fault profiler: user exception termination ──
        if let Some(memory) = crate::kernel::memory::global_mut() {
            memory.fault_profiler.inc_faults_terminated();
        }
        // Record the fault in the per-process fault ring buffer for
        // post-mortem crash diagnosis.
        record_process_fault_record(context, fault_address);
        crate::kernel::process::terminate_current_with_reason(reason);
    }

    // ── fault profiler: kernel fatal halt ──
    if let Some(memory) = crate::kernel::memory::global_mut() {
        memory.fault_profiler.inc_faults_kernel_fatal();
    }

    crate::arch::x86_64::interrupts::disable();
    loop {
        crate::arch::instructions::hlt();
    }
}

pub(crate) fn exception_log_prefix(context: &InterruptContext) -> &'static str {
    if context.entered_from_user_mode() {
        "user "
    } else {
        "FATAL"
    }
}

pub(crate) fn fault_address_from_interrupt_context(
    context: &InterruptContext,
    cr2: u64,
) -> Option<usize> {
    (context.vector == X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64).then_some(cr2 as usize)
}

pub(crate) fn user_exception_termination_reason(
    context: &InterruptContext,
    fault_address: Option<usize>,
) -> Option<TerminationReason> {
    context
        .entered_from_user_mode()
        .then_some(TerminationReason::exception(
            context.vector as u8,
            context.error_code,
            fault_address,
        ))
}

fn log_user_exception_termination(context: &InterruptContext, fault_address: Option<usize>) {
    let vector = context.vector;
    if let Some(thread) =
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    {
        if vector == X86_64_EXCEPTION_PAGE_FAULT_VECTOR as u64 {
            // Page-fault termination: include decoded PF error info.
            let pf = PageFaultError::from_error_code(context.error_code);
            let (access, mode, reason) = (pf.access_kind(), pf.privilege_level(), pf.reason());
            if let Some(addr) = fault_address {
                println!(
                    "[user] terminating pid={} tid={} after {} vector={} error={:#018x} addr={:#018x} access={} mode={} reason={}",
                    thread.pid(),
                    thread.tid(),
                    exception_name(vector),
                    vector,
                    context.error_code,
                    addr,
                    access,
                    mode,
                    reason,
                );
            } else {
                println!(
                    "[user] terminating pid={} tid={} after {} vector={} error={:#018x} access={} mode={} reason={}",
                    thread.pid(),
                    thread.tid(),
                    exception_name(vector),
                    vector,
                    context.error_code,
                    access,
                    mode,
                    reason,
                );
            }
        } else {
            // Non-page-fault termination: include structured diagnosis.
            let diagnosis = diagnose_non_page_fault(vector, context.error_code, context.rip);
            if let Some(addr) = fault_address {
                println!(
                    "[user] terminating pid={} tid={} after {} vector={} error={:#018x} addr={:#018x} diagnosis={}",
                    thread.pid(),
                    thread.tid(),
                    exception_name(vector),
                    vector,
                    context.error_code,
                    addr,
                    diagnosis,
                );
            } else {
                println!(
                    "[user] terminating pid={} tid={} after {} vector={} error={:#018x} diagnosis={}",
                    thread.pid(),
                    thread.tid(),
                    exception_name(vector),
                    vector,
                    context.error_code,
                    diagnosis,
                );
            }
        }
    }
}

pub(crate) fn diagnose_page_fault(
    page_fault: PageFaultError,
    insight: crate::kernel::memory::PageFaultInsight,
) -> &'static str {
    match (
        page_fault.present,
        insight.in_kernel_heap,
        insight.translation,
        insight.bootstrap_translation,
        insight.prepared_active,
        insight.prepared_translation,
        insight.planned_region,
    ) {
        (false, _, None, Some(_), _, _, Some(region))
            if region.kind == crate::kernel::memory::PlannedKernelRegionKind::KernelHeap =>
        {
            "bootstrap-map-expected-but-not-present"
        }
        (false, _, None, _, false, Some(_), _) => "prepared-kernel-page-table-not-active",
        (false, _, None, _, true, Some(_), _) => "active-kernel-page-table-reported-not-present",
        (false, _, None, Some(_), _, None, Some(_)) => "planned-kernel-region-still-bootstrap-only",
        (false, _, None, Some(_), _, None, None) => "bootstrap-map-expected-but-not-present",
        (false, true, None, None, _, None, Some(region))
            if region.kind == crate::kernel::memory::PlannedKernelRegionKind::KernelHeap =>
        {
            "missing-kernel-heap-mapping"
        }
        (false, _, None, None, _, None, Some(_)) => "planned-kernel-region-missing",
        (false, _, None, None, _, None, None) => "access-to-unmapped-address",
        (false, _, Some(_), _, false, Some(_), _) => "software-mapped-and-prepared-but-not-active",
        (false, _, Some(_), _, true, Some(_), _) => {
            "active-kernel-page-table-and-software-reported-present-but-faulted"
        }
        (false, _, Some(_), _, _, None, _) => "software-mapped-but-hardware-missing",
        (true, _, Some(translation), _, _, _, _) if page_fault.write => {
            if translation
                .permissions
                .contains(crate::kernel::memory::paging::PagePermissions::WRITE)
            {
                "protection-fault-on-writable-page"
            } else {
                "write-to-read-only-page"
            }
        }
        (true, _, Some(translation), _, _, _, _) if page_fault.instruction_fetch => {
            if translation
                .permissions
                .contains(crate::kernel::memory::paging::PagePermissions::EXECUTE)
            {
                "protection-fault-on-executable-page"
            } else {
                "execute-on-non-executable-page"
            }
        }
        (true, _, Some(translation), _, _, _, _) => {
            if translation
                .permissions
                .contains(crate::kernel::memory::paging::PagePermissions::READ)
            {
                "protection-fault-on-readable-page"
            } else {
                "read-from-non-readable-page"
            }
        }
        (true, _, None, _, true, Some(_), _) => "active-kernel-page-table-protection-fault",
        (true, _, None, _, false, Some(_), _) => "prepared-kernel-page-table-protection-fault",
        (true, _, None, Some(_), _, None, _) => {
            "bootstrap-mapped-but-software-untracked-protection-fault"
        }
        (true, _, None, None, _, None, Some(_)) => {
            "planned-kernel-region-protection-fault-without-software-tracking"
        }
        (true, _, None, None, _, None, None) => "protection-fault-on-untracked-address",
    }
}

/// Record a fault in the current process's per-process fault ring buffer.
pub(crate) fn record_process_fault_record(
    context: &InterruptContext,
    fault_address: Option<usize>,
) {
    if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
        if let Some(thread) = scheduler.current_thread() {
            thread.push_fault_record(
                context.vector as u8,
                context.error_code,
                fault_address,
                context.rip,
                context.entered_from_user_mode(),
            );
        }
    }
}

// ── Non-page-fault exception diagnostics ──

/// Produce a compact diagnostic string for exceptions other than page faults.
pub(crate) fn diagnose_non_page_fault(vector: u64, error_code: u64, rip: u64) -> &'static str {
    match vector {
        v if v == X86_64_EXCEPTION_INVALID_OPCODE_VECTOR as u64 => diagnose_invalid_opcode(rip),
        v if v == X86_64_EXCEPTION_DOUBLE_FAULT_VECTOR as u64 => "double-fault",
        v if v == X86_64_EXCEPTION_INVALID_TSS_VECTOR as u64 => {
            X86_64InvalidTssError::from_error_code(error_code).description()
        }
        v if v == X86_64_EXCEPTION_SEGMENT_NOT_PRESENT_VECTOR as u64 => {
            X86_64SegmentNotPresentError::from_error_code(error_code).description()
        }
        v if v == X86_64_EXCEPTION_STACK_SEGMENT_VECTOR as u64 => {
            X86_64StackSegmentError::from_error_code(error_code).description()
        }
        v if v == X86_64_EXCEPTION_GENERAL_PROTECTION_VECTOR as u64 => {
            X86_64GeneralProtectionError::from_error_code(error_code).description()
        }
        _ => "unknown-exception",
    }
}

/// Invalid Opcode (#UD) has no error code; note the instruction pointer.
fn diagnose_invalid_opcode(_rip: u64) -> &'static str {
    "invalid-opcode"
}

// ── Page-fault recovery evaluation ──

pub(crate) fn evaluate_page_fault_recovery_strategy(
    context: &InterruptContext,
    page_fault: PageFaultError,
    insight: crate::kernel::memory::PageFaultInsight,
) -> ExceptionRecoveryDecision {
    // User faults are handled by the thread-level exception delivery path. Only
    // a couple of narrowly scoped kernel-heap faults are recoverable in place.
    if context.entered_from_user_mode() {
        return ExceptionRecoveryDecision::terminate_current();
    }

    if !page_fault.present && insight.translation.is_none() {
        if let Some(region) = insight.planned_region {
            if region.kind == crate::kernel::memory::PlannedKernelRegionKind::KernelHeap {
                return ExceptionRecoveryDecision::recover_now(
                    ExceptionRecoveryAction::MapKernelHeapPage,
                );
            }
        }
    }

    if page_fault.present && page_fault.write {
        if let Some(translation) = insight.translation {
            if translation.kind == crate::kernel::memory::paging::MappingKind::KernelHeap
                && !translation
                    .permissions
                    .contains(crate::kernel::memory::paging::PagePermissions::WRITE)
            {
                return ExceptionRecoveryDecision::recover_now(
                    ExceptionRecoveryAction::UpgradeKernelHeapPageWrite,
                );
            }
        }
    }

    ExceptionRecoveryDecision::fatal()
}

pub(crate) fn apply_page_fault_recovery_action(
    memory: &mut crate::kernel::memory::MemoryManager,
    fault_address: usize,
    action: ExceptionRecoveryAction,
) -> ExceptionRecoveryActionResult {
    match action {
        ExceptionRecoveryAction::MapKernelHeapPage => {
            let page_start = fault_address & !(crate::kernel::memory::paging::PAGE_SIZE - 1);
            if memory
                .map_region_with_kind(
                    page_start,
                    crate::kernel::memory::paging::PAGE_SIZE,
                    crate::kernel::memory::paging::PagePermissions::READ_WRITE,
                    crate::kernel::memory::paging::MappingKind::KernelHeap,
                )
                .is_ok()
            {
                ExceptionRecoveryActionResult::Applied
            } else {
                ExceptionRecoveryActionResult::Error
            }
        }
        ExceptionRecoveryAction::UpgradeKernelHeapPageWrite => {
            let page_start = fault_address & !(crate::kernel::memory::paging::PAGE_SIZE - 1);
            let Some((physical_address, _)) = memory.translate(page_start) else {
                return ExceptionRecoveryActionResult::Declined;
            };

            // Remap the same heap-owned page with wider permissions so the
            // physical backing and mapping-kind bookkeeping stay unchanged.
            if memory
                .unmap(page_start, crate::kernel::memory::paging::PAGE_SIZE)
                .is_err()
            {
                return ExceptionRecoveryActionResult::Error;
            }

            if memory
                .map_to_with_kind(
                    page_start,
                    physical_address,
                    crate::kernel::memory::paging::PAGE_SIZE,
                    crate::kernel::memory::paging::PagePermissions::READ_WRITE,
                    crate::kernel::memory::paging::MappingKind::KernelHeap,
                )
                .is_ok()
            {
                ExceptionRecoveryActionResult::Applied
            } else {
                ExceptionRecoveryActionResult::Error
            }
        }
        ExceptionRecoveryAction::DeliverLowerElSyncUserException => {
            ExceptionRecoveryActionResult::Declined
        }
    }
}

pub(crate) fn exception_name(vector: u64) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "non-maskable interrupt",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range exceeded",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        10 => "invalid TSS",
        11 => "segment not present",
        12 => "stack-segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating-point exception",
        17 => "alignment check",
        18 => "machine check",
        19 => "SIMD floating-point exception",
        20 => "virtualization exception",
        21 => "control protection exception",
        29 => "VMM communication exception",
        30 => "security exception",
        _ => "exception",
    }
}

/// Handle a #DB (vector 1) single-step trap from user mode for ptrace.
///
/// Clears RFLAGS.TF so the tracee does not keep single-stepping, enqueues a
/// `PTRACE_EVENT_SINGLESTEP` event, suspends the current thread, and yields
/// to the scheduler so the tracer can inspect the tracee.
///
/// Returns `true` when the stop was handled (tracee is ptrace-traced). Returns
/// `false` when the process is not being traced — the caller should fall through
/// to normal exception delivery.
fn handle_ptrace_singlestop(context: &mut InterruptContext) -> bool {
    // Clear TF in the iret frame so the tracee executes normally when
    // the tracer later resumes it.
    context.rflags &= !X86_64_RFLAGS_TF;
    let rflags_after = context.rflags;

    let scheduler = match crate::kernel::process::Scheduler::global() {
        Some(s) => s,
        None => return false,
    };
    let thread = match scheduler.current_thread() {
        Some(t) => t,
        None => return false,
    };
    let pid = thread.pid();
    let _ = scheduler;

    // Update the thread's saved context so PTRACE_GETREGS shows RFLAGS without TF.
    if let Some(mut user_ctx) = thread.x86_64_user_context() {
        user_ctx.rflags = rflags_after;
        thread.set_x86_64_user_context(user_ctx);
    }

    // Check if the process has PF_TRACED set (ptrace is active).
    let scheduler = match crate::kernel::process::Scheduler::global() {
        Some(s) => s,
        None => return false,
    };
    let process = match scheduler.process_by_pid(pid) {
        Some(p) => p,
        None => return false,
    };
    let flags = *process.ptrace_options.lock();
    if flags & crate::kernel::process::process::types::ptrace_flags::PF_TRACED == 0 {
        return false;
    }

    // Enqueue a single-step ptrace event.
    process.ptrace_event_queue.lock().push_back(
        crate::kernel::process::process::types::PtraceEvent {
            tid: thread.tid(),
            event: crate::abi::ptrace::PTRACE_EVENT_SINGLESTEP as u32,
            message: 0,
            syscall_number: 0,
        },
    );

    // Suspend the current thread so the tracer can process the event.
    thread.suspend();
    let _ = scheduler;
    crate::kernel::process::yield_current();

    true
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn page_fault_address() -> u64 {
    let address: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
    }
    address
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn page_fault_address() -> u64 {
    0
}

pub(crate) fn sync_user_iret_stack(context: &mut InterruptContext) {
    if !context.entered_from_user_mode() {
        return;
    }

    unsafe {
        // `InterruptContext` stores the saved user rsp/ss in explicit fields,
        // but `iretq` still consumes them from the hardware frame tail.
        let frame = (context as *mut InterruptContext).cast::<u64>();
        let iret_stack_pointer = frame.add(size_of::<InterruptContext>() / size_of::<u64>());
        let iret_stack_segment = iret_stack_pointer.add(1);
        iret_stack_pointer.write(context.saved_stack_pointer);
        iret_stack_segment.write(context.saved_stack_segment);
    }
}
