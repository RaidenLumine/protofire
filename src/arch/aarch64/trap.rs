//! src/arch/aarch64/trap.rs
//!
//! AArch64 trap decoding, IRQ routing, and exception logging helpers.

use core::arch::asm;
use core::mem::size_of;
use core::ptr::read_volatile;
use core::sync::atomic::{AtomicBool, Ordering};

use super::exception;
use crate::abi::syscall as syscall_abi;
use crate::arch::exception_recoverability::{
    recovery_action_log_line, ExceptionRecoverability, ExceptionRecoveryAction,
    ExceptionRecoveryActionResult, RecoveryActionLogRecord,
};
use crate::arch::syscall_trap;
use crate::kernel::process::{thread::AArch64UserThreadContext, TerminationReason};
use crate::kernel::syscall::table::user_memory;
use crate::kernel::syscall::{self, SyscallAction, SyscallContext};
use crate::println;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

const SPSR_MODE_MASK: u64 = 0b1111;
const SPSR_MODE_EL0T: u64 = 0b0000;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub stack_pointer: u64,
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
    pub vector: u64,
    _reserved: u64,
}

const _: [(); 304] = [(); size_of::<TrapFrame>()];

unsafe extern "C" {
    static __aarch64_exception_vectors: u8;
}

pub fn init() {
    if INITIALIZED.swap(true, Ordering::Acquire) {
        return;
    }

    unsafe {
        let vector_base = &raw const __aarch64_exception_vectors;
        asm!(
            "msr VBAR_EL1, {vector_base}",
            "isb",
            vector_base = in(reg) vector_base,
            options(nostack, preserves_flags)
        );
    }
}

pub fn entered_from_user_mode(frame: &TrapFrame) -> bool {
    frame.spsr & SPSR_MODE_MASK == SPSR_MODE_EL0T
}

pub fn instruction_pointer(frame: &TrapFrame) -> usize {
    frame.elr as usize
}

pub fn vector(frame: &TrapFrame) -> u8 {
    frame.vector as u8
}

pub fn exception_class(frame: &TrapFrame) -> u8 {
    ((frame.esr >> 26) & 0x3f) as u8
}

pub fn exception_iss(frame: &TrapFrame) -> u32 {
    (frame.esr & 0x01ff_ffff) as u32
}

#[no_mangle]
extern "C" fn aarch64_trap_dispatch(frame: &mut TrapFrame) {
    let entered_from_user = entered_from_user_mode(frame);
    validate_user_entry_frame_or_terminate(frame, entered_from_user);
    capture_current_user_context(frame);

    // ── NMI-class exceptions (SError / FIQ) ───────────────────────────
    // SError (the architectural NMI) and FIQ (used as a higher-priority
    // interrupt on some systems) are not masked by the normal IRQ mask.
    // They run on a dedicated minimal path: count, run registered NMI
    // handlers, log if unhandled — no softirqs or async signal delivery.
    if exception::is_nmi_vector(vector(frame)) {
        handle_nmi_frame(frame);
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    if exception::is_irq_vector(vector(frame)) {
        handle_irq(frame);
        // Process softirqs and deliver pending async signals before returning
        // to user mode, matching the x86_64 interrupt_dispatch ordering.
        crate::kernel::softirq::process_softirqs();
        if entered_from_user {
            try_async_signal_delivery_aarch64(frame);
        }
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    if vector(frame) == exception::VECTOR_LOWER_EL_AARCH64_SYNC && handle_lower_el_sync(frame) {
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    // CURRENT_EL sync exceptions (kernel-mode faults): attempt kernel heap
    // recovery before declaring a fatal error.
    if exception::is_current_el_sync_vector(vector(frame)) && handle_current_el_sync(frame) {
        validate_user_return_frame_or_terminate(frame, entered_from_user);
        return;
    }

    // ── fault profiler: unhandled trap fatal ──
    if let Some(memory) = crate::kernel::memory::global_mut() {
        memory.fault_profiler.inc_faults_kernel_fatal();
    }

    super::interrupts::disable();

    println!(
        "[FATAL] aarch64 trap vector={} ({}) ec={:#04x} iss={:#010x} far={:#018x} elr={:#018x} spsr={:#018x} sp={:#018x}",
        vector(frame),
        exception::vector_name(vector(frame)),
        exception_class(frame),
        exception_iss(frame),
        frame.far,
        frame.elr,
        frame.spsr,
        frame.stack_pointer
    );

    loop {
        crate::arch::instructions::hlt();
    }
}

fn validate_user_entry_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool) {
    validate_user_frame_or_terminate(frame, entered_from_user, "entry");
}

fn validate_user_return_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool) {
    validate_user_frame_or_terminate(frame, entered_from_user, "return");
}

fn validate_user_frame_or_terminate(frame: &TrapFrame, entered_from_user: bool, phase: &str) {
    let frame_valid =
        !entered_from_user || AArch64UserThreadContext::validated_from_trap(frame).is_ok();
    let current_thread = if entered_from_user && !frame_valid {
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    } else {
        None
    };

    match exception::aarch64_user_frame_validation_action(
        entered_from_user,
        frame_valid,
        current_thread.is_some(),
    ) {
        exception::UserFrameValidationAction::Continue => return,
        exception::UserFrameValidationAction::TerminateCurrentThread => {
            // ── fault profiler: invalid frame termination ──
            if let Some(memory) = crate::kernel::memory::global_mut() {
                memory.fault_profiler.inc_faults_terminated();
            }
            let thread = current_thread.expect("validation action requires current thread");
            // Record the fault for post-mortem diagnosis.
            push_fault_record_from_trap(frame);
            println!(
                "[user] refusing invalid aarch64 {} frame pid={} tid={} elr={:#018x} spsr={:#018x} sp={:#018x}",
                phase,
                thread.pid(),
                thread.tid(),
                frame.elr,
                frame.spsr,
                frame.stack_pointer
            );
            crate::kernel::process::terminate_current_with_reason(TerminationReason::exception(
                exception::EXCEPTION_CLASS_ILLEGAL_EXECUTION_STATE,
                0,
                None,
            ));
        }
        exception::UserFrameValidationAction::FatalWithoutCurrentThread => {}
    }

    // ── fault profiler: kernel fatal ──
    if let Some(memory) = crate::kernel::memory::global_mut() {
        memory.fault_profiler.inc_faults_kernel_fatal();
    }

    println!(
        "[FATAL] invalid aarch64 {} frame without current thread elr={:#018x} spsr={:#018x} sp={:#018x}",
        phase,
        frame.elr,
        frame.spsr,
        frame.stack_pointer
    );
    super::interrupts::disable();
    loop {
        crate::arch::instructions::hlt();
    }
}

fn capture_current_user_context(frame: &TrapFrame) {
    if !entered_from_user_mode(frame) {
        return;
    }

    if let Some(thread) =
        crate::kernel::process::Scheduler::global().and_then(|scheduler| scheduler.current_thread())
    {
        thread.capture_aarch64_user_context_from_trap(frame);
    }
}

fn handle_lower_el_sync(frame: &mut TrapFrame) -> bool {
    let class = exception_class(frame);
    let recovery = exception::lower_el_sync_recovery_decision(
        vector(frame),
        entered_from_user_mode(frame),
        class,
    );
    let fault_address = lower_el_sync_fault_address(frame);

    // ── fault profiler: lower-EL sync exception counters ──
    if class != exception::EXCEPTION_CLASS_SVC64 {
        if let Some(memory) = crate::kernel::memory::global_mut() {
            memory.fault_profiler.inc_faults_total();
            if exception::is_lower_el_sync_abort_class(class) {
                memory.fault_profiler.inc_page_faults_total();
                memory.fault_profiler.inc_page_faults_user();
                // Classify abort using ISS fault status code.
                // 0x04-0x07: translation fault → not-present
                // 0x0c-0x0f: permission fault → protection violation
                let fc = (exception_iss(frame) & 0x3f) as u8;
                match fc {
                    0x04..=0x07 => {
                        memory.fault_profiler.inc_page_faults_not_present();
                    }
                    0x0c..=0x0f => {
                        memory.fault_profiler.inc_page_faults_protection_violation();
                    }
                    _ => {}
                }
            }
        }
    }

    // ── demand-paging / CoW resolution for user-mode page faults ──
    // Attempt MemoryManager::resolve_page_fault before falling through
    // to user-exception delivery.  When the faulting page is registered
    // as DemandPaged or Cow in the software PageTable, this call handles
    // the allocation or copy-on-write transparently.
    if exception::is_lower_el_sync_abort_class(class) {
        if let Some(addr) = fault_address {
            let iss = exception_iss(frame);
            let is_write = (iss >> 6) & 1 == 1; // WnR bit in ISS
            if let Some(mut memory) = crate::kernel::memory::global_mut() {
                if memory.resolve_page_fault(addr, is_write) {
                    return true;
                }
            }
        }
    }

    match class {
        exception::EXCEPTION_CLASS_SVC64 => {
            handle_syscall(frame);
            true
        }
        _ => {
            if recovery.recoverability == ExceptionRecoverability::Fatal {
                println!(
                    "[WARN] aarch64 lower-el sync fatal ec={:#04x} recoverability={} addr={:?} elr={:#018x}",
                    class,
                    recovery.recoverability.as_str(),
                    fault_address,
                    frame.elr
                );
                // ── fault profiler: kernel fatal ──
                if let Some(memory) = crate::kernel::memory::global_mut() {
                    memory.fault_profiler.inc_faults_kernel_fatal();
                }
                return false;
            }

            let mut action_result = None;

            if let Some(action) = recovery.action {
                match apply_lower_el_sync_recovery_action(frame, action) {
                    Ok(action_result)
                        if action_result == ExceptionRecoveryActionResult::Applied =>
                    {
                        println!(
                            "{}",
                            recovery_action_log_line(RecoveryActionLogRecord {
                                level: "RECOV",
                                exception: exception::exception_name(class),
                                action,
                                result: action_result,
                                recoverability: recovery.recoverability,
                                downgraded: None,
                                addr: fault_address,
                                ip: frame.elr,
                                error: None,
                            })
                        );
                        return true;
                    }
                    Ok(result_action) => {
                        action_result = Some(result_action);
                        println!(
                            "{}",
                            recovery_action_log_line(RecoveryActionLogRecord {
                                level: "WARN",
                                exception: exception::exception_name(class),
                                action,
                                result: result_action,
                                recoverability: recovery.recoverability,
                                downgraded: Some(
                                    recovery.effective_recoverability_after_action(Some(
                                        result_action,
                                    )),
                                ),
                                addr: fault_address,
                                ip: frame.elr,
                                error: None,
                            })
                        );
                    }
                    Err(error) => {
                        action_result = Some(ExceptionRecoveryActionResult::Error);
                        println!(
                            "{}",
                            recovery_action_log_line(RecoveryActionLogRecord {
                                level: "WARN",
                                exception: exception::exception_name(class),
                                action,
                                result: ExceptionRecoveryActionResult::Error,
                                recoverability: recovery.recoverability,
                                downgraded: Some(recovery.effective_recoverability_after_action(
                                    Some(ExceptionRecoveryActionResult::Error,)
                                ),),
                                addr: fault_address,
                                ip: frame.elr,
                                error: Some(error.as_str()),
                            })
                        );
                    }
                }
            }

            let effective_recoverability =
                recovery.effective_recoverability_after_action(action_result);

            if matches!(
                effective_recoverability,
                ExceptionRecoverability::TerminateCurrent | ExceptionRecoverability::RecoverNow
            ) {
                if let Some(reason) = lower_el_sync_termination_reason(frame) {
                    log_user_exception_termination(frame);
                    // ── fault profiler: user exception termination ──
                    if let Some(memory) = crate::kernel::memory::global_mut() {
                        memory.fault_profiler.inc_faults_terminated();
                    }
                    crate::kernel::process::terminate_current_with_reason(reason);
                }
            }

            false
        }
    }
}

/// Handle a CURRENT_EL (kernel-mode) sync exception.
///
/// On AArch64, kernel-mode page faults arrive via `VECTOR_CURRENT_EL_SP0_SYNC`
/// or `VECTOR_CURRENT_EL_SPX_SYNC`.  This handler attempts to recover from
/// kernel heap faults (non-present → map; read-only → upgrade write) using
/// the same `MemoryManager` paths that x86_64 uses.
///
/// Returns `true` when the fault was recovered; `false` means the caller
/// should treat the trap as fatal.
fn handle_current_el_sync(frame: &mut TrapFrame) -> bool {
    use crate::arch::exception_recoverability::ExceptionRecoveryAction;
    use crate::kernel::memory::{global_mut, paging::PagePermissions};

    let class = exception_class(frame);

    // Only recover data aborts (translation or permission faults).
    if !exception::is_data_abort_class(class) {
        return false;
    }

    let Some(fault_address) = current_el_fault_address(frame) else {
        return false;
    };

    let Some(mut memory) = global_mut() else {
        return false;
    };
    let (heap_start, heap_end) = memory.heap_bounds();

    // Only recover faults within the kernel heap.
    if fault_address < heap_start || fault_address >= heap_end {
        return false;
    }

    let iss = exception_iss(frame);
    let fc = (iss & 0x3f) as u8; // fault status code
    let not_present = matches!(fc, 0x04..=0x07); // translation fault
    let permission_fault = matches!(fc, 0x0c..=0x0f); // permission fault
    let write = (iss >> 6) & 1 == 1; // WnR bit

    let action = if not_present {
        Some(ExceptionRecoveryAction::MapKernelHeapPage)
    } else if permission_fault && write {
        Some(ExceptionRecoveryAction::UpgradeKernelHeapPageWrite)
    } else {
        None
    };

    let Some(action) = action else {
        return false;
    };

    let page_start = fault_address & !(crate::kernel::memory::paging::PAGE_SIZE - 1);

    match action {
        ExceptionRecoveryAction::MapKernelHeapPage => {
            if memory
                .map_region_with_kind(
                    page_start,
                    crate::kernel::memory::paging::PAGE_SIZE,
                    PagePermissions::READ_WRITE,
                    crate::kernel::memory::paging::MappingKind::KernelHeap,
                )
                .is_ok()
            {
                crate::println!(
                    "[RECOV] aarch64 kernel heap page mapped addr={:#018x}",
                    page_start
                );
                return true;
            }
        }
        ExceptionRecoveryAction::UpgradeKernelHeapPageWrite => {
            if let Some((phys, _)) = memory.translate(page_start) {
                // Unmap the read-only entry and re-map with RW.
                let _ = memory.unmap(page_start, crate::kernel::memory::paging::PAGE_SIZE);
                if memory
                    .map_to_with_kind(
                        page_start,
                        phys,
                        crate::kernel::memory::paging::PAGE_SIZE,
                        PagePermissions::READ_WRITE,
                        crate::kernel::memory::paging::MappingKind::KernelHeap,
                    )
                    .is_ok()
                {
                    crate::println!(
                        "[RECOV] aarch64 kernel heap page upgraded to RW addr={:#018x}",
                        page_start
                    );
                    return true;
                }
            }
        }
        _ => {}
    }

    memory.fault_profiler.inc_faults_kernel_fatal();
    false
}

fn apply_lower_el_sync_recovery_action(
    frame: &mut TrapFrame,
    action: ExceptionRecoveryAction,
) -> crate::Result<ExceptionRecoveryActionResult> {
    match action {
        ExceptionRecoveryAction::DeliverLowerElSyncUserException => {
            deliver_lower_el_sync_user_exception(frame)
        }
        ExceptionRecoveryAction::MapKernelHeapPage
        | ExceptionRecoveryAction::UpgradeKernelHeapPageWrite => {
            // Kernel heap recovery actions are applied in the CURRENT_EL
            // handler; they should never reach the lower-EL path.
            Ok(ExceptionRecoveryActionResult::Declined)
        }
    }
}

fn deliver_lower_el_sync_user_exception(
    frame: &mut TrapFrame,
) -> crate::Result<ExceptionRecoveryActionResult> {
    let exception_class = exception_class(frame);
    if !exception::should_deliver_lower_el_sync_user_exception(
        vector(frame),
        entered_from_user_mode(frame),
        exception_class,
    ) {
        return Ok(ExceptionRecoveryActionResult::Declined);
    }

    let Some(thread) = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread())
    else {
        return Ok(ExceptionRecoveryActionResult::Declined);
    };

    match thread.deliver_aarch64_user_exception(
        frame,
        exception_class,
        exception_iss(frame) as u64,
        lower_el_sync_fault_address(frame),
    ) {
        Ok(true) => {
            // ── fault profiler: delivered to user handler ──
            if let Some(memory) = crate::kernel::memory::global_mut() {
                memory.fault_profiler.inc_faults_delivered_to_handler();
            }
            Ok(ExceptionRecoveryActionResult::Applied)
        }
        Ok(false) => {
            // ── fault profiler: no user handler ──
            if let Some(memory) = crate::kernel::memory::global_mut() {
                memory.fault_profiler.inc_faults_no_handler();
            }
            Ok(ExceptionRecoveryActionResult::Declined)
        }
        Err(error) => Err(error),
    }
}

fn handle_syscall(frame: &mut TrapFrame) {
    if !entered_from_user_mode(frame) {
        println!(
            "[WARN] kernel-mode svc elr={:#018x} esr={:#018x}",
            frame.elr, frame.esr
        );
        return;
    }

    let current_thread = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread());
    let mut syscall_context = SyscallContext::new(
        frame.x8 as usize,
        [
            frame.x0 as usize,
            frame.x1 as usize,
            frame.x2 as usize,
            frame.x3 as usize,
            frame.x4 as usize,
            frame.x5 as usize,
        ],
    );
    syscall_context.caller_pid = current_thread.as_ref().map(|thread| thread.pid());

    // Pre-validate user-memory pointers declared in the static syscall
    // pointer-spec table.  Return early with a clear error if any pointer
    // is out of bounds or unmapped — the individual handler never runs.
    if let Err(error) =
        user_memory::validate_syscall_pointers(syscall_context.number, &syscall_context.args)
    {
        frame.x0 = syscall_abi::encode_error(error) as u64;
        return;
    }

    let mut post_action = SyscallAction::None;

    match syscall::dispatch_with_action(&mut syscall_context) {
        Ok(dispatch) => match dispatch.action {
            SyscallAction::ReturnFromException { frame_pointer } => {
                let resume_result = current_thread
                    .as_ref()
                    .ok_or(crate::Error::InternalError)
                    .and_then(|thread| thread.resume_aarch64_user_exception(frame, frame_pointer));

                match syscall_trap::resolve_return_from_exception_resume(resume_result) {
                    syscall_trap::ReturnFromExceptionResolution::ReturnToUser => {
                        if let Some(thread) = current_thread.as_ref() {
                            thread.capture_aarch64_user_context_from_trap(frame);
                        }
                        return;
                    }
                    syscall_trap::ReturnFromExceptionResolution::SetError(error) => {
                        frame.x0 = syscall_abi::encode_error(error) as u64;
                    }
                }
            }
            action => {
                frame.x0 = syscall_abi::encode_result(Ok(dispatch.value)) as u64;
                post_action = action;
            }
        },
        Err(error) => {
            frame.x0 = syscall_abi::encode_error(error) as u64;
        }
    }

    match syscall_trap::user_context_capture_point(post_action) {
        syscall_trap::UserContextCapturePoint::BeforePostAction => {
            capture_current_user_context(frame);
        }
        syscall_trap::UserContextCapturePoint::AfterExecProcessApply => {}
    }

    match post_action {
        SyscallAction::Yield => {
            crate::kernel::process::yield_current();
        }
        SyscallAction::Exit { status } => {
            crate::kernel::process::terminate_current_with_reason(TerminationReason::Exit {
                status,
            });
        }
        SyscallAction::ExecProcess => {
            let apply_result = current_thread
                .as_ref()
                .ok_or(crate::Error::InternalError)
                .and_then(|thread| thread.write_aarch64_user_context_to_trap(frame));

            match syscall_trap::resolve_exec_process_apply_result(apply_result) {
                syscall_trap::ExecProcessApplyResolution::CaptureUserContext => {
                    if let Some(thread) = current_thread.as_ref() {
                        thread.capture_aarch64_user_context_from_trap(frame);
                    }
                }
                syscall_trap::ExecProcessApplyResolution::SetErrorAndCaptureUserContext(error) => {
                    frame.x0 = syscall_abi::encode_error(error) as u64;
                    capture_current_user_context(frame);
                }
            }
        }
        SyscallAction::None | SyscallAction::ReturnFromException { .. } => {}
        SyscallAction::SigReturn => {
            // Restore the AArch64 user context from the signal frame that
            // was injected by try_async_signal_delivery_aarch64.
            if let Some(thread) = current_thread.as_ref() {
                let _ = thread.write_aarch64_user_context_to_trap(frame);
            }
        }
    }
}

/// Handle an AArch64 NMI-class trap (SError or FIQ).
///
/// Runs the arch-neutral NMI handler registry; when no handler claims the
/// NMI, the condition is logged with the interrupted context so it is not
/// silently lost.  The frame is left untouched so execution resumes at the
/// interrupted ELR.
fn handle_nmi_frame(frame: &mut TrapFrame) {
    let handled = crate::kernel::nmi::dispatch();
    if !handled {
        println!(
            "[NMI   ] unhandled aarch64 {} elr={:#018x} spsr={:#018x} esr={:#018x} far={:#018x}",
            exception::vector_name(vector(frame)),
            frame.elr,
            frame.spsr,
            frame.esr,
            frame.far
        );
    }
}

fn handle_irq(frame: &mut TrapFrame) {
    let acknowledge = super::interrupt_controller::claim_interrupt();
    let pending_tick = super::timer::prepare_pending_interrupt();
    let (claimed_interrupt_id, claimed_timer_tick) = if pending_tick.is_none() {
        if let Some(acknowledge) = acknowledge.as_ref() {
            let interrupt_id = super::interrupt_controller::interrupt_id(*acknowledge);
            (interrupt_id, super::timer::prepare_interrupt(interrupt_id))
        } else {
            (0, None)
        }
    } else {
        (0, None)
    };

    // ── SGI (IPI) dispatch ─────────────────────────────────────────
    // SGIs arrive as interrupt IDs 0-15.  Handle them here before the
    // general IRQ disposition logic.
    if let Some(acknowledge) = acknowledge.as_ref() {
        let intid = super::interrupt_controller::interrupt_id(*acknowledge);
        if intid <= 15 {
            // SGI: acknowledge immediately, then dispatch.
            crate::kernel::irq_stats::record_ipi();
            super::interrupt_controller::acknowledge(*acknowledge);
            if intid == crate::arch::aarch64::smp::SGI_RESCHEDULE as u32 {
                crate::arch::aarch64::smp::handle_reschedule_sgi();
            } else if intid == crate::arch::aarch64::smp::SGI_TLB_SHOOTDOWN as u32 {
                crate::arch::aarch64::smp::handle_tlb_shootdown_sgi();
            }
            advance_past_idle_wfi(frame);
            return;
        }
    }

    match exception::classify_irq_disposition(
        acknowledge.is_some(),
        pending_tick,
        claimed_interrupt_id,
        claimed_timer_tick,
    ) {
        exception::IrqDisposition::ReturnWithoutHandling => {
            crate::kernel::irq_stats::record_spurious();
        }
        exception::IrqDisposition::TimerTick {
            ticks,
            acknowledge_claim,
        } => {
            crate::kernel::irq_stats::record_irq(super::timer::TIMER_INTERRUPT_ID);
            if acknowledge_claim {
                if let Some(acknowledge) = acknowledge {
                    super::interrupt_controller::acknowledge(acknowledge);
                }
            }

            let preempted = crate::kernel::process::on_timer_tick(ticks);
            log_user_exception_handler_preempt_resume(frame, ticks, preempted);
            advance_past_idle_wfi(frame);
        }
        exception::IrqDisposition::WarnClaimedInterrupt { interrupt_id } => {
            crate::kernel::irq_stats::record_irq(interrupt_id);
            if let Some(acknowledge) = acknowledge {
                super::interrupt_controller::acknowledge(acknowledge);
            }
            advance_past_idle_wfi(frame);
            println!(
                "[WARN] aarch64 irq intid={} vector={} ({}) elr={:#018x}",
                interrupt_id,
                vector(frame),
                exception::vector_name(vector(frame)),
                frame.elr
            );
        }
    }
}

fn log_user_exception_handler_preempt_resume(frame: &TrapFrame, ticks: u64, preempted: bool) {
    let Some(thread) = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread())
    else {
        return;
    };

    let depth = thread.aarch64_pending_exception_depth();
    if !exception::should_log_handler_preempt_resume(
        preempted,
        entered_from_user_mode(frame),
        depth,
    ) || !thread.mark_aarch64_exception_preempt_resume_logged()
    {
        return;
    }

    println!(
        "[user] aarch64 handler-preempt-resume pid={} tid={} depth={} tick={} elr={:#018x}",
        thread.pid(),
        thread.tid(),
        depth,
        ticks,
        frame.elr
    );
}

fn lower_el_sync_termination_reason(frame: &TrapFrame) -> Option<TerminationReason> {
    exception::lower_el_sync_termination_reason(
        vector(frame),
        entered_from_user_mode(frame),
        exception_class(frame),
        exception_iss(frame),
        frame.far,
    )
}

fn lower_el_sync_fault_address(frame: &TrapFrame) -> Option<usize> {
    exception::lower_el_sync_fault_address(exception_class(frame), frame.far)
}

/// Read the faulting virtual address from FAR_EL1 for a CURRENT_EL data abort.
///
/// On AArch64, FAR_EL1 holds the faulting address for synchronous data aborts
/// (both same-EL and lower-EL).  Returns `Some(addr)` for data abort classes
/// and `None` otherwise.
fn current_el_fault_address(frame: &TrapFrame) -> Option<usize> {
    let class = exception_class(frame);
    if exception::is_data_abort_class(class) {
        Some(frame.far as usize)
    } else {
        None
    }
}

/// Push a fault record into the current process's per-process fault ring buffer
/// for post-mortem crash diagnosis.  Mirrors the x86_64
/// `record_process_fault_record` in [`idt.rs`](super::super::x86_64::idt).
fn push_fault_record_from_trap(frame: &TrapFrame) {
    if let Some(scheduler) = crate::kernel::process::Scheduler::global() {
        if let Some(thread) = scheduler.current_thread() {
            thread.push_fault_record(
                exception_class(frame),
                exception_iss(frame) as u64,
                lower_el_sync_fault_address(frame),
                frame.elr,
                entered_from_user_mode(frame),
            );
        }
    }

    // Process pending softirqs before returning from the trap handler.
    if entered_from_user_mode(frame) {
        crate::kernel::softirq::process_softirqs();
    }
}

fn log_user_exception_termination(frame: &TrapFrame) {
    let Some(thread) = crate::kernel::process::Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread())
    else {
        return;
    };

    // Push a fault record for post-mortem crash diagnosis (charter §6 item 1).
    push_fault_record_from_trap(frame);

    match exception::lower_el_sync_termination_log(
        exception_class(frame),
        exception_iss(frame),
        frame.far,
    ) {
        exception::LowerElSyncTerminationLog::Abort {
            exception_name,
            abort_syndrome,
            fault_address,
        } => {
            println!(
                "[user] terminating pid={} tid={} after {} ec={:#04x} iss={:#010x} fsc={:#04x} ({}) access={} addr={:#018x} elr={:#018x}",
                thread.pid(),
                thread.tid(),
                exception_name,
                exception_class(frame),
                exception_iss(frame),
                abort_syndrome.fault_status_code(),
                abort_syndrome.fault_status_name(),
                abort_syndrome.access_kind(),
                fault_address,
                frame.elr
            );
        }
        exception::LowerElSyncTerminationLog::Basic { exception_name } => {
            println!(
                "[user] terminating pid={} tid={} after {} ec={:#04x} iss={:#010x} elr={:#018x}",
                thread.pid(),
                thread.tid(),
                exception_name,
                exception_class(frame),
                exception_iss(frame),
                frame.elr
            );
        }
    }
}

/// Attempt to deliver a pending async signal by injecting an
/// [`crate::abi::process::AArch64SignalFrame`] onto the user stack and
/// rewriting the [`TrapFrame`].
///
/// Semantics match the x86_64 `try_async_signal_delivery` — called from
/// the trap dispatch path before returning to user mode after an IRQ.
fn try_async_signal_delivery_aarch64(frame: &mut TrapFrame) {
    use crate::abi::process::{AArch64SignalFrame, AARCH64_SIGNAL_FRAME_SIZE};
    use crate::kernel::process::Process;
    use crate::kernel::process::Scheduler;
    use crate::kernel::syscall::table::user_memory;

    let scheduler = match Scheduler::global() {
        Some(s) => s,
        None => return,
    };
    let thread = match scheduler.current_thread() {
        Some(t) => t,
        None => return,
    };
    let process: &Process = thread.process();

    let record = match process.peek_pending_signal() {
        Some(r) => r,
        None => return,
    };
    let signal_num = record.signal;

    if process.is_signal_blocked(signal_num) {
        return;
    }

    let handler_addr = match process.user_signal_handler(signal_num) {
        Some(addr) if addr != 0 => addr,
        _ => return,
    };

    let trampoline_addr = process.signal_trampoline_addr();
    if trampoline_addr == 0 {
        return;
    }

    // Consume the signal.
    let _ = process.take_pending_signal();

    // ── Build the SignalFrame on the user stack ────────────────────
    //
    // Stack layout (addresses descending, AArch64 stack grows down):
    //
    //   [original stack]               ← user_sp (original)
    //   [AArch64SignalFrame: 32 bytes] ← user_sp - 40 (frame_base)
    //   [trampoline return addr]       ← user_sp - 8  (handler SP)
    //
    // After handler `ret`:
    //   - pops trampoline address, SP = user_sp - 32
    //   - trampoline runs, eventually calls SYS_SIGRETURN
    let user_sp = frame.stack_pointer;
    let trampoline_ret_addr = user_sp.wrapping_sub(8);
    let signal_frame_base = trampoline_ret_addr.wrapping_sub(AARCH64_SIGNAL_FRAME_SIZE as u64);

    let total_len = user_sp.wrapping_sub(signal_frame_base) as usize;
    if total_len == 0 || total_len > 128 {
        return;
    }

    let validation_ok = user_memory::validate_user_mapping(
        process,
        signal_frame_base as usize,
        total_len,
        crate::kernel::memory::paging::PagePermissions::WRITE,
    )
    .is_ok();

    if !validation_ok {
        return;
    }

    // ── SA_RESTART ─────────────────────────────────────────────────
    // On AArch64 (and RISC-V) an async signal is only ever delivered on
    // an IRQ frame returning to user mode, and the interrupted ELR there
    // is never an *executed* SVC: an SVC traps synchronously, so the IRQ
    // frame either points at an ordinary user instruction or at an SVC
    // that has not yet executed (in which case the handler returns and
    // the SVC runs fresh).  Rewinding ELR in either case would corrupt
    // the user PC.  The x86_64 rewind works because delivery there
    // happens on the syscall interrupt frame itself (`vector ==
    // SYSCALL_VECTOR`), i.e. after `int 0x80` was actually taken.
    // Restarting an interrupted syscall on AArch64 therefore has to be
    // driven from the synchronous syscall path, not here.
    let sig_frame = AArch64SignalFrame {
        orig_elr: frame.elr,
        orig_sp: user_sp,
        orig_spsr: frame.spsr,
        signal: signal_num as u64,
    };

    // SAFETY: both addresses validated as writable user pages above.
    unsafe {
        core::ptr::write(signal_frame_base as *mut AArch64SignalFrame, sig_frame);
        core::ptr::write(trampoline_ret_addr as *mut u64, trampoline_addr);
    }

    // ── Rewrite TrapFrame for handler entry ────────────────────────
    frame.elr = handler_addr;
    frame.stack_pointer = trampoline_ret_addr;
    frame.x0 = signal_num as u64; // x0 = first argument (signal number)

    // Zero volatile caller-saved registers for cleanliness.
    frame.x1 = 0;
    frame.x2 = 0;
    frame.x3 = 0;
    frame.x4 = 0;
    frame.x5 = 0;
    frame.x6 = 0;
    frame.x7 = 0;
}

fn advance_past_idle_wfi(frame: &mut TrapFrame) {
    if entered_from_user_mode(frame) {
        return;
    }

    let instruction = unsafe { read_volatile(frame.elr as *const u32) };
    frame.elr = exception::advanced_elr_after_idle_wfi(false, frame.elr, instruction);
}
