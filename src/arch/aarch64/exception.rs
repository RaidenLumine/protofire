//! src/arch/aarch64/exception.rs
//!
//! AArch64 exception classification helpers shared by traps, logs, and
//! termination records.

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

use crate::abi::exception::AArch64AbortSyndrome;
use crate::arch::exception_recoverability::ExceptionRecoverability;
use crate::arch::exception_recoverability::ExceptionRecoveryAction;
use crate::arch::exception_recoverability::ExceptionRecoveryDecision;
use crate::kernel::process::TerminationReason;

pub const VECTOR_CURRENT_EL_SP0_SYNC: u8 = 0;
pub const VECTOR_CURRENT_EL_SP0_IRQ: u8 = 1;
pub const VECTOR_CURRENT_EL_SP0_FIQ: u8 = 2;
pub const VECTOR_CURRENT_EL_SP0_SERROR: u8 = 3;
pub const VECTOR_CURRENT_EL_SPX_SYNC: u8 = 4;
pub const VECTOR_CURRENT_EL_SPX_IRQ: u8 = 5;
pub const VECTOR_CURRENT_EL_SPX_FIQ: u8 = 6;
pub const VECTOR_CURRENT_EL_SPX_SERROR: u8 = 7;
pub const VECTOR_LOWER_EL_AARCH64_SYNC: u8 = 8;
pub const VECTOR_LOWER_EL_AARCH64_IRQ: u8 = 9;
pub const VECTOR_LOWER_EL_AARCH64_FIQ: u8 = 10;
pub const VECTOR_LOWER_EL_AARCH64_SERROR: u8 = 11;
pub const VECTOR_LOWER_EL_AARCH32_SYNC: u8 = 12;
pub const VECTOR_LOWER_EL_AARCH32_IRQ: u8 = 13;
pub const VECTOR_LOWER_EL_AARCH32_FIQ: u8 = 14;
pub const VECTOR_LOWER_EL_AARCH32_SERROR: u8 = 15;

pub const EXCEPTION_CLASS_UNKNOWN: u8 = 0x00;
pub const EXCEPTION_CLASS_ILLEGAL_EXECUTION_STATE: u8 = 0x0E;
pub const EXCEPTION_CLASS_SVC64: u8 = 0x15;
pub const EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL: u8 = 0x20;
pub const EXCEPTION_CLASS_PC_ALIGNMENT_FAULT: u8 = 0x22;
pub const EXCEPTION_CLASS_DATA_ABORT_LOWER_EL: u8 = 0x24;
/// Data abort taken from the same exception level (kernel-mode page fault).
pub const EXCEPTION_CLASS_DATA_ABORT_SAME_EL: u8 = 0x25;
pub const EXCEPTION_CLASS_SP_ALIGNMENT_FAULT: u8 = 0x26;

pub const AARCH64_WFI_INSTRUCTION: u32 = 0xd503_207f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LowerElSyncTerminationLog {
    Abort {
        exception_name: &'static str,
        abort_syndrome: AArch64AbortSyndrome,
        fault_address: usize,
    },
    Basic {
        exception_name: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrqDisposition {
    ReturnWithoutHandling,
    TimerTick { ticks: u64, acknowledge_claim: bool },
    WarnClaimedInterrupt { interrupt_id: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserFrameValidationAction {
    Continue,
    TerminateCurrentThread,
    FatalWithoutCurrentThread,
}

pub(crate) fn aarch64_user_frame_validation_action(
    entered_from_user_mode: bool,
    frame_valid: bool,
    current_thread_present: bool,
) -> UserFrameValidationAction {
    if !entered_from_user_mode || frame_valid {
        UserFrameValidationAction::Continue
    } else if current_thread_present {
        UserFrameValidationAction::TerminateCurrentThread
    } else {
        UserFrameValidationAction::FatalWithoutCurrentThread
    }
}

pub fn exception_name(exception_class: u8) -> &'static str {
    match exception_class {
        EXCEPTION_CLASS_UNKNOWN => "unknown",
        EXCEPTION_CLASS_ILLEGAL_EXECUTION_STATE => "illegal execution state",
        EXCEPTION_CLASS_SVC64 => "svc64",
        EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL => "instruction abort",
        EXCEPTION_CLASS_PC_ALIGNMENT_FAULT => "pc alignment fault",
        EXCEPTION_CLASS_DATA_ABORT_LOWER_EL => "data abort",
        EXCEPTION_CLASS_SP_ALIGNMENT_FAULT => "sp alignment fault",
        _ => "exception",
    }
}

pub fn is_irq_vector(vector: u8) -> bool {
    matches!(
        vector,
        VECTOR_CURRENT_EL_SP0_IRQ
            | VECTOR_CURRENT_EL_SPX_IRQ
            | VECTOR_LOWER_EL_AARCH64_IRQ
            | VECTOR_LOWER_EL_AARCH32_IRQ
    )
}

/// Returns `true` when `vector` is an NMI-class exception: an SError (the
/// architectural asynchronous abort) or an FIQ, neither of which is masked
/// by the normal IRQ mask.
pub fn is_nmi_vector(vector: u8) -> bool {
    matches!(
        vector,
        VECTOR_CURRENT_EL_SP0_SERROR
            | VECTOR_CURRENT_EL_SP0_FIQ
            | VECTOR_CURRENT_EL_SPX_SERROR
            | VECTOR_CURRENT_EL_SPX_FIQ
            | VECTOR_LOWER_EL_AARCH64_SERROR
            | VECTOR_LOWER_EL_AARCH64_FIQ
            | VECTOR_LOWER_EL_AARCH32_SERROR
            | VECTOR_LOWER_EL_AARCH32_FIQ
    )
}

/// Returns `true` when `vector` is a CURRENT_EL sync exception — i.e. a
/// kernel-mode fault (data abort, instruction abort, etc.) taken at EL1.
pub fn is_current_el_sync_vector(vector: u8) -> bool {
    matches!(
        vector,
        VECTOR_CURRENT_EL_SP0_SYNC | VECTOR_CURRENT_EL_SPX_SYNC
    )
}

pub fn vector_name(vector: u8) -> &'static str {
    match vector {
        VECTOR_CURRENT_EL_SP0_SYNC => "current-el-sp0-sync",
        VECTOR_CURRENT_EL_SP0_IRQ => "current-el-sp0-irq",
        VECTOR_CURRENT_EL_SP0_FIQ => "current-el-sp0-fiq",
        VECTOR_CURRENT_EL_SP0_SERROR => "current-el-sp0-serror",
        VECTOR_CURRENT_EL_SPX_SYNC => "current-el-spx-sync",
        VECTOR_CURRENT_EL_SPX_IRQ => "current-el-spx-irq",
        VECTOR_CURRENT_EL_SPX_FIQ => "current-el-spx-fiq",
        VECTOR_CURRENT_EL_SPX_SERROR => "current-el-spx-serror",
        VECTOR_LOWER_EL_AARCH64_SYNC => "lower-el-aarch64-sync",
        VECTOR_LOWER_EL_AARCH64_IRQ => "lower-el-aarch64-irq",
        VECTOR_LOWER_EL_AARCH64_FIQ => "lower-el-aarch64-fiq",
        VECTOR_LOWER_EL_AARCH64_SERROR => "lower-el-aarch64-serror",
        VECTOR_LOWER_EL_AARCH32_SYNC => "lower-el-aarch32-sync",
        VECTOR_LOWER_EL_AARCH32_IRQ => "lower-el-aarch32-irq",
        VECTOR_LOWER_EL_AARCH32_FIQ => "lower-el-aarch32-fiq",
        VECTOR_LOWER_EL_AARCH32_SERROR => "lower-el-aarch32-serror",
        _ => "unknown",
    }
}

pub fn is_lower_el_sync_abort_class(exception_class: u8) -> bool {
    matches!(
        exception_class,
        EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL | EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
    )
}

/// Returns `true` when `exception_class` represents a data abort
/// (lower-EL or same-EL) — i.e. a page fault on a data access.
pub fn is_data_abort_class(exception_class: u8) -> bool {
    matches!(
        exception_class,
        EXCEPTION_CLASS_DATA_ABORT_LOWER_EL | EXCEPTION_CLASS_DATA_ABORT_SAME_EL
    )
}

pub fn should_deliver_lower_el_sync_user_exception(
    vector: u8,
    entered_from_user_mode: bool,
    exception_class: u8,
) -> bool {
    vector == VECTOR_LOWER_EL_AARCH64_SYNC
        && entered_from_user_mode
        && is_lower_el_sync_abort_class(exception_class)
}

#[cfg_attr(all(target_arch = "aarch64", not(test)), allow(dead_code))]
pub fn lower_el_sync_recoverability(
    vector: u8,
    entered_from_user_mode: bool,
    exception_class: u8,
) -> ExceptionRecoverability {
    lower_el_sync_recovery_decision(vector, entered_from_user_mode, exception_class).recoverability
}

pub fn lower_el_sync_recovery_decision(
    vector: u8,
    entered_from_user_mode: bool,
    exception_class: u8,
) -> ExceptionRecoveryDecision {
    if vector != VECTOR_LOWER_EL_AARCH64_SYNC || !entered_from_user_mode {
        return ExceptionRecoveryDecision::fatal();
    }

    if exception_class == EXCEPTION_CLASS_SVC64 {
        ExceptionRecoveryDecision {
            recoverability: ExceptionRecoverability::RecoverNow,
            action: None,
        }
    } else if is_lower_el_sync_abort_class(exception_class) {
        ExceptionRecoveryDecision::recover_now(
            ExceptionRecoveryAction::DeliverLowerElSyncUserException,
        )
    } else {
        ExceptionRecoveryDecision::terminate_current()
    }
}

pub fn advanced_elr_after_idle_wfi(
    entered_from_user_mode: bool,
    elr: u64,
    instruction: u32,
) -> u64 {
    if entered_from_user_mode || instruction != AARCH64_WFI_INSTRUCTION {
        elr
    } else {
        elr.wrapping_add(4)
    }
}

pub fn should_log_handler_preempt_resume(
    preempted: bool,
    entered_from_user_mode: bool,
    pending_exception_depth: usize,
) -> bool {
    preempted && entered_from_user_mode && pending_exception_depth != 0
}

pub(crate) fn classify_irq_disposition(
    acknowledge_present: bool,
    pending_tick: Option<u64>,
    claimed_interrupt_id: u32,
    claimed_timer_tick: Option<u64>,
) -> IrqDisposition {
    if let Some(ticks) = pending_tick {
        return IrqDisposition::TimerTick {
            ticks,
            acknowledge_claim: acknowledge_present,
        };
    }

    if !acknowledge_present {
        return IrqDisposition::ReturnWithoutHandling;
    }

    if let Some(ticks) = claimed_timer_tick {
        return IrqDisposition::TimerTick {
            ticks,
            acknowledge_claim: true,
        };
    }

    IrqDisposition::WarnClaimedInterrupt {
        interrupt_id: claimed_interrupt_id,
    }
}

pub fn lower_el_sync_fault_address(exception_class: u8, far: u64) -> Option<usize> {
    if is_lower_el_sync_abort_class(exception_class) {
        Some(far as usize)
    } else {
        None
    }
}

pub(crate) fn lower_el_sync_termination_log(
    exception_class: u8,
    iss: u32,
    far: u64,
) -> LowerElSyncTerminationLog {
    match AArch64AbortSyndrome::from_exception(exception_class, iss as u64) {
        Some(abort_syndrome) => LowerElSyncTerminationLog::Abort {
            exception_name: exception_name(exception_class),
            abort_syndrome,
            fault_address: far as usize,
        },
        None => LowerElSyncTerminationLog::Basic {
            exception_name: exception_name(exception_class),
        },
    }
}

pub fn lower_el_sync_termination_reason(
    vector: u8,
    entered_from_user_mode: bool,
    exception_class: u8,
    iss: u32,
    far: u64,
) -> Option<TerminationReason> {
    if vector != VECTOR_LOWER_EL_AARCH64_SYNC || !entered_from_user_mode {
        return None;
    }

    if exception_class == EXCEPTION_CLASS_SVC64 {
        return None;
    }

    Some(TerminationReason::exception(
        exception_class,
        iss as u64,
        lower_el_sync_fault_address(exception_class, far),
    ))
}

#[cfg(test)]
mod tests {
    use super::aarch64_user_frame_validation_action;
    use super::advanced_elr_after_idle_wfi;
    use super::classify_irq_disposition;
    use super::exception_name;
    use super::is_irq_vector;
    use super::is_lower_el_sync_abort_class;
    use super::lower_el_sync_fault_address;
    use super::lower_el_sync_recoverability;
    use super::lower_el_sync_recovery_decision;
    use super::lower_el_sync_termination_log;
    use super::lower_el_sync_termination_reason;
    use super::should_deliver_lower_el_sync_user_exception;
    use super::should_log_handler_preempt_resume;
    use super::vector_name;
    use super::IrqDisposition;
    use super::LowerElSyncTerminationLog;
    use super::UserFrameValidationAction;
    use super::AARCH64_WFI_INSTRUCTION;
    use super::EXCEPTION_CLASS_DATA_ABORT_LOWER_EL;
    use super::EXCEPTION_CLASS_ILLEGAL_EXECUTION_STATE;
    use super::EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL;
    use super::EXCEPTION_CLASS_PC_ALIGNMENT_FAULT;
    use super::EXCEPTION_CLASS_SP_ALIGNMENT_FAULT;
    use super::EXCEPTION_CLASS_SVC64;
    use super::EXCEPTION_CLASS_UNKNOWN;
    use super::VECTOR_CURRENT_EL_SP0_IRQ;
    use super::VECTOR_CURRENT_EL_SP0_SYNC;
    use super::VECTOR_CURRENT_EL_SPX_IRQ;
    use super::VECTOR_LOWER_EL_AARCH32_IRQ;
    use super::VECTOR_LOWER_EL_AARCH64_IRQ;
    use super::VECTOR_LOWER_EL_AARCH64_SYNC;
    use crate::abi::exception::AArch64AbortSyndrome;
    use crate::arch::exception_recoverability::ExceptionRecoverability;
    use crate::arch::exception_recoverability::ExceptionRecoveryAction;
    use crate::arch::exception_recoverability::ExceptionRecoveryDecision;
    use crate::kernel::process::ExceptionTermination;
    use crate::kernel::process::TerminationReason;

    #[test]
    fn exception_name_labels_common_lower_el_sync_classes() {
        assert_eq!(exception_name(EXCEPTION_CLASS_UNKNOWN), "unknown");
        assert_eq!(
            exception_name(EXCEPTION_CLASS_ILLEGAL_EXECUTION_STATE),
            "illegal execution state"
        );
        assert_eq!(exception_name(EXCEPTION_CLASS_SVC64), "svc64");
        assert_eq!(
            exception_name(EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL),
            "instruction abort"
        );
        assert_eq!(
            exception_name(EXCEPTION_CLASS_PC_ALIGNMENT_FAULT),
            "pc alignment fault"
        );
        assert_eq!(
            exception_name(EXCEPTION_CLASS_DATA_ABORT_LOWER_EL),
            "data abort"
        );
        assert_eq!(
            exception_name(EXCEPTION_CLASS_SP_ALIGNMENT_FAULT),
            "sp alignment fault"
        );
        assert_eq!(exception_name(0x3f), "exception");
    }

    #[test]
    fn vector_name_labels_common_vectors() {
        assert_eq!(
            vector_name(VECTOR_CURRENT_EL_SP0_SYNC),
            "current-el-sp0-sync"
        );
        assert_eq!(vector_name(VECTOR_CURRENT_EL_SP0_IRQ), "current-el-sp0-irq");
        assert_eq!(
            vector_name(VECTOR_LOWER_EL_AARCH64_SYNC),
            "lower-el-aarch64-sync"
        );
        assert_eq!(
            vector_name(VECTOR_LOWER_EL_AARCH64_IRQ),
            "lower-el-aarch64-irq"
        );
        assert_eq!(vector_name(0xff), "unknown");
    }

    #[test]
    fn is_irq_vector_matches_all_irq_slots() {
        assert!(is_irq_vector(VECTOR_CURRENT_EL_SP0_IRQ));
        assert!(is_irq_vector(VECTOR_CURRENT_EL_SPX_IRQ));
        assert!(is_irq_vector(VECTOR_LOWER_EL_AARCH64_IRQ));
        assert!(is_irq_vector(VECTOR_LOWER_EL_AARCH32_IRQ));
        assert!(!is_irq_vector(VECTOR_CURRENT_EL_SP0_SYNC));
        assert!(!is_irq_vector(VECTOR_LOWER_EL_AARCH64_SYNC));
    }

    #[test]
    fn aarch64_user_frame_validation_action_keeps_kernel_and_valid_user_frames_continuable() {
        assert_eq!(
            aarch64_user_frame_validation_action(false, false, false),
            UserFrameValidationAction::Continue
        );
        assert_eq!(
            aarch64_user_frame_validation_action(false, false, true),
            UserFrameValidationAction::Continue
        );
        assert_eq!(
            aarch64_user_frame_validation_action(true, true, false),
            UserFrameValidationAction::Continue
        );
    }

    #[test]
    fn aarch64_user_frame_validation_action_distinguishes_termination_from_fatal() {
        assert_eq!(
            aarch64_user_frame_validation_action(true, false, true),
            UserFrameValidationAction::TerminateCurrentThread
        );
        assert_eq!(
            aarch64_user_frame_validation_action(true, false, false),
            UserFrameValidationAction::FatalWithoutCurrentThread
        );
    }

    #[test]
    fn lower_el_sync_user_exception_delivery_requires_user_sync_abort() {
        assert!(is_lower_el_sync_abort_class(
            EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
        ));
        assert!(is_lower_el_sync_abort_class(
            EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL
        ));
        assert!(!is_lower_el_sync_abort_class(EXCEPTION_CLASS_SVC64));

        assert!(should_deliver_lower_el_sync_user_exception(
            VECTOR_LOWER_EL_AARCH64_SYNC,
            true,
            EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
        ));
        assert!(should_deliver_lower_el_sync_user_exception(
            VECTOR_LOWER_EL_AARCH64_SYNC,
            true,
            EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL
        ));
        assert!(!should_deliver_lower_el_sync_user_exception(
            VECTOR_CURRENT_EL_SP0_SYNC,
            true,
            EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
        ));
        assert!(!should_deliver_lower_el_sync_user_exception(
            VECTOR_LOWER_EL_AARCH64_SYNC,
            false,
            EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
        ));
        assert!(!should_deliver_lower_el_sync_user_exception(
            VECTOR_LOWER_EL_AARCH64_SYNC,
            true,
            EXCEPTION_CLASS_SVC64
        ));
    }

    #[test]
    fn lower_el_sync_recoverability_grades_user_and_kernel_paths() {
        assert_eq!(
            lower_el_sync_recoverability(VECTOR_LOWER_EL_AARCH64_SYNC, true, EXCEPTION_CLASS_SVC64),
            ExceptionRecoverability::RecoverNow
        );
        assert_eq!(
            lower_el_sync_recoverability(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
            ),
            ExceptionRecoverability::RecoverNow
        );
        assert_eq!(
            lower_el_sync_recoverability(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_PC_ALIGNMENT_FAULT
            ),
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(
            lower_el_sync_recoverability(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                false,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
            ),
            ExceptionRecoverability::Fatal
        );
        assert_eq!(
            lower_el_sync_recoverability(
                VECTOR_CURRENT_EL_SP0_SYNC,
                true,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
            ),
            ExceptionRecoverability::Fatal
        );

        assert_eq!(
            lower_el_sync_recovery_decision(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL
            ),
            ExceptionRecoveryDecision::recover_now(
                ExceptionRecoveryAction::DeliverLowerElSyncUserException,
            )
        );

        assert_eq!(
            lower_el_sync_recovery_decision(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_SVC64
            ),
            ExceptionRecoveryDecision {
                recoverability: ExceptionRecoverability::RecoverNow,
                action: None,
            }
        );
    }

    #[test]
    fn lower_el_sync_action_result_controls_effective_recoverability() {
        let decision = lower_el_sync_recovery_decision(
            VECTOR_LOWER_EL_AARCH64_SYNC,
            true,
            EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
        );

        assert_eq!(
            decision,
            ExceptionRecoveryDecision::recover_now(
                ExceptionRecoveryAction::DeliverLowerElSyncUserException,
            )
        );
        assert_eq!(
            decision.effective_recoverability_after_action(Some(
                crate::arch::exception_recoverability::ExceptionRecoveryActionResult::Applied,
            )),
            ExceptionRecoverability::RecoverNow
        );
        assert_eq!(
            decision.effective_recoverability_after_action(Some(
                crate::arch::exception_recoverability::ExceptionRecoveryActionResult::Declined,
            )),
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(
            decision.effective_recoverability_after_action(Some(
                crate::arch::exception_recoverability::ExceptionRecoveryActionResult::Error,
            )),
            ExceptionRecoverability::TerminateCurrent
        );
    }

    #[test]
    fn advanced_elr_after_idle_wfi_only_steps_kernel_wfi() {
        assert_eq!(
            advanced_elr_after_idle_wfi(false, 0x4000, AARCH64_WFI_INSTRUCTION),
            0x4004
        );
        assert_eq!(
            advanced_elr_after_idle_wfi(true, 0x4000, AARCH64_WFI_INSTRUCTION),
            0x4000
        );
        assert_eq!(advanced_elr_after_idle_wfi(false, 0x4000, 0), 0x4000);
    }

    #[test]
    fn handler_preempt_resume_logging_requires_preempted_user_exception_handler() {
        assert!(should_log_handler_preempt_resume(true, true, 1));
        assert!(should_log_handler_preempt_resume(true, true, 2));
        assert!(!should_log_handler_preempt_resume(false, true, 1));
        assert!(!should_log_handler_preempt_resume(true, false, 1));
        assert!(!should_log_handler_preempt_resume(true, true, 0));
    }

    #[test]
    fn irq_disposition_prefers_pending_timer_ticks() {
        assert_eq!(
            classify_irq_disposition(true, Some(7), 33, Some(9)),
            IrqDisposition::TimerTick {
                ticks: 7,
                acknowledge_claim: true,
            }
        );
        assert_eq!(
            classify_irq_disposition(false, Some(7), 33, Some(9)),
            IrqDisposition::TimerTick {
                ticks: 7,
                acknowledge_claim: false,
            }
        );
    }

    #[test]
    fn irq_disposition_returns_without_claim_when_nothing_is_pending() {
        assert_eq!(
            classify_irq_disposition(false, None, 0, None),
            IrqDisposition::ReturnWithoutHandling
        );
    }

    #[test]
    fn irq_disposition_uses_claimed_timer_when_no_pending_tick_exists() {
        assert_eq!(
            classify_irq_disposition(true, None, 48, Some(11)),
            IrqDisposition::TimerTick {
                ticks: 11,
                acknowledge_claim: true,
            }
        );
    }

    #[test]
    fn irq_disposition_warns_for_unrecognized_claimed_interrupts() {
        assert_eq!(
            classify_irq_disposition(true, None, 48, None),
            IrqDisposition::WarnClaimedInterrupt { interrupt_id: 48 }
        );
    }

    #[test]
    fn lower_el_sync_fault_address_returns_far_for_abort_classes() {
        assert_eq!(
            lower_el_sync_fault_address(EXCEPTION_CLASS_DATA_ABORT_LOWER_EL, 0x7fff_ffff_d000),
            Some(0x7fff_ffff_d000)
        );
        assert_eq!(
            lower_el_sync_fault_address(
                EXCEPTION_CLASS_INSTRUCTION_ABORT_LOWER_EL,
                0x0000_0000_0040_1000,
            ),
            Some(0x0000_0000_0040_1000)
        );
    }

    #[test]
    fn lower_el_sync_fault_address_ignores_non_abort_classes() {
        assert_eq!(lower_el_sync_fault_address(0x22, 0x7fff_ffff_d000), None);
        assert_eq!(
            lower_el_sync_fault_address(EXCEPTION_CLASS_SVC64, 0x7fff_ffff_d000),
            None
        );
    }

    #[test]
    fn lower_el_sync_termination_log_keeps_abort_syndrome_and_fault_address() {
        assert_eq!(
            lower_el_sync_termination_log(
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
                0x4f,
                0x7fff_ffff_d000,
            ),
            LowerElSyncTerminationLog::Abort {
                exception_name: "data abort",
                abort_syndrome: AArch64AbortSyndrome {
                    vector: EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
                    iss: 0x4f,
                },
                fault_address: 0x7fff_ffff_d000,
            }
        );
    }

    #[test]
    fn lower_el_sync_termination_log_uses_basic_form_for_non_abort_classes() {
        assert_eq!(
            lower_el_sync_termination_log(EXCEPTION_CLASS_PC_ALIGNMENT_FAULT, 0x17, 0x9000),
            LowerElSyncTerminationLog::Basic {
                exception_name: "pc alignment fault",
            }
        );
        assert_eq!(
            lower_el_sync_termination_log(EXCEPTION_CLASS_SVC64, 0, 0),
            LowerElSyncTerminationLog::Basic {
                exception_name: "svc64",
            }
        );
    }

    #[test]
    fn lower_el_sync_termination_reason_requires_user_lower_el_sync_vector() {
        assert_eq!(
            lower_el_sync_termination_reason(0, true, EXCEPTION_CLASS_DATA_ABORT_LOWER_EL, 0x4f, 0),
            None
        );
        assert_eq!(
            lower_el_sync_termination_reason(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                false,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
                0x4f,
                0
            ),
            None
        );
    }

    #[test]
    fn lower_el_sync_termination_reason_ignores_svc64() {
        assert_eq!(
            lower_el_sync_termination_reason(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_SVC64,
                0,
                0
            ),
            None
        );
    }

    #[test]
    fn lower_el_sync_termination_reason_preserves_abort_fault_address() {
        assert_eq!(
            lower_el_sync_termination_reason(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
                0x4f,
                0x7fff_ffff_d000,
            ),
            Some(TerminationReason::Exception(ExceptionTermination {
                vector: EXCEPTION_CLASS_DATA_ABORT_LOWER_EL,
                error_code: 0x4f,
                fault_address: Some(0x7fff_ffff_d000),
            }))
        );
    }

    #[test]
    fn lower_el_sync_termination_reason_keeps_non_abort_fault_address_empty() {
        assert_eq!(
            lower_el_sync_termination_reason(
                VECTOR_LOWER_EL_AARCH64_SYNC,
                true,
                0x22,
                0x17,
                0x9000
            ),
            Some(TerminationReason::Exception(ExceptionTermination {
                vector: 0x22,
                error_code: 0x17,
                fault_address: None,
            }))
        );
    }
}
