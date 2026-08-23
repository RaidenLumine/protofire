//! src/arch/exception_recoverability.rs
//! Shared helpers that pair trap diagnoses with recovery decisions and log output.

use alloc::format;
use alloc::string::String;
use core::fmt::LowerHex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionRecoverability {
    RecoverNow,
    TerminateCurrent,
    Fatal,
}

impl ExceptionRecoverability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoverNow => "recover-now",
            Self::TerminateCurrent => "terminate-current",
            Self::Fatal => "fatal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionRecoveryAction {
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    MapKernelHeapPage,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    UpgradeKernelHeapPageWrite,
    DeliverLowerElSyncUserException,
}

impl ExceptionRecoveryAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MapKernelHeapPage => "map-kernel-heap-page",
            Self::UpgradeKernelHeapPageWrite => "upgrade-kernel-heap-page-write",
            Self::DeliverLowerElSyncUserException => "deliver-lower-el-sync-user-exception",
        }
    }
}

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionRecoveryActionResult {
    Applied,
    Declined,
    Error,
}

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
impl ExceptionRecoveryActionResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Declined => "declined",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionRecoveryDecision {
    pub recoverability: ExceptionRecoverability,
    pub action: Option<ExceptionRecoveryAction>,
}

impl ExceptionRecoveryDecision {
    pub const fn recover_now(action: ExceptionRecoveryAction) -> Self {
        Self {
            recoverability: ExceptionRecoverability::RecoverNow,
            action: Some(action),
        }
    }

    pub const fn terminate_current() -> Self {
        Self {
            recoverability: ExceptionRecoverability::TerminateCurrent,
            action: None,
        }
    }

    pub const fn fatal() -> Self {
        Self {
            recoverability: ExceptionRecoverability::Fatal,
            action: None,
        }
    }

    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    pub const fn effective_recoverability_after_action(
        self,
        action_result: Option<ExceptionRecoveryActionResult>,
    ) -> ExceptionRecoverability {
        match (self.recoverability, self.action, action_result) {
            (
                ExceptionRecoverability::RecoverNow,
                Some(_),
                Some(ExceptionRecoveryActionResult::Applied),
            ) => ExceptionRecoverability::RecoverNow,
            (ExceptionRecoverability::RecoverNow, Some(_), _) => {
                ExceptionRecoverability::TerminateCurrent
            }
            _ => self.recoverability,
        }
    }
}

/// Named log fields keep recovery logs readable at call sites and avoid
/// brittle positional argument lists across architectures.
pub struct RecoveryActionLogRecord<'a, A, I> {
    pub level: &'a str,
    pub exception: &'a str,
    pub action: ExceptionRecoveryAction,
    pub result: ExceptionRecoveryActionResult,
    pub recoverability: ExceptionRecoverability,
    pub downgraded: Option<ExceptionRecoverability>,
    pub addr: Option<A>,
    pub ip: I,
    pub error: Option<&'a str>,
}

pub fn recovery_action_log_line<A, I>(record: RecoveryActionLogRecord<'_, A, I>) -> String
where
    A: LowerHex,
    I: LowerHex,
{
    let RecoveryActionLogRecord {
        level,
        exception,
        action,
        result,
        recoverability,
        downgraded,
        addr,
        ip,
        error,
    } = record;
    let downgraded = downgraded.map_or("-", ExceptionRecoverability::as_str);
    let addr = addr.map_or_else(|| String::from("-"), |value| format!("{value:#018x}"));
    let mut line = format!(
        "[{level}] recovery-action exception={exception} action={} result={} recoverability={} downgraded={} addr={} ip={:#018x}",
        action.as_str(),
        result.as_str(),
        recoverability.as_str(),
        downgraded,
        addr,
        ip,
    );

    if let Some(error) = error {
        line.push_str(" err=");
        line.push_str(error);
    }

    line
}

#[cfg(test)]
mod tests {
    use super::{
        recovery_action_log_line, ExceptionRecoverability, ExceptionRecoveryAction,
        ExceptionRecoveryActionResult, ExceptionRecoveryDecision, RecoveryActionLogRecord,
    };

    #[test]
    fn recover_now_with_action_stays_recover_now_when_action_applies() {
        let decision =
            ExceptionRecoveryDecision::recover_now(ExceptionRecoveryAction::MapKernelHeapPage);

        assert_eq!(
            decision.effective_recoverability_after_action(Some(
                ExceptionRecoveryActionResult::Applied,
            )),
            ExceptionRecoverability::RecoverNow
        );
    }

    #[test]
    fn recover_now_with_actions_downgrades_when_action_declines_or_errors() {
        let decisions = [
            ExceptionRecoveryDecision::recover_now(ExceptionRecoveryAction::MapKernelHeapPage),
            ExceptionRecoveryDecision::recover_now(
                ExceptionRecoveryAction::DeliverLowerElSyncUserException,
            ),
        ];

        for decision in decisions {
            assert_eq!(
                decision.effective_recoverability_after_action(Some(
                    ExceptionRecoveryActionResult::Declined,
                )),
                ExceptionRecoverability::TerminateCurrent
            );
            assert_eq!(
                decision.effective_recoverability_after_action(Some(
                    ExceptionRecoveryActionResult::Error,
                )),
                ExceptionRecoverability::TerminateCurrent
            );
        }
    }

    #[test]
    fn recover_now_without_action_keeps_recover_now() {
        let decision = ExceptionRecoveryDecision {
            recoverability: ExceptionRecoverability::RecoverNow,
            action: None,
        };

        assert_eq!(
            decision.effective_recoverability_after_action(None),
            ExceptionRecoverability::RecoverNow
        );
    }

    #[test]
    fn terminate_and_fatal_decisions_remain_unchanged() {
        let terminate = ExceptionRecoveryDecision::terminate_current();
        let fatal = ExceptionRecoveryDecision::fatal();

        assert_eq!(
            terminate.effective_recoverability_after_action(None),
            ExceptionRecoverability::TerminateCurrent
        );
        assert_eq!(
            fatal.effective_recoverability_after_action(Some(
                ExceptionRecoveryActionResult::Applied,
            )),
            ExceptionRecoverability::Fatal
        );
    }

    #[test]
    fn recovery_action_log_line_uses_the_shared_field_order() {
        assert_eq!(
            recovery_action_log_line(RecoveryActionLogRecord {
                level: "RECOV",
                exception: "page fault",
                action: ExceptionRecoveryAction::MapKernelHeapPage,
                result: ExceptionRecoveryActionResult::Applied,
                recoverability: ExceptionRecoverability::RecoverNow,
                downgraded: None,
                addr: Some(0x1234),
                ip: 0x5678,
                error: None,
            }),
            "[RECOV] recovery-action exception=page fault action=map-kernel-heap-page result=applied recoverability=recover-now downgraded=- addr=0x0000000000001234 ip=0x0000000000005678"
        );
        assert_eq!(
            recovery_action_log_line(RecoveryActionLogRecord {
                level: "WARN",
                exception: "data abort",
                action: ExceptionRecoveryAction::DeliverLowerElSyncUserException,
                result: ExceptionRecoveryActionResult::Error,
                recoverability: ExceptionRecoverability::RecoverNow,
                downgraded: Some(ExceptionRecoverability::TerminateCurrent),
                addr: Some(0xabc),
                ip: 0xdef,
                error: Some("internal-error"),
            }),
            "[WARN] recovery-action exception=data abort action=deliver-lower-el-sync-user-exception result=error recoverability=recover-now downgraded=terminate-current addr=0x0000000000000abc ip=0x0000000000000def err=internal-error"
        );
        assert_eq!(
            recovery_action_log_line(RecoveryActionLogRecord {
                level: "WARN",
                exception: "data abort",
                action: ExceptionRecoveryAction::DeliverLowerElSyncUserException,
                result: ExceptionRecoveryActionResult::Declined,
                recoverability: ExceptionRecoverability::RecoverNow,
                downgraded: Some(ExceptionRecoverability::TerminateCurrent),
                addr: None::<usize>,
                ip: 0x1111,
                error: None,
            }),
            "[WARN] recovery-action exception=data abort action=deliver-lower-el-sync-user-exception result=declined recoverability=recover-now downgraded=terminate-current addr=- ip=0x0000000000001111"
        );
    }
}
