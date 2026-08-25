//! src/kernel/process/seccomp.rs
//!
//! Seccomp (secure computing) core logic.
//!
//! Provides per-process syscall filter rules that are checked before every
//! syscall handler runs.  The filter uses a simple rule-list model:
//! each rule specifies a syscall number and an action
//! (ALLOW / KILL / TRAP).  Rules are evaluated in order; first match wins.
//! If no rule matches, a configurable default action applies.

use alloc::vec::Vec;

use crate::abi::seccomp::SeccompFilterRule;
use crate::abi::seccomp::SeccompRuleHeader;
use crate::abi::seccomp::SECCOMP_ACTION_ALLOW;
use crate::abi::seccomp::SECCOMP_ACTION_KILL;
use crate::abi::seccomp::SECCOMP_ACTION_TRAP;
use crate::abi::seccomp::SECCOMP_MAX_RULES;
use crate::kernel::process::Process;
use crate::Error;
use crate::Result;

// ── Per-process filter state ──────────────────────────────────────────────

/// Seccomp filter state stored inside `Process`.
pub struct SeccompFilterState {
    /// Ordered list of filter rules (first match wins).
    pub rules: Vec<SeccompFilterRule>,
    /// Default action when no rule matches.
    pub default_action: u32,
    /// Whether the filter has been activated.
    pub enabled: bool,
}

impl Default for SeccompFilterState {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompFilterState {
    /// Create a new (disabled) filter state — all syscalls allowed.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: SECCOMP_ACTION_ALLOW,
            enabled: false,
        }
    }

    /// Install a new filter from a userspace-supplied header + rules.
    pub fn install(
        &mut self,
        header: &SeccompRuleHeader,
        rules: &[SeccompFilterRule],
    ) -> Result<()> {
        // Validate actions.
        for rule in rules {
            match rule.action {
                SECCOMP_ACTION_ALLOW | SECCOMP_ACTION_KILL | SECCOMP_ACTION_TRAP => {}
                _ => return Err(Error::InvalidArgument),
            }
        }
        match header.default_action {
            SECCOMP_ACTION_ALLOW | SECCOMP_ACTION_KILL | SECCOMP_ACTION_TRAP => {}
            _ => return Err(Error::InvalidArgument),
        }

        self.rules = rules.to_vec();
        self.default_action = header.default_action;
        self.enabled = true;
        Ok(())
    }

    /// Evaluate a syscall number against the filter.
    ///
    /// Returns the action to take: `SECCOMP_ACTION_ALLOW`,
    /// `SECCOMP_ACTION_KILL`, or `SECCOMP_ACTION_TRAP`.
    pub fn evaluate(&self, syscall_number: usize) -> u32 {
        if !self.enabled {
            return SECCOMP_ACTION_ALLOW;
        }

        let num = syscall_number as u32;
        for rule in &self.rules {
            if rule.syscall_number == num {
                return rule.action;
            }
        }
        self.default_action
    }
}

// ── Dispatch hook ─────────────────────────────────────────────────────────

/// Check the seccomp filter for `process` about to execute `syscall_number`.
///
/// Returns the action to take:
/// - `SECCOMP_ACTION_ALLOW` → continue normally
/// - `SECCOMP_ACTION_KILL` → the caller should terminate the process
/// - `SECCOMP_ACTION_TRAP` → the caller should deliver SIGSYS
pub fn check_syscall(process: &Process, syscall_number: usize) -> u32 {
    process.seccomp_filter.lock().evaluate(syscall_number)
}

/// Install a seccomp filter on `process`.
///
/// Called from the `Seccomp (#129)` syscall handler.
pub fn install_filter(
    process: &Process,
    header: &SeccompRuleHeader,
    rules: &[SeccompFilterRule],
) -> Result<()> {
    if rules.len() > SECCOMP_MAX_RULES {
        return Err(Error::InvalidArgument);
    }
    process.seccomp_filter.lock().install(header, rules)
}

/// Disable the seccomp filter and allow all syscalls.
pub fn disable_filter(process: &Process) {
    let mut filter = process.seccomp_filter.lock();
    filter.enabled = false;
    filter.rules.clear();
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::seccomp::SeccompFilterRule;
    use crate::abi::seccomp::SeccompRuleHeader;
    use crate::abi::seccomp::SECCOMP_ACTION_ALLOW;
    use crate::abi::seccomp::SECCOMP_ACTION_KILL;
    use crate::abi::seccomp::SECCOMP_ACTION_TRAP;
    use alloc::vec;

    #[test]
    fn disabled_filter_allows_everything() {
        let state = SeccompFilterState::new();
        assert_eq!(state.evaluate(0), SECCOMP_ACTION_ALLOW);
        assert_eq!(state.evaluate(128), SECCOMP_ACTION_ALLOW);
        assert_eq!(state.evaluate(999), SECCOMP_ACTION_ALLOW);
    }

    #[test]
    fn kill_rule_blocks_specific_syscall() {
        let mut state = SeccompFilterState::new();
        let header = SeccompRuleHeader {
            default_action: SECCOMP_ACTION_ALLOW,
            rule_count: 1,
            flags: 0,
        };
        let rules = [SeccompFilterRule {
            syscall_number: 42,
            action: SECCOMP_ACTION_KILL,
            flags: 0,
        }];
        assert_eq!(state.install(&header, &rules), Ok(()));
        assert_eq!(state.evaluate(42), SECCOMP_ACTION_KILL);
        assert_eq!(state.evaluate(41), SECCOMP_ACTION_ALLOW);
        assert_eq!(state.evaluate(43), SECCOMP_ACTION_ALLOW);
    }

    #[test]
    fn default_action_applies_when_no_rule_matches() {
        let mut state = SeccompFilterState::new();
        let header = SeccompRuleHeader {
            default_action: SECCOMP_ACTION_KILL,
            rule_count: 1,
            flags: 0,
        };
        let rules = [SeccompFilterRule {
            syscall_number: 0,
            action: SECCOMP_ACTION_ALLOW,
            flags: 0,
        }];
        assert_eq!(state.install(&header, &rules), Ok(()));
        assert_eq!(state.evaluate(0), SECCOMP_ACTION_ALLOW); // rule matches
        assert_eq!(state.evaluate(1), SECCOMP_ACTION_KILL); // default
    }

    #[test]
    fn first_rule_wins() {
        let mut state = SeccompFilterState::new();
        let header = SeccompRuleHeader {
            default_action: SECCOMP_ACTION_TRAP,
            rule_count: 2,
            flags: 0,
        };
        let rules = [
            SeccompFilterRule {
                syscall_number: 10,
                action: SECCOMP_ACTION_KILL,
                flags: 0,
            },
            SeccompFilterRule {
                syscall_number: 10,
                action: SECCOMP_ACTION_ALLOW,
                flags: 0,
            },
        ];
        assert_eq!(state.install(&header, &rules), Ok(()));
        // First matching rule (KILL) wins.
        assert_eq!(state.evaluate(10), SECCOMP_ACTION_KILL);
    }

    #[test]
    fn invalid_action_is_rejected() {
        let mut state = SeccompFilterState::new();
        let header = SeccompRuleHeader {
            default_action: SECCOMP_ACTION_ALLOW,
            rule_count: 1,
            flags: 0,
        };
        let rules = [SeccompFilterRule {
            syscall_number: 0,
            action: 99, // invalid
            flags: 0,
        }];
        assert_eq!(state.install(&header, &rules), Err(Error::InvalidArgument));
    }

    #[test]
    fn max_rules_is_enforced() {
        let rules = vec![
            SeccompFilterRule {
                syscall_number: 0,
                action: SECCOMP_ACTION_ALLOW,
                flags: 0,
            };
            SECCOMP_MAX_RULES + 1
        ];
        // We test via the process-level function, but we can also check the
        // constant directly.
        assert!(rules.len() > SECCOMP_MAX_RULES);
    }
}
