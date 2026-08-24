//! src/user/shared/abi/seccomp.rs
//!
//! src/abi/seccomp.rs
//! Seccomp ABI types — secure computing / syscall filtering.
//!
//! Provides the user/kernel ABI boundary for the `Seccomp (#129)` syscall.
//! Unlike Linux's BPF-based seccomp, this uses a simple rule-list model:
//! each rule specifies a syscall number range and an action
//! (ALLOW / KILL / TRAP).  Rules are evaluated in order; first match wins.
//! If no rule matches, a configurable default action is applied.

// ── Syscall number ─────────────────────────────────────────────────────────

/// `Seccomp (#129)`: secure computing — set syscall filter rules.
pub const SYS_SECCOMP: usize = 129;

// ── Seccomp commands (passed as `operation` to the syscall) ───────────────

/// Set the seccomp filter from a userspace rule array.
pub const SECCOMP_SET_MODE_FILTER: i32 = 1;

// ── Rule actions ──────────────────────────────────────────────────────────

/// Allow the syscall to proceed normally.
pub const SECCOMP_ACTION_ALLOW: u32 = 0;
/// Immediately kill the calling process (SIGSYS).
pub const SECCOMP_ACTION_KILL: u32 = 1;
/// Deliver SIGSYS to the calling process (trap).
pub const SECCOMP_ACTION_TRAP: u32 = 2;

// ── Filter rule types ─────────────────────────────────────────────────────

/// A single seccomp filter rule.
///
/// Rules are matched in-order; the first matching rule decides the action.
/// If no rule matches, the filter's default action (set via
/// `SECCOMP_SET_MODE_FILTER` with `SeccompRuleHeader.default_action`) applies.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompFilterRule {
    /// Syscall number to match.
    pub syscall_number: u32,
    /// Action to take on match: `SECCOMP_ACTION_*`.
    pub action: u32,
    /// Reserved for future use; must be zero.
    pub flags: u32,
}

/// Header for the filter data passed to `SECCOMP_SET_MODE_FILTER`.
///
/// The caller writes this header followed by `rule_count` `SeccompFilterRule`
/// entries into a contiguous buffer.  The kernel copies the rules into
/// a per-process filter list.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompRuleHeader {
    /// Default action when no rule matches (`SECCOMP_ACTION_*`).
    pub default_action: u32,
    /// Number of rule entries that follow.
    pub rule_count: u32,
    /// Reserved; must be zero.
    pub flags: u32,
}

// ── Wire sizes ────────────────────────────────────────────────────────────

/// Wire size of a single filter rule.
pub const SECCOMP_FILTER_RULE_SIZE: usize = 12;

/// Wire size of the rule header.
pub const SECCOMP_RULE_HEADER_SIZE: usize = 12;

/// Maximum number of filter rules per process.
pub const SECCOMP_MAX_RULES: usize = 128;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn seccomp_filter_rule_size_is_stable() {
        assert_eq!(mem::size_of::<SeccompFilterRule>(), 12);
        assert_eq!(mem::size_of::<SeccompRuleHeader>(), 12);
    }

    #[test]
    fn seccomp_action_constants_are_stable() {
        assert_eq!(SECCOMP_ACTION_ALLOW, 0);
        assert_eq!(SECCOMP_ACTION_KILL, 1);
        assert_eq!(SECCOMP_ACTION_TRAP, 2);
    }

    #[test]
    fn seccomp_command_constants_are_stable() {
        assert_eq!(SECCOMP_SET_MODE_FILTER, 1);
    }
}
