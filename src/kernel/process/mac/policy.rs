//! src/kernel/process/mac/policy.rs
//!
//! MAC policy storage: the global policy (allow rules + enforcement mode) and
//! per-path type overrides.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;

use super::types::MacClass;
use super::types::MacPermission;
use super::types::MacRule;
use super::types::MacType;

/// The loaded MAC policy.  When `enabled` is false (the default) every check
/// is permissive, so loading no policy changes existing behaviour at all.
#[derive(Debug, Clone)]
pub struct MacPolicy {
    /// Allow rules, first-match wins.
    pub rules: Vec<MacRule>,
    /// When a request matches no rule, deny if `default_deny` is true.
    pub default_deny: bool,
    /// Whether enforcement is active.
    pub enabled: bool,
}

impl MacPolicy {
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_deny: false,
            enabled: false,
        }
    }

    /// Add an allow rule.  When `replace` is set, an existing rule with the
    /// same `(subject, object, class)` is replaced instead of appended.
    pub fn add_rule(&mut self, rule: MacRule, replace: bool) {
        if replace {
            self.rules.retain(|r| {
                !(r.subject == rule.subject && r.object == rule.object && r.class == rule.class)
            });
        }
        self.rules.push(rule);
    }

    /// Decide an access request.  Returns:
    /// - `None` — policy not enabled (permissive);
    /// - `Some(true)` — allow;
    /// - `Some(false)` — deny.
    pub fn decision(
        &self,
        subject: MacType,
        object: MacType,
        class: MacClass,
        perms: MacPermission,
    ) -> Option<bool> {
        if !self.enabled {
            return None;
        }
        for rule in &self.rules {
            if rule.subject == subject
                && rule.object == object
                && rule.class == class
                && rule.perms & perms == perms
            {
                return Some(true);
            }
        }
        Some(!self.default_deny)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for MacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// The global MAC policy state: the policy plus per-path type overrides.
pub struct MacPolicyState {
    pub policy: MacPolicy,
    pub path_types: BTreeMap<alloc::string::String, MacType>,
}

impl Default for MacPolicyState {
    fn default() -> Self {
        Self::new()
    }
}

impl MacPolicyState {
    pub const fn new() -> Self {
        Self {
            policy: MacPolicy::new(),
            path_types: BTreeMap::new(),
        }
    }

    pub fn label_count(&self) -> usize {
        self.path_types.len()
    }
}

/// The global MAC policy state singleton.
static MAC_POLICY_STATE: Mutex<MacPolicyState> = Mutex::new(MacPolicyState::new());

/// Access the global MAC policy state.
pub fn policy_state() -> &'static Mutex<MacPolicyState> {
    &MAC_POLICY_STATE
}
