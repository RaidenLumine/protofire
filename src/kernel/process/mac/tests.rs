//! src/kernel/process/mac/tests.rs
//!
//! Host tests for the MAC policy engine and object classification.

use super::check::check_file;
use super::check::object_type_for_path;
use super::check::set_path_type;
use super::policy::policy_state;
use super::policy::MacPolicy;
use super::types::*;
use crate::Error;

/// Reset the global MAC policy state to the permissive default.
fn reset_global_policy() {
    let mut state = policy_state().lock();
    state.policy = MacPolicy::new();
    state.path_types.clear();
}

#[test]
fn disabled_policy_is_permissive() {
    let policy = MacPolicy::new();
    assert!(!policy.enabled);
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_WRITE
        ),
        None
    );
}

#[test]
fn allow_rules_grant_coverage() {
    let mut policy = MacPolicy::new();
    policy.enabled = true;
    policy.default_deny = true;
    policy.add_rule(
        MacRule {
            subject: MAC_TYPE_USER,
            object: MAC_TYPE_SYSTEM,
            class: MAC_CLASS_FILE,
            perms: MAC_PERM_READ,
        },
        false,
    );
    policy.add_rule(
        MacRule {
            subject: MAC_TYPE_USER,
            object: MAC_TYPE_SYSTEM,
            class: MAC_CLASS_FILE,
            perms: MAC_PERM_READ | MAC_PERM_WRITE,
        },
        false,
    );
    // A rule covers the request only when it grants every requested bit.
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ
        ),
        Some(true)
    );
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ | MAC_PERM_WRITE
        ),
        Some(true)
    );
    // No rule grants EXEC → default deny applies.
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_EXEC
        ),
        Some(false)
    );
}

#[test]
fn default_deny_denies_unmatched() {
    let mut policy = MacPolicy::new();
    policy.enabled = true;
    policy.default_deny = true;
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ
        ),
        Some(false)
    );
}

#[test]
fn default_allow_allows_unmatched() {
    let mut policy = MacPolicy::new();
    policy.enabled = true;
    policy.default_deny = false;
    assert_eq!(
        policy.decision(
            MAC_TYPE_USER,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ
        ),
        Some(true)
    );
}

#[test]
fn allow_rule_requires_all_requested_perms() {
    let mut policy = MacPolicy::new();
    policy.enabled = true;
    policy.default_deny = true;
    policy.add_rule(
        MacRule {
            subject: MAC_TYPE_SYSTEM,
            object: MAC_TYPE_SYSTEM,
            class: MAC_CLASS_FILE,
            perms: MAC_PERM_READ | MAC_PERM_WRITE,
        },
        false,
    );
    // READ is covered by the rule; READ|WRITE is fully covered; WRITE alone
    // is a subset but our perms-check requires all requested bits.
    assert_eq!(
        policy.decision(
            MAC_TYPE_SYSTEM,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ
        ),
        Some(true)
    );
    assert_eq!(
        policy.decision(
            MAC_TYPE_SYSTEM,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_READ | MAC_PERM_WRITE
        ),
        Some(true)
    );
    assert_eq!(
        policy.decision(
            MAC_TYPE_SYSTEM,
            MAC_TYPE_SYSTEM,
            MAC_CLASS_FILE,
            MAC_PERM_WRITE
        ),
        Some(true)
    );
}

#[test]
fn object_type_for_path_classifies_layout() {
    reset_global_policy();
    assert_eq!(object_type_for_path("/system/bin/sh"), MAC_TYPE_SYSTEM);
    assert_eq!(object_type_for_path("/system"), MAC_TYPE_SYSTEM);
    assert_eq!(object_type_for_path("/apps/app1"), MAC_TYPE_APPS);
    assert_eq!(object_type_for_path("/data/users/u"), MAC_TYPE_USER);
    assert_eq!(object_type_for_path("/data"), MAC_TYPE_USER);
    assert_eq!(object_type_for_path("/dev/tty"), MAC_TYPE_DEVICE);
    assert_eq!(object_type_for_path("/tmp/f"), MAC_TYPE_TMP);
    assert_eq!(object_type_for_path("/misc/other"), MAC_TYPE_UNLABELED);
    // A path that merely shares a prefix must not match.
    assert_eq!(object_type_for_path("/systematic"), MAC_TYPE_UNLABELED);
}

#[test]
fn path_override_takes_precedence() {
    reset_global_policy();
    set_path_type("/data/secret", MAC_TYPE_TMP);
    assert_eq!(object_type_for_path("/data/secret"), MAC_TYPE_TMP);
    assert_eq!(object_type_for_path("/data/other"), MAC_TYPE_USER);
}

#[test]
fn check_file_denies_when_enforced() {
    reset_global_policy();
    {
        let mut state = policy_state().lock();
        state.policy.enabled = true;
        state.policy.default_deny = true;
        // Allow system subjects full access to user data.
        state.policy.add_rule(
            MacRule {
                subject: MAC_TYPE_SYSTEM,
                object: MAC_TYPE_USER,
                class: MAC_CLASS_DIR,
                perms: MAC_PERM_READ | MAC_PERM_WRITE | MAC_PERM_SEARCH,
            },
            false,
        );
    }

    // Untrusted subject writing to /data is denied by default.
    assert_eq!(
        check_file(
            MAC_TYPE_UNTRUSTED,
            "/data/f",
            MAC_CLASS_DIR,
            MAC_PERM_WRITE,
            1000
        ),
        Err(Error::PermissionDenied)
    );
    // System subject is allowed by the rule.
    assert!(check_file(MAC_TYPE_SYSTEM, "/data/f", MAC_CLASS_DIR, MAC_PERM_WRITE, 0).is_ok());

    // Disabling the policy restores permissive behaviour.
    policy_state().lock().policy.enabled = false;
    assert!(check_file(
        MAC_TYPE_UNTRUSTED,
        "/data/f",
        MAC_CLASS_DIR,
        MAC_PERM_WRITE,
        1000
    )
    .is_ok());
}
