//! src/kernel/security/mac/tests.rs
//!
//! Host tests for the MAC policy engine and object classification.

use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;

use super::check::check_file;
use super::check::object_type_for_path;
use super::check::set_path_type;
use super::policy::policy_state;
use super::policy::MacPolicy;
use super::types::*;
use crate::Error;

/// Serialise the tests that mutate the global policy.
///
/// The policy is one process-wide `Mutex`, so two tests that each install a
/// rule set would otherwise decide against each other's rules — and a test that
/// expects `PermissionDenied` would fail only when it happened to run beside
/// one that had allowed the request.  The same lock, for the same reason, is
/// in `tests/process/condvar.rs`.
fn policy_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
fn fresh_policy_defaults_to_deny() {
    // A freshly constructed policy is permissive until enabled, but defaults
    // to deny-by-default for unmatched requests once enforcement is on.
    let policy = MacPolicy::new();
    assert!(!policy.enabled);
    assert!(policy.default_deny);

    let mut policy = MacPolicy::new();
    policy.enabled = true;
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
fn explicit_default_allow_still_allows_unmatched() {
    // Manually opting into an allow-default remains supported.
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
    let _guard = policy_lock();
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
    let _guard = policy_lock();
    reset_global_policy();
    set_path_type("/data/secret", MAC_TYPE_TMP);
    assert_eq!(object_type_for_path("/data/secret"), MAC_TYPE_TMP);
    assert_eq!(object_type_for_path("/data/other"), MAC_TYPE_USER);
}

#[test]
fn check_file_denies_when_enforced() {
    let _guard = policy_lock();
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

#[test]
fn check_network_decides_against_the_network_object() {
    let _guard = policy_lock();
    reset_global_policy();
    {
        let mut state = policy_state().lock();
        state.policy.enabled = true;
        state.policy.default_deny = true;
        // A rule written the way an administrator would: the subject may use
        // the network to connect.
        state.policy.add_rule(
            MacRule {
                subject: MAC_TYPE_APPS,
                object: MAC_TYPE_NETWORK,
                class: MAC_CLASS_NETWORK,
                perms: MAC_PERM_CONNECT,
            },
            false,
        );
    }

    assert!(super::check::check_network(MAC_TYPE_APPS, MAC_PERM_CONNECT, 0).is_ok());
    // A permission the rule does not grant is denied by default, and so is a
    // subject the rule does not name.
    assert_eq!(
        super::check::check_network(MAC_TYPE_APPS, MAC_PERM_BIND, 0),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        super::check::check_network(MAC_TYPE_USER, MAC_PERM_CONNECT, 0),
        Err(Error::PermissionDenied)
    );

    reset_global_policy();
}

#[test]
fn check_process_decides_between_the_two_labels() {
    let _guard = policy_lock();
    reset_global_policy();
    {
        let mut state = policy_state().lock();
        state.policy.enabled = true;
        state.policy.default_deny = true;
        state.policy.add_rule(
            MacRule {
                subject: MAC_TYPE_SYSTEM,
                object: MAC_TYPE_USER,
                class: MAC_CLASS_PROCESS,
                perms: MAC_PERM_SIGNAL | MAC_PERM_TRACE,
            },
            false,
        );
    }

    assert!(
        super::check::check_process(MAC_TYPE_SYSTEM, MAC_TYPE_USER, MAC_PERM_SIGNAL, 0).is_ok()
    );
    // The object is the target's label, not the subject's: the same subject
    // acting on a differently labelled target matches nothing.
    assert_eq!(
        super::check::check_process(MAC_TYPE_SYSTEM, MAC_TYPE_APPS, MAC_PERM_SIGNAL, 0),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        super::check::check_process(MAC_TYPE_USER, MAC_TYPE_USER, MAC_PERM_SIGNAL, 0),
        Err(Error::PermissionDenied)
    );

    reset_global_policy();
}
