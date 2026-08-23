//! src/kernel/process/mac/mod.rs
//! Mandatory Access Control (MAC) — a SELinux-style Type-Enforcement engine.
//!
//! - `types`   — security types, object classes, permission bitmasks.
//! - `policy`  — the global allow-rule policy + per-path type overrides.
//! - `check`   — object-type classification and enforcement entry points.
//!
//! The subject label (`mac_type`) lives on [`crate::kernel::process::SecurityToken`];
//! the object label for a file is derived from its path (with optional runtime
//! overrides).  When no policy is loaded the engine is permissive, so existing
//! behaviour is unchanged.

pub mod check;
pub mod policy;
#[cfg(test)]
mod tests;
pub mod types;

pub use check::{check_file, check_network, check_process, object_type_for_path, set_path_type};
pub use policy::{policy_state, MacPolicy};
pub use types::{
    is_known_class, is_known_type, MacClass, MacPermission, MacRule, MacStatus, MacType,
    MAC_CLASS_DIR, MAC_CLASS_FILE, MAC_CLASS_NETWORK, MAC_CLASS_PROCESS, MAC_PERM_BIND,
    MAC_PERM_CONNECT, MAC_PERM_CREATE, MAC_PERM_DELETE, MAC_PERM_EXEC, MAC_PERM_READ,
    MAC_PERM_RECV, MAC_PERM_RENAME, MAC_PERM_SEARCH, MAC_PERM_SEND, MAC_PERM_SIGNAL,
    MAC_PERM_TRACE, MAC_PERM_WRITE, MAC_TYPE_APPS, MAC_TYPE_DEVICE, MAC_TYPE_NETWORK,
    MAC_TYPE_SYSTEM, MAC_TYPE_TMP, MAC_TYPE_UNLABELED, MAC_TYPE_UNTRUSTED, MAC_TYPE_USER,
};
