//! src/kernel/process/mac/mod.rs
//!
//! Mandatory Access Control (MAC) — a SELinux-style Type-Enforcement engine.
//!
//! - `types`   — security types, object classes, permission bitmasks.
//! - `policy`  — the global allow-rule policy + per-path type overrides.
//! - `check`   — object-type classification and enforcement entry points.
//!
//! The subject label (`mac_type`) lives on
//! [`crate::kernel::process::SecurityToken`]; the object label for a file is
//! derived from its path (with optional runtime overrides).  When no policy is
//! loaded the engine is permissive, so existing behaviour is unchanged; once
//! enforcement is enabled, requests matching no rule are denied by default.

pub mod check;
pub mod policy;
#[cfg(test)]
mod tests;
pub mod types;

pub use check::check_file;
pub use check::check_network;
pub use check::check_process;
pub use check::object_type_for_path;
pub use check::set_path_type;
pub use policy::policy_state;
pub use policy::MacPolicy;
pub use types::is_known_class;
pub use types::is_known_type;
pub use types::MacClass;
pub use types::MacPermission;
pub use types::MacRule;
pub use types::MacStatus;
pub use types::MacType;
pub use types::MAC_CLASS_DIR;
pub use types::MAC_CLASS_FILE;
pub use types::MAC_CLASS_NETWORK;
pub use types::MAC_CLASS_PROCESS;
pub use types::MAC_PERM_BIND;
pub use types::MAC_PERM_CONNECT;
pub use types::MAC_PERM_CREATE;
pub use types::MAC_PERM_DELETE;
pub use types::MAC_PERM_EXEC;
pub use types::MAC_PERM_READ;
pub use types::MAC_PERM_RECV;
pub use types::MAC_PERM_RENAME;
pub use types::MAC_PERM_SEARCH;
pub use types::MAC_PERM_SEND;
pub use types::MAC_PERM_SIGNAL;
pub use types::MAC_PERM_TRACE;
pub use types::MAC_PERM_WRITE;
pub use types::MAC_TYPE_APPS;
pub use types::MAC_TYPE_DEVICE;
pub use types::MAC_TYPE_NETWORK;
pub use types::MAC_TYPE_SYSTEM;
pub use types::MAC_TYPE_TMP;
pub use types::MAC_TYPE_UNLABELED;
pub use types::MAC_TYPE_UNTRUSTED;
pub use types::MAC_TYPE_USER;
