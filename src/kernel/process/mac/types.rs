//! src/kernel/process/mac/types.rs
//! MAC type-enforcement data types: security types, object classes, and
//! permission bitmasks.

/// A security type (subject or object label).
pub type MacType = u32;

pub const MAC_TYPE_UNLABELED: MacType = 0;
/// Kernel/system processes and `/system` files.
pub const MAC_TYPE_SYSTEM: MacType = 1;
/// Applications under `/apps`.
pub const MAC_TYPE_APPS: MacType = 2;
/// Ordinary user processes and user data under `/data`.
pub const MAC_TYPE_USER: MacType = 3;
/// Untrusted subjects (e.g. guest / low-integrity).
pub const MAC_TYPE_UNTRUSTED: MacType = 4;
/// Network-facing services.
pub const MAC_TYPE_NETWORK: MacType = 5;
/// Device nodes under `/dev`.
pub const MAC_TYPE_DEVICE: MacType = 6;
/// Temporary files under `/tmp`.
pub const MAC_TYPE_TMP: MacType = 7;

/// An object class.
pub type MacClass = u32;

pub const MAC_CLASS_FILE: MacClass = 1;
pub const MAC_CLASS_DIR: MacClass = 2;
pub const MAC_CLASS_PROCESS: MacClass = 3;
pub const MAC_CLASS_NETWORK: MacClass = 4;

/// A permission bitmask (class-specific).
pub type MacPermission = u32;

// File / Dir permissions.
pub const MAC_PERM_READ: MacPermission = 1;
pub const MAC_PERM_WRITE: MacPermission = 2;
pub const MAC_PERM_EXEC: MacPermission = 4;
/// Reserved for operation-specific hooks; v1 parent-dir WRITE covers create/
/// delete/rename.
pub const MAC_PERM_CREATE: MacPermission = 8;
pub const MAC_PERM_DELETE: MacPermission = 16;
pub const MAC_PERM_RENAME: MacPermission = 32;
/// Directory traverse (search).
pub const MAC_PERM_SEARCH: MacPermission = 64;

// Process permissions.
pub const MAC_PERM_SIGNAL: MacPermission = 1;
pub const MAC_PERM_TRACE: MacPermission = 2;

// Network permissions.
pub const MAC_PERM_BIND: MacPermission = 1;
pub const MAC_PERM_CONNECT: MacPermission = 2;
pub const MAC_PERM_SEND: MacPermission = 4;
pub const MAC_PERM_RECV: MacPermission = 8;

/// A single allow rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacRule {
    pub subject: MacType,
    pub object: MacType,
    pub class: MacClass,
    pub perms: MacPermission,
}

/// Policy status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacStatus {
    pub enabled: bool,
    pub default_deny: bool,
    pub rule_count: usize,
    pub label_count: usize,
}

/// Whether `mac_type` is a known constant.
pub const fn is_known_type(mac_type: MacType) -> bool {
    matches!(
        mac_type,
        MAC_TYPE_UNLABELED
            | MAC_TYPE_SYSTEM
            | MAC_TYPE_APPS
            | MAC_TYPE_USER
            | MAC_TYPE_UNTRUSTED
            | MAC_TYPE_NETWORK
            | MAC_TYPE_DEVICE
            | MAC_TYPE_TMP
    )
}

/// Whether `class` is a known object class.
pub const fn is_known_class(class: MacClass) -> bool {
    matches!(
        class,
        MAC_CLASS_FILE | MAC_CLASS_DIR | MAC_CLASS_PROCESS | MAC_CLASS_NETWORK
    )
}
