//! src/abi/mac.rs
//!
//! Shared ABI definitions for the MAC (mandatory access control) type-
//! enforcement engine — policy management syscalls (#175-178).

/// MAC management syscall numbers.
pub const SYS_MAC_SET_MODE: usize = 175;
pub const SYS_MAC_ADD_RULE: usize = 176;
pub const SYS_MAC_SET_PATH_TYPE: usize = 177;
pub const SYS_MAC_GET_STATUS: usize = 178;

/// Subject / object security types.
pub const MAC_TYPE_UNLABELED: u32 = 0;
pub const MAC_TYPE_SYSTEM: u32 = 1;
pub const MAC_TYPE_APPS: u32 = 2;
pub const MAC_TYPE_USER: u32 = 3;
pub const MAC_TYPE_UNTRUSTED: u32 = 4;
pub const MAC_TYPE_NETWORK: u32 = 5;
pub const MAC_TYPE_DEVICE: u32 = 6;
pub const MAC_TYPE_TMP: u32 = 7;

/// Object classes.
pub const MAC_CLASS_FILE: u32 = 1;
pub const MAC_CLASS_DIR: u32 = 2;
pub const MAC_CLASS_PROCESS: u32 = 3;
pub const MAC_CLASS_NETWORK: u32 = 4;

/// File / directory permissions.
pub const MAC_PERM_READ: u32 = 1;
pub const MAC_PERM_WRITE: u32 = 2;
pub const MAC_PERM_EXEC: u32 = 4;
pub const MAC_PERM_CREATE: u32 = 8;
pub const MAC_PERM_DELETE: u32 = 16;
pub const MAC_PERM_RENAME: u32 = 32;
pub const MAC_PERM_SEARCH: u32 = 64;
/// Process permissions.
pub const MAC_PERM_SIGNAL: u32 = 1;
pub const MAC_PERM_TRACE: u32 = 2;
/// Network permissions.
pub const MAC_PERM_BIND: u32 = 1;
pub const MAC_PERM_CONNECT: u32 = 2;
pub const MAC_PERM_SEND: u32 = 4;
pub const MAC_PERM_RECV: u32 = 8;

/// Policy-management flags.
pub const MAC_FLAG_NONE: u32 = 0;
/// Replace an existing rule (same subject/object/class) or path override.
pub const MAC_FLAG_REPLACE: u32 = 1;

/// Size of a serialised `MacRule` (4 × u32).
pub const MAC_RULE_SIZE: usize = 16;
/// Size of a serialised `MacStatus` (4 × u32).
pub const MAC_STATUS_SIZE: usize = 16;

/// One allow rule: `(subject, object, class)` with a permission mask.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacRule {
    pub subject: u32,
    pub object: u32,
    pub class: u32,
    pub perms: u32,
}

/// Policy status snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacStatus {
    pub enabled: u32,
    pub default_deny: u32,
    pub rule_count: u32,
    pub label_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn abi_struct_sizes_are_stable() {
        assert_eq!(size_of::<MacRule>(), MAC_RULE_SIZE);
        assert_eq!(size_of::<MacStatus>(), MAC_STATUS_SIZE);
    }
}
