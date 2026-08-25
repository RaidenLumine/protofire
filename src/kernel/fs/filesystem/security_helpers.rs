//! src/kernel/fs/filesystem/security_helpers.rs
//!
//! Security descriptor helpers (free functions).
//! These determine permission scopes, default descriptors, and
//! device-mode / zone-based security policies for normalized paths.

use crate::kernel::device;
use crate::Result;

use super::super::layout::StorageZone;
use super::super::vfs::NodeKind;
use super::super::vfs::SecurityDescriptor;
use super::super::vfs::SecurityDescriptorUpdate;
use super::super::DATA_DIRECTORY_MODE;
use super::super::DATA_FILE_MODE;
use super::super::DATA_ROOT_PATH;
use super::super::DATA_USERS_ROOT_PATH;
use super::super::PUBLIC_DEVICE_MODE;
use super::super::SYSTEM_DEVICE_MODE;
use super::super::SYSTEM_DIRECTORY_MODE;
use super::super::SYSTEM_FILE_MODE;
use super::super::TEMP_DIRECTORY_MODE;
use super::super::TEMP_FILE_MODE;
use super::super::TEMP_MOUNT_PATH;
use super::path_helpers::path_is_descendant_of;
use super::path_helpers::path_is_exact_or_child_of;
use super::types::PermissionMutationPolicy;
use super::types::PermissionMutationScope;

pub(crate) fn permission_mutation_scope_for_path(normalized: &str) -> PermissionMutationScope {
    if normalized == "/"
        || path_is_exact_or_child_of(normalized, "/system")
        || path_is_exact_or_child_of(normalized, "/apps")
    {
        return PermissionMutationScope::SystemManaged;
    }

    if normalized == DATA_ROOT_PATH || normalized == DATA_USERS_ROOT_PATH {
        return PermissionMutationScope::DataBoundary;
    }

    if path_is_descendant_of(normalized, DATA_ROOT_PATH)
        || path_is_exact_or_child_of(normalized, TEMP_MOUNT_PATH)
    {
        return PermissionMutationScope::UserData;
    }

    PermissionMutationScope::SystemManaged
}

pub(crate) fn permission_mutation_policy_for_path(normalized: &str) -> PermissionMutationPolicy {
    PermissionMutationPolicy {
        scope: permission_mutation_scope_for_path(normalized),
    }
}

pub(crate) fn update_changes_ownership(
    current: SecurityDescriptor,
    update: SecurityDescriptorUpdate,
) -> bool {
    matches!(update.owner_uid, Some(owner_uid) if owner_uid != current.owner_uid)
        || matches!(update.owner_gid, Some(owner_gid) if owner_gid != current.owner_gid)
}

pub(crate) fn default_security_descriptor_for_path(
    normalized: &str,
    kind: NodeKind,
) -> SecurityDescriptor {
    if normalized == "/" || is_data_system_boundary_directory(normalized) {
        return system_directory_security_descriptor();
    }

    if kind == NodeKind::Device {
        if let Some(mode) = device_mode_for_path(normalized) {
            return SecurityDescriptor::root(mode);
        }
    }

    if let Some(zone) = default_security_zone_for_path(normalized) {
        return zone_security_descriptor(zone, kind);
    }

    // /tmp is a memory-backed scratch volume writable by anyone.
    if path_is_exact_or_child_of(normalized, TEMP_MOUNT_PATH) {
        let mode = match kind {
            NodeKind::Directory => TEMP_DIRECTORY_MODE,
            NodeKind::File | NodeKind::Device | NodeKind::Symlink => TEMP_FILE_MODE,
        };
        return SecurityDescriptor::guest(mode);
    }

    SecurityDescriptor::root_for_kind(kind)
}

pub(crate) const fn system_directory_security_descriptor() -> SecurityDescriptor {
    SecurityDescriptor::root(SYSTEM_DIRECTORY_MODE)
}

pub(crate) fn device_mode_for_path(normalized: &str) -> Option<u16> {
    match normalized {
        device::CONSOLE_DEVICE_PATH
        | device::STDIN_DEVICE_PATH
        | device::STDOUT_DEVICE_PATH
        | device::STDERR_DEVICE_PATH
        | device::NULL_DEVICE_PATH
        | device::ZERO_DEVICE_PATH => Some(PUBLIC_DEVICE_MODE),
        device::DEBUG_DEVICE_PATH
        | device::SERIAL0_DEVICE_PATH
        | device::KEYBOARD_DEVICE_PATH
        | device::KEYBOARD_RAW_DEVICE_PATH => Some(SYSTEM_DEVICE_MODE),
        _ => None,
    }
}

pub(crate) fn default_security_zone_for_path(normalized: &str) -> Option<StorageZone> {
    if path_is_exact_or_child_of(normalized, "/system") {
        return Some(StorageZone::System);
    }

    if path_is_exact_or_child_of(normalized, "/apps") {
        return Some(StorageZone::Apps);
    }

    // `/data` itself and `/data/users` stay root-owned boundary directories.
    // Guest defaults only begin below those anchor points.
    if path_is_descendant_of(normalized, DATA_ROOT_PATH) {
        return Some(StorageZone::Data);
    }

    None
}

pub(crate) fn is_data_system_boundary_directory(normalized: &str) -> bool {
    normalized == DATA_ROOT_PATH || normalized == DATA_USERS_ROOT_PATH
}

pub(crate) const fn require_directory_kind(kind: NodeKind) -> Result<()> {
    if matches!(kind, NodeKind::Directory) {
        Ok(())
    } else {
        Err(crate::Error::InvalidArgument)
    }
}

pub(crate) const fn zone_mode_for_kind(zone: StorageZone, kind: NodeKind) -> u16 {
    match zone {
        StorageZone::System | StorageZone::Apps => match kind {
            NodeKind::Directory => SYSTEM_DIRECTORY_MODE,
            NodeKind::File => SYSTEM_FILE_MODE,
            NodeKind::Device => SYSTEM_DEVICE_MODE,
            NodeKind::Symlink => SYSTEM_FILE_MODE,
        },
        StorageZone::Data => match kind {
            NodeKind::Directory => DATA_DIRECTORY_MODE,
            NodeKind::File | NodeKind::Device | NodeKind::Symlink => DATA_FILE_MODE,
        },
    }
}

pub(crate) const fn zone_security_descriptor(
    zone: StorageZone,
    kind: NodeKind,
) -> SecurityDescriptor {
    match zone {
        StorageZone::System | StorageZone::Apps => {
            SecurityDescriptor::root(zone_mode_for_kind(zone, kind))
        }
        StorageZone::Data => SecurityDescriptor::guest(zone_mode_for_kind(zone, kind)),
    }
}
