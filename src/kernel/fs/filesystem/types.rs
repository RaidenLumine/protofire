//! src/kernel/fs/filesystem/types.rs
//!
//! Supporting types for the filesystem layer.
//!
//! Includes mount-point tracking, permission-mutation policies,
//! security-descriptor update plans, boot-disk layout sources,
//! storage-init reports, and the [`SecurityAttachable`] trait.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::Result;

use super::super::block::BlockDevice;
use super::super::layout::StorageZone;
use super::super::vfs::{
    DirectoryEntry, FileSystem as VfsTrait, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport,
};

pub(crate) struct MountPoint {
    pub(crate) fs: Arc<dyn VfsTrait>,
    pub(crate) fs_name: String,
    pub(crate) device: String,
    pub(crate) flags: u32,
}

pub(crate) type ZoneDeviceBindings = Vec<(StorageZone, Arc<dyn BlockDevice>)>;
pub(crate) type ResolvedMountEntry<'a> = (&'a MountPoint, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermissionMutationScope {
    SystemManaged,
    DataBoundary,
    UserData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PermissionMutationPolicy {
    pub(crate) scope: PermissionMutationScope,
}

impl PermissionMutationPolicy {
    pub(crate) const fn scope(self) -> PermissionMutationScope {
        self.scope
    }

    pub(crate) const fn requires_recovery_mode(self) -> bool {
        matches!(self.scope, PermissionMutationScope::SystemManaged)
    }

    pub(crate) const fn requires_privileged_actor(self) -> bool {
        !matches!(self.scope, PermissionMutationScope::UserData)
    }

    pub(crate) const fn allows_unprivileged_owned_mode_change(self) -> bool {
        matches!(self.scope, PermissionMutationScope::UserData)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PlannedSecurityDescriptorUpdate {
    pub(crate) current: SecurityDescriptor,
    pub(crate) updated: SecurityDescriptor,
    pub(crate) scope: PermissionMutationScope,
    pub(crate) backend_support: SecurityDescriptorMutationSupport,
}

impl PlannedSecurityDescriptorUpdate {
    // Kept crash-recovery / security-token primitive; the install pipeline moved
    // out of the kernel and will consume this when re-added.
    #[allow(dead_code)]
    pub(crate) const fn requires_recovery_mode(self) -> bool {
        PermissionMutationPolicy { scope: self.scope }.requires_recovery_mode()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn supports_persistent_backend_update(self) -> bool {
        self.backend_support.supports_persistent_updates()
    }

    pub(crate) fn require_persistent_backend_update(self) -> Result<Self> {
        if self.supports_persistent_backend_update() {
            Ok(self)
        } else {
            Err(crate::Error::Unsupported)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootDiskLayoutSource {
    MbrPartitions,
    FixedZoneFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageInitReport {
    BootDiskMbrPartitions,
    BootDiskFixedZoneFallback,
    // Constructed only on host / demo-disk / test builds; on any bare-metal
    // non-demo boot (x86_64 / aarch64 / riscv64) the variant is never built.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    MemoryDemo {
        boot_disk_error: Option<crate::Error>,
    },
    Failed {
        boot_disk_error: Option<crate::Error>,
        memory_demo_error: crate::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub path: String,
    pub fs_name: String,
    pub device: String,
    pub flags: u32,
}

pub(crate) trait SecurityAttachable: Sized {
    fn node_kind(&self) -> NodeKind;
    fn attach_security(self, security: SecurityDescriptor) -> Self;
}

impl SecurityAttachable for Metadata {
    fn node_kind(&self) -> NodeKind {
        self.kind
    }

    fn attach_security(self, security: SecurityDescriptor) -> Self {
        self.with_security(security)
    }
}

impl SecurityAttachable for DirectoryEntry {
    fn node_kind(&self) -> NodeKind {
        self.kind
    }

    fn attach_security(self, security: SecurityDescriptor) -> Self {
        self.with_security(security)
    }
}
