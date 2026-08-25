//! src/kernel/fs/filesystem/security.rs
//!
//! FileSystem authorization and access-control methods.

use alloc::string::String;
use alloc::sync::Arc;

use crate::kernel::process::SecurityToken;
use crate::Result;

use super::super::vfs::{
    Metadata, MetadataAccessQueryContext, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, SecurityDescriptorUpdate, VNode,
};
use super::super::FileSystem;
use super::super::{ACCESS_EXECUTE_BIT, ACCESS_READ_BIT, ACCESS_WRITE_BIT};
use super::access_helpers::{
    mount_allows_write_for_security_token, open_requires_mount_write_access,
    path_write_access_visible_to_security_token, required_open_access,
};
use super::path_helpers::parent_normalized_path;
use super::security_helpers::{
    default_security_descriptor_for_path, require_directory_kind, update_changes_ownership,
};
use super::types::MountPoint;
use super::types::{PermissionMutationScope, ResolvedMountEntry, SecurityAttachable};

impl FileSystem {
    pub(crate) fn with_default_security<T: SecurityAttachable>(
        &self,
        normalized: &str,
        item: T,
    ) -> T {
        let kind = item.node_kind();
        item.attach_security(default_security_descriptor_for_path(normalized, kind))
    }

    pub(crate) fn with_mount_effective_security<T: SecurityAttachable>(
        &self,
        normalized: &str,
        backend_support: SecurityDescriptorMutationSupport,
        item: T,
    ) -> T {
        if backend_support.provides_persistent_metadata() {
            item
        } else {
            self.with_default_security(normalized, item)
        }
    }

    pub(crate) fn open_existing_file_node(
        &self,
        normalized: &str,
        desired_access: u32,
        security_token: SecurityToken,
    ) -> Result<Arc<dyn VNode>> {
        self.authorize_existing_open(normalized, desired_access, security_token)?;
        self.lookup(normalized)
    }

    pub(crate) fn create_new_file_node(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<Arc<dyn VNode>> {
        self.with_authorized_namespace_mutation(
            normalized,
            security_token,
            |mount, relative_path| match Self::lookup_mount_node(mount, relative_path)? {
                Some(_) => Err(crate::Error::AlreadyExists),
                None => mount.fs.create_file(relative_path),
            },
        )
    }

    pub(crate) fn open_or_create_file_node(
        &self,
        normalized: &str,
        desired_access: u32,
        security_token: SecurityToken,
    ) -> Result<Arc<dyn VNode>> {
        let (mount, relative_path) = self.require_mount_entry(normalized)?;
        match Self::lookup_mount_node(mount, &relative_path)? {
            Some(node) => {
                self.authorize_existing_open(normalized, desired_access, security_token)?;
                Ok(node)
            }
            None => self.create_missing_file_node(normalized, security_token),
        }
    }

    pub(crate) fn authorize_existing_open(
        &self,
        normalized: &str,
        desired_access: u32,
        security_token: SecurityToken,
    ) -> Result<()> {
        let (metadata, required_access) =
            self.authorized_existing_open_metadata_for(normalized, desired_access, security_token)?;
        if open_requires_mount_write_access(metadata.kind, required_access) {
            // Device I/O may legitimately remain writable through a read-only
            // devfs mount because the mount protects namespace mutation, not
            // the device backend's read/write operations.
            self.require_mount_write_access(normalized, security_token)?;
        }
        Ok(())
    }

    pub(crate) fn authorize_parent_directory_mutation(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        let parent = parent_normalized_path(normalized).ok_or(crate::Error::InvalidArgument)?;
        self.require_mount_write_access(normalized, security_token)?;
        self.authorize_directory_access(
            parent,
            ACCESS_WRITE_BIT | ACCESS_EXECUTE_BIT,
            security_token,
        )
    }

    pub(crate) fn resolve_authorized_namespace_mutation(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<(&MountPoint, String)> {
        // Namespace mutations share the same gate: writable parent directory
        // plus a mount that is writable for the current security context.
        self.authorize_parent_directory_mutation(normalized, security_token)?;
        self.require_mount_entry(normalized)
    }

    pub(crate) fn resolve_same_mount_rename_entries(
        &self,
        normalized_old: &str,
        normalized_new: &str,
    ) -> Result<(ResolvedMountEntry<'_>, ResolvedMountEntry<'_>)> {
        let old_entry = self.require_mount_entry(normalized_old)?;
        let new_entry = self.require_mount_entry(normalized_new)?;
        if !Arc::ptr_eq(&old_entry.0.fs, &new_entry.0.fs) {
            return Err(crate::Error::Unsupported);
        }

        Ok((old_entry, new_entry))
    }

    pub(crate) fn create_missing_file_node(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<Arc<dyn VNode>> {
        self.with_authorized_namespace_mutation(
            normalized,
            security_token,
            |mount, relative_path| mount.fs.create_file(relative_path),
        )
    }

    pub(crate) fn with_authorized_namespace_mutation<T>(
        &self,
        normalized: &str,
        security_token: SecurityToken,
        f: impl FnOnce(&MountPoint, &str) -> Result<T>,
    ) -> Result<T> {
        let (mount, relative_path) =
            self.resolve_authorized_namespace_mutation(normalized, security_token)?;
        f(mount, &relative_path)
    }

    pub(crate) fn authorize_namespace_mutation_targets(
        &self,
        normalized_paths: &[&str],
        security_token: SecurityToken,
    ) -> Result<()> {
        for normalized in normalized_paths {
            self.authorize_parent_directory_mutation(normalized, security_token)?;
        }

        Ok(())
    }

    pub(crate) fn authorize_directory_access(
        &self,
        normalized: &str,
        required_access: u16,
        security_token: SecurityToken,
    ) -> Result<()> {
        self.authorized_directory_metadata_for(normalized, required_access, security_token)
            .map(|_| ())
    }

    pub(crate) fn authorized_existing_open_metadata_for(
        &self,
        normalized: &str,
        desired_access: u32,
        security_token: SecurityToken,
    ) -> Result<(Metadata, u16)> {
        let metadata = self.stat_normalized_path(normalized)?;
        let required_access = required_open_access(metadata.kind, desired_access);
        let context = self.effective_access_query_context_for_metadata(
            normalized,
            &metadata,
            required_access,
            security_token,
        );
        if !context.access.allowed {
            return Err(crate::Error::PermissionDenied);
        }
        Ok((metadata, required_access))
    }

    pub(crate) fn authorized_directory_metadata_for(
        &self,
        normalized: &str,
        required_access: u16,
        security_token: SecurityToken,
    ) -> Result<Metadata> {
        let metadata = self.stat_normalized_path(normalized)?;
        require_directory_kind(metadata.kind)?;
        let context = self.effective_access_query_context_for_metadata(
            normalized,
            &metadata,
            required_access,
            security_token,
        );
        if !context.access.allowed {
            return Err(crate::Error::PermissionDenied);
        }
        Ok(metadata)
    }

    pub(crate) fn access_query_context_for_normalized_path_with_security_token(
        &self,
        normalized: &str,
        required_access: u16,
        security_token: SecurityToken,
    ) -> Result<MetadataAccessQueryContext> {
        let metadata = self.stat_normalized_path(normalized)?;
        Ok(self.effective_access_query_context_for_metadata(
            normalized,
            &metadata,
            required_access,
            security_token,
        ))
    }

    pub(crate) fn authorize_security_descriptor_update_for_normalized_path(
        &self,
        normalized: &str,
        current: SecurityDescriptor,
        update: SecurityDescriptorUpdate,
        security_token: SecurityToken,
    ) -> Result<PermissionMutationScope> {
        self.require_mount_write_access(normalized, security_token)?;

        let policy = self.permission_mutation_policy_for_normalized_path(normalized);
        let scope = policy.scope();
        if security_token.is_system() {
            return Ok(scope);
        }

        if policy.requires_recovery_mode() {
            return if security_token.is_recovery_mode() {
                Ok(scope)
            } else {
                Err(crate::Error::PermissionDenied)
            };
        }

        if policy.requires_privileged_actor() {
            return if security_token.is_admin_mode() || security_token.is_recovery_mode() {
                Ok(scope)
            } else {
                Err(crate::Error::PermissionDenied)
            };
        }

        if security_token.is_admin_mode() || security_token.is_recovery_mode() {
            return Ok(scope);
        }

        if !policy.allows_unprivileged_owned_mode_change()
            || security_token.user_id != current.owner_uid
            || update_changes_ownership(current, update)
        {
            return Err(crate::Error::PermissionDenied);
        }

        Ok(scope)
    }

    pub(crate) fn require_mount_write_access(
        &self,
        normalized: &str,
        security_token: SecurityToken,
    ) -> Result<()> {
        let Some((mount, _relative_path)) = self.resolve_mount_entry(normalized) else {
            return Ok(());
        };

        // Ordinary writes require a writable mount. Recovery is the only
        // privileged mode that may temporarily bypass a read-only mount flag
        // to repair a writable backend without widening the general admin
        // write surface.
        if !mount_allows_write_for_security_token(mount.flags, security_token) {
            return Err(crate::Error::PermissionDenied);
        }

        Ok(())
    }

    pub(crate) fn effective_access_query_context_for_metadata(
        &self,
        normalized: &str,
        metadata: &Metadata,
        required_access: u16,
        security_token: SecurityToken,
    ) -> MetadataAccessQueryContext {
        let mut context = metadata.access_query_context_for(required_access, security_token);

        if metadata.kind != NodeKind::Device
            && context.access.can_write
            && !path_write_access_visible_to_security_token(normalized, security_token, self)
        {
            context.access.granted_mode_bits &= !ACCESS_WRITE_BIT;
            context.access.can_write = false;
            context.access.allowed = required_access & !context.access.granted_mode_bits == 0;
        }

        // ── MAC (type enforcement) check ────────────────────────────────
        // Runs after the DAC + Biba result, on the same single hook that all
        // file operations flow through.  When the loaded MAC policy denies the
        // (subject type, object type, class, perms) request, the access is
        // revoked regardless of the DAC outcome.
        if context.access.allowed {
            let class = if metadata.kind == NodeKind::Directory {
                crate::kernel::process::mac::MAC_CLASS_DIR
            } else {
                crate::kernel::process::mac::MAC_CLASS_FILE
            };
            let mut perms = 0;
            if required_access & ACCESS_READ_BIT != 0 {
                perms |= crate::kernel::process::mac::MAC_PERM_READ;
            }
            if required_access & ACCESS_WRITE_BIT != 0 {
                perms |= crate::kernel::process::mac::MAC_PERM_WRITE;
            }
            if required_access & ACCESS_EXECUTE_BIT != 0 {
                if metadata.kind == NodeKind::Directory {
                    perms |= crate::kernel::process::mac::MAC_PERM_SEARCH;
                } else {
                    perms |= crate::kernel::process::mac::MAC_PERM_EXEC;
                }
            }
            if crate::kernel::process::mac::check_file(
                security_token.mac_type(),
                normalized,
                class,
                perms,
                security_token.user_id,
            )
            .is_err()
            {
                context.access.allowed = false;
                context.access.granted_mode_bits = 0;
                context.access.can_read = false;
                context.access.can_write = false;
                context.access.can_execute = false;
            }
        }

        context
    }
}
