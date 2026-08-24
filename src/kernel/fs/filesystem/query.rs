//! src/kernel/fs/filesystem/query.rs
//!
//! filesystem/query — FileSystem query, stat, normalize, lookup, and security methods.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::process::SecurityToken;
use crate::Result;

use super::super::block::BlockDeviceInfo;
use super::super::path;
use super::super::vfs::{
    Metadata, NodeKind, PermissionMetadataRecord, SecurityDescriptorMutationSupport,
    SecurityDescriptorUpdate, VNode, VolumeCheckReport,
};
use super::super::{FileSystem, MountInfo};
use super::profiler;
use super::security_helpers::*;
use super::types::{PermissionMutationPolicy, PlannedSecurityDescriptorUpdate, StorageInitReport};

impl FileSystem {
    pub fn check_and_repair_volume(&self, path: &str) -> Result<VolumeCheckReport> {
        let normalized = self.normalize_path(path)?;
        self.check_and_repair_volume_normalized(&normalized)
    }

    pub fn check_and_repair_volume_from(&self, path: &str, cwd: &str) -> Result<VolumeCheckReport> {
        let normalized = self.normalize_path_from(path, cwd)?;
        self.check_and_repair_volume_normalized(&normalized)
    }

    pub(crate) fn check_and_repair_volume_normalized(
        &self,
        normalized: &str,
    ) -> Result<VolumeCheckReport> {
        if normalized == "/" {
            return Err(crate::Error::Unsupported);
        }

        let (fs, _) = self.require_mount(normalized)?;
        fs.check_and_repair()
    }

    pub fn set_current_working_dir(&self, path: &str) -> Result<()> {
        let normalized = self.normalize_path(path)?;
        *self.current_working_dir.lock() = normalized;
        Ok(())
    }

    pub fn current_working_dir(&self) -> String {
        self.current_working_dir.lock().clone()
    }

    // Kept storage-init status primitive; the install pipeline moved out of the
    // kernel and will consume this when re-added.
    #[allow(dead_code)]
    pub(crate) fn storage_init_report(&self) -> Option<StorageInitReport> {
        *self.storage_init_report.lock()
    }

    pub fn mount_points(&self) -> Vec<MountInfo> {
        self.mounted_fs
            .iter()
            .map(|(path, mount)| MountInfo {
                path: path.clone(),
                fs_name: mount.fs_name.clone(),
                device: mount.device.clone(),
                flags: mount.flags,
            })
            .collect()
    }

    pub fn block_devices(&self) -> Vec<BlockDeviceInfo> {
        self.block_devices
            .values()
            .map(|device| BlockDeviceInfo {
                name: device.name().to_string(),
                block_size: device.block_size(),
                block_count: device.block_count(),
                read_only: device.is_read_only(),
            })
            .collect()
    }

    /// Aggregate filesystem operation counters across all mounted volumes.
    pub fn fs_profiler_snapshot(&self) -> profiler::FsProfilerSnapshot {
        let mut snap = profiler::FsProfilerSnapshot::default();
        for vfs in self.filesystems.values() {
            let v = vfs.fs_profiler_snapshot();
            snap.lookups = snap.lookups.saturating_add(v.lookups);
            snap.reads = snap.reads.saturating_add(v.reads);
            snap.writes = snap.writes.saturating_add(v.writes);
            snap.creates = snap.creates.saturating_add(v.creates);
            snap.deletes = snap.deletes.saturating_add(v.deletes);
            snap.renames = snap.renames.saturating_add(v.renames);
            snap.transactions = snap.transactions.saturating_add(v.transactions);
            snap.metadata_flushes = snap.metadata_flushes.saturating_add(v.metadata_flushes);
            snap.elapsed_ticks = snap.elapsed_ticks.saturating_add(v.elapsed_ticks);
        }
        snap
    }

    pub fn normalize_path(&self, path: &str) -> Result<String> {
        let cwd = self.current_working_dir.lock().clone();
        self.normalize_path_from(path, &cwd)
    }

    pub(crate) fn normalize_path_from(&self, path: &str, cwd: &str) -> Result<String> {
        path::normalize_path(path, cwd)
    }

    pub(crate) fn normalize_path_pair_from(
        &self,
        first: &str,
        second: &str,
        cwd: &str,
    ) -> Result<(String, String)> {
        Ok((
            path::normalize_path(first, cwd)?,
            path::normalize_path(second, cwd)?,
        ))
    }

    pub(crate) fn lookup(&self, normalized: &str) -> Result<Arc<dyn VNode>> {
        if normalized == "/" {
            return Ok(self.root.clone());
        }

        let (fs, relative_path) = self.require_mount(normalized)?;
        fs.lookup(&relative_path)
    }

    pub(crate) fn stat_normalized_path(&self, normalized: &str) -> Result<Metadata> {
        if normalized == "/" {
            return Ok(self.with_default_security(
                normalized,
                Metadata::new(NodeKind::Directory, self.root_dir_entries().len()),
            ));
        }

        let (fs, relative_path) = self.require_mount(normalized)?;
        let backend_support = fs.security_descriptor_mutation_support();
        let metadata = self.with_mount_effective_security(
            normalized,
            backend_support,
            fs.stat(&relative_path)?,
        );
        if metadata.kind != NodeKind::Directory {
            return Ok(metadata);
        }

        Ok(self.with_mount_effective_security(
            normalized,
            backend_support,
            Metadata::new(
                NodeKind::Directory,
                self.merged_directory_entries(normalized)?.len(),
            )
            .with_security(metadata.security),
        ))
    }

    pub(crate) fn permission_metadata_for_normalized_path(
        &self,
        normalized: &str,
    ) -> Result<PermissionMetadataRecord> {
        Ok(self
            .stat_normalized_path(normalized)?
            .permission_metadata_record())
    }

    pub(crate) fn permission_mutation_policy_for_normalized_path(
        &self,
        normalized: &str,
    ) -> PermissionMutationPolicy {
        permission_mutation_policy_for_path(normalized)
    }

    pub(crate) fn security_descriptor_mutation_support_for_normalized_path(
        &self,
        normalized: &str,
    ) -> SecurityDescriptorMutationSupport {
        match self.resolve_mount_entry(normalized) {
            Some((mount, _relative_path)) => mount.fs.security_descriptor_mutation_support(),
            None => SecurityDescriptorMutationSupport::LayoutDerivedOnly,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn plan_security_descriptor_update_for_normalized_path(
        &self,
        normalized: &str,
        update: SecurityDescriptorUpdate,
        security_token: SecurityToken,
    ) -> Result<PlannedSecurityDescriptorUpdate> {
        let metadata = self.stat_normalized_path(normalized)?;
        let scope = self.authorize_security_descriptor_update_for_normalized_path(
            normalized,
            metadata.security,
            update,
            security_token,
        )?;
        let updated = metadata.security.apply_update(update)?;
        let backend_support =
            self.security_descriptor_mutation_support_for_normalized_path(normalized);

        Ok(PlannedSecurityDescriptorUpdate {
            current: metadata.security,
            updated,
            scope,
            backend_support,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn preflight_persistent_security_descriptor_update_for_normalized_path(
        &self,
        normalized: &str,
        update: SecurityDescriptorUpdate,
        security_token: SecurityToken,
    ) -> Result<PlannedSecurityDescriptorUpdate> {
        self.plan_security_descriptor_update_for_normalized_path(
            normalized,
            update,
            security_token,
        )?
        .require_persistent_backend_update()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn update_persistent_security_descriptor_for_normalized_path(
        &self,
        normalized: &str,
        update: SecurityDescriptorUpdate,
        security_token: SecurityToken,
    ) -> Result<PlannedSecurityDescriptorUpdate> {
        let planned = self.preflight_persistent_security_descriptor_update_for_normalized_path(
            normalized,
            update,
            security_token,
        )?;
        let (mount, relative_path) = self.require_mount_entry(normalized)?;
        mount
            .fs
            .update_security_descriptor(&relative_path, planned.updated)?;
        Ok(planned)
    }
}
