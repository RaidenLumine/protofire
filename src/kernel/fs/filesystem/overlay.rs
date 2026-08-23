//! src/kernel/fs/filesystem/overlay.rs
//! filesystem/overlay — FileSystem merge directory listing methods.

use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use super::super::vfs::Metadata;
use super::path_helpers::{direct_mount_child_name, join_normalized_child};
use super::security_helpers::*;
use crate::Result;

use super::super::vfs::{DirectoryEntry, NodeKind};
use super::super::FileSystem;

impl FileSystem {
    pub(crate) fn root_dir_entries(&self) -> Vec<DirectoryEntry> {
        self.mount_overlay_entries("/")
    }

    pub(crate) fn merged_directory_entries(&self, normalized: &str) -> Result<Vec<DirectoryEntry>> {
        let mut entries = BTreeMap::new();

        if normalized != "/" {
            let (fs, relative_path) = self.require_mount(normalized)?;
            let metadata = fs.stat(&relative_path)?;
            require_directory_kind(metadata.kind)?;
            let backend_support = fs.security_descriptor_mutation_support();

            // Build a single merged listing so nested mounts shadow same-name
            // backing entries and callers observe one stable namespace view.
            let mut index = 0;
            loop {
                match fs.read_dir(&relative_path, index) {
                    Ok(entry) => {
                        let child_path = join_normalized_child(normalized, &entry.name);
                        entries.insert(
                            entry.name.clone(),
                            self.with_mount_effective_security(&child_path, backend_support, entry),
                        );
                        index += 1;
                    }
                    Err(crate::Error::NotFound) => break,
                    Err(error) => return Err(error),
                }
            }
        }

        for entry in self.mount_overlay_entries(normalized) {
            entries.insert(entry.name.clone(), entry);
        }

        Ok(entries.into_values().collect())
    }

    pub(crate) fn mount_overlay_entries(&self, parent: &str) -> Vec<DirectoryEntry> {
        let mut entries = BTreeMap::new();

        for (path, mount) in &self.mounted_fs {
            let Some(name) = direct_mount_child_name(parent, path) else {
                continue;
            };

            let child_path = join_normalized_child(parent, name);
            let backend_support = mount.fs.security_descriptor_mutation_support();
            let metadata = mount
                .fs
                .stat("/")
                .unwrap_or(Metadata::new(NodeKind::Directory, 0));
            entries.insert(
                name.to_string(),
                self.with_mount_effective_security(
                    &child_path,
                    backend_support,
                    DirectoryEntry::new(NodeKind::Directory, metadata.size, name.to_string())
                        .with_security(metadata.security),
                ),
            );
        }

        entries.into_values().collect()
    }
}
