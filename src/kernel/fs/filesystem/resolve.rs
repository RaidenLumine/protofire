//! src/kernel/fs/filesystem/resolve.rs
//! FileSystem mount resolution methods.
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::Result;

use super::super::vfs::{FileSystem as VfsTrait, VNode};
use super::super::FileSystem;
use super::path_helpers::matches_mount;
use super::types::MountPoint;

impl FileSystem {
    pub(crate) fn resolve_mount(&self, path: &str) -> Option<(Arc<dyn VfsTrait>, String)> {
        self.resolve_mount_entry(path)
            .map(|(mount, relative)| (mount.fs.clone(), relative))
    }

    pub(crate) fn require_mount(&self, path: &str) -> Result<(Arc<dyn VfsTrait>, String)> {
        self.resolve_mount(path).ok_or(crate::Error::NotFound)
    }

    pub(crate) fn resolve_mount_entry(&self, path: &str) -> Option<(&MountPoint, String)> {
        let mut best: Option<(&str, &MountPoint)> = None;

        // Use longest-prefix matching so nested mounts shadow broader roots in
        // the same way a conventional VFS mount table behaves.
        for (prefix, mount) in &self.mounted_fs {
            if matches_mount(path, prefix) {
                match best {
                    Some((best_prefix, _)) if best_prefix.len() >= prefix.len() => {}
                    _ => best = Some((prefix.as_str(), mount)),
                }
            }
        }

        best.map(|(prefix, mount)| {
            let relative = if path == prefix {
                "/".to_string()
            } else {
                let suffix = &path[prefix.len()..];
                if suffix.starts_with('/') {
                    suffix.to_string()
                } else {
                    format!("/{}", suffix)
                }
            };

            (mount, relative)
        })
    }

    pub(crate) fn require_mount_entry(&self, path: &str) -> Result<(&MountPoint, String)> {
        self.resolve_mount_entry(path).ok_or(crate::Error::NotFound)
    }

    pub(crate) fn lookup_mount_node(
        mount: &MountPoint,
        relative_path: &str,
    ) -> Result<Option<Arc<dyn VNode>>> {
        match mount.fs.lookup(relative_path) {
            Ok(node) => Ok(Some(node)),
            Err(crate::Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
