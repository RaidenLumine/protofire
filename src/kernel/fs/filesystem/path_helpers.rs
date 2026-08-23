//! src/kernel/fs/filesystem/path_helpers.rs
//! Path manipulation helpers (free functions) operating on normalized paths.
use alloc::string::String;

use crate::Result;

#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
use super::super::block::{BlockDevice, MemoryBlockDevice};
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
use super::super::demo::build_zone_image;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
use super::super::layout::StorageZone;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
use alloc::sync::Arc;

#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub(crate) fn build_demo_memory_device(
    zone: StorageZone,
    name: &str,
) -> (StorageZone, Arc<dyn BlockDevice>) {
    let image = build_zone_image(zone);
    (
        zone,
        MemoryBlockDevice::new(name, image, zone.device_read_only()),
    )
}

pub(crate) fn matches_mount(path: &str, mount: &str) -> bool {
    if path == mount {
        return true;
    }

    if mount.ends_with('/') || mount == "/" {
        return path.starts_with(mount);
    }

    path.strip_prefix(mount)
        .map(|suffix| suffix.starts_with('/'))
        .unwrap_or(false)
}

pub(crate) fn direct_mount_child_name<'a>(parent: &str, mount_path: &'a str) -> Option<&'a str> {
    if parent == "/" {
        let relative = mount_path.strip_prefix('/')?;
        return single_path_component(relative);
    }

    let relative = mount_path.strip_prefix(parent)?.strip_prefix('/')?;
    single_path_component(relative)
}

pub(crate) fn join_normalized_child(parent: &str, child_name: &str) -> String {
    if parent == "/" {
        let mut path = String::with_capacity(child_name.len() + 1);
        path.push('/');
        path.push_str(child_name);
        return path;
    }

    let mut path = String::with_capacity(parent.len() + child_name.len() + 1);
    path.push_str(parent);
    path.push('/');
    path.push_str(child_name);
    path
}

// Kept crash-recovery / security-token primitive; the install pipeline moved
// out of the kernel and will consume this when re-added.
#[allow(dead_code)]
pub(crate) fn probe_child_normalized_path(
    normalized_dir: &str,
    probe_name: &str,
) -> Result<String> {
    if !is_valid_child_name(probe_name) {
        return Err(crate::Error::InvalidArgument);
    }

    Ok(join_normalized_child(normalized_dir, probe_name))
}

pub(crate) fn single_path_component(component: &str) -> Option<&str> {
    (!component.is_empty() && !component.contains('/')).then_some(component)
}

// Kept crash-recovery / security-token primitive; the install pipeline moved
// out of the kernel and will consume this when re-added.
#[allow(dead_code)]
pub(crate) fn is_valid_child_name(name: &str) -> bool {
    matches!(single_path_component(name), Some(component) if component != "." && component != "..")
}

pub(crate) fn parent_normalized_path(normalized: &str) -> Option<&str> {
    if normalized == "/" {
        return None;
    }

    let (parent, _name) = normalized.rsplit_once('/')?;
    if parent.is_empty() {
        Some("/")
    } else {
        Some(parent)
    }
}

pub(crate) fn path_is_exact_or_child_of(path: &str, root: &str) -> bool {
    path == root || path_is_descendant_of(path, root)
}

pub(crate) fn path_is_descendant_of(path: &str, root: &str) -> bool {
    let Some(remainder) = path.strip_prefix(root) else {
        return false;
    };

    remainder.starts_with('/')
}
