//! src/user/program/launch_reference.rs
//! Launch-reference resolution and trust-boundary validation for catalog-launched programs.
//!
//! This module is the kernel-side launch core: it resolves a launch reference
//! (`current:app`, `app:id@version`, or a plain catalog path) to a catalog
//! file, loads the program image, and validates that the resolved catalog,
//! manifest, and payload stay inside the installed-app trust boundary under
//! `/apps/packages`.  It was relocated here from the removed package-management
//! module so the kernel keeps its process-launch mechanism without any
//! install/uninstall/repo/trusted-key surface.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::fs::path::has_drive_prefix;
use crate::kernel::fs::{self, FileSystem};
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

use super::catalog::SpawnProcessOverrides;
use super::catalog::{normalize_path_relative_to_file, path_parent_dir, read_text_file};
use super::constants::{INSTALLED_CATALOG_ROOT, INSTALLED_CURRENT_ROOT, INSTALLED_PACKAGE_ROOT};
use super::loader::{
    finish_loading_program, resolve_and_load_catalog_image_at_depth, LoadedProgram,
};
use super::metadata::parse_launch_manifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedInstalledLaunchReference {
    pub catalog_path: String,
    pub appended_arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstalledAppReference<'a> {
    pub app_id: &'a str,
    pub version: Option<&'a str>,
}

/// Load an installed program in two phases so the filesystem lock is released
/// before [`finish_loading_program`] calls `global_mut()`.  This prevents a
/// cross-CPU deadlock: the filesystem `SpinLock` disables local interrupts,
/// which would prevent the local CPU from acknowledging a TLB-shootdown IPI
/// from another CPU that holds the memory-manager lock.
pub(crate) fn load_installed_catalog_split_phase(
    fs: &'static Mutex<FileSystem>,
    cwd: &str,
    launch_reference: &str,
    overrides: SpawnProcessOverrides,
) -> Result<LoadedProgram> {
    let normalized_cwd = crate::kernel::fs::path::normalize_path(cwd, "/")?;
    let allow_working_dir_override = overrides.working_dir.is_some();

    // ── Phase 1: resolve the launch reference and read the ELF image from
    //    the filesystem.  Use lock_without_irq_disable so that interrupts
    //    remain enabled — another CPU may hold the memory-manager lock and
    //    need a TLB-shootdown IPI acknowledgment from us. ──
    let (catalog_path, descriptor, image) = {
        let fs_guard = fs.lock_without_irq_disable();
        let resolved =
            resolve_installed_launch_reference(&fs_guard, &normalized_cwd, launch_reference)?;
        let (descriptor, image) = resolve_and_load_catalog_image_at_depth(
            &fs_guard,
            &normalized_cwd,
            &resolved.catalog_path,
            overrides,
            &resolved.appended_arguments,
            0,
        )?;
        (resolved.catalog_path, descriptor, image)
    };
    // ── fs lock released here.  The memory-manager lock may now be acquired
    //    (in finish_loading_program / prepare_runtime) without risking a
    //    deadlock with a cross-CPU TLB shootdown. ──

    // ── Phase 2: validate ELF, prepare runtime (page allocation, etc.). ──
    let loaded = finish_loading_program(descriptor, image)?;

    // ── Phase 3: validate the installed catalog (briefly re-lock fs). ──
    {
        let fs_guard = fs.lock_without_irq_disable();
        validate_installed_catalog_launch_with_options(
            &fs_guard,
            &catalog_path,
            &loaded,
            allow_working_dir_override,
        )?;
    }

    Ok(loaded)
}

pub(crate) fn resolve_installed_launch_reference(
    fs: &FileSystem,
    cwd: &str,
    reference: &str,
) -> Result<ResolvedInstalledLaunchReference> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument);
    }

    Ok(ResolvedInstalledLaunchReference {
        catalog_path: resolve_installed_catalog_reference(fs, cwd, trimmed)?,
        appended_arguments: Vec::new(),
    })
}

pub(crate) fn resolve_installed_catalog_reference(
    fs: &FileSystem,
    cwd: &str,
    reference: &str,
) -> Result<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument);
    }

    if let Some(app_id) = trimmed.strip_prefix("current:") {
        return installed_current_path_from_app_id(app_id);
    }

    // Support both explicit `app:foo` and bare `foo` references so the public
    // launch surface stays concise while still distinguishing obvious paths.
    if let Some(app_reference) = catalog_reference_app_id_candidate(trimmed) {
        return resolve_installed_app_id_reference(fs, app_reference);
    }

    crate::kernel::fs::path::normalize_path(trimmed, cwd)
}

pub(super) fn parse_installed_app_reference(reference: &str) -> Result<InstalledAppReference<'_>> {
    // Installed app references use the compact `app-id` or `app-id@version`
    // syntax rather than a full manifest/catalog URI.
    if let Some((app_id, version)) = reference.split_once('@') {
        if !is_valid_app_id(app_id) || !is_valid_app_version(version) {
            return Err(Error::InvalidArgument);
        }

        return Ok(InstalledAppReference {
            app_id,
            version: Some(version),
        });
    }

    if !is_valid_app_id(reference) {
        return Err(Error::InvalidArgument);
    }

    Ok(InstalledAppReference {
        app_id: reference,
        version: None,
    })
}

pub(super) fn installed_current_path_from_app_id(app_id: &str) -> Result<String> {
    if !is_valid_app_id(app_id) {
        return Err(Error::InvalidArgument);
    }

    Ok(format!("{INSTALLED_CURRENT_ROOT}/{app_id}.toml"))
}

pub(super) fn installed_catalog_path_from_app_reference(
    app_id: &str,
    version: Option<&str>,
) -> Result<String> {
    if !is_valid_app_id(app_id) {
        return Err(Error::InvalidArgument);
    }

    if let Some(version) = version {
        if !is_valid_app_version(version) {
            return Err(Error::InvalidArgument);
        }

        return Ok(format!("{INSTALLED_CATALOG_ROOT}/{app_id}@{version}.toml"));
    }

    Ok(format!("{INSTALLED_CATALOG_ROOT}/{app_id}.toml"))
}

pub(super) fn installed_package_version_root(app_id: &str, version: &str) -> Result<String> {
    let _ = installed_catalog_path_from_app_reference(app_id, Some(version))?;
    Ok(format!("{INSTALLED_PACKAGE_ROOT}/{app_id}/{version}"))
}

pub(super) fn installed_catalog_reference_from_path(
    catalog_path: &str,
) -> Result<InstalledAppReference<'_>> {
    // Recover the logical app reference from the on-disk catalog file name so
    // validation can compare path-derived identity against parsed metadata.
    let file_name = catalog_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or(Error::InvalidArgument)?;
    let Some((catalog_reference, extension)) = file_name.rsplit_once('.') else {
        return Err(Error::InvalidArgument);
    };

    if extension != "toml" {
        return Err(Error::InvalidArgument);
    }

    parse_installed_app_reference(catalog_reference)
}

pub(super) fn installed_package_root_for_app_id(app_id: &str) -> String {
    format!("{INSTALLED_PACKAGE_ROOT}/{app_id}")
}

fn installed_package_version_root_if_present(
    fs: &FileSystem,
    app_id: &str,
    version: Option<&str>,
) -> Result<Option<String>> {
    let Some(version) = version else {
        return Ok(None);
    };
    let version_root = installed_package_version_root(app_id, version)?;
    if path_exists_with_kind(fs, &version_root, fs::NodeKind::Directory)? {
        return Ok(Some(version_root));
    }

    Ok(None)
}

pub(crate) fn installed_expected_package_root(
    fs: &FileSystem,
    app_id: &str,
    version: Option<&str>,
) -> Result<String> {
    // Prefer the version-scoped payload tree when it exists so `app@version`
    // cannot drift across sibling installed versions. Legacy flat app roots are
    // still accepted for older built-in packages that predate versioned trees.
    if let Some(version_root) = installed_package_version_root_if_present(fs, app_id, version)? {
        return Ok(version_root);
    }

    if !is_valid_app_id(app_id) {
        return Err(Error::InvalidArgument);
    }

    Ok(installed_package_root_for_app_id(app_id))
}

pub(crate) fn installed_expected_package_root_for_catalog_path(
    fs: &FileSystem,
    catalog_path: &str,
) -> Result<String> {
    let reference = installed_catalog_reference_from_path(catalog_path)?;
    installed_expected_package_root(fs, reference.app_id, reference.version)
}

pub(super) fn catalog_reference_looks_like_app_id(reference: &str) -> bool {
    // Bare app-id references must not be mistaken for relative paths, absolute
    // paths, drive-prefixed inputs, or already-resolved catalog file names.
    if reference.starts_with('.')
        || reference.contains('/')
        || reference.contains('\\')
        || reference.ends_with(".toml")
        || has_drive_prefix(reference)
    {
        return false;
    }

    true
}

pub(super) fn catalog_reference_app_id_candidate(reference: &str) -> Option<&str> {
    reference
        .strip_prefix("app:")
        .or_else(|| catalog_reference_looks_like_app_id(reference).then_some(reference))
}

pub(super) fn is_installed_launch_catalog_path(path: &str) -> bool {
    path_is_within_root(path, INSTALLED_CATALOG_ROOT)
        || path_is_within_root(path, INSTALLED_CURRENT_ROOT)
}

pub(crate) fn path_is_within_root(path: &str, root: &str) -> bool {
    // Use a segment boundary check so `/apps/catalog-old` does not count as
    // being inside `/apps/catalog`.
    path == root
        || path
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

pub(crate) fn validate_installed_catalog_launch_with_options(
    fs: &FileSystem,
    catalog_path: &str,
    loaded: &LoadedProgram,
    allow_working_dir_override: bool,
) -> Result<()> {
    // Treat installed catalog entries as a trust boundary: the user-facing
    // catalog path, redirected leaf catalog, manifest, binary, working
    // directory, id, and version must all agree before launch is accepted.
    let catalog_reference = installed_catalog_reference_from_path(catalog_path)?;

    if !is_installed_launch_catalog_path(catalog_path) {
        return Err(Error::PermissionDenied);
    }

    if !is_installed_launch_catalog_path(&loaded.catalog_path) {
        return Err(Error::PermissionDenied);
    }

    let leaf_catalog_reference = installed_catalog_reference_from_path(&loaded.catalog_path)?;
    let package_root = installed_expected_package_root(
        fs,
        leaf_catalog_reference.app_id,
        leaf_catalog_reference.version,
    )?;

    if leaf_catalog_reference.app_id != catalog_reference.app_id {
        return Err(Error::PermissionDenied);
    }

    if loaded.catalog_id != catalog_reference.app_id {
        return Err(Error::PermissionDenied);
    }

    if let Some(version) = catalog_reference.version {
        if loaded.version != version {
            return Err(Error::PermissionDenied);
        }
    }

    if catalog_reference.version.is_some()
        && leaf_catalog_reference.version != catalog_reference.version
    {
        return Err(Error::PermissionDenied);
    }

    if let Some(version) = leaf_catalog_reference.version {
        if loaded.version != version {
            return Err(Error::PermissionDenied);
        }
    }

    if !all_paths_within_root(
        &package_root,
        [loaded.manifest_path.as_str(), loaded.path.as_str()],
    ) {
        return Err(Error::PermissionDenied);
    }

    // Always validate the manifest-declared working directory boundary.
    let manifest_text = read_text_file(
        fs,
        path_parent_dir(&loaded.manifest_path),
        &loaded.manifest_path,
    )?;
    let manifest = parse_launch_manifest(&manifest_text)?;
    let manifest_working_dir =
        normalize_path_relative_to_file(&manifest.working_dir, &loaded.manifest_path)?;
    if !all_paths_within_root(&package_root, [manifest_working_dir.as_str()]) {
        return Err(Error::PermissionDenied);
    }

    // In default mode, loaded working_dir must match manifest resolution.
    // Explicit spawn/exec working-dir overrides can opt into relaxed matching.
    if !allow_working_dir_override && loaded.working_dir != manifest_working_dir {
        return Err(Error::PermissionDenied);
    }

    Ok(())
}

pub(super) fn is_valid_app_id(app_id: &str) -> bool {
    !app_id.is_empty()
        && app_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn is_valid_app_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn resolve_installed_app_id_reference(fs: &FileSystem, app_id: &str) -> Result<String> {
    let reference = parse_installed_app_reference(app_id)?;
    if let Some(version) = reference.version {
        return installed_catalog_path_from_app_reference(reference.app_id, Some(version));
    }

    // Prefer the active `current:` redirect first, then the stable catalog
    // alias.  (The latest-published-version scan was removed with the package
    // manager — unknown bare app ids are simply not found.)
    let current_path = installed_current_path_from_app_id(reference.app_id)?;
    if path_exists_with_kind(fs, &current_path, fs::NodeKind::File)? {
        return Ok(current_path);
    }

    let catalog_path = installed_catalog_path_from_app_reference(reference.app_id, None)?;
    if path_exists_with_kind(fs, &catalog_path, fs::NodeKind::File)? {
        return Ok(catalog_path);
    }

    Err(Error::NotFound)
}

// ── filesystem helpers (relocated from the removed install/fs_util.rs) ──

fn path_exists_with_kind(fs: &FileSystem, path: &str, expected_kind: fs::NodeKind) -> Result<bool> {
    match fs.stat_path(path) {
        Ok(metadata) if metadata.kind == expected_kind => Ok(true),
        Ok(_) => Err(Error::InvalidArgument),
        Err(Error::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

fn all_paths_within_root<'a>(root: &str, paths: impl IntoIterator<Item = &'a str>) -> bool {
    paths
        .into_iter()
        .all(|path| path_is_within_root(path, root))
}
