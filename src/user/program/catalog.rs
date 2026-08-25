//! src/user/program/catalog.rs
//!
//! Catalog entry, launch manifest, and catalog→image resolution chain.
//!
//! This module resolves a catalog path (e.g. `/apps/current/shell.toml`)
//! through optional redirects, parses the launch manifest, verifies signatures
//! and checksums, and loads the ELF image bytes.  The resulting
//! [`ResolvedCatalogLaunch`] is consumed by the loader layer to produce a
//! [`super::loader::LoadedProgram`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::fs::FileSystem;
use crate::kernel::fs::{self};
use crate::kernel::process::Scheduler;
use crate::kernel::process::SecurityToken;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::Error;
use crate::Result;

use super::constants;
use super::integrity;
// Resolved from launch_reference directly (the install module re-exported these
// path helpers but is gated out of host builds, while catalog stays live via
// the spawn path).
use super::launch_reference::installed_expected_package_root_for_catalog_path;
use super::launch_reference::path_is_within_root;
use super::metadata::parse_catalog_entry;
use super::metadata::parse_launch_manifest;
use super::signature;

// ── public catalog / manifest types ───────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct CatalogEntry {
    pub id: String,
    pub version: Option<String>,
    pub manifest_path: Option<String>,
    pub catalog_path: Option<String>,
    pub manifest_sha256: Option<String>,
    pub manifest_signature: Option<String>,
    pub source_reference: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct LaunchManifest {
    pub name: String,
    pub version: String,
    pub format: String,
    pub entry_path: String,
    pub entry_sha256: Option<String>,
    pub entry_signature: Option<String>,
    pub working_dir: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    pub(crate) host_proxy: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnProcessOverrides {
    pub arguments: Option<Vec<String>>,
    pub environment: Option<Vec<String>>,
    pub working_dir: Option<String>,
}

// ── private resolution types ──────────────────────────────────────────

pub(crate) struct ResolvedCatalogLaunch {
    pub catalog_path: String,
    pub catalog_id: String,
    pub manifest_path: String,
    pub image_path: String,
    pub name: String,
    pub version: String,
    pub working_dir: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    pub host_proxy: Option<String>,
    pub image: Vec<u8>,
}

struct ResolvedCatalogLaunchArtifacts {
    manifest_path: String,
    image_path: String,
    manifest_working_dir: String,
    image: Vec<u8>,
}

struct ResolvedCatalogLaunchContent {
    name: String,
    version: String,
    working_dir: String,
    arguments: Vec<String>,
    environment: Vec<String>,
    host_proxy: Option<String>,
}

struct ResolvedCatalogEntry {
    normalized_cwd: String,
    normalized_catalog_path: String,
    catalog: CatalogEntry,
}

// ── ResolvedCatalogEntry impl ─────────────────────────────────────────

impl ResolvedCatalogEntry {
    fn load(fs: &FileSystem, cwd: &str, catalog_path: &str) -> Result<Self> {
        let normalized_cwd = crate::kernel::fs::path::normalize_path(cwd, "/")?;
        let normalized_catalog_path =
            crate::kernel::fs::path::normalize_path(catalog_path, &normalized_cwd)?;
        let catalog_text = read_text_file(fs, &normalized_cwd, &normalized_catalog_path)?;
        let catalog = parse_catalog_entry(&catalog_text)?;

        Ok(Self {
            normalized_cwd,
            normalized_catalog_path,
            catalog,
        })
    }

    fn resolve_launch_at_depth(
        self,
        fs: &FileSystem,
        overrides: SpawnProcessOverrides,
        appended_arguments: &[String],
        redirect_depth: usize,
    ) -> Result<ResolvedCatalogLaunch> {
        if let Some(resolved) = self.resolve_redirect_at_depth(
            fs,
            overrides.clone(),
            appended_arguments,
            redirect_depth,
        )? {
            return Ok(resolved);
        }

        self.resolve_direct_launch(fs, overrides, appended_arguments)
    }

    fn resolve_redirect_at_depth(
        &self,
        fs: &FileSystem,
        overrides: SpawnProcessOverrides,
        appended_arguments: &[String],
        redirect_depth: usize,
    ) -> Result<Option<ResolvedCatalogLaunch>> {
        let Some(redirect_catalog_path) = self.catalog.catalog_path.as_deref() else {
            return Ok(None);
        };
        if redirect_depth >= constants::MAX_CATALOG_REDIRECT_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let normalized_redirect_catalog_path =
            normalize_path_relative_to_file(redirect_catalog_path, &self.normalized_catalog_path)?;
        validate_catalog_redirect_target(
            &self.normalized_catalog_path,
            &normalized_redirect_catalog_path,
        )?;
        let resolved = resolve_catalog_launch_with_appended_arguments_at_depth(
            fs,
            &self.normalized_cwd,
            &normalized_redirect_catalog_path,
            overrides,
            appended_arguments,
            redirect_depth + 1,
        )?;
        validate_catalog_redirect_entry(&self.catalog, &resolved)?;
        Ok(Some(resolved))
    }

    fn resolve_direct_launch(
        self,
        fs: &FileSystem,
        overrides: SpawnProcessOverrides,
        appended_arguments: &[String],
    ) -> Result<ResolvedCatalogLaunch> {
        let normalized_manifest_path = normalize_path_relative_to_file(
            self.catalog
                .manifest_path
                .as_deref()
                .ok_or(Error::InvalidArgument)?,
            &self.normalized_catalog_path,
        )?;
        let manifest_text = read_text_file(
            fs,
            path_parent_dir(&normalized_manifest_path),
            &normalized_manifest_path,
        )?;
        let manifest = parse_launch_manifest(&manifest_text)?;
        validate_catalog_manifest_entry(&self.catalog, &manifest)?;
        let _ = integrity::verify_optional_sha256(
            manifest_text.as_bytes(),
            self.catalog.manifest_sha256.as_deref(),
        )?;
        signature::verify_optional_signature(
            fs,
            manifest_text.as_bytes(),
            self.catalog.manifest_signature.as_deref(),
        )?;
        let artifacts = ResolvedCatalogLaunchArtifacts::resolve_from_manifest(
            fs,
            &self.normalized_catalog_path,
            normalized_manifest_path,
            &manifest,
        )?;
        let content = ResolvedCatalogLaunchContent::resolve_from_manifest(
            manifest,
            overrides,
            appended_arguments,
            &artifacts.manifest_working_dir,
            &self.normalized_cwd,
        )?;

        Ok(ResolvedCatalogLaunch {
            catalog_path: self.normalized_catalog_path,
            catalog_id: self.catalog.id,
            manifest_path: artifacts.manifest_path,
            image_path: artifacts.image_path,
            name: content.name,
            version: content.version,
            working_dir: content.working_dir,
            arguments: content.arguments,
            environment: content.environment,
            host_proxy: content.host_proxy,
            image: artifacts.image,
        })
    }
}

// ── ResolvedCatalogLaunchArtifacts impl ───────────────────────────────

impl ResolvedCatalogLaunchArtifacts {
    fn resolve_from_manifest(
        fs: &FileSystem,
        normalized_catalog_path: &str,
        normalized_manifest_path: String,
        manifest: &LaunchManifest,
    ) -> Result<Self> {
        let installed_package_root = installed_catalog_package_root(fs, normalized_catalog_path)?;
        let normalized_manifest_working_dir =
            normalize_path_relative_to_file(&manifest.working_dir, &normalized_manifest_path)?;
        let normalized_image_path =
            normalize_path_relative_to_file(&manifest.entry_path, &normalized_manifest_path)?;
        validate_installed_catalog_launch_paths(
            installed_package_root.as_deref(),
            &normalized_manifest_path,
            &normalized_image_path,
            &normalized_manifest_working_dir,
        )?;
        let image = read_program_image(
            fs,
            path_parent_dir(&normalized_manifest_path),
            &normalized_image_path,
        )?;
        let _ = integrity::verify_optional_sha256(&image, manifest.entry_sha256.as_deref())?;
        signature::verify_optional_signature(fs, &image, manifest.entry_signature.as_deref())?;

        Ok(Self {
            manifest_path: normalized_manifest_path,
            image_path: normalized_image_path,
            manifest_working_dir: normalized_manifest_working_dir,
            image,
        })
    }
}

// ── ResolvedCatalogLaunchContent impl ─────────────────────────────────

impl ResolvedCatalogLaunchContent {
    fn resolve_from_manifest(
        manifest: LaunchManifest,
        overrides: SpawnProcessOverrides,
        appended_arguments: &[String],
        normalized_manifest_working_dir: &str,
        normalized_cwd: &str,
    ) -> Result<Self> {
        let LaunchManifest {
            name,
            version,
            arguments: manifest_arguments,
            environment: manifest_environment,
            host_proxy,
            ..
        } = manifest;
        let SpawnProcessOverrides {
            arguments,
            environment,
            working_dir,
        } = overrides;
        let mut arguments = arguments.unwrap_or(manifest_arguments);
        if !appended_arguments.is_empty() {
            // `open:` launches append the target path after the manifest or override
            // argv so the opened file becomes a normal positional argument.
            arguments.extend(appended_arguments.iter().cloned());
        }
        let environment = environment.unwrap_or(manifest_environment);
        let working_dir =
            working_dir.unwrap_or_else(|| String::from(normalized_manifest_working_dir));
        let working_dir = crate::kernel::fs::path::normalize_path(&working_dir, normalized_cwd)?;

        Ok(Self {
            name,
            version,
            working_dir,
            arguments,
            environment,
            host_proxy,
        })
    }
}

// ── catalog resolution entry point ────────────────────────────────────

pub fn resolve_catalog_launch_with_appended_arguments_at_depth(
    fs: &FileSystem,
    cwd: &str,
    catalog_path: &str,
    overrides: SpawnProcessOverrides,
    appended_arguments: &[String],
    redirect_depth: usize,
) -> Result<ResolvedCatalogLaunch> {
    let entry = ResolvedCatalogEntry::load(fs, cwd, catalog_path)?;
    entry.resolve_launch_at_depth(fs, overrides, appended_arguments, redirect_depth)
}

// ── file I/O helpers ──────────────────────────────────────────────────

pub fn read_program_image(fs: &FileSystem, cwd: &str, path: &str) -> Result<Vec<u8>> {
    let mut file =
        open_file_from_with_current_security(fs, cwd, path, HANDLE_RIGHT_READ, fs::OPEN_EXISTING)?;
    let mut image = Vec::new();
    let mut chunk = [0_u8; 128];

    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }

        image.extend_from_slice(&chunk[..count]);
    }

    Ok(image)
}

pub fn read_text_file(fs: &FileSystem, cwd: &str, path: &str) -> Result<String> {
    let image = read_program_image(fs, cwd, path)?;
    String::from_utf8(image).map_err(|_| Error::InvalidArgument)
}

pub fn path_parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((parent, _)) => parent,
    }
}

pub fn normalize_path_relative_to_file(path: &str, source_file: &str) -> Result<String> {
    // Catalog and manifest metadata paths are resolved from the declaring file,
    // not from the caller's cwd.
    crate::kernel::fs::path::normalize_path(path, path_parent_dir(source_file))
}

pub fn current_execution_security_token() -> SecurityToken {
    Scheduler::global()
        .and_then(|scheduler| scheduler.current_thread())
        .map(|thread| thread.process().security_token())
        .unwrap_or_else(SecurityToken::system)
}

fn open_file_from_with_current_security(
    fs: &FileSystem,
    cwd: &str,
    path: &str,
    desired_access: u32,
    creation_disposition: u32,
) -> Result<fs::FileHandle> {
    let normalized = crate::kernel::fs::path::normalize_path(path, cwd)?;
    fs.create_file_normalized_with_security_token(
        &normalized,
        desired_access,
        0,
        creation_disposition,
        current_execution_security_token(),
    )
}

pub fn normalize_path_from_root(path: &str) -> Result<String> {
    crate::kernel::fs::path::normalize_path(path, "/")
}

pub fn normalize_path_pair_from_root(first: &str, second: &str) -> Result<(String, String)> {
    Ok((
        normalize_path_from_root(first)?,
        normalize_path_from_root(second)?,
    ))
}

// ── FS mutation helpers (used by the appctl/lumina CLI surface) ───────
// These are user-facing complete-OS operations that belong out of the kernel;
// they are reachable only through the demo disk / tests, so they are gated
// with the app module that calls them.

#[cfg(any(feature = "demo-disk", test))]
pub fn create_dir_with_current_security(fs: &FileSystem, path: &str) -> Result<()> {
    let normalized = normalize_path_from_root(path)?;
    fs.create_dir_normalized_with_security_token(&normalized, current_execution_security_token())
}

#[cfg(any(feature = "demo-disk", test))]
pub fn remove_path_with_current_security(fs: &FileSystem, path: &str) -> Result<()> {
    let normalized = normalize_path_from_root(path)?;
    fs.remove_normalized_path_with_security_token(&normalized, current_execution_security_token())
}

#[cfg(any(feature = "demo-disk", test))]
pub fn write_entire_file(fs: &FileSystem, path: &str, bytes: &[u8]) -> Result<()> {
    let normalized = normalize_path_from_root(path)?;
    fs.replace_file_contents_normalized_with_security_token(
        &normalized,
        bytes,
        current_execution_security_token(),
    )
}

#[cfg(any(feature = "demo-disk", test))]
pub fn write_entire_text_file(fs: &FileSystem, path: &str, text: &str) -> Result<()> {
    write_entire_file(fs, path, text.as_bytes())
}

// ── validation helpers ────────────────────────────────────────────────

fn validate_catalog_redirect_target(
    normalized_catalog_path: &str,
    normalized_redirect_catalog_path: &str,
) -> Result<()> {
    // Installed `/apps/current` and `/apps/catalog` entries may redirect only
    // within the installed catalog root.
    if (path_is_within_root(normalized_catalog_path, constants::INSTALLED_CURRENT_ROOT)
        || path_is_within_root(normalized_catalog_path, constants::INSTALLED_CATALOG_ROOT))
        && !path_is_within_root(
            normalized_redirect_catalog_path,
            constants::INSTALLED_CATALOG_ROOT,
        )
    {
        return Err(Error::PermissionDenied);
    }

    Ok(())
}

fn validate_catalog_redirect_entry(
    entry: &CatalogEntry,
    resolved: &ResolvedCatalogLaunch,
) -> Result<()> {
    // Redirect aliases may change the catalog file path, but they must still
    // resolve to the same app identity and declared version.
    if resolved.catalog_id != entry.id {
        return Err(Error::InvalidArgument);
    }

    if let Some(version) = entry.version.as_deref() {
        if resolved.version != version {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}

fn validate_catalog_manifest_entry(entry: &CatalogEntry, manifest: &LaunchManifest) -> Result<()> {
    // Versioned catalog records remain authoritative for the published version.
    if let Some(version) = entry.version.as_deref() {
        if manifest.version != version {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}

pub fn installed_catalog_package_root(
    fs: &FileSystem,
    normalized_catalog_path: &str,
) -> Result<Option<String>> {
    if path_is_within_root(normalized_catalog_path, constants::INSTALLED_CURRENT_ROOT)
        || path_is_within_root(normalized_catalog_path, constants::INSTALLED_CATALOG_ROOT)
    {
        return installed_expected_package_root_for_catalog_path(fs, normalized_catalog_path)
            .map(Some);
    }

    Ok(None)
}

fn validate_installed_catalog_launch_paths(
    package_root: Option<&str>,
    manifest_path: &str,
    image_path: &str,
    manifest_working_dir: &str,
) -> Result<()> {
    let Some(package_root) = package_root else {
        return Ok(());
    };

    // Installed-app metadata must stay self-contained under that app's
    // package root instead of pointing across package boundaries.
    if !path_is_within_root(manifest_path, package_root)
        || !path_is_within_root(image_path, package_root)
        || !path_is_within_root(manifest_working_dir, package_root)
    {
        return Err(Error::PermissionDenied);
    }

    Ok(())
}
