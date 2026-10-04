//! src/user/program/install.rs
//!
//! Install management: the format a package is installed through, the atomic
//! switch that makes a version active, and the recovery pass that repairs what
//! a crash leaves behind.
//!
//! [`install_staged_package`] is the install itself: a package is a directory
//! named `<app_id>@<version>` — the shape a completed download leaves in
//! `/data/downloads` — holding a launch manifest whose paths are relative to
//! itself, and the program that manifest names.  It advances a transaction
//! through `prepare`, `verify`, `commit` and `activate`; the first two only
//! read, `commit` makes the version installed, and `activate` switches
//! `/apps/current` to it in one step.
//!
//! The recovery pass below is called once during kernel boot after the file
//! system is mounted, and reads the same transaction records back.  It inspects
//! two on-disk areas a crash can leave behind:
//!
//! * the install transaction log at [`INSTALL_TRANSACTION_LOG_ROOT`], and
//! * the download cache at [`DOWNLOAD_CACHE_ROOT`].
//!
//! Valid completed transactions are reported (with a per-transaction
//! outcome) so the boot log can describe what happened; invalid entries are
//! removed and recorded in the returned repair report.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::fs::FileSystem;
use crate::fs::{self};
use crate::Error;
use crate::Result;

use super::catalog::path_parent_dir;
use super::catalog::read_text_file;
use super::constants::INSTALLED_CATALOG_ROOT;
use super::metadata::parse_optional_string_field;
use super::metadata::parse_string_field;

// ── paths ─────────────────────────────────────────────────────────────

/// Root directory for the install transaction log.  Each transaction is a
/// directory named `<app_id>@<version>` containing a `state.toml` record.
pub(crate) const INSTALL_TRANSACTION_LOG_ROOT: &str = "/apps/transactions";

/// Root directory for the download cache.  Completed downloads live here as
/// `<app_id>@<version>` directories; in-flight downloads are staged under
/// the `.staging` subdirectory.
pub(crate) const DOWNLOAD_CACHE_ROOT: &str = "/data/downloads";

/// Staging directory inside the download cache (transient, in-flight state).
const DOWNLOAD_CACHE_STAGING_DIR: &str = ".staging";

// ── recovery outcome / repair enums ───────────────────────────────────

/// Outcome of recovering a single install transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallTransactionRecoveryOutcome {
    /// The transaction was interrupted before its payload was committed; the
    /// partial state was cleaned up.
    CleanedPartialState,
    /// The payload was installed but the active `/apps/current` redirect was
    /// not yet updated.
    ReconciledInstalledState,
    /// The installed version was fully activated.
    ActivatedInstalledVersion,
}

/// Outcome of pruning a single download cache entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadCachePruneOutcome {
    /// The entry was not a valid download-cache entry and was removed.
    RemovedInvalidEntry,
    /// The entry duplicated an already-installed version and was removed.
    RemovedInstalledDuplicate,
}

/// Reason a transaction log entry was repaired (removed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionLogRepairReason {
    /// The entry references an install target outside the expected package
    /// root, or its state record disagrees with its directory name.
    InvalidReference,
    /// The entry has the wrong node kind for a transaction directory.
    UnexpectedEntryKind,
    /// The entry name is not a valid `<app_id>@<version>` transaction name.
    UnexpectedEntryName,
}

// ── record types ──────────────────────────────────────────────────────
//
// Under the demo-disk build (feature `demo-disk`, no `test`) the appctl
// surface only reports the aggregate counts, so these per-entry fields are
// never read there; the kernel's boot-recovery reporter (kernel/mod.rs,
// compiled under `test`/`target_os = "none"`) reads every field.  The layout
// is part of the recovery-report contract, so the fields are kept.

/// A transaction that was recovered from the transaction log.
#[allow(dead_code)]
pub struct RecoveredInstallTransaction {
    pub app_id: String,
    pub version: String,
    pub outcome: InstallTransactionRecoveryOutcome,
}

/// A transaction log entry that was repaired (removed).
#[allow(dead_code)]
pub struct RepairedTransactionLogEntry {
    pub path: String,
    pub entry_kind: fs::NodeKind,
    pub reason: TransactionLogRepairReason,
}

/// A download cache entry that was pruned during recovery.
#[allow(dead_code)]
pub struct RepairedDownloadCacheEntry {
    pub root_path: String,
    pub app_id: Option<String>,
    pub version: Option<String>,
    pub staging_state: Option<String>,
    pub source_reference: Option<String>,
    pub outcome: DownloadCachePruneOutcome,
}

/// Aggregate recovery report for one install-management recovery pass.
pub struct InstallManagementRecoveryReport {
    pub recovered_transactions: Vec<RecoveredInstallTransaction>,
    pub repaired_transaction_logs: Vec<RepairedTransactionLogEntry>,
    pub repaired_download_cache: Vec<RepairedDownloadCacheEntry>,
    pub transaction_recovery_error: Option<Error>,
    pub download_cache_recovery_error: Option<Error>,
}

// ── recovery entry point ──────────────────────────────────────────────

/// Recover install-management state after a crash.
///
/// Each phase degrades gracefully: a phase failure is recorded in the
/// report instead of aborting boot, and the two phases run independently.
pub(crate) fn recover_install_management_state(
    fs: &FileSystem,
) -> Result<InstallManagementRecoveryReport> {
    let (recovered_transactions, repaired_transaction_logs, transaction_recovery_error) =
        recover_transaction_log(fs);
    let (repaired_download_cache, download_cache_recovery_error) = recover_download_cache(fs);

    Ok(InstallManagementRecoveryReport {
        recovered_transactions,
        repaired_transaction_logs,
        repaired_download_cache,
        transaction_recovery_error,
        download_cache_recovery_error,
    })
}

// ── transaction log recovery ──────────────────────────────────────────

/// Walk the install transaction log, recovering valid transactions and
/// removing invalid entries.
fn recover_transaction_log(
    fs: &FileSystem,
) -> (
    Vec<RecoveredInstallTransaction>,
    Vec<RepairedTransactionLogEntry>,
    Option<Error>,
) {
    let mut recovered = Vec::new();
    let mut repaired = Vec::new();

    let metadata = match fs.stat_path(INSTALL_TRANSACTION_LOG_ROOT) {
        Err(Error::NotFound) => return (recovered, repaired, None),
        Err(error) => return (recovered, repaired, Some(error)),
        Ok(metadata) => metadata,
    };

    if metadata.kind != fs::NodeKind::Directory {
        // The transaction log root itself is not a directory.  Remove it and
        // record the repair; a fresh root is recreated by the install path
        // on demand.
        if let Err(error) = fs.remove_path(INSTALL_TRANSACTION_LOG_ROOT) {
            return (recovered, repaired, Some(error));
        }
        repaired.push(RepairedTransactionLogEntry {
            path: String::from(INSTALL_TRANSACTION_LOG_ROOT),
            entry_kind: metadata.kind,
            reason: TransactionLogRepairReason::UnexpectedEntryKind,
        });
        return (recovered, repaired, None);
    }

    let children = match read_dir_children(fs, INSTALL_TRANSACTION_LOG_ROOT) {
        Ok(children) => children,
        Err(error) => return (recovered, repaired, Some(error)),
    };

    for child in children {
        if child.kind != fs::NodeKind::Directory {
            // A non-directory entry directly inside the log root cannot be a
            // transaction — remove it.
            if let Err(error) = fs.remove_path(&child.path) {
                return (recovered, repaired, Some(error));
            }
            repaired.push(RepairedTransactionLogEntry {
                path: child.path,
                entry_kind: child.kind,
                reason: TransactionLogRepairReason::UnexpectedEntryKind,
            });
            continue;
        }

        match recover_transaction_directory(fs, &child) {
            Ok(TransactionAction::Report {
                app_id,
                version,
                outcome,
            }) => {
                recovered.push(RecoveredInstallTransaction {
                    app_id,
                    version,
                    outcome,
                });
            }
            Ok(TransactionAction::CleanPartial { app_id, version }) => {
                // The transaction never committed — remove the partial state.
                if let Err(error) = remove_recursive(fs, &child.path) {
                    return (recovered, repaired, Some(error));
                }
                recovered.push(RecoveredInstallTransaction {
                    app_id,
                    version,
                    outcome: InstallTransactionRecoveryOutcome::CleanedPartialState,
                });
            }
            Ok(TransactionAction::Repair { reason }) => {
                if let Err(error) = remove_recursive(fs, &child.path) {
                    return (recovered, repaired, Some(error));
                }
                repaired.push(RepairedTransactionLogEntry {
                    path: child.path,
                    entry_kind: child.kind,
                    reason,
                });
            }
            Err(error) => return (recovered, repaired, Some(error)),
        }
    }

    (recovered, repaired, None)
}

/// Classify a single transaction directory.
fn recover_transaction_directory(
    fs: &FileSystem,
    child: &DirectoryChild,
) -> Result<TransactionAction> {
    // The transaction identity is encoded in the directory name.
    let Some((app_id, version)) = parse_cached_version_name(&child.name) else {
        return Ok(TransactionAction::Repair {
            reason: TransactionLogRepairReason::UnexpectedEntryName,
        });
    };

    let state_path = format!("{}/state.toml", child.path);
    let state = match read_transaction_state(fs, &state_path) {
        Ok(state) => state,
        Err(Error::NotFound) => {
            // A transaction directory without a state record was interrupted
            // before any metadata was written.
            return Ok(TransactionAction::CleanPartial { app_id, version });
        }
        Err(_) => {
            // Unreadable or malformed state record — the reference is invalid.
            return Ok(TransactionAction::Repair {
                reason: TransactionLogRepairReason::InvalidReference,
            });
        }
    };

    // The state record must agree with its directory name; a mismatch means
    // the transaction log was corrupted or written out of order.
    if state.app_id != app_id || state.version != version {
        return Ok(TransactionAction::Repair {
            reason: TransactionLogRepairReason::InvalidReference,
        });
    }

    match state.stage.as_str() {
        "activate" => Ok(TransactionAction::Report {
            app_id,
            version,
            outcome: InstallTransactionRecoveryOutcome::ActivatedInstalledVersion,
        }),
        "commit" => Ok(TransactionAction::Report {
            app_id,
            version,
            outcome: InstallTransactionRecoveryOutcome::ReconciledInstalledState,
        }),
        // `prepare`, `verify`, `download`, and any unknown stage all mean the
        // payload was never committed.
        _ => Ok(TransactionAction::CleanPartial { app_id, version }),
    }
}

struct TransactionState {
    app_id: String,
    version: String,
    stage: String,
}

enum TransactionAction {
    Report {
        app_id: String,
        version: String,
        outcome: InstallTransactionRecoveryOutcome,
    },
    CleanPartial {
        app_id: String,
        version: String,
    },
    Repair {
        reason: TransactionLogRepairReason,
    },
}

fn read_transaction_state(fs: &FileSystem, state_path: &str) -> Result<TransactionState> {
    let text = read_text_file(fs, path_parent_dir(state_path), state_path)?;
    let app_id = parse_string_field(&text, "app_id")?;
    let version = parse_string_field(&text, "version")?;
    let stage = parse_optional_string_field(&text, "stage")?.unwrap_or_default();

    Ok(TransactionState {
        app_id,
        version,
        stage,
    })
}

// ── download cache recovery ───────────────────────────────────────────

/// Walk the download cache, pruning the staging tree, orphaned entries, and
/// duplicates of already-installed versions.
fn recover_download_cache(fs: &FileSystem) -> (Vec<RepairedDownloadCacheEntry>, Option<Error>) {
    let mut repaired = Vec::new();

    let metadata = match fs.stat_path(DOWNLOAD_CACHE_ROOT) {
        Err(Error::NotFound) => return (repaired, None),
        Err(error) => return (repaired, Some(error)),
        Ok(metadata) => metadata,
    };

    if metadata.kind != fs::NodeKind::Directory {
        // The download root was clobbered by a regular file (or another
        // non-directory).  Replace it with a directory so future downloads
        // have a valid root.
        if let Err(error) = fs.remove_path(DOWNLOAD_CACHE_ROOT) {
            return (repaired, Some(error));
        }
        if let Err(error) = fs.create_dir(DOWNLOAD_CACHE_ROOT) {
            return (repaired, Some(error));
        }
        repaired.push(RepairedDownloadCacheEntry {
            root_path: String::from(DOWNLOAD_CACHE_ROOT),
            app_id: None,
            version: None,
            staging_state: None,
            source_reference: None,
            outcome: DownloadCachePruneOutcome::RemovedInvalidEntry,
        });
        return (repaired, None);
    }

    let children = match read_dir_children(fs, DOWNLOAD_CACHE_ROOT) {
        Ok(children) => children,
        Err(error) => return (repaired, Some(error)),
    };

    for child in children {
        if child.name == DOWNLOAD_CACHE_STAGING_DIR {
            // The staging tree is transient: any leftover means an in-flight
            // download was interrupted.  Clear it wholesale.
            if let Err(error) = remove_recursive(fs, &child.path) {
                return (repaired, Some(error));
            }
            repaired.push(RepairedDownloadCacheEntry {
                root_path: child.path,
                app_id: None,
                version: None,
                staging_state: Some(String::from("cleared")),
                source_reference: None,
                outcome: DownloadCachePruneOutcome::RemovedInvalidEntry,
            });
            continue;
        }

        if child.kind != fs::NodeKind::Directory {
            // A stray file directly under the download root — remove it.
            if let Err(error) = fs.remove_path(&child.path) {
                return (repaired, Some(error));
            }
            repaired.push(RepairedDownloadCacheEntry {
                root_path: child.path,
                app_id: None,
                version: None,
                staging_state: None,
                source_reference: None,
                outcome: DownloadCachePruneOutcome::RemovedInvalidEntry,
            });
            continue;
        }

        // A completed download-cache entry is named `<app_id>@<version>`.
        // Prune it only when the matching version is already installed;
        // otherwise it is a valid cache entry and is kept.
        if let Some((app_id, version)) = parse_cached_version_name(&child.name) {
            if installed_version_present(fs, &app_id, &version) {
                if let Err(error) = remove_recursive(fs, &child.path) {
                    return (repaired, Some(error));
                }
                repaired.push(RepairedDownloadCacheEntry {
                    root_path: child.path,
                    app_id: Some(app_id),
                    version: Some(version),
                    staging_state: None,
                    source_reference: None,
                    outcome: DownloadCachePruneOutcome::RemovedInstalledDuplicate,
                });
            }
            continue;
        }

        // An orphaned directory that is neither the staging root nor a
        // completed cache entry — remove it.
        if let Err(error) = remove_recursive(fs, &child.path) {
            return (repaired, Some(error));
        }
        repaired.push(RepairedDownloadCacheEntry {
            root_path: child.path,
            app_id: None,
            version: None,
            staging_state: None,
            source_reference: None,
            outcome: DownloadCachePruneOutcome::RemovedInvalidEntry,
        });
    }

    (repaired, None)
}

// ── shared helpers ────────────────────────────────────────────────────

struct DirectoryChild {
    name: String,
    path: String,
    kind: fs::NodeKind,
}

/// List all children of `dir` as absolute paths.
fn read_dir_children(fs: &FileSystem, dir: &str) -> Result<Vec<DirectoryChild>> {
    let mut children = Vec::new();
    let mut index = 0usize;
    loop {
        match fs.read_dir(dir, index) {
            Ok(entry) => {
                let path = format!("{dir}/{}", entry.name);
                children.push(DirectoryChild {
                    name: entry.name,
                    path,
                    kind: entry.kind,
                });
                index += 1;
            }
            Err(Error::NotFound) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(children)
}

/// Remove `path` and, if it is a directory, all of its contents first.
///
/// The VFS `remove_path` rejects non-empty directories, so a subtree must
/// be torn down leaf-first.
fn remove_recursive(fs: &FileSystem, path: &str) -> Result<()> {
    let metadata = fs.stat_path(path)?;
    if metadata.kind != fs::NodeKind::Directory {
        return fs.remove_path(path);
    }

    let children = read_dir_children(fs, path)?;
    for child in children {
        remove_recursive(fs, &child.path)?;
    }
    fs.remove_path(path)
}

/// Parse a cache/transaction directory name of the form `<app_id>@<version>`.
fn parse_cached_version_name(name: &str) -> Option<(String, String)> {
    let (app_id, version) = name.split_once('@')?;
    if app_id.is_empty() || version.is_empty() {
        return None;
    }
    Some((app_id.to_string(), version.to_string()))
}

/// Return true when the installed catalog already contains a record for the
/// given `app_id@version` (i.e. the download cache entry is redundant).
fn installed_version_present(fs: &FileSystem, app_id: &str, version: &str) -> bool {
    let catalog_path = format!("{INSTALLED_CATALOG_ROOT}/{app_id}@{version}.toml");
    fs.stat_path(&catalog_path).is_ok()
}

// ── the install path ──────────────────────────────────────────────────
//
// The gate is the caller's.  Today that is the appctl surface — `mod app` is
// compiled with a demo disk or in tests — and a distribution's installer would
// reach it through a syscall, which is the day this moves.  The recovery half
// above runs on every boot and stays ungated.
#[cfg(any(feature = "demo-disk", test))]
pub(crate) mod package {
    use super::*;

    use super::super::catalog::create_dir_with_current_security;
    use super::super::catalog::current_execution_security_token;
    use super::super::catalog::normalize_path_from_root;
    use super::super::catalog::normalize_path_relative_to_file;
    use super::super::catalog::read_program_image;
    use super::super::catalog::write_entire_file;
    use super::super::catalog::write_entire_text_file;
    use super::super::catalog::LaunchManifest;
    use super::super::constants::INSTALLED_CURRENT_ROOT;
    use super::super::integrity;
    use super::super::launch_reference::installed_package_version_root;
    use super::super::launch_reference::path_is_within_root;
    use super::super::metadata::parse_launch_manifest;
    use super::super::signature;

    // The recovery pass above repairs what this leaves behind, so the two share
    // one format: a transaction directory named `<app_id>@<version>` with a
    // `state.toml` whose `stage` says how far the install got.  The stages are the
    // words the recovery pass reads — everything before `commit` means the payload
    // was never installed, and `commit`/`activate` mean it was.

    /// The manifest a package carries, relative to its own directory.
    pub(super) const PACKAGE_MANIFEST_NAME: &str = "manifest.toml";

    /// The suffix a package's payload is staged under before it is swapped in.
    ///
    /// A sibling of the version root, because the swap is one step and both
    /// names have to be on the same filesystem.
    pub(super) const PACKAGE_STAGE_SUFFIX: &str = ".staged";

    /// The name the writability probe writes and removes.
    const INSTALL_PROBE_NAME: &str = ".install-probe";

    /// The stage words, in the order an install passes through them.
    pub(super) const STAGE_PREPARE: &str = "prepare";
    pub(super) const STAGE_VERIFY: &str = "verify";
    pub(super) const STAGE_COMMIT: &str = "commit";
    pub(super) const STAGE_ACTIVATE: &str = "activate";

    /// A package that was installed and activated.
    pub struct InstalledPackage {
        pub app_id: String,
        pub version: String,
    }

    /// Install one staged package.
    ///
    /// `source` is a directory named `<app_id>@<version>` holding the launch
    /// manifest and the program it names — the shape the download cache holds
    /// (`/data/downloads/<app_id>@<version>`) once a download completes.  The
    /// manifest's paths are relative to itself, so the same manifest describes
    /// the package wherever it is read from and the installed copy needs no
    /// rewriting.
    ///
    /// The install advances the transaction through four stages: `prepare` (the
    /// manifest is read and checked), `verify` (the program matches the
    /// manifest's digest and, when it carries one, its signature), `commit`
    /// (the payload lands under `/apps/packages/<id>/<version>` and the
    /// versioned catalog record is written, which is what makes the version
    /// *installed*), and `activate` (`/apps/current/<id>.toml` is switched
    /// to it in one step).
    ///
    /// A failure before the version is installed removes the transaction and
    /// the staged payload and leaves the machine exactly as it was.  A
    /// failure *after* that leaves the transaction record behind: the next
    /// boot reports a version that was installed and not activated, and the
    /// version that was active stays active — which is the rollback.
    pub(crate) fn install_staged_package(
        fs: &FileSystem,
        source: &str,
    ) -> Result<InstalledPackage> {
        let source = normalize_path_from_root(source)?;
        let (app_id, version) = package_identity(&source)?;
        let version_root = installed_package_version_root(&app_id, &version)?;
        let mut paths = InstallPaths {
            staged_root: format!("{version_root}{PACKAGE_STAGE_SUFFIX}"),
            catalog_path: versioned_catalog_path(&app_id, &version)?,
            source,
            version_root: version_root.clone(),
            entry: String::new(),
        };

        // A payload that cannot be written is worth knowing before anything is
        // touched: the app zone may be mounted read-only, and an install that found
        // that out halfway through would have to roll back for it.
        probe_install_writable(fs, &version_root)?;

        // A version is installed when its record exists — that is what the loader
        // looks for and what the recovery pass calls a duplicate.  Installing it
        // again is not what this is for, and saying so is the honest answer: an
        // upgrade is a new version, and a re-build of one that is already running
        // has to be uninstalled first.
        if fs.stat_path(&paths.catalog_path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let manifest_text = read_package_manifest(fs, &paths.source)?;
        let manifest = parse_launch_manifest(&manifest_text)?;
        if manifest.version != version {
            return Err(Error::InvalidArgument);
        }
        paths.entry = package_entry_path(&manifest, &paths.source)?;

        write_transaction_stage(fs, &app_id, &version, STAGE_PREPARE)?;

        // The digest and the signature are the package's own claims about the
        // program; the keys a signature is checked against live in `/system`, which
        // an install cannot write to.
        if let Err(error) = verify_stage(fs, &paths, &manifest) {
            remove_install_staging(fs, &app_id, &version, &paths.staged_root);
            return Err(error);
        }

        write_transaction_stage(fs, &app_id, &version, STAGE_VERIFY)?;

        if let Err(error) = commit_payload(fs, &app_id, &version, &paths) {
            // Nothing was installed: the staged tree is not a version, and the
            // transaction says so.  Take both away and leave the installed
            // versions — if there are any — exactly as they were.
            remove_install_staging(fs, &app_id, &version, &paths.staged_root);
            return Err(error);
        }

        write_transaction_stage(fs, &app_id, &version, STAGE_COMMIT)?;

        activate_version(fs, &app_id, &version)?;
        write_transaction_stage(fs, &app_id, &version, STAGE_ACTIVATE)?;

        Ok(InstalledPackage { app_id, version })
    }

    /// Where one install's files are: the package it reads, the version it
    /// installs to, and the names the commit and the activation write.
    pub(super) struct InstallPaths {
        /// The staged package: a directory named `<app_id>@<version>`.
        pub(super) source: String,
        /// `/apps/packages/<app_id>/<version>`.
        pub(super) version_root: String,
        /// The version root's staging sibling, which the payload is renamed
        /// from.
        pub(super) staged_root: String,
        /// `/apps/catalog/<app_id>@<version>.toml`, the record that *is* the
        /// install.
        pub(super) catalog_path: String,
        /// The program, inside the package.
        pub(super) entry: String,
    }

    /// Check the program against the claims its manifest makes about it.
    ///
    /// A digest or a signature that does not hold is a refusal: what would be
    /// installed is not what the package says it is, and the point of the stage
    /// is that the machine never has to find that out later.
    fn verify_stage(
        fs: &FileSystem,
        paths: &InstallPaths,
        manifest: &LaunchManifest,
    ) -> Result<()> {
        let image = read_program_image(fs, &paths.source, &paths.entry)?;
        integrity::verify_optional_sha256(&image, manifest.entry_sha256.as_deref())?;
        signature::verify_optional_signature(fs, &image, manifest.entry_signature.as_deref())
    }

    /// The `app_id` and `version` a package directory names.
    fn package_identity(source: &str) -> Result<(String, String)> {
        let name = source.rsplit('/').next().ok_or(Error::InvalidArgument)?;
        parse_cached_version_name(name).ok_or(Error::InvalidArgument)
    }

    /// Fail unless the version's payload could be written.
    ///
    /// The probe writes and removes one file under the nearest existing
    /// ancestor of the payload root, so a read-only app zone is refused
    /// here rather than after the transaction has started.
    fn probe_install_writable(fs: &FileSystem, version_root: &str) -> Result<()> {
        fs.probe_nearest_existing_directory_writable_normalized_with_security_token(
            version_root,
            INSTALL_PROBE_NAME,
            current_execution_security_token(),
        )
    }

    /// Create every directory in `path` that is not there yet.
    ///
    /// The install path is the first thing to write under `/apps` on a machine
    /// whose app zone is bare, and `create_dir` only makes the last component:
    /// the zones a distribution ships have these directories, and a machine
    /// that does not gets them here.
    pub(super) fn ensure_directory(fs: &FileSystem, path: &str) -> Result<()> {
        let mut prefix = String::new();
        for component in path.split('/').filter(|part| !part.is_empty()) {
            prefix.push('/');
            prefix.push_str(component);
            match fs.stat_path(&prefix) {
                Ok(metadata) if metadata.kind == fs::NodeKind::Directory => {}
                Ok(_) => return Err(Error::AlreadyExists),
                Err(Error::NotFound) => match create_dir_with_current_security(fs, &prefix) {
                    Ok(()) | Err(Error::AlreadyExists) => {}
                    Err(error) => return Err(error),
                },
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    /// Read the manifest the package carries at its own root.
    fn read_package_manifest(fs: &FileSystem, source: &str) -> Result<String> {
        read_text_file(fs, source, &format!("{source}/{PACKAGE_MANIFEST_NAME}"))
    }

    /// The path of the program a package's manifest names.
    ///
    /// It has to stay inside the package: a manifest that points somewhere else
    /// is either a mistake or an attempt to have the install copy a file
    /// from outside the package it was handed.
    fn package_entry_path(manifest: &LaunchManifest, source: &str) -> Result<String> {
        let entry = normalize_path_relative_to_file(
            &manifest.entry_path,
            &format!("{source}/{PACKAGE_MANIFEST_NAME}"),
        )?;
        if !path_is_within_root(&entry, source) {
            return Err(Error::PermissionDenied);
        }

        Ok(entry)
    }

    /// Copy the package into the payload root and write its catalog record.
    ///
    /// The payload lands in a sibling of the version root first and is renamed
    /// in, so the version root appears complete or not at all — there is no
    /// moment when it holds half a package.  What makes the version
    /// *installed* is the record written after it, which is why that is the
    /// last thing this does: a reader that finds the record always finds
    /// the payload it names.
    pub(super) fn commit_payload(
        fs: &FileSystem,
        app_id: &str,
        version: &str,
        paths: &InstallPaths,
    ) -> Result<()> {
        let token = current_execution_security_token();

        // A payload with no record is not an install — the record is what makes one
        // — so a tree an interrupted attempt left behind is dead weight here.
        let _ = remove_recursive(fs, &paths.version_root);
        let _ = remove_recursive(fs, &paths.staged_root);

        let entry_relative = paths
            .entry
            .strip_prefix(&format!("{}/", paths.source))
            .ok_or(Error::InvalidArgument)?;
        let staged_entry = format!("{}/{entry_relative}", paths.staged_root);
        match staged_entry.rsplit_once('/') {
            Some((parent, _)) => ensure_directory(fs, parent)?,
            None => ensure_directory(fs, &paths.staged_root)?,
        }
        write_entire_file(
            fs,
            &staged_entry,
            &read_program_image(fs, &paths.source, &paths.entry)?,
        )?;
        let manifest_text = read_text_file(
            fs,
            &paths.source,
            &format!("{}/{PACKAGE_MANIFEST_NAME}", paths.source),
        )?;
        write_entire_file(
            fs,
            &format!("{}/{PACKAGE_MANIFEST_NAME}", paths.staged_root),
            manifest_text.as_bytes(),
        )?;

        // The payload becomes the version root in one step.
        fs.rename_normalized_paths_with_security_token(
            &paths.staged_root,
            &paths.version_root,
            token,
        )?;

        ensure_directory(fs, INSTALLED_CATALOG_ROOT)?;
        let manifest_path = format!("{}/{PACKAGE_MANIFEST_NAME}", paths.version_root);
        let record = format!(
        "id = \"{app_id}\"\nversion = \"{version}\"\nmanifest = \"{manifest_path}\"\nmanifest_sha256 = \"{}\"\n",
        integrity::sha256_hex(manifest_text.as_bytes())
    );
        if let Err(error) = write_entire_text_file(fs, &paths.catalog_path, &record) {
            // The record never landed, so this version is not installed: take the
            // payload with it and leave the machine as it was.
            let _ = remove_recursive(fs, &paths.version_root);
            return Err(error);
        }

        Ok(())
    }

    /// Point `/apps/current/<app_id>.toml` at `version`, in one step.
    ///
    /// The record is written beside its name first and then swapped with it, so
    /// the name always holds a complete record: a crash leaves either the
    /// old version or the new one, never a half-written file and never
    /// nothing.
    fn activate_version(fs: &FileSystem, app_id: &str, version: &str) -> Result<()> {
        let current = format!("{INSTALLED_CURRENT_ROOT}/{app_id}.toml");
        let staged = format!("{current}{PACKAGE_STAGE_SUFFIX}");
        ensure_directory(fs, INSTALLED_CURRENT_ROOT)?;
        let record = format!(
        "id = \"{app_id}\"\nversion = \"{version}\"\ncatalog = \"../catalog/{app_id}@{version}.toml\"\n"
    );
        write_entire_text_file(fs, &staged, &record)?;

        let token = current_execution_security_token();
        if fs.stat_path(&current).is_ok() {
            fs.swap_normalized_paths_with_security_token(&current, &staged, token)?;
        } else {
            fs.rename_normalized_paths_with_security_token(&staged, &current, token)?;
        }
        let _ = fs.remove_normalized_path_if_exists_with_security_token(&staged, token);

        // The unversioned catalog record is the alias a launch by bare path finds;
        // it names the same version as the current record, so the two agree.
        ensure_directory(fs, INSTALLED_CATALOG_ROOT)?;
        let alias = format!("{INSTALLED_CATALOG_ROOT}/{app_id}.toml");
        write_entire_text_file(
            fs,
            &alias,
            &format!(
            "id = \"{app_id}\"\nversion = \"{version}\"\ncatalog = \"./{app_id}@{version}.toml\"\n"
        ),
        )
    }

    /// Take away what a failed install left while it was still staging.
    ///
    /// Only what this attempt *made*: the transaction record and the staged
    /// tree. The version roots of other installs — and of this one, if it
    /// turns out the record was already there — are not this cleanup's
    /// business.
    fn remove_install_staging(fs: &FileSystem, app_id: &str, version: &str, staged_root: &str) {
        let transaction = format!("{INSTALL_TRANSACTION_LOG_ROOT}/{app_id}@{version}");
        let _ = remove_recursive(fs, &transaction);
        let _ = remove_recursive(fs, staged_root);
    }

    /// Write the state record that says how far one transaction has got.
    pub(super) fn write_transaction_stage(
        fs: &FileSystem,
        app_id: &str,
        version: &str,
        stage: &str,
    ) -> Result<()> {
        let transaction = format!("{INSTALL_TRANSACTION_LOG_ROOT}/{app_id}@{version}");
        ensure_directory(fs, &transaction)?;
        write_entire_text_file(
            fs,
            &format!("{transaction}/state.toml"),
            &format!("app_id = \"{app_id}\"\nversion = \"{version}\"\nstage = \"{stage}\"\n"),
        )
    }

    /// `/apps/catalog/<app_id>@<version>.toml`.
    pub(super) fn versioned_catalog_path(app_id: &str, version: &str) -> Result<String> {
        let _ = installed_package_version_root(app_id, version)?;
        Ok(format!("{INSTALLED_CATALOG_ROOT}/{app_id}@{version}.toml"))
    }
}

#[cfg(any(feature = "demo-disk", test))]
pub(crate) use package::install_staged_package;

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::sync::Arc;

    use super::package::commit_payload;
    use super::package::ensure_directory;
    use super::package::install_staged_package;
    use super::package::versioned_catalog_path;
    use super::package::write_transaction_stage;
    use super::package::InstallPaths;
    use super::package::PACKAGE_MANIFEST_NAME;
    use super::package::PACKAGE_STAGE_SUFFIX;
    use super::package::STAGE_COMMIT;
    use super::package::STAGE_VERIFY;
    use super::*;
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::simplefs::SimpleFs;
    use crate::fs::simplefs::SimpleFsVolume;
    use crate::kernel::sync::Mutex;
    use crate::user::program::catalog::read_program_image;
    use crate::user::program::catalog::write_entire_file;
    use crate::user::program::catalog::write_entire_text_file;
    use crate::user::program::integrity;
    use crate::user::program::launch_reference::installed_package_version_root;

    /// A filesystem with the three zones the install path uses, each a writable
    /// SimpleFs volume of its own.
    ///
    /// The zones are the production filesystem rather than a mock because the
    /// switch the install ends with is the filesystem's own primitive: a
    /// fixture that cannot swap two paths cannot show the install working.
    struct InstallTree {
        fs: &'static Mutex<FileSystem>,
    }

    impl InstallTree {
        fn mount() -> Self {
            let fs = Box::leak(Box::new(Mutex::new(FileSystem::new())));
            {
                let mut fs_guard = fs.lock();
                for (name, path) in [("system", "/system"), ("apps", "/apps"), ("data", "/data")] {
                    // Headroom, because the install writes into these zones:
                    // a volume sized for nothing but its own superblock has no
                    // inode to put a package in.
                    let image = SimpleFs::build_image_with_headroom(name, &[], 64, 128, 512)
                        .expect("build a writable zone image");
                    let device = MemoryBlockDevice::new(name, image, false);
                    let volume = SimpleFs::open(device, true).expect("open the zone");
                    fs_guard.register(name, Arc::new(SimpleFsVolume::new(volume)));
                    fs_guard
                        .mount(&format!("/dev/{name}"), path, name, 0)
                        .expect("mount the zone");
                }
            }

            crate::fs::install_global(fs);
            Self { fs }
        }
    }

    impl Drop for InstallTree {
        fn drop(&mut self) {
            crate::fs::uninstall_global(self.fs);
        }
    }

    /// Stage a package in the download cache, the way a completed download
    /// leaves one.
    fn stage_package(
        fs: &FileSystem,
        app_id: &str,
        version: &str,
        payload: &[u8],
        digest: Option<&str>,
    ) -> String {
        let source = format!("{DOWNLOAD_CACHE_ROOT}/{app_id}@{version}");
        ensure_directory(fs, &source).expect("create the package directory");

        let manifest = format!(
            "name = \"{app_id}\"\nversion = \"{version}\"\nformat = \"{}\"\nentry = \"bin/{app_id}.elf\"\nworking_dir = \".\"\n{}",
            crate::user::program::DEMO_PROGRAM_FORMAT,
            digest
                .map(|digest| format!("entry_sha256 = \"{digest}\"\n"))
                .unwrap_or_default(),
        );
        write_entire_text_file(fs, &format!("{source}/{PACKAGE_MANIFEST_NAME}"), &manifest)
            .expect("write the manifest");

        let entry = format!("{source}/bin/{app_id}.elf");
        ensure_directory(fs, path_parent_dir(&entry)).expect("create the bin directory");
        write_entire_file(fs, &entry, payload).expect("write the payload");

        source
    }

    #[test]
    fn an_install_commits_the_payload_and_activates_it() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let payload = b"an installed program";
        let digest = integrity::sha256_hex(payload);
        let source = stage_package(&fs, "logger", "1.2.0", payload, Some(&digest));

        let installed = install_staged_package(&fs, &source).expect("install");
        assert_eq!(installed.app_id, "logger");
        assert_eq!(installed.version, "1.2.0");

        // The payload is where the manifest says it is, byte for byte.
        assert_eq!(
            read_program_image(&fs, "/", "/apps/packages/logger/1.2.0/bin/logger.elf")
                .expect("read the installed payload"),
            payload
        );
        assert!(fs
            .stat_path("/apps/packages/logger/1.2.0/manifest.toml")
            .is_ok());

        // The versioned record is what makes the version installed, and it
        // carries the digest of the manifest it points at.
        let versioned = read_text_file(&fs, "/", "/apps/catalog/logger@1.2.0.toml")
            .expect("read the versioned record");
        let manifest_text = read_text_file(&fs, "/", "/apps/packages/logger/1.2.0/manifest.toml")
            .expect("read the installed manifest");
        assert!(
            versioned.contains(&format!(
                "manifest_sha256 = \"{}\"",
                integrity::sha256_hex(manifest_text.as_bytes())
            )),
            "{versioned}"
        );

        // And the active record names that version, redirecting through the
        // catalog the loader follows.
        let current =
            read_text_file(&fs, "/", "/apps/current/logger.toml").expect("read the current record");
        assert!(current.contains("version = \"1.2.0\""), "{current}");
        assert!(
            current.contains("catalog = \"../catalog/logger@1.2.0.toml\""),
            "{current}"
        );

        // No transaction is left behind in a state the next boot would have to
        // repair: the install finished.
        let state = read_text_file(&fs, "/", "/apps/transactions/logger@1.2.0/state.toml")
            .expect("read the transaction state");
        assert!(state.contains("stage = \"activate\""), "{state}");
        let report = recover_install_management_state(&fs).expect("recover");
        assert_eq!(report.recovered_transactions.len(), 1);
        assert_eq!(
            report.recovered_transactions[0].outcome,
            InstallTransactionRecoveryOutcome::ActivatedInstalledVersion
        );
        assert!(report.repaired_transaction_logs.is_empty());
    }

    #[test]
    fn a_payload_that_does_not_match_its_digest_installs_nothing() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let source = stage_package(
            &fs,
            "logger",
            "1.2.0",
            b"an installed program",
            Some(&integrity::sha256_hex(b"something else")),
        );

        assert_eq!(
            install_staged_package(&fs, &source).map(|_| ()),
            Err(Error::PermissionDenied)
        );

        // Nothing of this attempt is left: no payload, no catalog record, and
        // no transaction for the next boot to clean up.
        assert!(fs.stat_path("/apps/packages/logger/1.2.0").is_err());
        assert!(fs.stat_path("/apps/catalog/logger@1.2.0.toml").is_err());
        assert!(fs.stat_path("/apps/current/logger.toml").is_err());
        assert!(fs.stat_path("/apps/transactions/logger@1.2.0").is_err());
    }

    #[test]
    fn a_failed_install_leaves_the_active_version_alone() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let good = b"version one";
        let source = stage_package(
            &fs,
            "logger",
            "1.0.0",
            good,
            Some(&integrity::sha256_hex(good)),
        );
        install_staged_package(&fs, &source).expect("install 1.0.0");

        // The next version arrives without matching its own digest.
        let bad = stage_package(
            &fs,
            "logger",
            "2.0.0",
            b"version two",
            Some(&integrity::sha256_hex(b"not version two")),
        );
        assert!(install_staged_package(&fs, &bad).is_err());

        // The machine still runs what it ran: the active record, the payload
        // and the installed version's own record are untouched.
        let current = read_text_file(&fs, "/", "/apps/current/logger.toml").expect("current");
        assert!(current.contains("version = \"1.0.0\""), "{current}");
        assert_eq!(
            read_program_image(&fs, "/", "/apps/packages/logger/1.0.0/bin/logger.elf")
                .expect("read 1.0.0"),
            good
        );
        assert!(fs.stat_path("/apps/catalog/logger@2.0.0.toml").is_err());
    }

    #[test]
    fn an_upgrade_switches_the_active_version_in_one_step() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let first = b"version one";
        let source = stage_package(
            &fs,
            "logger",
            "1.0.0",
            first,
            Some(&integrity::sha256_hex(first)),
        );
        install_staged_package(&fs, &source).expect("install 1.0.0");

        let second = b"version two";
        let source = stage_package(
            &fs,
            "logger",
            "2.0.0",
            second,
            Some(&integrity::sha256_hex(second)),
        );
        install_staged_package(&fs, &source).expect("install 2.0.0");

        // The active record was *replaced*, which is the path a first install
        // does not take: the name always held a record, the old one or the new
        // one.
        let current = read_text_file(&fs, "/", "/apps/current/logger.toml").expect("current");
        assert!(current.contains("version = \"2.0.0\""), "{current}");
        assert!(fs.stat_path("/apps/catalog/logger@1.0.0.toml").is_ok());
        assert_eq!(
            read_program_image(&fs, "/", "/apps/packages/logger/2.0.0/bin/logger.elf")
                .expect("read 2.0.0"),
            second
        );
        assert_eq!(
            read_program_image(&fs, "/", "/apps/packages/logger/1.0.0/bin/logger.elf")
                .expect("read 1.0.0"),
            first
        );

        // The alias a launch by bare path follows names the same version, so
        // the two records cannot disagree about what is current.
        let alias = read_text_file(&fs, "/", "/apps/catalog/logger.toml").expect("alias");
        assert!(alias.contains("version = \"2.0.0\""), "{alias}");
    }

    #[test]
    fn an_installed_version_is_not_installed_again() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let first = b"the installed build";
        let source = stage_package(
            &fs,
            "logger",
            "1.0.0",
            first,
            Some(&integrity::sha256_hex(first)),
        );
        install_staged_package(&fs, &source).expect("install");

        // A second build of a version that is already installed is a different
        // thing to ship — and what is running has to keep running, so the
        // answer is a refusal rather than a replacement under a live name.
        let second = b"a second build of the same version";
        let source = stage_package(
            &fs,
            "logger",
            "1.0.0",
            second,
            Some(&integrity::sha256_hex(second)),
        );
        assert_eq!(
            install_staged_package(&fs, &source).map(|_| ()),
            Err(Error::AlreadyExists)
        );
        assert_eq!(
            read_program_image(&fs, "/", "/apps/packages/logger/1.0.0/bin/logger.elf")
                .expect("read the installed payload"),
            first
        );
    }

    #[test]
    fn a_package_whose_entry_escapes_its_directory_is_refused() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        let source = format!("{DOWNLOAD_CACHE_ROOT}/logger@1.0.0");
        ensure_directory(&fs, &source).expect("create the package directory");
        write_entire_text_file(
            &fs,
            &format!("{source}/{PACKAGE_MANIFEST_NAME}"),
            "name = \"logger\"\nversion = \"1.0.0\"\nformat = \"elf\"\nentry = \"../../../etc/shadow\"\nworking_dir = \".\"\n",
        )
        .expect("write the manifest");

        assert_eq!(
            install_staged_package(&fs, &source).map(|_| ()),
            Err(Error::PermissionDenied)
        );
        assert!(fs.stat_path("/apps/transactions/logger@1.0.0").is_err());
    }

    #[test]
    fn a_transaction_that_committed_but_did_not_activate_is_reported_not_repaired() {
        let tree = InstallTree::mount();
        let fs = tree.fs.lock();

        // The state a crash between the two steps leaves: the payload and its
        // versioned record are in place, the active record was never written,
        // and the transaction says `commit`.
        let payload = b"installed but not activated";
        let source = stage_package(
            &fs,
            "logger",
            "1.0.0",
            payload,
            Some(&integrity::sha256_hex(payload)),
        );
        let version_root = installed_package_version_root("logger", "1.0.0").expect("root");
        let paths = InstallPaths {
            staged_root: format!("{version_root}{PACKAGE_STAGE_SUFFIX}"),
            catalog_path: versioned_catalog_path("logger", "1.0.0").expect("catalog"),
            source: source.clone(),
            version_root,
            entry: format!("{source}/bin/logger.elf"),
        };
        write_transaction_stage(&fs, "logger", "1.0.0", STAGE_VERIFY).expect("stage verify");
        commit_payload(&fs, "logger", "1.0.0", &paths).expect("commit");
        write_transaction_stage(&fs, "logger", "1.0.0", STAGE_COMMIT).expect("stage commit");

        let report = recover_install_management_state(&fs).expect("recover");
        assert_eq!(report.recovered_transactions.len(), 1);
        assert_eq!(
            report.recovered_transactions[0].outcome,
            InstallTransactionRecoveryOutcome::ReconciledInstalledState
        );
        assert!(report.repaired_transaction_logs.is_empty());

        // Which is the rollback: the version is installed, and it is *not*
        // what the machine would launch.
        assert!(fs.stat_path("/apps/catalog/logger@1.0.0.toml").is_ok());
        assert!(fs.stat_path("/apps/current/logger.toml").is_err());
    }
}
