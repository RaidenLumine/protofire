//! src/user/program/install.rs
//!
//! Install-management recovery: transaction log and download cache repair.
//!
//! Called once during kernel boot after the file system is mounted.  The
//! recovery pass inspects two on-disk areas that a crash can leave behind:
//!
//! * the install transaction log at [`INSTALL_TRANSACTION_LOG_ROOT`], and
//! * the download cache at [`DOWNLOAD_CACHE_ROOT`].
//!
//! Valid completed transactions are reported (with a per-transaction
//! outcome) so the boot log can describe what happened; invalid entries are
//! removed and recorded in the returned repair report.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::kernel::fs::{self, FileSystem};
use crate::{Error, Result};

use super::catalog::{path_parent_dir, read_text_file};
use super::constants::INSTALLED_CATALOG_ROOT;
use super::metadata::{parse_optional_string_field, parse_string_field};

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
