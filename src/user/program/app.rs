//! src/user/program/app.rs
//!
//! User-visible `appctl` / `app-center` command surfaces plus the `lumina`
//! package-manager front end.
//!
//! All three resolve against the host filesystem through the standard
//! `/apps/catalog`, `/apps/current`, and `/apps/packages` layout.  The
//! implementations are intentionally compact: they read and report the
//! installed-app state that the rest of the kernel already maintains, and
//! the destructive operations (`uninstall`, `recover`) reuse the same
//! security-token guarded helpers used by the install-management recovery
//! path.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::kernel::fs::{FileSystem, NodeKind};
use crate::{Error, Result};

use super::catalog::{
    create_dir_with_current_security, read_text_file, remove_path_with_current_security,
};
use super::constants::{INSTALLED_CATALOG_ROOT, INSTALLED_CURRENT_ROOT, INSTALLED_PACKAGE_ROOT};

// ── shared directory helpers ─────────────────────────────────────────

struct DirChild {
    name: String,
    path: String,
    kind: NodeKind,
}

/// List all children of `dir` as absolute paths.
fn read_dir_children(fs: &FileSystem, dir: &str) -> Result<Vec<DirChild>> {
    let mut children = Vec::new();
    let mut index = 0usize;
    loop {
        match fs.read_dir(dir, index) {
            Ok(entry) => {
                let path = format!("{dir}/{}", entry.name);
                children.push(DirChild {
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
    if metadata.kind == NodeKind::Directory {
        let children = read_dir_children(fs, path)?;
        for child in children {
            remove_recursive(fs, &child.path)?;
        }
    }
    remove_path_with_current_security(fs, path)
}

/// The set of installed app ids, derived from `/apps/current/*.toml`.
fn installed_app_ids(fs: &FileSystem) -> Vec<String> {
    let mut ids = Vec::new();
    let children = match read_dir_children(fs, INSTALLED_CURRENT_ROOT) {
        Ok(children) => children,
        Err(_) => return ids,
    };
    for child in children {
        if child.kind == NodeKind::File && child.name.ends_with(".toml") {
            let id = child.name.trim_end_matches(".toml").to_string();
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids.sort();
    ids
}

/// The active version recorded in `/apps/current/<app-id>.toml`.
fn current_version(fs: &FileSystem, app_id: &str) -> Option<String> {
    let path = format!("{INSTALLED_CURRENT_ROOT}/{app_id}.toml");
    let text = read_text_file(fs, "/", &path).ok()?;
    super::metadata::parse_string_field(&text, "version").ok()
}

/// Every published version of `app_id` from `/apps/catalog/<app-id>@*.toml`.
fn catalog_versions(fs: &FileSystem, app_id: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let children = match read_dir_children(fs, INSTALLED_CATALOG_ROOT) {
        Ok(children) => children,
        Err(_) => return versions,
    };
    let prefix = format!("{app_id}@");
    for child in children {
        if child.kind == NodeKind::File
            && child.name.starts_with(&prefix)
            && child.name.ends_with(".toml")
        {
            let version = &child.name[prefix.len()..child.name.len() - ".toml".len()];
            if !version.is_empty() && !version.contains('@') {
                versions.push(version.to_string());
            }
        }
    }
    versions.sort();
    versions
}

// ── appctl ───────────────────────────────────────────────────────────

/// Execute one `appctl` command against `fs`, returning its output text.
pub(super) fn run_appctl_command(fs: &FileSystem, _cwd: &str, argv: &[String]) -> String {
    let args = effective_arguments(argv);
    match args.first().map(String::as_str) {
        None | Some("help") => appctl_help(args.get(1).map(String::as_str)),
        Some("status") => appctl_status(fs),
        Some("list") => appctl_list(fs),
        Some("versions") => appctl_versions(fs, args.get(1)),
        Some("current") => appctl_current(fs, args.get(1)),
        Some("associations") => appctl_associations(fs),
        Some("uninstall") => appctl_uninstall(fs, args.get(1), args.get(2)),
        Some("recover") => appctl_recover(fs),
        Some("cache-prune") => appctl_cache_prune(fs),
        Some(other) => format!("appctl: unknown command `{other}`\n"),
    }
}

/// Drop `argv[0]` (the program name) from the argument list.
fn effective_arguments(argv: &[String]) -> &[String] {
    match argv.first().map(String::as_str) {
        Some(name) if name == "appctl" || name == "app-center" || name == "lumina" => &argv[1..],
        _ => argv,
    }
}

fn appctl_help(topic: Option<&str>) -> String {
    match topic {
        Some("status") => "usage: appctl status\nshows installed app, catalog, package, and recovery counts\n".into(),
        Some("list") => "usage: appctl list\nlists installed apps with their active versions\n".into(),
        Some("versions") => "usage: appctl versions <app-id>\nlists every published version for one app\n".into(),
        Some("current") => "usage: appctl current <app-id>\nshows the active version selected under /apps/current\n".into(),
        Some("uninstall") => "usage: appctl uninstall <app-id> [version]\nremoves one installed version or an entire app\n".into(),
        Some("recover") => "usage: appctl recover\nreconciles unfinished install transactions and cleans download-cache state\n".into(),
        Some("cache-prune") => "usage: appctl cache-prune\nremoves invalid cached downloads\n".into(),
        _ => {
            "usage: appctl <command> [args]\n\
             commands: status, list, versions, current, associations,\n\
             uninstall, recover, cache-prune, help\n"
                .into()
        }
    }
}

fn appctl_status(fs: &FileSystem) -> String {
    let installed = installed_app_ids(fs);
    let catalog_entries = match read_dir_children(fs, INSTALLED_CATALOG_ROOT) {
        Ok(children) => children
            .iter()
            .filter(|child| child.kind == NodeKind::File && child.name.ends_with(".toml"))
            .count(),
        Err(_) => 0,
    };
    let packages = match read_dir_children(fs, INSTALLED_PACKAGE_ROOT) {
        Ok(children) => children
            .iter()
            .filter(|child| child.kind == NodeKind::Directory)
            .count(),
        Err(_) => 0,
    };
    format!(
        "appctl status\ninstalled apps: {}\ncatalog entries: {}\npackages: {}\n",
        installed.len(),
        catalog_entries,
        packages
    )
}

fn appctl_list(fs: &FileSystem) -> String {
    let ids = installed_app_ids(fs);
    let mut output = String::from("appctl list\n");
    if ids.is_empty() {
        output.push_str("(no installed apps)\n");
        return output;
    }
    for id in ids {
        let version = current_version(fs, &id).unwrap_or_else(|| "(none)".into());
        output.push_str(&format!("{id:20} {version}\n"));
    }
    output
}

fn appctl_versions(fs: &FileSystem, app_id: Option<&String>) -> String {
    let Some(app_id) = app_id else {
        return "appctl: invalid usage for `versions` (requires an app id)\n".into();
    };
    let versions = catalog_versions(fs, app_id);
    let mut output = format!("appctl versions {app_id}\n");
    if versions.is_empty() {
        output.push_str(&format!("(no published versions for `{app_id}`)\n"));
        return output;
    }
    for version in versions {
        output.push_str(&format!("{version}\n"));
    }
    output
}

fn appctl_current(fs: &FileSystem, app_id: Option<&String>) -> String {
    let Some(app_id) = app_id else {
        return "appctl: invalid usage for `current` (requires an app id)\n".into();
    };
    match current_version(fs, app_id) {
        Some(version) => format!("appctl current {app_id}\n{app_id}@{} (active)\n", version),
        None => format!("appctl current {app_id}\n(no active version for `{app_id}`)\n"),
    }
}

fn appctl_associations(fs: &FileSystem) -> String {
    let mut output = String::from("appctl associations\n");
    match read_dir_children(fs, "/apps/associations") {
        Ok(children) => {
            let mut names: Vec<&str> = children
                .iter()
                .filter(|child| child.kind == NodeKind::File)
                .map(|child| child.name.as_str())
                .collect();
            names.sort();
            if names.is_empty() {
                output.push_str("(no associations)\n");
            } else {
                for name in names {
                    output.push_str(&format!("{name}\n"));
                }
            }
        }
        Err(_) => output.push_str("(no associations)\n"),
    }
    output
}

fn appctl_uninstall(fs: &FileSystem, app_id: Option<&String>, version: Option<&String>) -> String {
    let Some(app_id) = app_id else {
        return "appctl: invalid usage for `uninstall` (requires an app id)\n".into();
    };

    let mut removed = 0usize;
    let mut failures = Vec::new();

    if let Some(version) = version {
        // Remove a single published version.
        let catalog_path = format!("{INSTALLED_CATALOG_ROOT}/{app_id}@{version}.toml");
        match remove_path_with_current_security(fs, &catalog_path) {
            Ok(()) => removed += 1,
            Err(Error::NotFound) => {}
            Err(error) => failures.push(format!("{catalog_path}: {}", error.as_str())),
        }
    } else {
        // Remove the current redirect, the catalog redirect, every published
        // version, and the package directory.
        for path in [
            format!("{INSTALLED_CURRENT_ROOT}/{app_id}.toml"),
            format!("{INSTALLED_CATALOG_ROOT}/{app_id}.toml"),
        ] {
            match remove_path_with_current_security(fs, &path) {
                Ok(()) => removed += 1,
                Err(Error::NotFound) => {}
                Err(error) => failures.push(format!("{path}: {}", error.as_str())),
            }
        }
        for version in catalog_versions(fs, app_id) {
            let catalog_path = format!("{INSTALLED_CATALOG_ROOT}/{app_id}@{version}.toml");
            match remove_path_with_current_security(fs, &catalog_path) {
                Ok(()) => removed += 1,
                Err(Error::NotFound) => {}
                Err(error) => failures.push(format!("{catalog_path}: {}", error.as_str())),
            }
        }
        let package_root = format!("{INSTALLED_PACKAGE_ROOT}/{app_id}");
        match remove_recursive(fs, &package_root) {
            Ok(()) => removed += 1,
            Err(Error::NotFound) => {}
            Err(error) => failures.push(format!("{package_root}: {}", error.as_str())),
        }
    }

    let mut output = format!("appctl uninstall {app_id}\nremoved {removed} entries\n");
    for failure in failures {
        output.push_str(&format!("warning: {failure}\n"));
    }
    output
}

fn appctl_recover(fs: &FileSystem) -> String {
    match super::install::recover_install_management_state(fs) {
        Ok(report) => {
            let mut output = String::from("appctl recover\n");
            output.push_str(&format!(
                "recovered transactions: {}\n",
                report.recovered_transactions.len()
            ));
            output.push_str(&format!(
                "repaired transaction log entries: {}\n",
                report.repaired_transaction_logs.len()
            ));
            output.push_str(&format!(
                "repaired download cache entries: {}\n",
                report.repaired_download_cache.len()
            ));
            if let Some(error) = report.transaction_recovery_error {
                output.push_str(&format!(
                    "transaction recovery warning: {}\n",
                    error.as_str()
                ));
            }
            if let Some(error) = report.download_cache_recovery_error {
                output.push_str(&format!(
                    "download cache recovery warning: {}\n",
                    error.as_str()
                ));
            }
            output
        }
        Err(error) => format!("appctl recover failed: {}\n", error.as_str()),
    }
}

fn appctl_cache_prune(fs: &FileSystem) -> String {
    match super::install::recover_install_management_state(fs) {
        Ok(report) => format!(
            "appctl cache-prune\npruned {} download cache entries\n",
            report.repaired_download_cache.len()
        ),
        Err(error) => format!("appctl cache-prune failed: {}\n", error.as_str()),
    }
}

// ── app-center ───────────────────────────────────────────────────────

/// Execute one `app-center` command against `fs`, returning its output text.
pub(super) fn run_app_center_command(fs: &FileSystem, _cwd: &str, argv: &[String]) -> String {
    let args = effective_arguments(argv);
    match args.first().map(String::as_str) {
        None | Some("dashboard") | Some("help") => app_center_dashboard(fs),
        Some("installed") => app_center_installed(fs),
        Some("versions") => app_center_versions(fs, args.get(1)),
        Some("details") => app_center_details(fs, args.get(1)),
        Some("recover") => app_center_recover(fs),
        Some(other) => format!("app-center: unknown command `{other}`\n"),
    }
}

fn app_center_dashboard(fs: &FileSystem) -> String {
    let ids = installed_app_ids(fs);
    let mut output = format!("app-center dashboard\ninstalled apps: {}\n", ids.len());
    for id in ids {
        let version = current_version(fs, &id).unwrap_or_else(|| "(none)".into());
        output.push_str(&format!("  {id:20} {version}\n"));
    }
    output
}

fn app_center_installed(fs: &FileSystem) -> String {
    app_center_dashboard(fs)
}

fn app_center_versions(fs: &FileSystem, app_id: Option<&String>) -> String {
    let Some(app_id) = app_id else {
        return "app-center: invalid usage for `versions` (requires an app id)\n".into();
    };
    let versions = catalog_versions(fs, app_id);
    let mut output = format!("app-center versions {app_id}\n");
    if versions.is_empty() {
        output.push_str(&format!("(no published versions for `{app_id}`)\n"));
        return output;
    }
    for version in versions {
        let active = match current_version(fs, app_id) {
            Some(current) if current == version => " (active)",
            _ => "",
        };
        output.push_str(&format!("{version}{active}\n"));
    }
    output
}

fn app_center_details(fs: &FileSystem, app_id: Option<&String>) -> String {
    let Some(app_id) = app_id else {
        return "app-center: invalid usage for `details` (requires an app id)\n".into();
    };
    let current = current_version(fs, app_id).unwrap_or_else(|| "(none)".into());
    let versions = catalog_versions(fs, app_id);
    let mut output = format!("app-center details {app_id}\n");
    output.push_str(&format!("active version: {current}\n"));
    output.push_str(&format!("published versions: {}\n", versions.len()));
    output
}

fn app_center_recover(fs: &FileSystem) -> String {
    appctl_recover(fs)
}

// ── lumina ───────────────────────────────────────────────────────────

/// Execute one `lumina` command against `fs`, returning `(exit_code, output)`.
pub(super) fn run_lumina_command(fs: &FileSystem, _cwd: &str, argv: &[String]) -> (i32, String) {
    let args = effective_arguments(argv);
    match args.first().map(String::as_str) {
        None | Some("help") => (0, lumina_help()),
        Some("list") => (0, lumina_list(fs)),
        Some("search") => (0, lumina_search(fs, args.get(1))),
        Some("repo") => (0, lumina_repo(fs, &args[1..])),
        Some(other) => (1, format!("lumina: unknown command `{other}`\n")),
    }
}

fn lumina_help() -> String {
    "usage: lumina <command> [args]\n\
     commands: list, search <term>, repo, help\n"
        .into()
}

fn lumina_list(fs: &FileSystem) -> String {
    let ids = installed_app_ids(fs);
    let mut output = String::from("lumina list\n");
    if ids.is_empty() {
        output.push_str("(no installed packages)\n");
        return output;
    }
    for id in ids {
        let version = current_version(fs, &id).unwrap_or_else(|| "(none)".into());
        output.push_str(&format!("{id}@{version}\n"));
    }
    output
}

fn lumina_search(fs: &FileSystem, term: Option<&String>) -> String {
    let term = match term {
        Some(term) => term.as_str(),
        None => return "lumina: invalid usage for `search` (requires a search term)\n".into(),
    };
    let mut output = format!("lumina search {term}\n");
    let children = match read_dir_children(fs, INSTALLED_CATALOG_ROOT) {
        Ok(children) => children,
        Err(_) => return output + "(catalog unavailable)\n",
    };
    let mut matches: Vec<String> = Vec::new();
    for child in children {
        if child.kind != NodeKind::File || !child.name.ends_with(".toml") {
            continue;
        }
        if child.name.contains('@') {
            continue;
        }
        let id = child.name.trim_end_matches(".toml");
        if id.contains(term) {
            matches.push(id.to_string());
        }
    }
    matches.sort();
    if matches.is_empty() {
        output.push_str("(no matching packages)\n");
    } else {
        for id in matches {
            output.push_str(&format!("{id}\n"));
        }
    }
    output
}

fn lumina_repo(fs: &FileSystem, args: &[String]) -> String {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let mut output = String::from("lumina repo list\n");
            match read_dir_children(fs, "/data/repos") {
                Ok(children) => {
                    let mut names: Vec<&str> = children
                        .iter()
                        .filter(|child| child.kind == NodeKind::File)
                        .map(|child| child.name.as_str())
                        .collect();
                    names.sort();
                    if names.is_empty() {
                        output.push_str("(no repositories configured)\n");
                    } else {
                        for name in names {
                            output.push_str(&format!("{name}\n"));
                        }
                    }
                }
                Err(_) => output.push_str("(no repositories configured)\n"),
            }
            output
        }
        Some("add") => {
            let name = match args.get(1) {
                Some(name) => name,
                None => {
                    return "lumina: invalid usage for `repo add` (requires a name and url)\n"
                        .into()
                }
            };
            let url = match args.get(2) {
                Some(url) => url,
                None => {
                    return "lumina: invalid usage for `repo add` (requires a name and url)\n"
                        .into()
                }
            };
            if let Err(error) = create_dir_with_current_security(fs, "/data/repos") {
                if error != Error::AlreadyExists {
                    return format!("lumina: repo add failed: {}\n", error.as_str());
                }
            }
            let path = format!("/data/repos/{name}.toml");
            let text = format!(
                "name = {}\nurl = {}\nenabled = true\n",
                super::metadata::render_string_literal(name),
                super::metadata::render_string_literal(url)
            );
            match super::catalog::write_entire_text_file(fs, &path, &text) {
                Ok(()) => format!("lumina: added repository `{name}`\n"),
                Err(error) => format!("lumina: repo add failed: {}\n", error.as_str()),
            }
        }
        Some(other) => format!("lumina: unknown repo subcommand `{other}`\n"),
    }
}
