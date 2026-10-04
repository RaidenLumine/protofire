//! src/kernel/service.rs
//!
//! Service manager and runtime service registry.
//!
//! The manager loads service definitions from `/system/rc.d/*.toml` and spawns
//! kernel worker threads and user programs at boot.  The registry remembers
//! what happened to each one afterwards — whether it is still running, how many
//! times the supervisor has restarted it, and why it last failed — and is the
//! single source of truth behind the read-only `/service` filesystem.
//!
//! Replaces the hard-coded `spawn_system_programs()` with a config-driven
//! approach. The distribution provides the config files; the kernel provides
//! the mechanism.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::process::GroupId;
use crate::kernel::process::IntegrityLevel;
use crate::kernel::process::ProcessId;
use crate::kernel::process::SecurityToken;
use crate::kernel::process::UserId;
use crate::kernel::sync::Mutex;
use crate::user::shared::config::ConfigEntryLookup;
use crate::user::shared::config::{self};

/// The directory on the boot filesystem where service config TOML files live.
pub const SERVICE_CONFIG_DIR: &str = "/system/rc.d";

/// The zone a service declaration has to live in.
///
/// A declaration decides what runs and as whom, so the kernel only reads one
/// out of the read-only system zone.  A program that hands over a path is
/// naming a file the machine's own image put there; it cannot invent the bytes,
/// which is what lets a privileged level rest on where its declaration came
/// from.
pub const SERVICE_DECLARATION_ROOT: &str = "/system";

/// Longest declaration file the kernel reads.
///
/// A declaration is a handful of keys per service; this is far above any real
/// one and far below a size that would hold the filesystem lock for long while
/// it parses.  Both readers enforce it — the boot path and `service_declare` —
/// so a disk cannot make the kernel allocate without bound.
pub const MAX_DECLARATION_BYTES: usize = 64 * 1024;

/// Whether a declaration may be read from `path`.
///
/// The kernel only reads a declaration out of the read-only system zone, which
/// is what makes the origin worth recording: the file is part of the machine's
/// own image, put there by the distribution, and a caller cannot write one.
/// `path` is expected to be absolute and already normalized, so the check is a
/// prefix and nothing more.
fn is_declaration_path(path: &str) -> bool {
    path.strip_prefix(SERVICE_DECLARATION_ROOT)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Read one declaration file, register every service in it, and return how
/// many.
///
/// This is the one way a program reaches the registry: `service_declare` hands
/// over the path its init read, and everything that decides what may be
/// declared happens here — the path is resolved against the root (so the answer
/// cannot depend on the caller's working directory), it has to name a file in
/// the read-only system zone, and the services come back stamped with the file
/// they were read from.
pub fn declare_file(fs: &crate::fs::FileSystem, path: &str, now_tick: u64) -> crate::Result<usize> {
    let path = crate::fs::path::normalize_path(path, "/")?;
    if !is_declaration_path(&path) {
        return Err(crate::Error::PermissionDenied);
    }

    let services = read_declaration_file(fs, &path)?;
    for service in &services {
        register(service, now_tick);
    }
    Ok(services.len())
}

/// The account a privileged service runs as when its definition does not name
/// one.
///
/// Requiring the account rather than assuming root is what makes a privileged
/// declaration an authorization: the name has to resolve in the user database
/// before the service runs at all.
pub const DEFAULT_PRIVILEGED_ACCOUNT: &str = "root";

// ── Service definition types ─────────────────────────────────────────────────

/// The kind of service to launch.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceKind {
    /// A ring3 user program (ELF binary).
    UserProgram,
    /// A kernel worker thread (runs in ring0).
    KernelThread,
}

impl ServiceKind {
    /// Return the name reported by `/service/<name>/kind`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UserProgram => "user_program",
            Self::KernelThread => "kernel_thread",
        }
    }
}

/// Security level for a user program service.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceSecurity {
    Guest,
    Admin,
    System,
}

impl ServiceSecurity {
    /// Parse a security level from a string.
    pub fn parse(s: &str) -> Self {
        match s {
            "admin" => ServiceSecurity::Admin,
            "system" => ServiceSecurity::System,
            _ => ServiceSecurity::Guest,
        }
    }

    /// Return the name reported by `/service/<name>/security`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }

    /// Return the token a user program declared at this level runs under.
    ///
    /// `account` is the `(uid, gid)` the caller resolved from the user
    /// database.  The guest level has no account to carry; every level above
    /// it does, and is refused without one rather than quietly handed the
    /// guest token.  Neither token carries password authentication: the flag
    /// that proves a login keeps the discretionary-permission bypass out of
    /// reach here, and only [`SecurityToken::system`] — the kernel's own
    /// threads — is above the discretionary checks.
    pub const fn security_token(
        &self,
        account: Option<(UserId, GroupId)>,
    ) -> crate::Result<SecurityToken> {
        match self {
            Self::Guest => Ok(SecurityToken::guest()),
            Self::Admin => match account {
                Some((uid, gid)) => Ok(SecurityToken::provisioned(uid, gid, IntegrityLevel::High)),
                None => Err(crate::Error::PermissionDenied),
            },
            Self::System => match account {
                Some((uid, gid)) => {
                    Ok(SecurityToken::provisioned(uid, gid, IntegrityLevel::System))
                }
                None => Err(crate::Error::PermissionDenied),
            },
        }
    }

    /// Return true when this level needs an account resolved before the
    /// service may run.
    pub const fn requires_account(&self) -> bool {
        !matches!(self, Self::Guest)
    }
}

/// Where a service's declaration came from.
///
/// A declaration is a file, and this says which one and which bytes of it.  It
/// is what a reader needs to attribute a service — and, for a privileged one,
/// to say what the privilege rests on: the file is in the read-only system
/// zone, and the digest is the one the kernel computed from what it read, not
/// one the declarer supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceOrigin {
    /// The declaration file, as an absolute path.
    pub path: String,
    /// Lowercase hex SHA-256 of that file's bytes.
    pub sha256: String,
}

/// A parsed service definition from a config file.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceDefinition {
    pub name: String,
    pub kind: ServiceKind,
    /// Which declaration file this definition was read from, and which bytes.
    ///
    /// The parser leaves it `None`: it holds the text, not the file.  Whoever
    /// *read* the declaration fills it in — the boot path and the kernel half
    /// of `service_declare` both go through [`read_declaration_file`] — so a
    /// service can always be attributed to the file that declared it.  A
    /// definition that no file produced (the built-in fallback, a test) has no
    /// origin to report.
    pub origin: Option<ServiceOrigin>,
    /// For UserProgram: path to the ELF binary (e.g. `/system/shell.elf`).
    pub path: Option<String>,
    /// For KernelThread: name of the entry function (e.g. `demo_worker_a`).
    pub entry: Option<String>,
    /// Command-line arguments for UserProgram services.
    pub args: Vec<String>,
    /// Services this one is started after.
    ///
    /// Ordering, not a promise about what those services achieve: a daemon
    /// that binds a port is not "done" when it has been spawned, and a service
    /// manager that waited for one would wait forever.  What the declaration
    /// does buy is attribution — a service whose prerequisite never started is
    /// reported as blocked, with the prerequisite named, instead of failing
    /// later for a reason nobody can see from `/service`.
    pub after: Vec<String>,
    /// If true, the service is restarted when it exits.
    pub auto_restart: bool,
    /// Security token for UserProgram services.
    pub security: ServiceSecurity,
    /// Account a privileged service runs as, resolved through the user
    /// database at spawn time.  Only meaningful above
    /// [`ServiceSecurity::Guest`], which is why the parser rejects the
    /// combination rather than ignoring it.
    pub account: Option<String>,
}

impl ServiceDefinition {
    /// Return the account this definition claims, or `None` for a guest
    /// service, which claims no privilege and therefore needs no identity.
    pub fn account_name(&self) -> Option<&str> {
        if !self.security.requires_account() {
            return None;
        }

        Some(
            self.account
                .as_deref()
                .unwrap_or(DEFAULT_PRIVILEGED_ACCOUNT),
        )
    }
}

// ── Loading from config files ────────────────────────────────────────────────

/// Load service definitions from a TOML config text.
///
/// Expected format:
/// ```toml
/// format = "protofire-service-1"
///
/// [[service]]
/// name = "shell"
/// kind = "user_program"
/// path = "/system/shell.elf"
/// args = ["--interactive"]
/// auto_restart = false
/// security = "guest"
///
/// [[service]]
/// name = "netd"
/// kind = "user_program"
/// path = "/system/netd.elf"
/// security = "admin"
/// account = "root"        # required above "guest"; defaults to "root"
///
/// [[service]]
/// name = "netd"
/// kind = "user_program"
/// path = "/system/netd.elf"
/// security = "admin"
/// account = "root"        # required above "guest"; defaults to "root"
///
/// [[service]]
/// name = "httpd"
/// after = ["netd"]        # started after netd has been started
///
/// [[service]]
/// name = "kworker-a"
/// kind = "kernel_thread"
/// entry = "demo_worker_a"
/// auto_restart = true
/// ```
pub fn parse_service_config(text: &str) -> Result<Vec<ServiceDefinition>, String> {
    let doc = config::parse_config(text)
        .map_err(|e| alloc::format!("failed to parse service config: {}", e.as_str()))?;

    // Validate format marker.
    let format = doc.get_str_or("format", "");
    if format != "protofire-service-1" {
        return Err(alloc::format!(
            "unsupported service config format: {:?}",
            format
        ));
    }

    let elements = doc.array_elements("service");
    let mut services = Vec::with_capacity(elements.len());

    for element in &elements {
        let kind_str = element.get_str_or("kind", "user_program");
        let kind = match kind_str {
            "kernel_thread" => ServiceKind::KernelThread,
            _ => ServiceKind::UserProgram,
        };

        let security = ServiceSecurity::parse(element.get_str_or("security", "guest"));
        let account = element.get_str("account").ok().map(String::from);

        // A guest service claims no privilege, so naming an account for one is
        // a contradiction the author wants to hear about rather than a field
        // to ignore: it reads like an escalation that silently did not happen.
        if account.is_some() && !security.requires_account() {
            return Err(alloc::format!(
                "service {:?} declares `account` with `security = \"guest\"`",
                element.get_str_or("name", "unnamed")
            ));
        }

        let svc = ServiceDefinition {
            name: element
                .get_str("name")
                .map(String::from)
                .unwrap_or_else(|_| String::from("unnamed")),
            kind,
            // The text does not know which file it came from; the reader that
            // supplies it does.
            origin: None,
            path: element.get_str("path").ok().map(String::from),
            entry: element.get_str("entry").ok().map(String::from),
            args: element.get_string_list("args").unwrap_or_default(),
            after: element.get_string_list("after").unwrap_or_default(),
            auto_restart: element.get_bool_or("auto_restart", false),
            security,
            account,
        };

        services.push(svc);
    }

    Ok(services)
}

/// Read one declaration file and return the services it declares.
///
/// The kernel reads the file itself, from its own filesystem: `service_declare`
/// is handed a *path*, and the boot path walks this directory itself.  A
/// program therefore chooses *which* files are declarations without being able
/// to say what they contain, and every definition comes back stamped with the
/// file it came from ([`ServiceOrigin`]).
///
/// The read is bounded by [`MAX_DECLARATION_BYTES`] so a disk cannot make the
/// kernel allocate without bound.  A file that cannot be read, or that does not
/// parse, is an error rather than an empty list: the caller is the one that
/// knows whether that is worth reporting.
pub fn read_declaration_file(
    fs: &crate::fs::FileSystem,
    path: &str,
) -> crate::Result<Vec<ServiceDefinition>> {
    use crate::fs::OPEN_EXISTING;
    use crate::kernel::process::HANDLE_RIGHT_READ;

    let metadata = fs
        .stat_path(path)
        .map_err(|_error| crate::Error::NotFound)?;
    if metadata.size > MAX_DECLARATION_BYTES {
        return Err(crate::Error::InvalidArgument);
    }

    // Open the file for reading (existing files only).
    let mut handle = fs
        .create_file(path, HANDLE_RIGHT_READ, 0, OPEN_EXISTING)
        .map_err(|_error| crate::Error::NotFound)?;

    // Read the entire file.
    let mut buf = alloc::vec![0u8; metadata.size];
    let n = fs
        .read(&mut handle, &mut buf)
        .map_err(|_error| crate::Error::InternalError)?;
    buf.truncate(n);

    let text = core::str::from_utf8(&buf).map_err(|_error| crate::Error::InvalidArgument)?;
    let mut services =
        parse_service_config(text).map_err(|_error| crate::Error::InvalidArgument)?;

    let origin = ServiceOrigin {
        path: alloc::string::String::from(path),
        sha256: crate::kernel::crypto::sha256_hex(&buf),
    };
    for service in &mut services {
        service.origin = Some(origin.clone());
    }

    Ok(services)
}

/// Load service definitions from `/system/rc.d/*.toml` on the given filesystem.
///
/// Reads all directory entries in `dir`, filters for `.toml` files, and hands
/// each one to [`read_declaration_file`] — the same reader `service_declare`
/// uses, so a service the boot found and one a program declared carry the same
/// origin.
///
/// Files that fail to open, read, or parse are silently skipped so a single
/// malformed config file doesn't prevent the system from booting — the kernel
/// falls back to the embedded default configuration when this function returns
/// an empty list.
pub fn load_services_from_fs(fs: &crate::fs::FileSystem, dir: &str) -> Vec<ServiceDefinition> {
    let mut all_services: Vec<ServiceDefinition> = Vec::new();

    // Walk directory entries by index.  The kernel doesn't have a
    // read_dir_all() iterator, so we loop until NotFound.
    let mut index: usize = 0;
    while let Ok(entry) = fs.read_dir(dir, index) {
        index += 1;

        // Only process .toml files.
        if !entry.name.ends_with(".toml") {
            continue;
        }

        // Construct the full path: "{dir}/{name}".  We strip a trailing
        // slash from dir so we don't produce double slashes.
        let dir_trimmed = dir.trim_end_matches('/');
        let path = alloc::format!("{}/{}", dir_trimmed, entry.name);

        if let Ok(services) = read_declaration_file(fs, &path) {
            all_services.extend(services);
        }
    }

    all_services
}

// ── The default service set, and its written form ───────────────────────────

/// The name a launch reference contributes to the service table.
///
/// The last path segment with its extension removed, so
/// `/apps/current/demo-launcher.toml` is `demo-launcher`.  A leading dot names
/// a hidden file rather than an extension, so `.profile` keeps its name.
#[cfg(any(feature = "demo-disk", test))]
fn default_service_name(launch_reference: &str) -> String {
    let file = launch_reference
        .rsplit('/')
        .next()
        .unwrap_or(launch_reference);
    match file.rsplit_once('.') {
        Some((stem, _extension)) if !stem.is_empty() => String::from(stem),
        _ => String::from(file),
    }
}

/// The service set a boot uses when its disk declares none, and the set the
/// demo disk ships as `/system/rc.d/defaults.toml`.
///
/// One list, two renderings.  The failure this avoids is the one that hides:
/// two copies that agree until somebody edits one, after which a boot disk
/// works only because the kernel kept its own version of the configuration.
/// The demo-disk builder writes [`render_config`] of this, and the boot path
/// falls back to it, so a disk with `/system/rc.d` and a disk without run the
/// same system.
#[cfg(any(feature = "demo-disk", test))]
pub fn default_definitions() -> Vec<ServiceDefinition> {
    let mut services = Vec::new();

    for (name, entry) in [
        ("kworker-a", "demo_worker_a"),
        ("kworker-b", "demo_worker_b"),
        ("kworker-syscall-fs", "demo_syscall_fs_worker"),
    ] {
        services.push(ServiceDefinition {
            name: String::from(name),
            kind: ServiceKind::KernelThread,
            origin: None,
            path: None,
            entry: Some(String::from(entry)),
            args: Vec::new(),
            after: Vec::new(),
            auto_restart: false,
            security: ServiceSecurity::Guest,
            account: None,
        });
    }

    let shell = crate::user::program::SHELL_CURRENT_PATH;
    services.push(ServiceDefinition {
        name: default_service_name(shell),
        kind: ServiceKind::UserProgram,
        origin: None,
        path: Some(String::from(shell)),
        entry: None,
        args: Vec::new(),
        after: Vec::new(),
        auto_restart: false,
        security: ServiceSecurity::Guest,
        account: None,
    });

    for &(launch_reference, auto_restart) in crate::arch::platform::demo_user_programs() {
        services.push(ServiceDefinition {
            name: default_service_name(launch_reference),
            kind: ServiceKind::UserProgram,
            origin: None,
            path: Some(String::from(launch_reference)),
            entry: None,
            args: Vec::new(),
            after: Vec::new(),
            auto_restart,
            security: ServiceSecurity::Guest,
            account: None,
        });
    }

    services
}

/// Render definitions as the TOML [`parse_service_config`] reads.
///
/// The inverse is a property rather than a hope: a round-trip test parses what
/// this writes and compares it with what went in, which is what lets the demo
/// disk ship a configuration generated from the same list the kernel falls
/// back to.
///
/// Keys are written where they differ from the parser's defaults — no
/// `security = "guest"` or `auto_restart = false` on every entry — because the
/// defaults are what the parser documents, and a generated file that spells
/// each one out is harder to read than the list it came from.
pub fn render_config(services: &[ServiceDefinition]) -> String {
    let mut out = String::from("format = \"protofire-service-1\"\n");

    for service in services {
        out.push_str("\n[[service]]\n");
        write_field(&mut out, "name", &service.name);
        write_field(&mut out, "kind", service.kind.as_str());
        if let Some(path) = &service.path {
            write_field(&mut out, "path", path);
        }
        if let Some(entry) = &service.entry {
            write_field(&mut out, "entry", entry);
        }
        if !service.args.is_empty() {
            write_list(&mut out, "args", &service.args);
        }
        if !service.after.is_empty() {
            write_list(&mut out, "after", &service.after);
        }
        if service.auto_restart {
            out.push_str("auto_restart = true\n");
        }
        if service.security != ServiceSecurity::Guest {
            write_field(&mut out, "security", service.security.as_str());
        }
        if let Some(account) = &service.account {
            write_field(&mut out, "account", account);
        }
    }

    out
}

/// Append `key = "value"`, escaping what the parser un-escapes.
fn write_field(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    write_quoted(out, value);
    out.push('\n');
}

/// Append `key = ["a", "b"]`.
fn write_list(out: &mut String, key: &str, values: &[String]) {
    out.push_str(key);
    out.push_str(" = [");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write_quoted(out, value);
    }
    out.push_str("]\n");
}

/// Append a quoted string, using the escapes the config parser reads back.
fn write_quoted(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            other => out.push(other),
        }
    }
    out.push('"');
}

// ── Runtime registry ─────────────────────────────────────────────────────────

/// What the boot path should start, and in what order.
#[derive(Debug, Default)]
pub struct StartOrder {
    /// Services with a place in the order, earliest first.
    pub start: Vec<ServiceDefinition>,
    /// Declared services nothing will start, with the reason, by name.
    pub blocked: Vec<(ServiceDefinition, String)>,
}

/// Work out the order to start `services` in, and what cannot start at all.
///
/// A definition's `after` names services it must be started after.  The order
/// is a function of the declarations alone — services with nothing to wait for
/// keep the order they were read in — so two boots of the same `rc.d` start the
/// same things in the same order and a test can pin it.
///
/// A service with no place in the order is *blocked* rather than started
/// anyway, and the reason says which of three things went wrong: a
/// prerequisite that is not declared, a prerequisite that is itself blocked,
/// or a cycle, named in full.  Blocking is transitive, which is the point — a
/// chain of three services ending at a name nobody declared is one error that
/// names all of them, not three failures that each look like their own.
///
/// A repeated name keeps its last declaration, matching [`register`].
pub fn plan_start_order(services: &[ServiceDefinition]) -> StartOrder {
    let mut declared: BTreeMap<&str, &ServiceDefinition> = BTreeMap::new();
    let mut position: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, service) in services.iter().enumerate() {
        declared.insert(service.name.as_str(), service);
        // Last declaration wins here too: the position the order uses is the
        // one that matches the definition the registry ends up holding.
        position.insert(service.name.as_str(), index);
    }

    // 1. A prerequisite that is not declared — or that is the service itself —
    //    leaves the service with no order to be in.
    let mut blocked: BTreeMap<&str, String> = BTreeMap::new();
    for (name, service) in &declared {
        let missing = service
            .after
            .iter()
            .find(|target| target.as_str() == *name || !declared.contains_key(target.as_str()));
        if let Some(prerequisite) = missing {
            blocked.insert(
                name,
                if prerequisite == *name {
                    alloc::format!("after \"{name}\", which is itself")
                } else {
                    alloc::format!("after \"{prerequisite}\", which is not declared")
                },
            );
        }
    }

    // 2. Kahn's algorithm over what is left, taking the frontier in the order the
    //    declarations were read so the result is deterministic *and* a system whose
    //    declarations say nothing keeps the order it had before the order was
    //    computed at all.
    let mut start_order: Vec<&str> = Vec::new();
    let mut started: BTreeMap<&str, ()> = BTreeMap::new();
    loop {
        let mut ready: Vec<(&str, usize)> = declared
            .iter()
            .filter(|(name, service)| {
                !started.contains_key(*name)
                    && !blocked.contains_key(*name)
                    && service
                        .after
                        .iter()
                        .all(|target| started.contains_key(target.as_str()))
            })
            .map(|(name, _)| (*name, position[name]))
            .collect();
        if ready.is_empty() {
            break;
        }
        ready.sort_by_key(|(_, index)| *index);
        for (name, _) in ready {
            started.insert(name, ());
            start_order.push(name);
        }
    }

    // 3. A service whose prerequisite is blocked is blocked for that reason,
    //    transitively: repeated until nothing changes, because a chain can be as
    //    long as the declarations.
    loop {
        let newly: Vec<(&str, String)> = declared
            .iter()
            .filter(|(name, _)| !started.contains_key(*name) && !blocked.contains_key(*name))
            .filter_map(|(name, service)| {
                service
                    .after
                    .iter()
                    .find(|target| blocked.contains_key(target.as_str()))
                    .map(|prerequisite| {
                        (
                            *name,
                            alloc::format!("after \"{prerequisite}\", which is blocked"),
                        )
                    })
            })
            .collect();
        if newly.is_empty() {
            break;
        }
        for (name, reason) in newly {
            blocked.insert(name, reason);
        }
    }

    // 4. What is left has every prerequisite unstarted too, so following
    //    prerequisites from any of them must revisit a service: each one is in, or
    //    leads into, a cycle.  The walk is deterministic — name order, then the
    //    first prerequisite — so the cycle a reason names is the same one every
    //    boot.
    let mut cycles: BTreeMap<&str, String> = BTreeMap::new();
    for name in declared.keys() {
        if started.contains_key(name) || blocked.contains_key(name) || cycles.contains_key(name) {
            continue;
        }

        let mut path: Vec<&str> = Vec::new();
        let mut position: BTreeMap<&str, usize> = BTreeMap::new();
        let mut cursor = *name;
        let cycle = loop {
            if let Some(&entered_at) = position.get(cursor) {
                break Some(path[entered_at..].to_vec());
            }
            position.insert(cursor, path.len());
            path.push(cursor);

            let next = declared[cursor]
                .after
                .iter()
                .map(String::as_str)
                .filter(|target| {
                    declared.contains_key(target)
                        && !started.contains_key(target)
                        && !blocked.contains_key(target)
                })
                .min();
            match next {
                Some(target) => cursor = target,
                None => break None,
            }
        };

        let reason = match &cycle {
            Some(cycle) => {
                alloc::format!("dependency cycle: {} -> {}", cycle.join(" -> "), cycle[0])
            }
            // Unreachable: a service whose every prerequisite is started or
            // blocked would have been placed by step 2 or 3.  Saying so beats
            // a panic in the boot path if that ever stops being true.
            None => String::from("no place in the start order"),
        };
        for member in path {
            cycles.insert(member, reason.clone());
        }
    }

    StartOrder {
        start: start_order
            .iter()
            .map(|name| (*declared[name]).clone())
            .collect(),
        blocked: declared
            .iter()
            .filter_map(|(name, service)| {
                blocked
                    .get(name)
                    .or_else(|| cycles.get(name))
                    .map(|reason| ((*service).clone(), reason.clone()))
            })
            .collect(),
    }
}

/// Maximum number of automatic restarts before a service is abandoned.
///
/// A service that fails this many times is treated as misconfigured rather
/// than transient.  Restarting without a budget turns one crash loop into a
/// permanently burning core, which is worse than a service that stays down and
/// says so in `/service/<name>/state`.
pub const MAX_SERVICE_RESTARTS: u32 = 3;

/// Minimum number of scheduler ticks between two restarts of the same service.
///
/// At the scheduler's 100 Hz tick this is a two-second backoff: long enough
/// that a fast crash loop cannot starve the rest of the system, short enough
/// that a service recovering from a transient fault comes back promptly.
///
/// The window is measured from the service's last spawn, not from the moment
/// the supervisor noticed it had died.  A service that dies a few ticks after
/// starting is in a crash loop and waits; one that ran for longer than the
/// window was not, and restarts as soon as its death is seen.
pub const SERVICE_RESTART_BACKOFF_TICKS: u64 = 200;

/// Lifecycle state of one service.
///
/// The registry moves a service through these states, and
/// `/service/<name>/state` reports the current one:
///
/// - `Pending` → `Running`: the boot path or the supervisor spawned it.
/// - `Running` → `Failed`: the supervisor observed that its process is gone.
/// - `Failed` → `Running`: the supervisor restarted it.
/// - `Failed` → `Abandoned`: the restart budget ran out.
/// - `Failed` → `Stopped`: the service asked for no restart.
/// - `Pending` → `Blocked`: the boot path planned a start order and this
///   service had no place in it (a prerequisite that is not declared, or a
///   dependency cycle).  Nothing ran it, so nothing ever observed it die.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Declared, but never spawned.
    Pending,
    /// Spawned and not yet observed to exit.
    Running,
    /// Exited normally and not configured for restart.
    Stopped,
    /// Exited unexpectedly; the supervisor may still restart it.
    Failed,
    /// Exited and the supervisor gave up on it.
    Abandoned,
    /// Declared, but nothing could start it: its place in the start order
    /// could not be worked out.  `last_error` names the reason.
    Blocked,
}

impl ServiceState {
    /// Return the name reported by `/service/<name>/state`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
            Self::Blocked => "blocked",
        }
    }

    /// Return true while a live instance is expected to exist.
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Return true when the service will not move again without intervention.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Abandoned | Self::Blocked)
    }
}

/// What the supervisor should do about a service that is not running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionAction {
    /// Spawn the service again.
    Restart,
    /// Leave it down: it is not configured for restart.
    LeaveStopped,
    /// Stop trying: the restart budget is exhausted.
    Abandon,
    /// Do nothing yet — the backoff window has not elapsed.
    WaitForBackoff,
}

/// The registry's view of one service.
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    /// The declaration this record was created from.  Retained in full so the
    /// supervisor can respawn the service without re-reading `/system/rc.d`.
    pub definition: ServiceDefinition,
    pub state: ServiceState,
    /// Number of times the supervisor has respawned this service.
    pub restarts: u32,
    /// Why the service last left the running state.  This survives a
    /// successful restart, so a running service can still be asked what went
    /// wrong before it came back.
    pub last_error: Option<String>,
    /// Scheduler tick at which `state` was entered.
    pub state_since_tick: u64,
    /// PID of the current instance, when one was observed.
    pub pid: Option<ProcessId>,
}

impl ServiceRecord {
    /// Return the service name.
    pub fn name(&self) -> &str {
        &self.definition.name
    }

    /// Return true when the supervisor restarts this service on exit.
    pub fn auto_restart(&self) -> bool {
        self.definition.auto_restart
    }

    /// Return the ELF path for a user program, or the worker entry name for a
    /// kernel thread.
    pub fn launch_target(&self) -> Option<&str> {
        match self.definition.kind {
            ServiceKind::UserProgram => self.definition.path.as_deref(),
            ServiceKind::KernelThread => self.definition.entry.as_deref(),
        }
    }
}

/// Decide what to do about a service that has left the running state.
///
/// `now_tick` is compared against [`ServiceRecord::state_since_tick`] — the
/// time of the last spawn — to enforce [`SERVICE_RESTART_BACKOFF_TICKS`].
/// Keeping this a pure function of the record and the clock is deliberate: the
/// restart policy is the part of supervision that is worth testing
/// exhaustively, and it needs no scheduler, no filesystem, and no live process
/// to exercise.
pub fn supervision_action(record: &ServiceRecord, now_tick: u64) -> SupervisionAction {
    if !record.auto_restart() {
        return SupervisionAction::LeaveStopped;
    }
    if record.restarts >= MAX_SERVICE_RESTARTS {
        return SupervisionAction::Abandon;
    }
    if now_tick.saturating_sub(record.state_since_tick) < SERVICE_RESTART_BACKOFF_TICKS {
        return SupervisionAction::WaitForBackoff;
    }
    SupervisionAction::Restart
}

/// One unit of supervision work, decided under the registry lock and carried
/// out after it is released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisionStep {
    pub name: String,
    pub action: SupervisionAction,
}

/// Every service the kernel knows about, sorted by name.
///
/// A `BTreeMap` rather than an insertion-ordered map because `ls /service` has
/// to be stable: the shell reads a directory one entry at a time, so a listing
/// that reorders itself between two reads would duplicate or skip services.
struct ServiceRegistry {
    services: BTreeMap<String, ServiceRecord>,
    /// The declarations in the order they arrived.
    ///
    /// The registry itself is a map, so it cannot answer "what order were these
    /// declared in" — which is exactly what the start order needs.  A repeated
    /// name is kept here as well; [`plan_start_order`] keeps the last
    /// declaration, the same way [`register`] does.
    declarations: Vec<ServiceDefinition>,
    /// Tick by which someone must have started the declared services, if the
    /// boot asked for the start to be left to the disk's init program.
    ///
    /// `None` means nobody is waiting: either the boot started them itself or
    /// something has started them since.
    deferred_start_deadline: Option<u64>,
}

impl ServiceRegistry {
    const fn new() -> Self {
        Self {
            services: BTreeMap::new(),
            declarations: Vec::new(),
            deferred_start_deadline: None,
        }
    }
}

/// Global registry of every service the kernel has been told about.
static SERVICE_REGISTRY: Mutex<ServiceRegistry> = Mutex::new(ServiceRegistry::new());

/// Register a definition, leaving the service in [`ServiceState::Pending`].
///
/// A declaration says what a service *is*; a service that has already run keeps
/// what it *did*.  Re-declaring a name therefore replaces the definition and
/// the start-order position — the boot path may parse the same service from two
/// files, and the last declaration wins — but leaves the state, the pid, the
/// restart count and the last error alone.  Otherwise an init program declaring
/// a service the boot already started would report it as pending while it ran.
pub fn register(definition: &ServiceDefinition, now_tick: u64) {
    // One lock for both halves: a reader that saw the declaration without the
    // record would be looking at a service that has no state to report.
    let mut registry = SERVICE_REGISTRY.lock();
    registry.declarations.push(definition.clone());
    // A declaration says what a service *is*; a service that has already run
    // keeps what it *did*.  Re-declaring a name replaces the definition and the
    // start-order position — the last file to name a service wins — but leaves
    // the state, the pid, the restart count and the last error alone.  An init
    // program declares services the boot may already have started, and a
    // declaration that reset a running service to pending would report it as
    // down while it ran.
    match registry.services.get_mut(&definition.name) {
        Some(record) => record.definition = definition.clone(),
        None => {
            registry.services.insert(
                definition.name.clone(),
                ServiceRecord {
                    definition: definition.clone(),
                    state: ServiceState::Pending,
                    restarts: 0,
                    last_error: None,
                    state_since_tick: now_tick,
                    pid: None,
                },
            );
        }
    }
}

/// Mark a service as spawned for the first time.
///
/// Does nothing when the service was never registered, so a spawn path that
/// runs before the registry is populated cannot invent a record.
pub fn mark_running(name: &str, pid: Option<ProcessId>, now_tick: u64) {
    update(name, |record| {
        record.state = ServiceState::Running;
        record.pid = pid;
        record.state_since_tick = now_tick;
    });
}

/// Record that the supervisor is about to respawn a service.
///
/// The attempt is counted here rather than on success, so that a service whose
/// program can never be loaded still runs out of budget instead of being
/// retried forever.  The state is left alone: the spawn that follows either
/// moves it to `Running` via [`mark_running`] or back to `Failed` via
/// [`mark_failed`].
pub fn note_restart_attempt(name: &str, now_tick: u64) {
    update(name, |record| {
        record.restarts = record.restarts.saturating_add(1);
        record.state_since_tick = now_tick;
    });
}

/// Mark a service as having exited unexpectedly.
pub fn mark_failed(name: &str, reason: &str, now_tick: u64) {
    update(name, |record| {
        record.state = ServiceState::Failed;
        record.pid = None;
        record.last_error = Some(String::from(reason));
        record.state_since_tick = now_tick;
    });
}

/// Mark a service as exited with no restart pending.
pub fn mark_stopped(name: &str, reason: &str, now_tick: u64) {
    update(name, |record| {
        record.state = ServiceState::Stopped;
        record.pid = None;
        record.last_error = Some(String::from(reason));
        record.state_since_tick = now_tick;
    });
}

/// Mark a service as given up on.
pub fn mark_abandoned(name: &str, reason: &str, now_tick: u64) {
    update(name, |record| {
        record.state = ServiceState::Abandoned;
        record.pid = None;
        record.last_error = Some(String::from(reason));
        record.state_since_tick = now_tick;
    });
}

/// Mark a service as never started, because its place in the start order
/// could not be worked out.
///
/// Distinct from [`mark_failed`]: nothing observed this service die, because
/// nothing ever ran it.  The supervisor leaves a blocked service alone — it is
/// not a restart candidate, and retrying it would produce the same plan.
pub fn mark_blocked(name: &str, reason: &str, now_tick: u64) {
    update(name, |record| {
        record.state = ServiceState::Blocked;
        record.pid = None;
        record.last_error = Some(String::from(reason));
        record.state_since_tick = now_tick;
    });
}

/// Apply `edit` to one record, if it exists.
fn update(name: &str, edit: impl FnOnce(&mut ServiceRecord)) {
    let mut registry = SERVICE_REGISTRY.lock();
    if let Some(record) = registry.services.get_mut(name) {
        edit(record);
    }
}

/// Return a copy of one service's record.
pub fn record(name: &str) -> Option<ServiceRecord> {
    SERVICE_REGISTRY.lock().services.get(name).cloned()
}

/// Return a copy of every record, sorted by service name.
pub fn snapshot() -> Vec<ServiceRecord> {
    SERVICE_REGISTRY.lock().services.values().cloned().collect()
}

/// Return the number of registered services.
pub fn service_count() -> usize {
    SERVICE_REGISTRY.lock().services.len()
}

/// Forget every registered service.
///
/// The registry is process-global, so a host test that leaves records behind
/// changes what the next test observes.  Only tests should call this.
pub fn reset_registry_for_tests() {
    let mut registry = SERVICE_REGISTRY.lock();
    registry.services.clear();
    registry.declarations.clear();
    registry.deferred_start_deadline = None;
}

/// Leave the declared services for the disk's init program to start.
///
/// The distribution's half of the service manager is a program on the disk: it
/// reads `/system/rc.d` and asks for the services to be started through
/// the `service_start_all` syscall.  When the boot has such a program, it
/// registers the declarations — `/service` and the supervisor need them either
/// way — and leaves the start to it.
///
/// `deadline_tick` is what keeps that from becoming a way to boot with no
/// services at all: a disk whose init never starts them is started by the
/// supervisor past that tick, the same way the boot path starts them when
/// there is no init program at all.
pub fn defer_declared_start(deadline_tick: u64) {
    SERVICE_REGISTRY.lock().deferred_start_deadline = Some(deadline_tick);
}

/// End a deferral: the declared services have been started.
///
/// Called wherever services are started, so that the caller which does the
/// work is the one that ends the wait — a start that happened before the
/// deadline must not leave the supervisor waiting to start them again.
pub fn cancel_deferred_start() {
    SERVICE_REGISTRY.lock().deferred_start_deadline = None;
}

/// Whether the deferral's deadline has arrived, consuming it.
///
/// True at most once per [`defer_declared_start`]: the caller this answers is
/// the supervisor, and a deadline that answered twice would have it plan the
/// same start again on every later pass.
pub fn take_expired_deferral(now_tick: u64) -> bool {
    let mut registry = SERVICE_REGISTRY.lock();
    match registry.deferred_start_deadline {
        Some(deadline) if now_tick >= deadline => {
            registry.deferred_start_deadline = None;
            true
        }
        _ => false,
    }
}

/// Plan the start order from the declarations the registry holds.
pub fn plan_declared() -> StartOrder {
    let declarations = SERVICE_REGISTRY.lock().declarations.clone();
    plan_start_order(&declarations)
}

/// Parse one declaration's text and register every service in it.
///
/// Test-only, and deliberately so: every declaration a boot sees comes from a
/// *file*, through [`read_declaration_file`], which is what stamps the origin
/// the privilege of a service rests on.  Text with no origin is something only
/// a test has, so only a test can register one.
#[cfg(test)]
pub fn declare_from_text(text: &str, now_tick: u64) -> Result<usize, String> {
    let services = parse_service_config(text)?;
    for service in &services {
        register(service, now_tick);
    }
    Ok(services.len())
}

/// Work out what the supervisor should do next, without doing any of it.
///
/// `is_alive` answers whether a process is still running; the caller supplies
/// it so this function stays independent of the scheduler and can be tested
/// against a fixed process population.  A service is only reported once it has
/// left the running state, so a healthy system returns an empty plan.
///
/// The returned steps must be carried out **after** this call returns.
/// Restarting re-enters the scheduler and the filesystem, and doing that while
/// holding the registry lock would deadlock against the next `/service` read.
pub fn plan_supervision(
    now_tick: u64,
    is_alive: impl Fn(ProcessId) -> bool,
) -> Vec<SupervisionStep> {
    // Snapshot, query, then apply — never query while holding this lock.
    //
    // `is_alive` reaches into the scheduler, so calling it under the registry
    // lock would nest a second subsystem's lock inside this one.
    let running: Vec<(String, ProcessId)> = {
        let registry = SERVICE_REGISTRY.lock();
        registry
            .services
            .values()
            .filter_map(|record| match (record.state, record.pid) {
                (ServiceState::Running, Some(pid)) => Some((record.name().into(), pid)),
                _ => None,
            })
            .collect()
    };

    let dead: Vec<String> = running
        .into_iter()
        .filter(|(_, pid)| !is_alive(*pid))
        .map(|(name, _)| name)
        .collect();

    let mut registry = SERVICE_REGISTRY.lock();
    let mut steps = Vec::new();

    for name in dead {
        if let Some(record) = registry.services.get_mut(&name) {
            // Observe a death that has not been recorded yet.
            //
            // `state_since_tick` is deliberately left alone here: it holds the
            // time of the last spawn, which is what `supervision_action`
            // measures the backoff against.  Resetting it to the observation
            // time would make every restart wait out a full window, including
            // the restart of a service that had been running healthily for
            // hours before it finally failed.
            record.state = ServiceState::Failed;
            record.pid = None;
            record.last_error = Some(String::from("process exited"));
        }
    }

    for record in registry.services.values() {
        if record.state != ServiceState::Failed {
            continue;
        }
        match supervision_action(record, now_tick) {
            SupervisionAction::WaitForBackoff => {}
            action => steps.push(SupervisionStep {
                name: record.name().into(),
                action,
            }),
        }
    }

    steps
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    /// Serialises the registry tests.
    ///
    /// The registry is process-global and `cargo test` runs one binary's tests
    /// in parallel, so a test that registers services and then asserts on
    /// counts or snapshots has to hold this for its whole body.
    static REGISTRY_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Take the registry lock and start from an empty registry.
    fn exclusive_registry() -> crate::kernel::sync::MutexGuard<'static, ()> {
        let guard = REGISTRY_TEST_LOCK.lock();
        reset_registry_for_tests();
        guard
    }

    /// Build a minimal user-program definition.
    fn definition(name: &str, auto_restart: bool) -> ServiceDefinition {
        ServiceDefinition {
            name: String::from(name),
            kind: ServiceKind::UserProgram,
            origin: None,
            path: Some(alloc::format!("/system/{}.elf", name)),
            entry: None,
            args: Vec::new(),
            after: Vec::new(),
            auto_restart,
            security: ServiceSecurity::Guest,
            account: None,
        }
    }

    /// Build a definition that follows `after`, for the ordering tests.
    fn following(name: &str, after: &[&str]) -> ServiceDefinition {
        ServiceDefinition {
            after: after.iter().map(|name| String::from(*name)).collect(),
            ..definition(name, false)
        }
    }

    // -- Registry ---------------------------------------------------------

    #[test]
    fn register_creates_pending_record() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 10);

        let record = record("alpha").expect("record");
        assert_eq!(record.state, ServiceState::Pending);
        assert_eq!(record.restarts, 0);
        assert_eq!(record.state_since_tick, 10);
        assert!(record.last_error.is_none());
        assert_eq!(record.pid, None);
        assert_eq!(record.launch_target(), Some("/system/alpha.elf"));
    }

    #[test]
    fn register_same_name_replaces_the_definition_and_keeps_the_state() {
        let _guard = exclusive_registry();
        register(&definition("alpha", false), 10);

        // The second declaration is the one that stands: the last file to name
        // a service says what that service is.
        register(&definition("alpha", true), 20);
        assert_eq!(service_count(), 1);
        assert!(record("alpha").expect("alpha").auto_restart());

        // What it *did* is not reset.  An init program declares services the
        // boot may already have started, and a declaration that reset a running
        // service to pending would report it as down while it ran — and the
        // supervisor would lose the pid it watches.
        mark_running("alpha", Some(7), 30);
        register(&definition("alpha", true), 40);
        let record = record("alpha").expect("alpha");
        assert_eq!(record.state, ServiceState::Running);
        assert_eq!(record.pid, Some(7));
        assert_eq!(record.state_since_tick, 30);
    }

    #[test]
    fn snapshot_is_sorted_by_name() {
        let _guard = exclusive_registry();
        for name in ["gamma", "alpha", "beta"] {
            register(&definition(name, true), 0);
        }

        let names: Vec<String> = snapshot().into_iter().map(|r| r.definition.name).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn a_deferred_start_answers_once_the_deadline_arrives() {
        let _guard = exclusive_registry();
        defer_declared_start(100);

        // Before the deadline the boot is still waiting for init, and the
        // supervisor must not start anything.
        assert!(!take_expired_deferral(99));

        // The deadline is the first tick that counts, and it only counts once:
        // a deadline that answered twice would have the supervisor plan the
        // same start on every later pass.
        assert!(take_expired_deferral(100));
        assert!(!take_expired_deferral(101));
        assert!(!take_expired_deferral(u64::MAX));
    }

    #[test]
    fn no_deferral_is_a_deadline_that_never_arrives() {
        let _guard = exclusive_registry();

        // Nothing deferred the start, so the supervisor has no fallback to run.
        assert!(!take_expired_deferral(0));
        assert!(!take_expired_deferral(u64::MAX));
    }

    #[test]
    fn starting_the_services_ends_the_deferral() {
        let _guard = exclusive_registry();
        defer_declared_start(100);

        // Whoever started the declared services ends the wait: init asking
        // through `service_start_all` must not leave the supervisor planning
        // the same start at the deadline.
        cancel_deferred_start();
        assert!(!take_expired_deferral(u64::MAX));
    }

    #[test]
    fn mark_running_records_state_and_pid() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 10);
        mark_running("alpha", Some(7), 25);

        let record = record("alpha").expect("record");
        assert_eq!(record.state, ServiceState::Running);
        assert_eq!(record.pid, Some(7));
        assert_eq!(record.state_since_tick, 25);
        assert_eq!(record.restarts, 0);
    }

    #[test]
    fn note_restart_attempt_counts_but_keeps_the_failure_state() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_failed("alpha", "process exited", 10);
        note_restart_attempt("alpha", 20);

        let record = record("alpha").expect("record");
        assert_eq!(record.restarts, 1);
        // The attempt is counted even though the spawn that follows has not
        // succeeded yet, so a program that can never be loaded still runs out
        // of budget instead of being retried forever.
        assert_eq!(record.state, ServiceState::Failed);
        // The failure reason survives a successful restart, so a running
        // service can still be asked what went wrong before it came back.
        assert_eq!(record.last_error.as_deref(), Some("process exited"));
    }

    #[test]
    fn mark_failed_records_reason_and_drops_the_pid() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(7), 5);
        mark_failed("alpha", "fault at 0x1000", 30);

        let record = record("alpha").expect("record");
        assert_eq!(record.state, ServiceState::Failed);
        assert_eq!(record.pid, None);
        assert_eq!(record.last_error.as_deref(), Some("fault at 0x1000"));
        assert_eq!(record.state_since_tick, 30);
    }

    #[test]
    fn mark_stopped_and_abandoned_are_terminal() {
        let _guard = exclusive_registry();
        register(&definition("alpha", false), 0);
        register(&definition("beta", true), 0);

        mark_stopped("alpha", "exited with status 0", 10);
        mark_abandoned("beta", "restart budget exhausted", 20);

        assert_eq!(record("alpha").expect("alpha").state, ServiceState::Stopped);
        assert_eq!(record("beta").expect("beta").state, ServiceState::Abandoned);
        assert!(record("alpha").expect("alpha").state.is_terminal());
        assert!(record("beta").expect("beta").state.is_terminal());
        assert!(!ServiceState::Running.is_terminal());
        assert!(!ServiceState::Failed.is_terminal());
        assert!(ServiceState::Running.is_running());
        assert!(!ServiceState::Pending.is_running());
    }

    #[test]
    fn state_updates_on_unregistered_service_are_ignored() {
        let _guard = exclusive_registry();
        mark_running("ghost", Some(1), 0);
        mark_failed("ghost", "boom", 1);
        note_restart_attempt("ghost", 2);

        assert_eq!(service_count(), 0);
        assert!(record("ghost").is_none());
    }

    // -- Restart policy ---------------------------------------------------

    #[test]
    fn supervision_action_restarts_once_the_backoff_has_elapsed() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 100);
        mark_failed("alpha", "process exited", 100);

        let record = record("alpha").expect("record");
        assert_eq!(
            supervision_action(&record, 100 + SERVICE_RESTART_BACKOFF_TICKS),
            SupervisionAction::Restart
        );
    }

    #[test]
    fn supervision_action_waits_inside_the_backoff_window() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_failed("alpha", "process exited", 100);

        let record = record("alpha").expect("record");
        assert_eq!(
            supervision_action(&record, 100),
            SupervisionAction::WaitForBackoff
        );
        assert_eq!(
            supervision_action(&record, 100 + SERVICE_RESTART_BACKOFF_TICKS - 1),
            SupervisionAction::WaitForBackoff
        );
    }

    #[test]
    fn supervision_action_abandons_once_the_budget_is_spent() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_failed("alpha", "process exited", 0);
        for attempt in 0..MAX_SERVICE_RESTARTS {
            note_restart_attempt("alpha", 1000 * (attempt as u64 + 1));
            mark_failed("alpha", "process exited", 1000 * (attempt as u64 + 1));
        }

        let record = record("alpha").expect("record");
        assert_eq!(record.restarts, MAX_SERVICE_RESTARTS);
        assert_eq!(
            supervision_action(&record, 10_000),
            SupervisionAction::Abandon
        );
    }

    #[test]
    fn supervision_action_leaves_manual_services_stopped() {
        let _guard = exclusive_registry();
        register(&definition("alpha", false), 0);
        mark_failed("alpha", "process exited", 0);

        let record = record("alpha").expect("record");
        assert_eq!(
            supervision_action(&record, 10_000),
            SupervisionAction::LeaveStopped
        );
    }

    // -- Supervision planning ---------------------------------------------

    #[test]
    fn plan_supervision_is_empty_while_every_service_runs() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 0);

        assert!(plan_supervision(10_000, |_| true).is_empty());
    }

    #[test]
    fn plan_supervision_observes_death_and_schedules_a_restart() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 0);

        // Alive on the first pass: nothing to do.
        assert!(plan_supervision(10, |_| true).is_empty());

        // Dead on the next, and past the backoff: one restart.
        let steps = plan_supervision(10_000, |_| false);
        assert_eq!(
            steps,
            vec![SupervisionStep {
                name: String::from("alpha"),
                action: SupervisionAction::Restart,
            }]
        );
        let record = record("alpha").expect("record");
        assert_eq!(record.state, ServiceState::Failed);
        assert_eq!(record.last_error.as_deref(), Some("process exited"));
    }

    #[test]
    fn plan_supervision_holds_back_a_service_that_died_immediately() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 0);

        // The death is noticed at tick 100, but the window is measured from
        // the spawn at tick 0 — a service that died this soon is in a crash
        // loop, so the restart cannot happen before the window has elapsed.
        assert!(plan_supervision(100, |_| false).is_empty());
        assert_eq!(record("alpha").expect("record").state, ServiceState::Failed);
        assert!(plan_supervision(SERVICE_RESTART_BACKOFF_TICKS - 1, |_| false).is_empty());
        assert_eq!(
            plan_supervision(SERVICE_RESTART_BACKOFF_TICKS, |_| false).len(),
            1
        );
    }

    #[test]
    fn plan_supervision_restarts_a_long_lived_service_at_once() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 0);

        // A service that survived well past the backoff was not crashing in a
        // loop, so there is nothing to protect the system from: restart it as
        // soon as the death is seen.
        let steps = plan_supervision(SERVICE_RESTART_BACKOFF_TICKS * 10, |_| false);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, SupervisionAction::Restart);
    }

    #[test]
    fn plan_supervision_abandons_after_the_budget_is_spent() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_running("alpha", Some(1), 0);
        mark_failed("alpha", "process exited", 0);
        for attempt in 0..MAX_SERVICE_RESTARTS {
            note_restart_attempt("alpha", 1000 * (attempt as u64 + 1));
            mark_failed("alpha", "process exited", 1000 * (attempt as u64 + 1));
        }

        assert_eq!(
            plan_supervision(10_000, |_| false),
            vec![SupervisionStep {
                name: String::from("alpha"),
                action: SupervisionAction::Abandon,
            }]
        );
    }

    #[test]
    fn plan_supervision_reports_manual_services_as_leave_stopped() {
        let _guard = exclusive_registry();
        register(&definition("alpha", false), 0);
        mark_running("alpha", Some(1), 0);

        assert_eq!(
            plan_supervision(10_000, |_| false),
            vec![SupervisionStep {
                name: String::from("alpha"),
                action: SupervisionAction::LeaveStopped,
            }]
        );
    }

    #[test]
    fn plan_supervision_is_empty_for_a_stopped_service() {
        let _guard = exclusive_registry();
        register(&definition("alpha", true), 0);
        mark_stopped("alpha", "exited with status 0", 0);

        // A terminal service must not be re-planned, or the supervisor would
        // spin on it forever.
        assert!(plan_supervision(10_000, |_| false).is_empty());
    }

    #[test]
    fn parse_empty_service_config() {
        let text = "format = \"protofire-service-1\"\n";
        let services = parse_service_config(text).expect("parse");
        assert!(services.is_empty());
    }

    #[test]
    fn parse_user_program_service() {
        let text = "\
format = \"protofire-service-1\"

[[service]]
name = \"shell\"
kind = \"user_program\"
path = \"/system/shell.elf\"
args = [\"--interactive\"]
auto_restart = false
security = \"guest\"
";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services.len(), 1);
        let svc = &services[0];
        assert_eq!(svc.name, "shell");
        assert_eq!(svc.kind, ServiceKind::UserProgram);
        assert_eq!(svc.path.as_deref(), Some("/system/shell.elf"));
        assert_eq!(svc.args, vec!["--interactive".to_string()]);
        assert!(!svc.auto_restart);
        assert_eq!(svc.security, ServiceSecurity::Guest);
    }

    #[test]
    fn parse_kernel_thread_service() {
        let text = "\
format = \"protofire-service-1\"

[[service]]
name = \"kworker-a\"
kind = \"kernel_thread\"
entry = \"demo_worker_a\"
auto_restart = true
";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services.len(), 1);
        let svc = &services[0];
        assert_eq!(svc.name, "kworker-a");
        assert_eq!(svc.kind, ServiceKind::KernelThread);
        assert_eq!(svc.entry.as_deref(), Some("demo_worker_a"));
        assert!(svc.auto_restart);
    }

    #[test]
    fn parse_multiple_services() {
        let text = "\
format = \"protofire-service-1\"

[[service]]
name = \"shell\"
path = \"/system/shell.elf\"

[[service]]
name = \"httpd\"
kind = \"user_program\"
path = \"/system/httpd.elf\"
auto_restart = true

[[service]]
name = \"kworker\"
kind = \"kernel_thread\"
entry = \"worker_fn\"
";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "shell");
        assert_eq!(services[1].name, "httpd");
        assert!(services[1].auto_restart);
        assert_eq!(services[2].name, "kworker");
        assert_eq!(services[2].kind, ServiceKind::KernelThread);
    }

    #[test]
    fn parse_defaults_for_missing_fields() {
        let text = "\
format = \"protofire-service-1\"

[[service]]
name = \"minimal\"
path = \"/system/minimal.elf\"
";
        let services = parse_service_config(text).expect("parse");
        let svc = &services[0];
        assert_eq!(svc.kind, ServiceKind::UserProgram); // default
        assert!(!svc.auto_restart); // default
        assert!(svc.args.is_empty()); // default
        assert_eq!(svc.security, ServiceSecurity::Guest); // default
    }

    #[test]
    fn parse_admin_service() {
        let text = "\
format = \"protofire-service-1\"

[[service]]
name = \"admin_tool\"
path = \"/system/admin.elf\"
security = \"admin\"
";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services[0].security, ServiceSecurity::Admin);
    }

    #[test]
    fn rejects_unknown_format() {
        let text = "format = \"unknown-v2\"\n";
        assert!(parse_service_config(text).is_err());
    }

    #[test]
    fn rejects_missing_format() {
        let text = "[[service]]\nname = \"a\"\n";
        assert!(parse_service_config(text).is_err());
    }

    // -- Declared level to token ------------------------------------------

    #[test]
    fn guest_service_runs_without_superuser_rights() {
        let token = ServiceSecurity::Guest
            .security_token(None)
            .expect("a guest service needs no account");
        assert!(!token.is_superuser());
        assert!(!token.is_admin_mode());
        assert!(!token.may_bypass_discretionary_permissions());
    }

    #[test]
    fn admin_service_carries_its_account_and_is_elevated_but_unauthenticated() {
        let token = ServiceSecurity::Admin
            .security_token(Some((1000, 1000)))
            .expect("account resolved");
        assert_eq!(token.user_id, 1000);
        assert_eq!(token.primary_group_id, 1000);
        assert!(token.is_admin_mode());
        // Kernel provisioning is not a password: the flag stays clear and the
        // discretionary bypass stays out of reach.
        assert!(!token.is_authenticated());
        assert!(!token.may_bypass_discretionary_permissions());
    }

    #[test]
    fn system_service_carries_its_account_and_is_not_the_kernel() {
        let token = ServiceSecurity::System
            .security_token(Some((0, 0)))
            .expect("account resolved");
        assert_eq!(token.user_id, 0);
        // The declared level reaches the token: System integrity, the kernel's
        // MAC subject, uid 0.
        assert!(token.is_system());
        // But a config file asks for the kernel's trust level, not its
        // identity.  The shortcut callers use to mean "this is the kernel" —
        // the discretionary bypass, unconditional descriptor changes, the
        // `is_kernel` report — stays out of reach.
        assert!(token.is_provisioned());
        assert!(!token.is_kernel_token());
        assert!(!token.may_bypass_discretionary_permissions());
    }

    #[test]
    fn a_privileged_level_without_an_account_is_refused() {
        // Refused, not downgraded: a service that asked for privilege and did
        // not get it must not look like one that was authorised.
        assert_eq!(
            ServiceSecurity::Admin.security_token(None),
            Err(crate::Error::PermissionDenied)
        );
        assert_eq!(
            ServiceSecurity::System.security_token(None),
            Err(crate::Error::PermissionDenied)
        );
    }

    // -- The discretionary bypass is not a service privilege --------------

    #[test]
    fn no_service_declaration_reaches_the_discretionary_bypass() {
        // The decision this pins: a definition is trusted for what it may
        // *manage*, never for what it may *ignore*.  None of the three levels
        // reaches the owner/group/other bypass, at any account — so no service
        // reads another account's private files, and none of them can change a
        // security descriptor unconditionally.
        //
        // The bypass has exactly two producers left: the kernel's own threads,
        // and a login that verified a password.  Written down here rather than
        // assumed, because the difference is one enum variant in this file.
        for level in [
            ServiceSecurity::Guest,
            ServiceSecurity::Admin,
            ServiceSecurity::System,
        ] {
            for account in [(0, 0), (500, 500)] {
                let token = level
                    .security_token(Some(account))
                    .expect("an account was resolved");
                assert!(
                    !token.may_bypass_discretionary_permissions(),
                    "{level:?} as {account:?} must not bypass"
                );
                assert!(!token.is_kernel_token(), "{level:?} is not the kernel");
                // Nor may it be mistaken for a login: the kernel establishing
                // an identity is not the same act as a password proving one.
                assert!(!token.is_authenticated(), "{level:?} is not a login");
            }
        }
    }

    #[test]
    fn the_kernel_bypasses_its_own_way_and_a_login_bypasses_its_own_way() {
        // The two producers that keep the bypass, so a change here fails next
        // to the test above rather than in the filesystem layer.
        assert!(SecurityToken::system().may_bypass_discretionary_permissions());
        assert!(SecurityToken::system().is_kernel_token());
        assert!(!SecurityToken::system().is_authenticated());

        let login = SecurityToken::root().with_authentication();
        assert!(login.may_bypass_discretionary_permissions());
        assert!(!login.is_kernel_token());
    }

    #[test]
    fn declared_level_reaches_the_token() {
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\npath = \"/system/netd.elf\"\nsecurity = \"system\"\n";
        let services = parse_service_config(text).expect("parse");
        let token = services[0]
            .security
            .security_token(Some((0, 0)))
            .expect("account resolved");
        // Asserted as behaviour rather than as an exact token: the provisioned
        // shape carries no supplementary groups, which `SecurityToken::system`
        // fills with root's own group.  What has to hold is that the declared
        // level is the one the spawned process ends up at — trust level, not
        // identity, which is why the kernel shortcut below stays false.
        assert!(token.is_system());
        assert_eq!(token.user_id, 0);
        assert!(token.is_provisioned());
        assert!(!token.is_kernel_token());
    }

    #[test]
    fn privileged_service_defaults_to_the_root_account() {
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\nsecurity = \"admin\"\n";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services[0].account_name(), Some("root"));
    }

    #[test]
    fn privileged_service_can_name_its_own_account() {
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\nsecurity = \"admin\"\naccount = \"netadmin\"\n";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services[0].account, Some(String::from("netadmin")));
        assert_eq!(services[0].account_name(), Some("netadmin"));
    }

    #[test]
    fn guest_service_claims_no_account() {
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"shell\"\nkind = \"user_program\"\n";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(services[0].account_name(), None);
    }

    #[test]
    fn guest_service_with_an_account_is_rejected() {
        // The account key on a guest service reads like an escalation that
        // silently did not happen, so the parser refuses it outright.
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"shell\"\nkind = \"user_program\"\nsecurity = \"guest\"\naccount = \"root\"\n";
        assert!(parse_service_config(text).is_err());
    }

    #[test]
    fn a_declaration_can_name_what_it_follows() {
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"httpd\"\nkind = \"user_program\"\npath = \"/system/httpd.elf\"\nafter = [\"netd\", \"logger\"]\n";
        let services = parse_service_config(text).expect("parse");
        assert_eq!(
            services[0].after,
            vec![String::from("netd"), String::from("logger")]
        );
    }

    #[test]
    fn the_start_order_follows_the_declarations() {
        // Declared out of order on purpose: the plan is a function of the
        // `after` lists, not of the order the files happened to be read in.
        let services = vec![
            following("httpd", &["netd"]),
            following("logger", &[]),
            following("netd", &["logger"]),
        ];
        let plan = plan_start_order(&services);

        let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
        assert_eq!(order, vec!["logger", "netd", "httpd"]);
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn services_with_no_declared_order_keep_the_order_they_were_read_in() {
        // Determinism is the property that makes the plan testable: two boots
        // of the same declarations cannot disagree about what starts first.
        // Keeping the read order also means a system that declares nothing —
        // the embedded defaults — starts exactly as it did before the order
        // was computed at all.
        let services = vec![
            definition("zulu", false),
            definition("alpha", false),
            definition("mike", false),
        ];
        let order: Vec<String> = plan_start_order(&services)
            .start
            .iter()
            .map(|svc| svc.name.clone())
            .collect();
        assert_eq!(order, vec!["zulu", "alpha", "mike"]);
    }

    #[test]
    fn an_undeclared_prerequisite_blocks_its_dependents_transitively() {
        let services = vec![
            following("httpd", &["netd"]),
            following("netd", &["dnsmasq"]),
            definition("logger", false),
        ];
        let plan = plan_start_order(&services);

        let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
        assert_eq!(order, vec!["logger"]);

        let blocked: Vec<(&str, &str)> = plan
            .blocked
            .iter()
            .map(|(svc, reason)| (svc.name.as_str(), reason.as_str()))
            .collect();
        assert_eq!(
            blocked,
            vec![
                ("httpd", "after \"netd\", which is blocked"),
                ("netd", "after \"dnsmasq\", which is not declared"),
            ]
        );
    }

    #[test]
    fn a_cycle_is_named_and_blocks_every_service_in_it() {
        let services = vec![
            following("alpha", &["beta"]),
            following("beta", &["alpha"]),
            definition("gamma", false),
        ];
        let plan = plan_start_order(&services);

        let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
        assert_eq!(order, vec!["gamma"]);

        let blocked: Vec<(&str, String)> = plan
            .blocked
            .iter()
            .map(|(svc, reason)| (svc.name.as_str(), reason.clone()))
            .collect();
        assert_eq!(
            blocked,
            vec![
                (
                    "alpha",
                    String::from("dependency cycle: alpha -> beta -> alpha")
                ),
                (
                    "beta",
                    String::from("dependency cycle: alpha -> beta -> alpha")
                ),
            ]
        );
    }

    #[test]
    fn a_service_cannot_follow_itself() {
        let plan = plan_start_order(&[following("loop", &["loop"])]);
        assert!(plan.start.is_empty());
        assert_eq!(
            plan.blocked[0].1,
            String::from("after \"loop\", which is itself")
        );
    }

    #[test]
    fn a_repeated_name_keeps_its_last_declaration() {
        // `register` lets the last declaration win; the order has to agree
        // with the record that ends up in `/service`.
        let first = following("httpd", &["netd"]);
        let last = definition("httpd", false);
        let services = vec![following("netd", &[]), first, last];

        let plan = plan_start_order(&services);
        let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
        assert_eq!(order, vec!["netd", "httpd"]);
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn a_blocked_service_is_not_a_restart_candidate() {
        let _guard = exclusive_registry();
        register(&definition("netd", true), 0);
        mark_blocked("netd", "after \"dnsmasq\", which is not declared", 0);

        let record = record("netd").expect("netd");
        assert_eq!(record.state, ServiceState::Blocked);
        assert!(record.state.is_terminal());
        assert_eq!(record.pid, None);
        assert_eq!(
            record.last_error.as_deref(),
            Some("after \"dnsmasq\", which is not declared")
        );

        // The supervisor only ever acts on a service it watched die, so a
        // blocked one stays blocked.
        assert!(plan_supervision(1_000, |_| false).is_empty());
    }

    #[test]
    fn rendering_a_config_is_the_inverse_of_parsing_one() {
        // Every field, in both kinds, so the writer cannot quietly drop one.
        let mut thread = definition("kworker", false);
        thread.kind = ServiceKind::KernelThread;
        thread.path = None;
        thread.entry = Some(String::from("demo_worker_a"));

        let mut privileged = definition("netd", true);
        privileged.security = ServiceSecurity::Admin;
        privileged.account = Some(String::from("netadmin"));
        privileged.args = vec![String::from("--listen"), String::from(":443")];
        privileged.after = vec![String::from("logger")];

        let services = vec![thread, privileged];
        let text = render_config(&services);

        assert_eq!(parse_service_config(&text).expect("parse"), services);
    }

    #[test]
    fn the_default_set_round_trips_through_its_written_form() {
        // The demo disk ships exactly this text, so the property that matters
        // is that reading it back gives the list the kernel would have used.
        let services = default_definitions();
        let text = render_config(&services);
        assert_eq!(parse_service_config(&text).expect("parse"), services);

        let names: Vec<&str> = services.iter().map(|svc| svc.name.as_str()).collect();
        for expected in ["kworker-a", "kworker-b", "kworker-syscall-fs", "shell"] {
            assert!(names.contains(&expected), "{names:?} lacks {expected}");
        }

        // And the one restart in the set comes from the machine's list, not
        // from a copy that could drift away from it.
        assert_eq!(
            services.iter().filter(|svc| svc.auto_restart).count(),
            crate::arch::platform::demo_user_programs()
                .iter()
                .filter(|(_, restart)| *restart)
                .count()
        );
    }

    #[test]
    fn declaring_from_text_registers_what_the_file_says() {
        let _guard = exclusive_registry();
        let text = "format = \"protofire-service-1\"\n\n[[service]]\nname = \"logger\"\nkind = \"kernel_thread\"\nentry = \"demo_worker_a\"\n\n[[service]]\nname = \"httpd\"\nkind = \"user_program\"\npath = \"/system/httpd.elf\"\nafter = [\"logger\"]\n";

        assert_eq!(declare_from_text(text, 0), Ok(2));
        assert_eq!(service_count(), 2);
        assert_eq!(record("httpd").expect("httpd").state, ServiceState::Pending);

        // The plan comes from the declarations the registry holds, in the order
        // they arrived — which is what an init program's `service_start_all`
        // works from.
        let order: Vec<String> = plan_declared()
            .start
            .iter()
            .map(|svc| svc.name.clone())
            .collect();
        assert_eq!(order, vec![String::from("logger"), String::from("httpd")]);
    }

    #[test]
    fn a_declaration_that_does_not_parse_registers_nothing() {
        let _guard = exclusive_registry();
        assert!(declare_from_text("[[service]\n", 0).is_err());
        assert_eq!(service_count(), 0);
    }

    #[test]
    fn a_service_declared_twice_is_started_once() {
        // Two rc.d files may name the same service; the last declaration wins
        // for both the record and the order, so a start cannot produce a second
        // copy under one name.
        let _guard = exclusive_registry();
        assert_eq!(
            declare_from_text(
                "format = \"protofire-service-1\"\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\npath = \"/system/netd.elf\"\nafter = [\"logger\"]\n",
                0
            ),
            Ok(1)
        );
        assert_eq!(
            declare_from_text(
                "format = \"protofire-service-1\"\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\npath = \"/system/netd.elf\"\n",
                1
            ),
            Ok(1)
        );

        let plan = plan_declared();
        let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
        assert_eq!(order, vec!["netd"]);
        assert!(plan.blocked.is_empty());
    }
}
