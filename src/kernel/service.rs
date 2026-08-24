//! src/kernel/service.rs
//!
//! Service manager: loads service definitions from `/system/rc.d/*.toml` and
//! spawns kernel worker threads and user programs at boot.
//!
//! Replaces the hard-coded `spawn_system_programs()` with a config-driven
//! approach. The distribution provides the config files; the kernel provides
//! the mechanism.

use alloc::string::String;
use alloc::vec::Vec;

use crate::kernel::config::{self, ConfigEntryLookup};

/// The directory on the boot filesystem where service config TOML files live.
pub const SERVICE_CONFIG_DIR: &str = "/system/rc.d";

// ── Service definition types ─────────────────────────────────────────────────

/// The kind of service to launch.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceKind {
    /// A ring3 user program (ELF binary).
    UserProgram,
    /// A kernel worker thread (runs in ring0).
    KernelThread,
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
}

/// A parsed service definition from a config file.
#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    pub name: String,
    pub kind: ServiceKind,
    /// For UserProgram: path to the ELF binary (e.g. `/system/shell.elf`).
    pub path: Option<String>,
    /// For KernelThread: name of the entry function (e.g. `demo_worker_a`).
    pub entry: Option<String>,
    /// Command-line arguments for UserProgram services.
    pub args: Vec<String>,
    /// If true, the service is restarted when it exits.
    pub auto_restart: bool,
    /// Security token for UserProgram services.
    pub security: ServiceSecurity,
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

        let svc = ServiceDefinition {
            name: element
                .get_str("name")
                .map(String::from)
                .unwrap_or_else(|_| String::from("unnamed")),
            kind,
            path: element.get_str("path").ok().map(String::from),
            entry: element.get_str("entry").ok().map(String::from),
            args: element.get_string_list("args").unwrap_or_default(),
            auto_restart: element.get_bool_or("auto_restart", false),
            security,
        };

        services.push(svc);
    }

    Ok(services)
}

/// Load service definitions from `/system/rc.d/*.toml` on the given filesystem.
///
/// Reads all directory entries in `dir`, filters for `.toml` files, opens each
/// one, reads its contents, and parses it with [`parse_service_config`].
///
/// Files that fail to open, read, or parse are silently skipped so a single
/// malformed config file doesn't prevent the system from booting — the kernel
/// falls back to the embedded default configuration when this function returns
/// an empty list.
pub fn load_services_from_fs(
    fs: &crate::kernel::fs::FileSystem,
    dir: &str,
) -> Vec<ServiceDefinition> {
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

        // Try to open and read the config file.
        match read_config_file(fs, &path) {
            Some(text) => match parse_service_config(&text) {
                Ok(services) => all_services.extend(services),
                Err(_e) => {
                    // Malformed config — skip silently.
                    let _ = _e;
                }
            },
            None => {
                // Couldn't open or read — skip silently.
            }
        }
    }

    all_services
}

/// Open `path` for reading, stat it to get the size, read the entire file
/// into a `String`, and return it.  Returns `None` on any I/O error.
fn read_config_file(
    fs: &crate::kernel::fs::FileSystem,
    path: &str,
) -> Option<alloc::string::String> {
    use crate::kernel::fs::OPEN_EXISTING;
    use crate::kernel::process::HANDLE_RIGHT_READ;

    // Open the file for reading (existing files only).
    let mut handle = fs
        .create_file(path, HANDLE_RIGHT_READ, 0, OPEN_EXISTING)
        .ok()?;

    // Determine how many bytes to allocate.
    let metadata = fs.stat_path(path).ok()?;
    let len = metadata.size;
    let mut buf = alloc::vec![0u8; len];

    // Read the entire file.
    let n = fs.read(&mut handle, &mut buf).ok()?;
    buf.truncate(n);

    // Convert to UTF-8.
    core::str::from_utf8(&buf)
        .ok()
        .map(alloc::string::String::from)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

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
}
