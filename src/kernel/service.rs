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

use crate::kernel::config::ConfigEntryLookup;
use crate::kernel::config::{self};
use crate::kernel::process::ProcessId;
use crate::kernel::sync::Mutex;

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

// ── Runtime registry ─────────────────────────────────────────────────────────

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
        }
    }

    /// Return true while a live instance is expected to exist.
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Return true when the service will not move again without intervention.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Abandoned)
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
}

impl ServiceRegistry {
    const fn new() -> Self {
        Self {
            services: BTreeMap::new(),
        }
    }
}

/// Global registry of every service the kernel has been told about.
static SERVICE_REGISTRY: Mutex<ServiceRegistry> = Mutex::new(ServiceRegistry::new());

/// Register a definition, leaving the service in [`ServiceState::Pending`].
///
/// Re-registering a name replaces the previous record: the boot path may parse
/// the same service name from two config files, and the last declaration wins.
pub fn register(definition: &ServiceDefinition, now_tick: u64) {
    let record = ServiceRecord {
        definition: definition.clone(),
        state: ServiceState::Pending,
        restarts: 0,
        last_error: None,
        state_since_tick: now_tick,
        pid: None,
    };
    SERVICE_REGISTRY
        .lock()
        .services
        .insert(record.definition.name.clone(), record);
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
    SERVICE_REGISTRY.lock().services.clear();
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
            path: Some(alloc::format!("/system/{}.elf", name)),
            entry: None,
            args: Vec::new(),
            auto_restart,
            security: ServiceSecurity::Guest,
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
    fn register_same_name_replaces_previous_declaration() {
        let _guard = exclusive_registry();
        register(&definition("alpha", false), 10);
        register(&definition("alpha", true), 20);

        assert_eq!(service_count(), 1);
        let record = record("alpha").expect("record");
        assert!(record.auto_restart());
        assert_eq!(record.state_since_tick, 20);
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
}
