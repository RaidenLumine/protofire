//! src/kernel/fs/servicefs.rs
//!
//! ServiceFS — a read-only view of the kernel's runtime service registry.
//!
//! The service manager (`src/kernel/service.rs`) owns the registry; this
//! filesystem only renders it.  Every byte is produced from the registry at
//! read time, so the tree is a view and never a copy, and a service that
//! restarts between two reads shows up as restarted on the second one.
//!
//! ## Nodes
//!
//! | Path | Description |
//! |------|-------------|
//! | `/service/` | One directory per registered service |
//! | `/service/<name>/state` | `pending`, `running`, `stopped`, `failed`, `abandoned` |
//! | `/service/<name>/kind` | `user_program` or `kernel_thread` |
//! | `/service/<name>/restarts` | Times the supervisor has respawned the service |
//! | `/service/<name>/auto_restart` | `true` or `false` |
//! | `/service/<name>/security` | `guest`, `admin`, or `system` |
//! | `/service/<name>/describe` | All of the above, one `key: value` per line |
//!
//! All nodes are read-only.  Writes fail with `PermissionDenied` rather than
//! `Unsupported`: the interface is closed on purpose, not unfinished.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::vfs::DirectoryEntry;
use crate::kernel::fs::vfs::FileSystem as VfsTrait;
use crate::kernel::fs::vfs::Metadata;
use crate::kernel::fs::vfs::NodeKind;
use crate::kernel::fs::vfs::PermissionMode;
use crate::kernel::fs::vfs::SecurityDescriptor;
use crate::kernel::fs::vfs::SecurityDescriptorMutationSupport;
use crate::kernel::fs::vfs::VNode;
use crate::kernel::fs::vfs::VolumeCheckReport;
use crate::kernel::service;
use crate::Error;
use crate::Result;

// ---------------------------------------------------------------------------
// Per-service files
// ---------------------------------------------------------------------------

/// Permission bits for every directory in this tree.
const SERVICE_DIRECTORY_MODE: PermissionMode = 0o555;

/// Permission bits for every file in this tree.
///
/// The tree refuses writes regardless — [`VNode::write`] returns
/// `PermissionDenied` — but the mode has to say so as well, or a caller that
/// checks permission before opening is handed a handle it can only fail to
/// use.
const SERVICE_FILE_MODE: PermissionMode = 0o444;

/// The files that live inside one `/service/<name>/` directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceFileType {
    State,
    Kind,
    Restarts,
    AutoRestart,
    Security,
    Describe,
}

impl ServiceFileType {
    /// Every file, in the order `ls /service/<name>` reports them.
    const ALL: [Self; 6] = [
        Self::State,
        Self::Kind,
        Self::Restarts,
        Self::AutoRestart,
        Self::Security,
        Self::Describe,
    ];

    /// Map a path component to a file type.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "state" => Some(Self::State),
            "kind" => Some(Self::Kind),
            "restarts" => Some(Self::Restarts),
            "auto_restart" => Some(Self::AutoRestart),
            "security" => Some(Self::Security),
            "describe" => Some(Self::Describe),
            _ => None,
        }
    }

    /// Return the filename this variant is reachable as.
    fn name(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Kind => "kind",
            Self::Restarts => "restarts",
            Self::AutoRestart => "auto_restart",
            Self::Security => "security",
            Self::Describe => "describe",
        }
    }

    /// Render this file's contents for `record`.
    ///
    /// Single-value files end with a newline so that `cat` produces a
    /// well-formed line, matching the `/proc` convention.
    fn produce(self, record: &service::ServiceRecord) -> Vec<u8> {
        match self {
            Self::State => format!("{}\n", record.state.as_str()).into_bytes(),
            Self::Kind => format!("{}\n", record.definition.kind.as_str()).into_bytes(),
            Self::Restarts => format!("{}\n", record.restarts).into_bytes(),
            Self::AutoRestart => format!("{}\n", record.auto_restart()).into_bytes(),
            Self::Security => format!("{}\n", record.definition.security.as_str()).into_bytes(),
            Self::Describe => describe_data(record),
        }
    }
}

/// Render the full record as `key: value` lines.
fn describe_data(record: &service::ServiceRecord) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |key: &str, value: &str| {
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b":\t");
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    };

    field("Name", record.name());
    field("Kind", record.definition.kind.as_str());
    field("Target", record.launch_target().unwrap_or("(none)"));
    field("State", record.state.as_str());
    field(
        "Pid",
        &record
            .pid
            .map(|pid| format!("{}", pid))
            .unwrap_or_else(|| String::from("(none)")),
    );
    field("Restarts", &format!("{}", record.restarts));
    field("AutoRestart", &format!("{}", record.auto_restart()));
    field("Security", record.definition.security.as_str());
    field("StateSinceTick", &format!("{}", record.state_since_tick));
    field(
        "LastError",
        record.last_error.as_deref().unwrap_or("(none)"),
    );

    out
}

/// A file inside `/service/<name>/`.
struct ServiceFileVNode {
    service_name: String,
    file_type: ServiceFileType,
}

impl ServiceFileVNode {
    fn new(service_name: &str, file_type: ServiceFileType) -> Self {
        Self {
            service_name: String::from(service_name),
            file_type,
        }
    }

    /// Read the record this file renders, failing if the service is gone.
    fn record(&self) -> Result<service::ServiceRecord> {
        service::record(&self.service_name).ok_or(Error::NotFound)
    }
}

impl VNode for ServiceFileVNode {
    fn name(&self) -> &str {
        self.file_type.name()
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        self.record()
            .map(|record| self.file_type.produce(&record).len())
            .unwrap_or(0)
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind(), self.size())
            .with_security(SecurityDescriptor::root(SERVICE_FILE_MODE)))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let data = self.file_type.produce(&self.record()?);
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

/// A directory node: `/service` itself, or one `/service/<name>/`.
struct ServiceDirVNode {
    name: String,
}

impl ServiceDirVNode {
    fn root() -> Self {
        Self {
            name: String::from("service"),
        }
    }

    fn service(service_name: &str) -> Self {
        Self {
            name: String::from(service_name),
        }
    }
}

impl VNode for ServiceDirVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn size(&self) -> usize {
        0
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind(), self.size())
            .with_security(SecurityDescriptor::root(SERVICE_DIRECTORY_MODE)))
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// A parsed servicefs path.  The `/service` mount prefix is already stripped.
#[derive(Debug, PartialEq, Eq)]
enum ServicefsPath<'a> {
    /// The mount root.
    Root,
    /// `/service/<name>/`
    ServiceDir(&'a str),
    /// `/service/<name>/<file>`
    ServiceFile(&'a str, &'a str),
}

fn parse_servicefs_path(path: &str) -> ServicefsPath<'_> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return ServicefsPath::Root;
    }

    let mut components = path.splitn(2, '/');
    let first = components.next().unwrap_or("");
    match components.next() {
        // A trailing slash names the directory: `alpha` and `alpha/` are the
        // same node, as they are in every other filesystem here.
        None | Some("") => {
            if first.is_empty() {
                ServicefsPath::Root
            } else {
                ServicefsPath::ServiceDir(first)
            }
        }
        // Anything deeper than `<name>/<file>` has no meaning in this
        // namespace, and the file-type lookup below rejects it.
        Some(filename) => ServicefsPath::ServiceFile(first, filename),
    }
}

// ---------------------------------------------------------------------------
// ServiceFS root
// ---------------------------------------------------------------------------

pub struct ServiceFs;

impl VfsTrait for ServiceFs {
    fn name(&self) -> &str {
        "servicefs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        match parse_servicefs_path(path) {
            ServicefsPath::Root => Ok(Arc::new(ServiceDirVNode::root())),

            ServicefsPath::ServiceDir(name) => {
                // Reject a name that matches nothing rather than handing back a
                // directory that could never be listed.
                service::record(name).ok_or(Error::NotFound)?;
                Ok(Arc::new(ServiceDirVNode::service(name)))
            }

            ServicefsPath::ServiceFile(name, filename) => {
                let file_type = ServiceFileType::parse(filename).ok_or(Error::NotFound)?;
                service::record(name).ok_or(Error::NotFound)?;
                Ok(Arc::new(ServiceFileVNode::new(name, file_type)))
            }
        }
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        if path.is_empty() || path == "/" {
            return Ok(Metadata {
                kind: NodeKind::Directory,
                size: 4,
                security: SecurityDescriptor::root(SERVICE_DIRECTORY_MODE),
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }
        self.lookup(path).and_then(|vnode| vnode.metadata())
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        match parse_servicefs_path(path) {
            ServicefsPath::Root => {
                let records = service::snapshot();
                let record = records.get(index).ok_or(Error::NotFound)?;
                Ok(DirectoryEntry::new(
                    NodeKind::Directory,
                    0,
                    record.name().into(),
                ))
            }

            ServicefsPath::ServiceDir(name) => {
                service::record(name).ok_or(Error::NotFound)?;
                let file_type = ServiceFileType::ALL.get(index).ok_or(Error::NotFound)?;
                Ok(DirectoryEntry::new(
                    NodeKind::File,
                    0,
                    String::from(file_type.name()),
                ))
            }

            ServicefsPath::ServiceFile(..) => Err(Error::NotFound),
        }
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        Err(Error::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Mount helper
// ---------------------------------------------------------------------------

/// Register and mount servicefs at the given path (typically `/service`).
pub fn mount_servicefs(mount_path: &str) -> Result<()> {
    let fs = crate::kernel::fs::global().ok_or(Error::InternalError)?;
    let mut fs_guard = fs.lock();
    fs_guard.register("servicefs", Arc::new(ServiceFs));
    fs_guard.mount("/dev/protofire-servicefs", mount_path, "servicefs", 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::service::ServiceDefinition;
    use crate::kernel::service::ServiceKind;
    use crate::kernel::service::ServiceSecurity;
    use crate::kernel::sync::Mutex;
    use alloc::vec;

    /// Serialises the registry-touching tests in this module.
    static SERVICE_FS_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Take the lock and start from an empty registry.
    fn exclusive_registry() -> crate::kernel::sync::MutexGuard<'static, ()> {
        let guard = SERVICE_FS_TEST_LOCK.lock();
        service::reset_registry_for_tests();
        guard
    }

    fn definition(name: &str, auto_restart: bool) -> ServiceDefinition {
        ServiceDefinition {
            name: String::from(name),
            kind: ServiceKind::UserProgram,
            path: Some(format!("/system/{}.elf", name)),
            entry: None,
            args: Vec::new(),
            auto_restart,
            security: ServiceSecurity::Guest,
        }
    }

    /// Read a whole file node into a `String`.
    fn read_to_string(vnode: &Arc<dyn VNode>) -> String {
        let mut buffer = vec![0_u8; 512];
        let n = vnode.read(0, &mut buffer).expect("read");
        String::from_utf8(buffer[..n].to_vec()).expect("utf8")
    }

    fn list_names(fs: &ServiceFs, path: &str) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0..64 {
            match fs.read_dir(path, index) {
                Ok(entry) => names.push(entry.name),
                Err(_) => break,
            }
        }
        names
    }

    #[test]
    fn parse_root_paths() {
        assert_eq!(parse_servicefs_path(""), ServicefsPath::Root);
        assert_eq!(parse_servicefs_path("/"), ServicefsPath::Root);
    }

    #[test]
    fn parse_service_dir_paths() {
        assert_eq!(
            parse_servicefs_path("alpha"),
            ServicefsPath::ServiceDir("alpha")
        );
        assert_eq!(
            parse_servicefs_path("/alpha/"),
            ServicefsPath::ServiceDir("alpha")
        );
    }

    #[test]
    fn parse_service_file_paths() {
        assert_eq!(
            parse_servicefs_path("alpha/state"),
            ServicefsPath::ServiceFile("alpha", "state")
        );
    }

    #[test]
    fn root_lists_every_registered_service_in_name_order() {
        let _guard = exclusive_registry();
        service::register(&definition("gamma", true), 0);
        service::register(&definition("alpha", true), 0);
        service::register(&definition("beta", true), 0);

        assert_eq!(list_names(&ServiceFs, ""), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn service_dir_lists_its_files() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);

        assert_eq!(
            list_names(&ServiceFs, "alpha"),
            vec![
                "state",
                "kind",
                "restarts",
                "auto_restart",
                "security",
                "describe"
            ]
        );
    }

    #[test]
    fn unknown_service_and_unknown_file_are_not_found() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);

        assert!(ServiceFs.lookup("ghost").is_err());
        assert!(ServiceFs.lookup("alpha/ghost").is_err());
        assert!(ServiceFs.lookup("alpha/state/deeper").is_err());
        assert!(ServiceFs.read_dir("ghost", 0).is_err());
    }

    #[test]
    fn state_file_reflects_the_registry() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);
        service::mark_running("alpha", Some(4), 10);

        let vnode = ServiceFs.lookup("alpha/state").expect("state node");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.name(), "state");
        assert_eq!(read_to_string(&vnode), "running\n");
    }

    #[test]
    fn every_single_value_file_renders() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);
        service::mark_running("alpha", Some(4), 0);
        service::note_restart_attempt("alpha", 500);

        assert_eq!(
            read_to_string(&ServiceFs.lookup("alpha/kind").expect("kind")),
            "user_program\n"
        );
        assert_eq!(
            read_to_string(&ServiceFs.lookup("alpha/restarts").expect("restarts")),
            "1\n"
        );
        assert_eq!(
            read_to_string(
                &ServiceFs
                    .lookup("alpha/auto_restart")
                    .expect("auto_restart")
            ),
            "true\n"
        );
        assert_eq!(
            read_to_string(&ServiceFs.lookup("alpha/security").expect("security")),
            "guest\n"
        );
    }

    #[test]
    fn describe_reports_every_field() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);
        service::mark_running("alpha", Some(4), 10);
        service::mark_failed("alpha", "fault at 0x1000", 20);

        let text = read_to_string(&ServiceFs.lookup("alpha/describe").expect("describe"));
        assert!(text.contains("Name:\talpha\n"), "{text}");
        assert!(text.contains("Kind:\tuser_program\n"), "{text}");
        assert!(text.contains("Target:\t/system/alpha.elf\n"), "{text}");
        assert!(text.contains("State:\tfailed\n"), "{text}");
        assert!(text.contains("Restarts:\t0\n"), "{text}");
        assert!(text.contains("AutoRestart:\ttrue\n"), "{text}");
        assert!(text.contains("LastError:\tfault at 0x1000\n"), "{text}");
    }

    #[test]
    fn describe_reports_a_missing_pid_as_none() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);

        let text = read_to_string(&ServiceFs.lookup("alpha/describe").expect("describe"));
        assert!(text.contains("Pid:\t(none)\n"), "{text}");
        assert!(text.contains("LastError:\t(none)\n"), "{text}");
    }

    #[test]
    fn a_restart_is_visible_on_the_next_read() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);
        service::mark_running("alpha", Some(4), 0);
        assert_eq!(
            read_to_string(&ServiceFs.lookup("alpha/state").expect("state")),
            "running\n"
        );

        // The node holds no cached copy, so the same path re-rendered after a
        // state change reports the new state.
        service::mark_failed("alpha", "process exited", 100);
        assert_eq!(
            read_to_string(&ServiceFs.lookup("alpha/state").expect("state")),
            "failed\n"
        );
    }

    #[test]
    fn offset_reads_walk_the_rendered_bytes() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);
        service::mark_running("alpha", Some(4), 0);

        // "running\n" is eight bytes; an offset of four lands mid-word.
        let vnode = ServiceFs.lookup("alpha/state").expect("state");
        let mut buffer = [0_u8; 3];
        assert_eq!(vnode.read(0, &mut buffer).expect("read"), 3);
        assert_eq!(&buffer, b"run");
        assert_eq!(vnode.read(4, &mut buffer).expect("read"), 3);
        assert_eq!(&buffer, b"ing");
        assert_eq!(vnode.read(6, &mut buffer).expect("read"), 2);
        assert_eq!(&buffer[..2], b"g\n");
        assert_eq!(vnode.read(64, &mut buffer).expect("read"), 0);
    }

    #[test]
    fn servicefs_is_read_only() {
        let _guard = exclusive_registry();
        service::register(&definition("alpha", true), 0);

        assert!(ServiceFs.create_file("alpha/new").is_err());
        assert!(ServiceFs.create_dir("new").is_err());
        assert!(ServiceFs.rename("alpha", "beta").is_err());
        assert!(ServiceFs.remove_path("alpha").is_err());

        let vnode = ServiceFs.lookup("alpha/state").expect("state");
        assert_eq!(vnode.write(0, b"running\n"), Err(Error::PermissionDenied));
    }

    #[test]
    fn root_stat_is_a_directory() {
        let meta = ServiceFs.stat("/").expect("stat root");
        assert_eq!(meta.kind, NodeKind::Directory);
    }

    #[test]
    fn name_is_servicefs() {
        assert_eq!(ServiceFs.name(), "servicefs");
    }
}
