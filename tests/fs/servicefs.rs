//! tests/fs/servicefs.rs
//!
//! Host-side integration tests for the `/service` filesystem.
//!
//! These drive the whole path rather than the filesystem object on its own:
//! the service registry is populated through the real `service` API, the
//! filesystem is mounted on a real `FileSystem` facade, and every assertion
//! reads back out through the same facade the shell uses.

use std::sync::Mutex;
use std::sync::OnceLock;

use protofire::abi::io::OPEN_FLAG_WRITE;
use protofire::fs::servicefs::mount_servicefs;
use protofire::fs::FileSystem;
use protofire::fs::NodeKind;
use protofire::kernel::service;
use protofire::kernel::service::ServiceDefinition;
use protofire::kernel::service::ServiceKind;
use protofire::kernel::service::ServiceSecurity;
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::Error;

/// Serialises these tests.
///
/// The service registry and the global filesystem are both process-wide, so a
/// test that mounts and registers has to hold this for its whole body.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A freshly mounted `/service` tree, torn down when the test ends.
///
/// The filesystem global and the service registry are process-wide, so both
/// have to be undone for the next test.  Doing that in `Drop` means a failing
/// assertion — or a panic — still leaves the process clean.
struct ServiceTree {
    fs: &'static KernelMutex<FileSystem>,
}

impl ServiceTree {
    fn mount() -> Self {
        service::reset_registry_for_tests();

        // The instance is intentionally leaked: the global keeps the pointer
        // for the life of the test binary, so freeing it would leave the slot
        // advertising storage that no longer exists.
        let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
        protofire::fs::install_global(fs);
        mount_servicefs("/service").expect("mount servicefs at /service");

        Self { fs }
    }

    /// Run `body` with the filesystem lock held.
    fn with_fs<T>(&self, body: impl FnOnce(&FileSystem) -> T) -> T {
        body(&self.fs.lock())
    }
}

impl Drop for ServiceTree {
    fn drop(&mut self) {
        protofire::fs::uninstall_global(self.fs);
        service::reset_registry_for_tests();
    }
}

/// Build a user-program service definition.
fn definition(name: &str, auto_restart: bool) -> ServiceDefinition {
    ServiceDefinition {
        name: String::from(name),
        kind: ServiceKind::UserProgram,
        origin: None,
        path: Some(format!("/system/{name}.elf")),
        entry: None,
        args: Vec::new(),
        after: Vec::new(),
        auto_restart,
        security: ServiceSecurity::Guest,
        account: None,
    }
}

/// Mount a directory of declaration files at `/system/rc.d`.
///
/// The `/system` above it is mounted too: a real disk has the zone as a
/// directory, and a declaration's path is only a path if every directory in it
/// is one.
fn mount_declaration_directory(
    tree: &ServiceTree,
    entries: &'static [(&'static str, NodeKind, &'static [u8])],
) {
    let mut fs = tree.fs.lock();
    let system = protofire::fs::vfs::StaticFileSystem::with_entries(
        "system",
        &[("/", NodeKind::Directory, &[])],
    );
    fs.register("system", std::sync::Arc::new(system));
    fs.mount("/dev/system", "/system", "system", 0)
        .expect("mount /system");

    let directory = protofire::fs::vfs::StaticFileSystem::with_entries("rc.d", entries);
    fs.register("rc.d", std::sync::Arc::new(directory));
    fs.mount("/dev/rc.d", "/system/rc.d", "rc.d", 0)
        .expect("mount the service directory");
}

/// Read a whole file through the facade.
fn read_file(fs: &FileSystem, path: &str) -> String {
    let mut handle = fs.open(path, 0).expect("open");
    let mut buffer = vec![0_u8; 1024];
    let n = handle.read(&mut buffer).expect("read");
    String::from_utf8(buffer[..n].to_vec()).expect("utf8")
}

/// Collect a directory listing through the facade.
fn list_directory(fs: &FileSystem, path: &str) -> Vec<String> {
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
fn service_directory_lists_registered_services() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("zulu", true), 0);
    service::register(&definition("alpha", true), 0);

    tree.with_fs(|fs| {
        assert_eq!(list_directory(fs, "/service"), vec!["alpha", "zulu"]);
        assert_eq!(
            fs.stat_path("/service/alpha").expect("stat").kind,
            NodeKind::Directory
        );
    });
}

#[test]
fn a_service_that_exits_is_reported_as_failed_through_the_facade() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("alpha", true), 0);
    service::mark_running("alpha", Some(11), 0);

    tree.with_fs(|fs| {
        assert_eq!(read_file(fs, "/service/alpha/state"), "running\n");
    });

    // The supervisor notices the process is gone.  The tree holds no cached
    // copy, so reading the same path again reports the new state.
    let steps = service::plan_supervision(10_000, |_| false);
    assert_eq!(steps.len(), 1);
    service::mark_failed("alpha", "process exited", 100);

    tree.with_fs(|fs| {
        assert_eq!(read_file(fs, "/service/alpha/state"), "failed\n");
        assert!(read_file(fs, "/service/alpha/describe").contains("LastError:\tprocess exited"));
    });
}

#[test]
fn describe_reports_the_declaration_the_registry_holds() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("alpha", false), 0);

    tree.with_fs(|fs| {
        let text = read_file(fs, "/service/alpha/describe");
        assert!(text.contains("Name:\talpha\n"), "{text}");
        assert!(text.contains("Target:\t/system/alpha.elf\n"), "{text}");
        assert!(text.contains("AutoRestart:\tfalse\n"), "{text}");
        assert!(text.contains("Security:\tguest\n"), "{text}");
    });
}

#[test]
fn service_tree_is_read_only_through_the_facade() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("alpha", true), 0);

    tree.with_fs(|fs| {
        // Creating and removing are refused outright.
        assert_eq!(fs.create_dir("/service/new"), Err(Error::PermissionDenied));
        assert!(fs.remove_path("/service/alpha").is_err());

        // Writing is what makes the tree read-only.  The facade opens with a
        // system token, which bypasses the discretionary check, so `open` for
        // write succeeds and the refusal lands on the write itself — which is
        // also why every node carries a read-only mode: a caller checking
        // permissions before opening is told the truth, and one that does not
        // still cannot change anything.
        let mut handle = fs
            .open("/service/alpha/state", OPEN_FLAG_WRITE as u32)
            .expect("open for write");
        assert_eq!(handle.write(b"stopped\n"), Err(Error::PermissionDenied));
    });
}

#[test]
fn a_missing_service_is_not_found_rather_than_empty() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("alpha", true), 0);

    tree.with_fs(|fs| {
        // An unregistered name must fail loudly: a caller that could not tell
        // "no such service" from "service has no state file" would read a typo
        // as a stopped service.
        assert!(matches!(
            fs.stat_path("/service/ghost"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            fs.stat_path("/service/alpha/ghost"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            fs.read_dir("/service/ghost", 0),
            Err(Error::NotFound)
        ));
    });
}

#[test]
fn an_empty_registry_yields_an_empty_directory() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    tree.with_fs(|fs| {
        assert!(list_directory(fs, "/service").is_empty());
        assert_eq!(
            fs.stat_path("/service").expect("stat root").kind,
            NodeKind::Directory
        );
    });
}

#[test]
fn the_service_tree_shares_the_root_with_the_other_namespaces() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    tree.with_fs(|fs| {
        // `/service` sits beside `/proc` and `/dev` in the same namespace
        // rather than inside `/media`: it is a namespace of system
        // capabilities, not a place removable media appeared.
        let root = list_directory(fs, "/");
        assert!(root.contains(&String::from("service")), "{root:?}");
    });
}

#[test]
fn re_registering_a_service_replaces_its_declaration() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();
    service::register(&definition("alpha", false), 0);
    service::register(&definition("alpha", true), 500);

    tree.with_fs(|fs| {
        assert_eq!(list_directory(fs, "/service"), vec!["alpha"]);
        assert_eq!(read_file(fs, "/service/alpha/auto_restart"), "true\n");
    });
}

#[test]
fn service_files_report_where_the_declaration_came_from() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    let mut declared = definition("alpha", true);
    declared.origin = Some(service::ServiceOrigin {
        path: String::from("/system/rc.d/defaults.toml"),
        sha256: String::from("2f8c1b0d"),
    });
    service::register(&declared, 0);

    tree.with_fs(|fs| {
        assert_eq!(
            read_file(fs, "/service/alpha/origin"),
            "/system/rc.d/defaults.toml\n"
        );
        assert_eq!(read_file(fs, "/service/alpha/sha256"), "2f8c1b0d\n");

        // The same two facts in the record's own rendering, so a reader that
        // reads one file sees them.
        let describe = read_file(fs, "/service/alpha/describe");
        assert!(
            describe.contains("Origin:\t/system/rc.d/defaults.toml\n"),
            "{describe}"
        );
        assert!(describe.contains("Sha256:\t2f8c1b0d\n"), "{describe}");
    });
}

#[test]
fn a_service_no_file_declared_reports_no_origin() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    // The built-in fallback the boot uses when a disk declares nothing has no
    // file behind it, and saying so beats an empty file that reads as a path
    // nobody can see.
    service::register(&definition("alpha", true), 0);

    tree.with_fs(|fs| {
        assert_eq!(read_file(fs, "/service/alpha/origin"), "(none)\n");
        assert_eq!(read_file(fs, "/service/alpha/sha256"), "(none)\n");
    });
}

#[test]
fn the_mount_is_recorded_under_its_own_filesystem_name() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    tree.with_fs(|fs| {
        let mounts = fs.mount_points();
        let service_mount = mounts
            .iter()
            .find(|mount| mount.path == "/service")
            .expect("service mount recorded");
        assert_eq!(service_mount.fs_name, "servicefs");
    });
}

#[test]
fn a_service_directory_on_a_real_filesystem_declares_the_start_order() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    // A real directory on the real facade, so this walks the same path the
    // boot takes when the distribution ships `/system/rc.d` instead of relying
    // on the embedded defaults: read the directory, open each file, parse it.
    //
    // The declarations are deliberately not in dependency order, one file is
    // not a `.toml`, and one is malformed — the loader skips the last two, and
    // the order that comes out is the one the `after` lists ask for.
    const LOGGER: &[u8] = b"format = \"protofire-service-1\"\n\n[[service]]\nname = \"logger\"\nkind = \"user_program\"\npath = \"/system/logger.elf\"\n";
    const NETD: &[u8] = b"format = \"protofire-service-1\"\n\n[[service]]\nname = \"httpd\"\nkind = \"user_program\"\npath = \"/system/httpd.elf\"\nafter = [\"netd\"]\n\n[[service]]\nname = \"netd\"\nkind = \"user_program\"\npath = \"/system/netd.elf\"\nafter = [\"logger\"]\n";
    const NOT_A_CONFIG: &[u8] = b"not a service config\n";
    const MALFORMED: &[u8] = b"[[service]\n";
    const DECLARATIONS: &[(&str, NodeKind, &[u8])] = &[
        ("/", NodeKind::Directory, &[]),
        ("/00-netd.toml", NodeKind::File, NETD),
        ("/10-logger.toml", NodeKind::File, LOGGER),
        ("/README", NodeKind::File, NOT_A_CONFIG),
        ("/20-broken.toml", NodeKind::File, MALFORMED),
    ];

    let services = {
        mount_declaration_directory(&tree, DECLARATIONS);
        let fs = tree.fs.lock();
        service::load_services_from_fs(&fs, "/system/rc.d")
    };

    let plan = service::plan_start_order(&services);
    let order: Vec<&str> = plan.start.iter().map(|svc| svc.name.as_str()).collect();
    assert_eq!(order, vec!["logger", "netd", "httpd"]);
    assert!(plan.blocked.is_empty());

    // Each definition carries the file it was read from: the origin is what a
    // privileged level rests on, and it is part of the definition rather than
    // something assembled from the text.
    for service in &services {
        let origin = service.origin.as_ref().expect("a file was read");
        assert!(origin.path.starts_with("/system/rc.d/"), "{}", origin.path);
        assert_eq!(origin.sha256.len(), 64, "{}", origin.sha256);
    }
    let netd = services
        .iter()
        .find(|service| service.name == "netd")
        .expect("netd");
    assert_eq!(
        netd.origin.as_ref().expect("netd origin").sha256,
        protofire::kernel::crypto::sha256_hex(NETD)
    );
}

#[test]
fn a_declaration_outside_the_system_zone_is_refused() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    const DEFAULTS: &[u8] =
        b"format = \"protofire-service-1\"\n\n[[service]]\nname = \"logger\"\nkind = \"user_program\"\npath = \"/system/logger.elf\"\n";
    mount_declaration_directory(
        &tree,
        &[
            ("/", NodeKind::Directory, &[]),
            ("/defaults.toml", NodeKind::File, DEFAULTS),
            ("/other.toml", NodeKind::File, DEFAULTS),
        ],
    );

    // Where a declaration may live is the kernel's rule, not the disk's: a
    // declaration decides what runs and as whom, so the file it is read from
    // has to be one the machine's own image put in the read-only zone.
    tree.with_fs(|fs| {
        assert_eq!(
            service::declare_file(fs, "/data/rc.d/evil.toml", 0),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            service::declare_file(fs, "/system", 0),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            service::declare_file(fs, "/system/rc.d/missing.toml", 0),
            Err(Error::PermissionDenied)
        );

        // The check is about where the file is, not how the path was spelled:
        // the path is resolved against the root, so a relative spelling of a
        // system file is not a way around the rule — and one spelled that way
        // is still read from `/system`.
        assert_eq!(
            service::declare_file(fs, "system/rc.d/other.toml", 0),
            Ok(1)
        );
    });
}

#[test]
fn a_declaration_that_is_a_link_is_refused() {
    let _guard = test_lock();
    let tree = ServiceTree::mount();

    // The filesystem resolves *through* a symlink, so a path spelled inside
    // `/system` can still deliver another volume's bytes — and the writable
    // zones are where a program can put those bytes after the boot.  A
    // declaration has to be the file it claims to be.
    mount_declaration_directory(
        &tree,
        &[
            ("/", NodeKind::Directory, &[]),
            (
                "/defaults.toml",
                NodeKind::Symlink,
                b"/data/users/guest/defaults.toml",
            ),
        ],
    );

    let refused = {
        let fs = tree.fs.lock();
        (
            service::declare_file(&fs, "/system/rc.d/defaults.toml", 0),
            service::load_services_from_fs(&fs, "/system/rc.d"),
        )
    };

    // The syscall's path is refused...
    assert_eq!(refused.0, Err(Error::PermissionDenied));
    // ...and the boot's own walk skips it, the way it skips a file that does
    // not parse.
    assert!(refused.1.is_empty(), "{:?}", refused.1);
}
