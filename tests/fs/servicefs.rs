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
use protofire::kernel::fs::servicefs::mount_servicefs;
use protofire::kernel::fs::FileSystem;
use protofire::kernel::fs::NodeKind;
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
        protofire::kernel::fs::install_global(fs);
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
        protofire::kernel::fs::uninstall_global(self.fs);
        service::reset_registry_for_tests();
    }
}

/// Build a user-program service definition.
fn definition(name: &str, auto_restart: bool) -> ServiceDefinition {
    ServiceDefinition {
        name: String::from(name),
        kind: ServiceKind::UserProgram,
        path: Some(format!("/system/{name}.elf")),
        entry: None,
        args: Vec::new(),
        auto_restart,
        security: ServiceSecurity::Guest,
    }
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
