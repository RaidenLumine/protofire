//! tests/syscall/install.rs
//!
//! Host-side integration tests for the install syscall.
//!
//! These drive the whole path a ring-3 program takes: a table dispatch with a
//! package staged on a writable data zone, the install that follows, and the
//! records it leaves under `/apps`.  The app zone here is writable — built for
//! the test, because the demo's is mounted read-only — so the success case and
//! the refusal case are both reachable.
//!
//! This file needs `--features demo-disk`.  The install handler is compiled
//! only with that feature; without it the library carries the `Unsupported`
//! stub, and every test here would fail saying "the install syscall:
//! Unsupported" — which describes the build, not the defect the reader is
//! looking for.  A test below asserts the feature is on, so that is the message
//! a mis-built run gets.  `make test` and `make test-fast` pass the feature; a
//! bare `cargo test` does not.
//!
//! That check is a test rather than a `compile_error!` because `make clippy`
//! lints every target without `demo-disk`, and a build failure there would
//! make the lint gate red for a configuration the gate never runs.

use std::sync::Arc;

use protofire::fs::block::MemoryBlockDevice;
use protofire::fs::layout::StorageZone;
use protofire::fs::simplefs::SimpleFs;
use protofire::fs::simplefs::SimpleFsVolume;
use protofire::fs::FileSystem;
use protofire::kernel::crypto::sha256_hex;
use protofire::kernel::process::Scheduler;
use protofire::kernel::process::SecurityToken;
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::syscall::SyscallContext;
use protofire::syscall::SyscallNumber;
use protofire::syscall::Table;
use protofire::Error;

/// Fail first, and say why, when this suite was built without its feature.
///
/// Every other test here would fail too, with a message about the install
/// returning `Unsupported` — which is what a build without the handler looks
/// like, not a defect in it.  This one names the real cause, and it runs before
/// the others because its name sorts first.
///
/// The probe is the syscall itself: a build with the handler answers
/// `NotFound` for a path that is not there, and a build without it answers
/// `Unsupported` before it ever looks.  Asking the library is the only way to
/// know — `cfg!(feature = ...)` reads *this* crate's features, and the handler
/// lives in the library the test links.
#[test]
fn a_build_without_demo_disk_says_so() {
    let _guard = test_lock();
    // The fixture installs the global filesystem the syscall reaches; nothing
    // else here reads it, which is why the binding is a `_`.
    let _fs = fixture(false);

    let scheduler = Box::new(Scheduler::new());
    let _thread = scheduler.spawn_named_with_security_token(
        "probe",
        SecurityToken::system(),
        0x1000,
    );
    // SAFETY: the test lock serialises every test that shares the global
    // scheduler slot, and this test installs its own scheduler before touching
    // it, so the pointer is only read while the box is alive.
    unsafe { scheduler.install_global_unchecked() };
    scheduler.schedule();

    let path = "/data/downloads/absent@1.0.0";
    let mut table = Table::new();
    table.init();
    let mut context = SyscallContext::new(
        SyscallNumber::InstallPackage as usize,
        [path.as_ptr() as usize, path.len(), 0, 0, 0, 0],
    );
    let result = table.dispatch(&mut context);

    assert_ne!(
        result,
        Err(Error::Unsupported),
        "tests/syscall/install.rs needs --features demo-disk: the install \
         syscall is compiled only with it, so every test here would exercise \
         the `Unsupported` stub instead of the path it is about"
    );
}

const PAYLOAD: &[u8] = b"a package handed to the kernel\n";
const SOURCE: &str = "/data/downloads/demo@1.0.0";

/// Serialise these tests: the filesystem global and the scheduler global are
/// process-wide, and each test installs its own.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A filesystem with the zones the install path uses and a staged package on
/// the data zone.
///
/// `apps_read_only` is the mount the machine under test would have: the demo's
/// app zone is a read-only device, and a test that wants the install to reach
/// the app zone has to give it one it can write.
fn fixture(apps_read_only: bool) -> &'static KernelMutex<FileSystem> {
    // Leaked deliberately: the global keeps the pointer for the life of the
    // test binary, so freeing it would leave the slot advertising storage that
    // no longer exists.
    let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
    {
        let mut fs_guard = fs.lock();
        // The mount flags and the read-only property come from the zone
        // itself, which is what the boot's `mount_zone` and its zone-device
        // cut use: a fixture that made up its own would be testing its own
        // opinion of the machine.
        for (zone, name, path, read_only) in [
            (StorageZone::Apps, "apps", "/apps", apps_read_only),
            (StorageZone::Data, "data", "/data", false),
        ] {
            let image = SimpleFs::build_image_with_headroom(name, &[], 64, 128, 512)
                .expect("build a writable zone");
            let device = MemoryBlockDevice::new(name, image, read_only);
            let volume = SimpleFs::open(device, true).expect("open the zone");
            fs_guard.register(name, Arc::new(SimpleFsVolume::new(volume)));
            fs_guard
                .mount(&format!("/dev/{name}"), path, name, zone.flags())
                .expect("mount the zone");
        }
    }

    let fs_guard = fs.lock();
    fs_guard
        .create_dir("/data/downloads")
        .expect("create the download cache");
    fs_guard.create_dir(SOURCE).expect("create the package");
    fs_guard
        .create_dir(&format!("{SOURCE}/bin"))
        .expect("create the payload directory");

    let manifest = format!(
        "name = \"demo\"\nversion = \"1.0.0\"\nformat = \"{}\"\nentry = \"bin/demo.elf\"\nworking_dir = \".\"\nentry_sha256 = \"{}\"\n",
        protofire::user::program::DEMO_PROGRAM_FORMAT,
        sha256_hex(PAYLOAD),
    );
    for (path, bytes) in [
        (format!("{SOURCE}/manifest.toml"), manifest.as_bytes()),
        (format!("{SOURCE}/bin/demo.elf"), PAYLOAD),
    ] {
        let mut file = fs_guard
            .create_file(&path, 0, 0, protofire::fs::OPEN_ALWAYS)
            .expect("create a package file");
        fs_guard
            .write(&mut file, bytes)
            .expect("write a package file");
    }
    drop(fs_guard);

    protofire::fs::install_global(fs);
    fs
}

/// Dispatch the install syscall with `token` as the caller's.
///
/// The fixture is built under the test lock, because building it replaces the
/// global filesystem the syscall reaches through.
fn install_on(apps_read_only: bool, token: SecurityToken, path: &str) -> Result<usize, Error> {
    let _guard = test_lock();
    let fs = fixture(apps_read_only);

    let scheduler = Box::new(Scheduler::new());
    let _thread = scheduler.spawn_named_with_security_token("install", token, 0x1000);
    // SAFETY: the test lock serialises every test that shares the global
    // scheduler slot, and this test installs its own scheduler before touching
    // it, so the pointer is only read while the box is alive.
    unsafe { scheduler.install_global_unchecked() };
    scheduler.schedule();

    let mut table = Table::new();
    table.init();
    let mut context = SyscallContext::new(
        SyscallNumber::InstallPackage as usize,
        [path.as_ptr() as usize, path.len(), 0, 0, 0, 0],
    );
    let result = table.dispatch(&mut context);

    // Whatever happened, the two must agree: a version is active exactly when
    // the install reported success.
    let installed = fs.lock().stat_path("/apps/current/demo.toml").is_ok();
    match &result {
        Ok(_) => assert!(
            installed,
            "the install reported success with nothing active"
        ),
        Err(_) => assert!(!installed, "a refused install left a version active"),
    }

    result
}

/// The same, against a filesystem with a writable app zone.
fn install_as(token: SecurityToken, path: &str) -> Result<usize, Error> {
    install_on(false, token, path)
}

/// Read a whole file through the facade.
fn read_file(fs: &FileSystem, path: &str) -> String {
    let mut file = fs.open(path, 0).expect("open");
    let mut buffer = vec![0_u8; 256];
    let count = file.read(&mut buffer).expect("read");
    String::from_utf8(buffer[..count].to_vec()).expect("utf8")
}

#[test]
fn the_install_syscall_installs_what_the_caller_staged() {
    let status = install_as(SecurityToken::system(), SOURCE).expect("the install syscall");
    assert_eq!(status, 0);

    let fs = protofire::fs::global()
        .expect("the global filesystem")
        .lock();
    assert_eq!(
        read_file(&fs, "/apps/packages/demo/1.0.0/bin/demo.elf"),
        String::from_utf8(PAYLOAD.to_vec()).expect("utf8")
    );
    assert!(read_file(&fs, "/apps/current/demo.toml").contains("version = \"1.0.0\""));
    assert!(fs.stat_path("/apps/catalog/demo@1.0.0.toml").is_ok());
}

#[test]
fn the_install_syscall_refuses_a_caller_that_cannot_write_the_app_zone() {
    // The app zone is system-managed: a guest cannot write it, and the syscall
    // adds no rule of its own — the filesystem refuses the first write the
    // install makes.
    assert_eq!(
        install_as(SecurityToken::guest(), SOURCE),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn the_install_syscall_refuses_a_package_that_is_not_there() {
    assert_eq!(
        install_as(SecurityToken::system(), "/data/downloads/nothing@1.0.0"),
        Err(Error::NotFound)
    );
}

#[test]
fn an_install_into_a_read_only_app_zone_is_refused() {
    // The zone is a block device that answers writes with a refusal, and the
    // install path is no exception to it: what a machine can install into is
    // what its app zone allows, and a read-only one allows nothing — not even
    // the system token the install runs as.
    assert_eq!(
        install_on(true, SecurityToken::system(), SOURCE),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn the_app_zone_the_boot_mounts_accepts_an_install() {
    // The test that answers "can this machine install an app?": both the
    // device property and the mount flags come from `StorageZone::Apps`, which
    // is what the boot uses, so a policy that closed the zone again would fail
    // here rather than only in the field.
    assert_eq!(
        install_on(
            StorageZone::Apps.device_read_only(),
            SecurityToken::system(),
            SOURCE,
        ),
        Ok(0)
    );
}
