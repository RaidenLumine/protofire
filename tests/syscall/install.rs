//! tests/syscall/install.rs
//!
//! Host-side integration tests for the install syscall.
//!
//! These drive the whole path a ring-3 program takes: a table dispatch with a
//! package staged on a writable data zone, the install that follows, and the
//! records it leaves under `/apps`.  The app zone here is writable — built for
//! the test, because the demo's is mounted read-only — so the success case and
//! the refusal case are both reachable.

use std::sync::Arc;

use protofire::fs::block::MemoryBlockDevice;
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

/// A filesystem with a writable app zone and a staged package on the data zone.
fn install_fixture() -> &'static KernelMutex<FileSystem> {
    // Leaked deliberately: the global keeps the pointer for the life of the
    // test binary, so freeing it would leave the slot advertising storage that
    // no longer exists.
    let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
    {
        let mut fs_guard = fs.lock();
        for (name, path) in [("apps", "/apps"), ("data", "/data")] {
            let image = SimpleFs::build_image_with_headroom(name, &[], 64, 128, 512)
                .expect("build a writable zone");
            let device = MemoryBlockDevice::new(name, image, false);
            let volume = SimpleFs::open(device, true).expect("open the zone");
            fs_guard.register(name, Arc::new(SimpleFsVolume::new(volume)));
            fs_guard
                .mount(&format!("/dev/{name}"), path, name, 0)
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

/// Dispatch the install syscall with `token` as the calling process's.
fn install_as(token: SecurityToken, path: &str) -> Result<usize, Error> {
    let _guard = test_lock();
    let fs = install_fixture();

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
