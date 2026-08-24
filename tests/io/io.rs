//! tests/io/io.rs
//!
//! Host-side integration tests for descriptor-based I/O and stdio routing.

use std::sync::{Mutex, OnceLock};

use protofire::kernel::console;
use protofire::kernel::device;
use protofire::kernel::drivers::{keyboard, serial};
use protofire::kernel::fs::{self, FileSystem, OPEN_ALWAYS, SEEK_SET};
use protofire::kernel::io;
use protofire::kernel::process::{
    KernelObject, Process, Scheduler, CONSOLE_DEVICE_NAME, HANDLE_RIGHT_READ, HANDLE_RIGHT_WRITE,
    NULL_DEVICE_NAME, SERIAL0_DEVICE_NAME, STDIN_FD, STDOUT_FD, ZERO_DEVICE_NAME,
};
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::kernel::syscall::Table;
use protofire::user::syscall::UserSyscall;
use protofire::Error;

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn install_test_fs() -> &'static KernelMutex<FileSystem> {
    // Each test gets a fresh FileSystem so that side effects (file creates,
    // writes, renames) do not leak across tests.  The previous instance is
    // intentionally leaked — calling init() on the same FileSystem a second
    // time drops old SimpleFs volumes whose Drop flushes the block cache,
    // which can deadlock when the device mutexes are held.
    let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
    fs.lock().init();
    fs::install_global(fs);
    fs
}

fn assert_device_binding(process: &Process, fd: usize, expected_name: &str, expected_rights: u32) {
    let entry = process.fd_entry(fd).expect("resolve device fd");
    assert!(matches!(entry.object, KernelObject::Device(ref name) if name == expected_name));
    assert_eq!(entry.rights, expected_rights);
}

#[test]
fn processes_get_default_standard_handles() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    assert_device_binding(process.as_ref(), STDIN_FD, "console", HANDLE_RIGHT_READ);
    assert_device_binding(process.as_ref(), STDOUT_FD, "debug", HANDLE_RIGHT_WRITE);
}

#[test]
fn generic_read_uses_stdin_binding_and_drains_cooked_bytes() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);

    let mut buffer = [0_u8; 8];
    let count = io::read(process.as_ref(), STDIN_FD, &mut buffer, 0).expect("read stdin");

    assert_eq!(count, 2);
    assert_eq!(&buffer[..count], b"a\n");
}

#[test]
fn generic_read_rejects_write_only_stdout() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    let mut buffer = [0_u8; 4];
    assert_eq!(
        io::read(process.as_ref(), STDOUT_FD, &mut buffer, 0),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn generic_read_zero_length_still_validates_rights() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    let mut empty = [0_u8; 0];
    assert_eq!(
        io::read(process.as_ref(), STDOUT_FD, &mut empty, 0),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        io::read(process.as_ref(), STDIN_FD, &mut empty, 0).expect("zero-length stdin read"),
        0
    );
}

#[test]
fn generic_read_accepts_an_explicit_open_file_descriptor() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_READ)
        .expect("open process file descriptor");

    let mut buffer = [0_u8; 128];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read file");
    let text = core::str::from_utf8(&buffer[..count]).expect("utf8");

    assert!(text.contains("block-backed demo image"));
}

#[test]
fn explicit_file_descriptors_are_resolved_via_fd_table() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_READ)
        .expect("open process file descriptor");
    let (kernel_handle, entry) = process.resolve_fd(fd).expect("resolve explicit fd");

    assert!(fd >= 3);
    assert_ne!(kernel_handle, fd as u64);
    assert_eq!(entry.rights, HANDLE_RIGHT_READ);
    assert!(matches!(entry.object, KernelObject::File(_)));
}

#[test]
fn generic_seek_repositions_an_open_file_descriptor() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("reader", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_READ)
        .expect("open process file descriptor");

    let mut buffer = [0_u8; 8];
    let first = io::read(process.as_ref(), fd, &mut buffer, 8).expect("first read");
    let reset = io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek");
    let second = io::read(process.as_ref(), fd, &mut buffer, 8).expect("second read");

    assert_eq!(first, second);
    assert_eq!(reset, 0);
    assert_eq!(&buffer[..second], b"System v");
}

#[test]
fn generic_duplicate_shares_open_file_position() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("dup-position", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_READ)
        .expect("open process file descriptor");
    let dup_fd = io::duplicate(process.as_ref(), fd).expect("duplicate fd");
    assert_ne!(dup_fd, fd);

    let mut buffer = [0_u8; 8];
    let first = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read through original fd");
    assert_eq!(first, 8);
    assert_eq!(&buffer, b"System v");

    assert_eq!(
        io::seek(process.as_ref(), dup_fd, 0, SEEK_SET).expect("seek through duplicate fd"),
        0
    );

    let second = io::read(process.as_ref(), fd, &mut buffer, 0)
        .expect("read through original fd after duplicate seek");
    assert_eq!(second, 8);
    assert_eq!(&buffer, b"System v");
}

#[test]
fn generic_io_rejects_directory_descriptors() {
    let _guard = test_lock();
    install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("dir-io", 0x1000);
    let process = thread.process().clone();

    let fd = process
        .open_directory_descriptor("/data/users/guest/downloads", HANDLE_RIGHT_READ)
        .expect("open directory descriptor");

    let mut buffer = [0_u8; 8];
    assert_eq!(
        io::read(process.as_ref(), fd, &mut buffer, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::write(process.as_ref(), fd, b"bad"),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::set_len(process.as_ref(), fd, 0),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn generic_io_rejects_directory_vnodes_wrapped_as_file_descriptors() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("dir-vnode-io", 0x1000);
    let process = thread.process().clone();

    let directory = fs
        .lock()
        .open_from(
            "/data/users/guest/downloads",
            &process.current_working_dir(),
            0,
        )
        .expect("open directory vnode");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads",
            directory,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("wrap directory vnode as file descriptor");

    let mut buffer = [0_u8; 8];
    assert_eq!(
        io::read(process.as_ref(), fd, &mut buffer, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::write(process.as_ref(), fd, b"bad"),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        io::set_len(process.as_ref(), fd, 0),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn generic_write_uses_stdout_binding() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let count = io::write(process.as_ref(), STDOUT_FD, b"debug line\n").expect("write stdout");
    assert_eq!(count, b"debug line\n".len());
}

#[test]
fn generic_write_to_read_only_file_returns_permission_denied() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_WRITE)
        .expect("open process file descriptor");

    assert_eq!(
        io::write(process.as_ref(), fd, b"mutate"),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn generic_write_zero_length_still_validates_rights() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/system/runtime/README.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open file");
    let fd = process
        .open_file_descriptor("/system/runtime/README.txt", file, HANDLE_RIGHT_READ)
        .expect("open read-only process file descriptor");

    assert_eq!(
        io::write(process.as_ref(), fd, b""),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        io::write(process.as_ref(), STDOUT_FD, b"").expect("zero-length stdout write"),
        0
    );
}

#[test]
fn generic_write_updates_existing_data_files() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/data/users/guest/documents/readme.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open data file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/documents/readme.txt",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    let payload = b"mutated data volume";
    let written = io::write(process.as_ref(), fd, payload).expect("write data file");
    assert_eq!(written, payload.len());

    let reset = io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek");
    assert_eq!(reset, 0);

    let mut buffer = [0_u8; 32];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read back");
    assert_eq!(&buffer[..payload.len()], payload);
    assert!(count >= payload.len());
}

#[test]
fn generic_write_can_create_new_data_files() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .create_file_from(
            "/data/users/guest/downloads/demo-session.log",
            &process.current_working_dir(),
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create data file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads/demo-session.log",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    let payload = b"io created file";
    let written = io::write(process.as_ref(), fd, payload).expect("write new file");
    assert_eq!(written, payload.len());

    let reset = io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek");
    assert_eq!(reset, 0);

    let mut buffer = [0_u8; 32];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read back");
    assert_eq!(&buffer[..payload.len()], payload);
    assert!(count >= payload.len());
}

#[test]
fn open_file_descriptor_survives_data_rename() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("open-fd-rename", 0x1000);
    let process = thread.process().clone();
    let old_path = "/data/users/guest/downloads/open-fd-rename-old.log";
    let new_path = "/data/users/guest/downloads/open-fd-rename-new.log";

    let file = fs
        .lock()
        .create_file_from(old_path, &process.current_working_dir(), 0, 0, OPEN_ALWAYS)
        .expect("create data file");
    let fd = process
        .open_file_descriptor(old_path, file, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open process file descriptor");

    let initial = b"open fd rename";
    assert_eq!(
        io::write(process.as_ref(), fd, initial).expect("write initial payload"),
        initial.len()
    );

    fs.lock()
        .rename_path(old_path, new_path)
        .expect("rename open data file");
    assert!(matches!(
        fs.lock()
            .open_from(old_path, &process.current_working_dir(), 0),
        Err(Error::NotFound)
    ));

    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek open fd after rename"),
        0
    );
    let mut buffer = [0_u8; 64];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read renamed open fd");
    assert_eq!(&buffer[..count], initial);

    let suffix = b" still writable";
    assert_eq!(
        io::write(process.as_ref(), fd, suffix).expect("write through renamed open fd"),
        suffix.len()
    );

    let mut expected = initial.to_vec();
    expected.extend_from_slice(suffix);
    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("rewind renamed open fd"),
        0
    );
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read updated open fd");
    assert_eq!(&buffer[..count], expected.as_slice());

    let mut reopened = fs
        .lock()
        .open_from(new_path, &process.current_working_dir(), 0)
        .expect("open renamed path");
    let mut reopened_buffer = [0_u8; 64];
    let reopened_count = reopened
        .read(&mut reopened_buffer)
        .expect("read renamed path");
    assert_eq!(&reopened_buffer[..reopened_count], expected.as_slice());
}

#[test]
fn open_file_descriptor_reports_not_found_after_data_remove() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("open-fd-remove", 0x1000);
    let process = thread.process().clone();
    let path = "/data/users/guest/downloads/open-fd-remove.log";

    let file = fs
        .lock()
        .create_file_from(path, &process.current_working_dir(), 0, 0, OPEN_ALWAYS)
        .expect("create data file");
    let fd = process
        .open_file_descriptor(path, file, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open process file descriptor");

    let payload = b"open fd remove";
    assert_eq!(
        io::write(process.as_ref(), fd, payload).expect("write initial payload"),
        payload.len()
    );

    fs.lock().remove_path(path).expect("remove open data file");
    assert!(matches!(
        fs.lock().open_from(path, &process.current_working_dir(), 0),
        Err(Error::NotFound)
    ));

    let mut buffer = [0_u8; 16];
    assert_eq!(
        io::read(process.as_ref(), fd, &mut buffer, 0),
        Err(Error::NotFound)
    );
    assert_eq!(
        io::write(process.as_ref(), fd, b"stale"),
        Err(Error::NotFound)
    );
    assert_eq!(io::set_len(process.as_ref(), fd, 0), Err(Error::NotFound));
}

#[test]
fn closing_explicit_file_descriptor_invalidates_all_generic_io_paths() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("close-explicit-fd", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .create_file_from(
            "/data/users/guest/downloads/close-me.log",
            &process.current_working_dir(),
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads/close-me.log",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    assert_eq!(
        io::write(process.as_ref(), fd, b"close fd").expect("seed file"),
        b"close fd".len()
    );
    process.close_fd(fd).expect("close explicit descriptor");

    let mut buffer = [0_u8; 8];
    assert_eq!(
        io::read(process.as_ref(), fd, &mut buffer, 0),
        Err(Error::NotFound)
    );
    assert_eq!(io::write(process.as_ref(), fd, b"x"), Err(Error::NotFound));
    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET),
        Err(Error::NotFound)
    );
    assert_eq!(io::set_len(process.as_ref(), fd, 0), Err(Error::NotFound));
}

#[test]
fn generic_set_len_rejects_read_only_descriptor() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("set-len-read-only", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .open_from(
            "/data/users/guest/documents/readme.txt",
            &process.current_working_dir(),
            0,
        )
        .expect("open read-only data file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/documents/readme.txt",
            file,
            HANDLE_RIGHT_READ,
        )
        .expect("open read-only descriptor");

    assert_eq!(
        io::set_len(process.as_ref(), fd, 4),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn stdio_device_paths_open_as_explicit_aliases() {
    let _guard = test_lock();
    install_test_fs();

    let keyboard = keyboard::init_device();
    let console = console::init_global();
    let serial = serial::init_device();
    keyboard.clear();
    console.clear();
    serial.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("stdio-aliases", 0x1000);
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));

    let mut table = Table::new();
    table.init();

    let stdin_path = protofire::kernel::io::STDIN_DEVICE_PATH.as_bytes();
    let mut stdin_ctx = UserSyscall::open(
        stdin_path.as_ptr() as usize,
        stdin_path.len(),
        protofire::abi::io::OPEN_FLAG_READ,
    );
    let stdin_fd = table.dispatch(&mut stdin_ctx).expect("open stdin alias");
    assert_device_binding(
        thread.process().as_ref(),
        stdin_fd,
        "console",
        HANDLE_RIGHT_READ,
    );

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);
    let mut stdin_buffer = [0_u8; 8];
    let stdin_count = io::read(thread.process().as_ref(), stdin_fd, &mut stdin_buffer, 0)
        .expect("read stdin alias");
    assert_eq!(&stdin_buffer[..stdin_count], b"a\n");
    serial.clear();

    let stdout_path = protofire::kernel::io::STDOUT_DEVICE_PATH.as_bytes();
    let mut stdout_ctx = UserSyscall::open(
        stdout_path.as_ptr() as usize,
        stdout_path.len(),
        protofire::abi::io::OPEN_FLAG_WRITE,
    );
    let stdout_fd = table.dispatch(&mut stdout_ctx).expect("open stdout alias");
    assert_device_binding(
        thread.process().as_ref(),
        stdout_fd,
        "debug",
        HANDLE_RIGHT_WRITE,
    );

    let stderr_path = protofire::kernel::io::STDERR_DEVICE_PATH.as_bytes();
    let mut stderr_ctx = UserSyscall::open(
        stderr_path.as_ptr() as usize,
        stderr_path.len(),
        protofire::abi::io::OPEN_FLAG_WRITE,
    );
    let stderr_fd = table.dispatch(&mut stderr_ctx).expect("open stderr alias");
    assert_device_binding(
        thread.process().as_ref(),
        stderr_fd,
        "debug",
        HANDLE_RIGHT_WRITE,
    );

    let payload = b"stdio alias output\n";
    assert_eq!(
        io::write(thread.process().as_ref(), stdout_fd, payload).expect("write stdout alias"),
        payload.len()
    );
    assert_eq!(
        io::write(thread.process().as_ref(), stderr_fd, payload).expect("write stderr alias"),
        payload.len()
    );
    assert_eq!(
        serial.captured_tx_bytes(),
        [payload.as_slice(), payload.as_slice()].concat()
    );
}

#[test]
fn keyboard_device_path_reads_decoded_chars_without_waiting_for_newline() {
    let _guard = test_lock();
    install_test_fs();

    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("keyboard-chars", 0x1000);
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));

    let mut table = Table::new();
    table.init();

    let keyboard_path = io::KEYBOARD_DEVICE_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        keyboard_path.as_ptr() as usize,
        keyboard_path.len(),
        protofire::abi::io::OPEN_FLAG_READ,
    );
    let keyboard_fd = table.dispatch(&mut open_ctx).expect("open keyboard device");
    assert_device_binding(
        thread.process().as_ref(),
        keyboard_fd,
        "keyboard",
        HANDLE_RIGHT_READ,
    );

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x30);

    let mut buffer = [0_u8; 8];
    let count = io::read(thread.process().as_ref(), keyboard_fd, &mut buffer, 0)
        .expect("read keyboard chars");
    assert_eq!(&buffer[..count], b"ab");
}

#[test]
fn keyboard_raw_device_path_reads_scancode_bytes() {
    let _guard = test_lock();
    install_test_fs();

    let keyboard = keyboard::init_device();
    let console = console::init_global();
    keyboard.clear();
    console.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("keyboard-raw", 0x1000);
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));

    let mut table = Table::new();
    table.init();

    let keyboard_path = io::KEYBOARD_RAW_DEVICE_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        keyboard_path.as_ptr() as usize,
        keyboard_path.len(),
        protofire::abi::io::OPEN_FLAG_READ,
    );
    let keyboard_fd = table
        .dispatch(&mut open_ctx)
        .expect("open keyboard raw device");
    assert_device_binding(
        thread.process().as_ref(),
        keyboard_fd,
        "keyboard-raw",
        HANDLE_RIGHT_READ,
    );

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x9E);

    let mut buffer = [0_u8; 8];
    let count = io::read(thread.process().as_ref(), keyboard_fd, &mut buffer, 0)
        .expect("read keyboard raw scancodes");
    assert_eq!(&buffer[..count], &[0x1E, 0x9E]);
}

#[test]
fn direct_keyboard_device_zero_length_reads_return_empty_without_waiting() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    keyboard.clear();

    let mut empty = [];
    assert_eq!(
        device::dispatch_device_read(device::KEYBOARD_DEVICE_NAME, &mut empty, 0),
        Ok(0)
    );
    assert_eq!(
        device::dispatch_device_read(device::KEYBOARD_RAW_DEVICE_NAME, &mut empty, 0),
        Ok(0)
    );
}

#[test]
fn serial_device_descriptor_supports_bidirectional_io() {
    let _guard = test_lock();
    let serial = serial::init_device();
    serial.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("serial-rw", 0x1000);
    let process = thread.process().clone();

    let serial_fd = process
        .open_device_descriptor(SERIAL0_DEVICE_NAME, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open serial0 descriptor");
    assert_device_binding(
        process.as_ref(),
        serial_fd,
        "serial0",
        HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
    );

    serial::inject_rx_bytes(b"rx");
    let mut read_buffer = [0_u8; 8];
    let read =
        io::read(process.as_ref(), serial_fd, &mut read_buffer, 0).expect("read serial0 bytes");
    assert_eq!(&read_buffer[..read], b"rx");

    serial.clear();
    let payload = b"tx";
    let written = io::write(process.as_ref(), serial_fd, payload).expect("write serial0 bytes");
    assert_eq!(written, payload.len());
    assert_eq!(serial.captured_tx_bytes(), payload);
}

#[test]
fn console_device_descriptor_supports_bidirectional_io() {
    let _guard = test_lock();
    let keyboard = keyboard::init_device();
    let console = console::init_global();
    let serial = serial::init_device();
    keyboard.clear();
    console.clear();
    serial.clear();

    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("console-rw", 0x1000);
    let process = thread.process().clone();

    let console_fd = process
        .open_device_descriptor(CONSOLE_DEVICE_NAME, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open console descriptor");
    assert_device_binding(
        process.as_ref(),
        console_fd,
        "console",
        HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
    );

    keyboard::inject_scancode(0x1E);
    keyboard::inject_scancode(0x1C);
    let mut read_buffer = [0_u8; 8];
    let read =
        io::read(process.as_ref(), console_fd, &mut read_buffer, 0).expect("read console bytes");
    assert_eq!(&read_buffer[..read], b"a\n");

    serial.clear();
    let payload = b"console tx";
    let written = io::write(process.as_ref(), console_fd, payload).expect("write console bytes");
    assert_eq!(written, payload.len());
    assert_eq!(serial.captured_tx_bytes(), payload);
}

#[test]
fn null_and_zero_device_descriptors_expose_standard_stream_semantics() {
    let _guard = test_lock();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("null-zero", 0x1000);
    let process = thread.process().clone();

    let null_fd = process
        .open_device_descriptor(NULL_DEVICE_NAME, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open null descriptor");
    assert_device_binding(
        process.as_ref(),
        null_fd,
        "null",
        HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
    );

    let zero_fd = process
        .open_device_descriptor(ZERO_DEVICE_NAME, HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE)
        .expect("open zero descriptor");
    assert_device_binding(
        process.as_ref(),
        zero_fd,
        "zero",
        HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
    );

    let mut null_buffer = [0xAA_u8; 4];
    let null_read =
        io::read(process.as_ref(), null_fd, &mut null_buffer, 123).expect("read null device");
    assert_eq!(null_read, 0);
    assert_eq!(null_buffer, [0xAA; 4]);

    let mut zero_buffer = [0xAA_u8; 4];
    let zero_read =
        io::read(process.as_ref(), zero_fd, &mut zero_buffer, 123).expect("read zero device");
    assert_eq!(zero_read, zero_buffer.len());
    assert_eq!(zero_buffer, [0_u8; 4]);

    let payload = b"discard me";
    assert_eq!(
        io::write(process.as_ref(), null_fd, payload).expect("write null device"),
        payload.len()
    );
    assert_eq!(
        io::write(process.as_ref(), zero_fd, payload).expect("write zero device"),
        payload.len()
    );
}

#[test]
fn generic_io_can_use_new_directories_created_under_data() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    fs.lock()
        .create_dir_from(
            "/data/users/guest/downloads/demo-state",
            &process.current_working_dir(),
        )
        .expect("create dir");

    let file = fs
        .lock()
        .create_file_from(
            "/data/users/guest/downloads/demo-state/demo-session.log",
            &process.current_working_dir(),
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create nested file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads/demo-state/demo-session.log",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    let payload = b"io nested file";
    let written = io::write(process.as_ref(), fd, payload).expect("write");
    assert_eq!(written, payload.len());

    let reset = io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek");
    assert_eq!(reset, 0);

    let mut buffer = [0_u8; 32];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read back");
    assert_eq!(&buffer[..payload.len()], payload);
    assert!(count >= payload.len());
}

#[test]
fn generic_set_len_truncates_data_files() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("writer", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .create_file_from(
            "/data/users/guest/downloads/demo-session.log",
            &process.current_working_dir(),
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create data file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads/demo-session.log",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    let payload = b"io truncate payload";
    let written = io::write(process.as_ref(), fd, payload).expect("write");
    assert_eq!(written, payload.len());

    let new_len = io::set_len(process.as_ref(), fd, 11).expect("truncate");
    assert_eq!(new_len, 11);

    let reset = io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("seek");
    assert_eq!(reset, 0);

    let mut buffer = [0_u8; 32];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read back");
    assert_eq!(count, 11);
    assert_eq!(&buffer[..count], b"io truncate");
}

#[test]
fn generic_set_len_clamps_position_before_followup_write() {
    let _guard = test_lock();
    let fs = install_test_fs();
    let scheduler = Scheduler::new();
    let thread = scheduler.spawn_named("set-len-position-clamp", 0x1000);
    let process = thread.process().clone();

    let file = fs
        .lock()
        .create_file_from(
            "/data/users/guest/downloads/set-len-position-clamp.log",
            &process.current_working_dir(),
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create data file");
    let fd = process
        .open_file_descriptor(
            "/data/users/guest/downloads/set-len-position-clamp.log",
            file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open process file descriptor");

    let payload = b"abcdefghi";
    assert_eq!(
        io::write(process.as_ref(), fd, payload).expect("write payload"),
        payload.len()
    );
    assert_eq!(
        io::set_len(process.as_ref(), fd, 4).expect("truncate below current position"),
        4
    );
    assert_eq!(
        io::write(process.as_ref(), fd, b"XY").expect("write after clamp"),
        2
    );
    assert_eq!(
        io::seek(process.as_ref(), fd, 0, SEEK_SET).expect("rewind"),
        0
    );

    let mut buffer = [0_u8; 16];
    let count = io::read(process.as_ref(), fd, &mut buffer, 0).expect("read back");
    assert_eq!(count, 6);
    assert_eq!(&buffer[..count], b"abcdXY");
}
