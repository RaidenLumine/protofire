//! tests/syscall/fs_entries.rs
//!
//! The two ways to name one object must answer the same thing.
//!
//! Every metadata family in the ABI has a path entry and a descriptor entry:
//! `stat`/`stat_fd`, `read_dir`/`read_dir_fd`,
//! `access_query`/`access_query_fd`, and
//! `permission_metadata`/`permission_metadata_fd`.  The pairs are separate
//! handlers, so the two halves can drift: one can grow a second opinion about
//! what a record should say.  This drives both halves against the same object
//! through the real syscall table and asserts the records are equal, and it
//! does it for a file (which the descriptor side answers from the open handle)
//! and a directory (which it answers by resolving back to the path).
//!
//! Host builds treat the caller's pointers as ordinary host pointers — there
//! is no user address space to validate against — so the "user" buffers here
//! are ordinary stack and heap allocations.

use std::sync::Mutex;
use std::sync::OnceLock;

use protofire::abi::fs as fs_abi;
use protofire::abi::io::OPEN_FLAG_READ;
use protofire::abi::io::OPEN_FLAG_READ_WRITE_CREATE;
use protofire::fs::FileSystem;
use protofire::fs::{self};
use protofire::kernel::process::Scheduler;
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::syscall::SyscallContext;
use protofire::syscall::SyscallNumber;
use protofire::syscall::Table;
use protofire::Error;

/// The filesystem global, the scheduler global and the syscall table are all
/// process-wide, so these tests run one at a time.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn install_test_fs() -> &'static KernelMutex<FileSystem> {
    // A fresh instance per test, leaked deliberately: the global keeps the
    // pointer for the life of the test binary, so freeing it would leave the
    // slot advertising storage that no longer exists.  This mirrors the
    // descriptor-I/O tests, whose setup has the same shape.
    let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
    fs.lock().init();
    fs::install_global(fs);
    fs
}

fn dispatch(table: &Table, number: SyscallNumber, args: [usize; 6]) -> Result<usize, Error> {
    let mut context = SyscallContext::new(number as usize, args);
    table.dispatch(&mut context)
}

fn open(table: &Table, path: &str, flags: usize) -> Result<usize, Error> {
    dispatch(
        table,
        SyscallNumber::Open,
        [path.as_ptr() as usize, path.len(), flags, 0, 0, 0],
    )
}

fn stat_path(table: &Table, path: &str) -> fs_abi::FileStat {
    let mut record = fs_abi::FileStat::new(0, 0);
    dispatch(
        table,
        SyscallNumber::Stat,
        [
            path.as_ptr() as usize,
            path.len(),
            &mut record as *mut fs_abi::FileStat as usize,
            fs_abi::FILE_STAT_SIZE,
            0,
            0,
        ],
    )
    .expect("stat by path");
    record
}

fn stat_fd(table: &Table, fd: usize) -> fs_abi::FileStat {
    let mut record = fs_abi::FileStat::new(0, 0);
    dispatch(
        table,
        SyscallNumber::StatFd,
        [
            fd,
            &mut record as *mut fs_abi::FileStat as usize,
            fs_abi::FILE_STAT_SIZE,
            0,
            0,
            0,
        ],
    )
    .expect("stat by descriptor");
    record
}

/// Read directory entry `index`, returning the whole output buffer so the
/// header and the name bytes are compared the same way.
fn read_dir_path(table: &Table, path: &str, index: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; fs_abi::DIRECTORY_ENTRY_RECORD_SIZE + 64];
    dispatch(
        table,
        SyscallNumber::ReadDir,
        [
            path.as_ptr() as usize,
            path.len(),
            index,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            0,
        ],
    )
    .expect("read_dir by path");
    buffer
}

fn read_dir_fd(table: &Table, fd: usize, index: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; fs_abi::DIRECTORY_ENTRY_RECORD_SIZE + 64];
    dispatch(
        table,
        SyscallNumber::ReadDirFd,
        [fd, index, buffer.as_mut_ptr() as usize, buffer.len(), 0, 0],
    )
    .expect("read_dir by descriptor");
    buffer
}

fn access_query_path(table: &Table, path: &str, required: u16) -> fs_abi::AccessQueryRecord {
    let mut record = fs_abi::AccessQueryRecord::new(0, 0, 0);
    dispatch(
        table,
        SyscallNumber::AccessQuery,
        [
            path.as_ptr() as usize,
            path.len(),
            required as usize,
            &mut record as *mut fs_abi::AccessQueryRecord as usize,
            fs_abi::ACCESS_QUERY_RECORD_SIZE,
            0,
        ],
    )
    .expect("access_query by path");
    record
}

fn access_query_fd(table: &Table, fd: usize, required: u16) -> fs_abi::AccessQueryRecord {
    let mut record = fs_abi::AccessQueryRecord::new(0, 0, 0);
    dispatch(
        table,
        SyscallNumber::AccessQueryFd,
        [
            fd,
            required as usize,
            &mut record as *mut fs_abi::AccessQueryRecord as usize,
            fs_abi::ACCESS_QUERY_RECORD_SIZE,
            0,
            0,
        ],
    )
    .expect("access_query by descriptor");
    record
}

fn permission_metadata_path(table: &Table, path: &str) -> fs_abi::PermissionMetadataRecord {
    let mut record = fs_abi::PermissionMetadataRecord::new(0, 0, 0);
    dispatch(
        table,
        SyscallNumber::PermissionMetadata,
        [
            path.as_ptr() as usize,
            path.len(),
            &mut record as *mut fs_abi::PermissionMetadataRecord as usize,
            fs_abi::PERMISSION_METADATA_RECORD_SIZE,
            0,
            0,
        ],
    )
    .expect("permission_metadata by path");
    record
}

fn permission_metadata_fd(table: &Table, fd: usize) -> fs_abi::PermissionMetadataRecord {
    let mut record = fs_abi::PermissionMetadataRecord::new(0, 0, 0);
    dispatch(
        table,
        SyscallNumber::PermissionMetadataFd,
        [
            fd,
            &mut record as *mut fs_abi::PermissionMetadataRecord as usize,
            fs_abi::PERMISSION_METADATA_RECORD_SIZE,
            0,
            0,
            0,
        ],
    )
    .expect("permission_metadata by descriptor");
    record
}

#[test]
fn path_and_descriptor_entries_answer_for_the_same_file() {
    let _guard = test_lock();
    install_test_fs();

    let scheduler = Scheduler::new();
    let _thread = scheduler.spawn_named("fs-entries", 0x1000);
    // SAFETY: the test lock serialises every test that shares the global
    // scheduler slot, and each of them installs its own scheduler before
    // touching it, so the pointer is only read while this one is alive.
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();

    let mut table = Table::new();
    table.init();

    // Write something into the subject first: an empty file would let every
    // record below agree by being zero.
    let path = "/data/users/guest/fs-entries.txt";
    let payload = b"entries\n";
    let fd = open(&table, path, OPEN_FLAG_READ_WRITE_CREATE).expect("create the subject");
    let written = dispatch(
        &table,
        SyscallNumber::Write,
        [fd, payload.as_ptr() as usize, payload.len(), 0, 0, 0],
    )
    .expect("write the subject");
    assert_eq!(written, payload.len());

    // The subject is a non-empty regular file, so the record the two entries
    // have to agree on is a non-trivial one.
    let by_path = stat_path(&table, path);
    assert_eq!(
        by_path,
        fs_abi::FileStat::new(fs_abi::FILE_KIND_FILE, payload.len())
    );
    assert_eq!(by_path, stat_fd(&table, fd));
    assert_eq!(
        access_query_path(&table, path, fs_abi::ACCESS_READ_BIT),
        access_query_fd(&table, fd, fs_abi::ACCESS_READ_BIT)
    );
    assert_eq!(
        permission_metadata_path(&table, path),
        permission_metadata_fd(&table, fd)
    );
}

#[test]
fn path_and_descriptor_entries_answer_for_the_same_directory() {
    let _guard = test_lock();
    install_test_fs();

    let scheduler = Scheduler::new();
    let _thread = scheduler.spawn_named("fs-entries-dir", 0x1000);
    // SAFETY: same contract as the test above.
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler.schedule();

    let mut table = Table::new();
    table.init();

    // Give the directory an entry so index 0 has something to describe.
    let subject = "/data/users/guest/fs-entries-dir-subject.txt";
    open(&table, subject, OPEN_FLAG_READ_WRITE_CREATE).expect("create the subject");

    let dir = "/data/users/guest";
    let dir_fd = open(&table, dir, OPEN_FLAG_READ).expect("open the directory");

    let by_path = stat_path(&table, dir);
    assert_eq!(
        by_path,
        fs_abi::FileStat::new(fs_abi::FILE_KIND_DIRECTORY, by_path.size)
    );
    assert_eq!(by_path, stat_fd(&table, dir_fd));

    // Index zero describes one of the directory's entries; the subject makes
    // sure the listing is not empty.
    let by_path = read_dir_path(&table, dir, 0);
    assert!(by_path.iter().any(|&byte| byte != 0));
    assert_eq!(by_path, read_dir_fd(&table, dir_fd, 0));
    assert_eq!(
        access_query_path(&table, dir, fs_abi::ACCESS_READ_BIT),
        access_query_fd(&table, dir_fd, fs_abi::ACCESS_READ_BIT)
    );
    assert_eq!(
        permission_metadata_path(&table, dir),
        permission_metadata_fd(&table, dir_fd)
    );
}
