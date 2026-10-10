//! tests/syscall/fallocate.rs
//!
//! An end-to-end punch, through the interface a program reaches: a real
//! `mkntfs` volume mounted as a mount, a file opened through the `open`
//! syscall, a hole punched through `fallocate` (#193), and the zeros read back
//! through `read`.  The volume the driver had its way with is left where the
//! check's script can hand it to a reader this tree did not write — which is
//! what the interface's own gate cannot do for itself.

use std::sync::Arc;

use protofire::fs::block::BlockDevice as _;
use protofire::fs::block::MemoryBlockDevice;
use protofire::fs::ntfs::NtfsFs;
use protofire::fs::FileSystem;
use protofire::kernel::process::Scheduler;
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::syscall::SyscallContext;
use protofire::syscall::SyscallNumber;
use protofire::syscall::Table;
use protofire::user::shared::abi::fs as fs_abi;
use protofire::user::shared::abi::io as io_abi;
use protofire::Error;

/// Serialise these tests: the filesystem global and the scheduler global are
/// process-wide, and each test installs its own.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn dispatch(table: &Table, number: SyscallNumber, args: [usize; 6]) -> Result<usize, Error> {
    let mut context = SyscallContext::new(number as usize, args);
    table.dispatch(&mut context)
}

#[test]
#[ignore = "driven by scripts/check-ntfs-image.sh, which makes the volume it needs"]
fn a_hole_punched_through_the_interface_reads_as_zeros() {
    let path = std::env::var("PROTOFIRE_NTFS_IMAGE")
        .expect("the check runs this test with a volume it made");
    let _guard = test_lock();

    // The volume, mounted as a mount: a reader reaches it through `/mnt`,
    // which is the shape a program sees.
    let image = std::fs::read(&path).expect("the volume mkntfs made");
    let device = MemoryBlockDevice::new("ntfs", image, false);
    let volume = NtfsFs::new(device.clone()).expect("mount the volume");
    let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
    {
        let mut fs_guard = fs.lock();
        fs_guard.register("ntfs", Arc::new(volume));
        fs_guard
            .mount("/dev/ntfs", "/mnt", "ntfs", 0)
            .expect("mount the volume");
    }
    protofire::fs::install_global(fs);

    let scheduler = Box::new(Scheduler::new());
    let _thread = scheduler.spawn_named("fallocate", 0x1000);
    // SAFETY: the test lock serialises every test that shares the global
    // scheduler slot, and this test installs its own before touching it, so
    // the pointer is only read while the box is alive.
    unsafe { scheduler.install_global_unchecked() };
    scheduler.schedule();

    let mut table = Table::new();
    table.init();

    const PUNCHED: usize = 1024;
    const SIZE: usize = 4 * 1024;

    // The file the check injected: four kilobytes of a pattern, which is more
    // than a record holds, so its bytes live in runs — the file a punch has
    // something to change.
    let name = "/mnt/punched.bin";
    let fd = dispatch(
        &table,
        SyscallNumber::Open,
        [
            name.as_ptr() as usize,
            name.len(),
            io_abi::OPEN_FLAG_WRITE,
            0,
            0,
            0,
        ],
    )
    .expect("open the file for writing through the interface");

    // The first quarter of it becomes a hole: the range is inside the file, so
    // the punch is legal, and it is a run list the record can hold, so what
    // this proves is the interface, the zeros it reaches down to, and the
    // zeros it reads back.
    let punch = fs_abi::FALLOC_FL_PUNCH_HOLE | fs_abi::FALLOC_FL_KEEP_SIZE;
    dispatch(
        &table,
        SyscallNumber::Fallocate,
        [fd, punch, 0, PUNCHED, 0, 0],
    )
    .expect("punch a hole through the interface");

    // Read through a descriptor of its own, so the whole file is read from its
    // start.
    let reader = dispatch(
        &table,
        SyscallNumber::Open,
        [name.as_ptr() as usize, name.len(), 0, 0, 0, 0],
    )
    .expect("open the file for reading");
    // A page's worth at a time: a read into a buffer that crosses one is the
    // caller's to split, which is the interface's own shape and not this
    // test's.
    let mut buffer = vec![0xAAu8; SIZE];
    for chunk in buffer.chunks_mut(1024) {
        assert_eq!(
            dispatch(
                &table,
                SyscallNumber::Read,
                [reader, chunk.as_mut_ptr() as usize, chunk.len(), 0, 0, 0],
            )
            .expect("read the file back through the interface"),
            chunk.len(),
            "the file is as long as it was"
        );
    }
    assert!(
        buffer[..PUNCHED].iter().all(|byte| *byte == 0),
        "and the hole reads as zeros"
    );
    assert!(
        buffer[PUNCHED..].iter().all(|byte| *byte == b'A'),
        "with the rest of the file as it was"
    );

    // The volume's own clean state — a volume still marked dirty is one
    // `ntfs-3g` refuses to mount — and then the image, for the script.
    dispatch(&table, SyscallNumber::Fsync, [fd, 0, 0, 0, 0, 0]).expect("settle the volume");
    if let Ok(out) = std::env::var("PROTOFIRE_NTFS_PUNCHED") {
        let mut written = vec![0u8; (device.block_count() * 512) as usize];
        device
            .read_blocks(0, &mut written)
            .expect("the volume the driver wrote");
        std::fs::write(&out, &written).expect("leave it where the check can judge it");
    }
}
