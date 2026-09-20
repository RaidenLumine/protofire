//! tests/fs/sync_lock.rs
//!
//! Host-side integration tests for the lock discipline of the global
//! filesystem flushes.
//!
//! `sync_global_all`, `sync_global_data` and `sync_global_caches_aged` each
//! walk the mount table and flush every mounted filesystem.  Flushing reaches a
//! block device, so the walk must not hold the global filesystem lock: doing so
//! serialises every other filesystem operation in the kernel behind the
//! slowest disk, for as long as the disk takes.
//!
//! These tests prove the property rather than describing it.  Each one mounts
//! a filesystem whose flush checks that the global lock is free at the moment
//! it runs, so holding the lock across the flush fails the test instead of
//! quietly costing throughput.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use protofire::kernel::fs::vfs::DirectoryEntry;
use protofire::kernel::fs::vfs::FileSystem as VfsTrait;
use protofire::kernel::fs::vfs::NodeKind;
use protofire::kernel::fs::vfs::VNode;
use protofire::kernel::fs::FileSystem;
use protofire::kernel::sync::Mutex as KernelMutex;
use protofire::Error;
use protofire::Result;

/// Serialises these tests: the global filesystem is process-wide.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Records what a flush observed about the global filesystem lock.
#[derive(Default)]
struct FlushObservation {
    /// The global lock was free while the flush ran.
    lock_was_free: bool,
    /// How many times the filesystem was flushed.
    flushes: usize,
    /// Highest age threshold seen by `flush_aged`, if any.
    last_age_ticks: Option<u64>,
}

static OBSERVED: Mutex<Option<FlushObservation>> = Mutex::new(None);

/// A minimal filesystem whose only real behaviour is its flush path.
struct FlushProbe;

/// Content the probe file returns, and the record of what its read observed.
const PROBE_CONTENT: &[u8] = b"probe-payload";

static READ_SAW_LOCK_FREE: Mutex<Option<bool>> = Mutex::new(None);

/// The file the probe filesystem hands out.
///
/// Its `read` records whether the global filesystem lock was free, which is
/// the property under test: once a file is open, moving its bytes must not
/// need the namespace lock.
struct ProbeFile;

impl VNode for ProbeFile {
    fn name(&self) -> &str {
        "probe"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        PROBE_CONTENT.len()
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let lock_was_free = protofire::kernel::fs::global()
            .and_then(|fs| fs.try_lock())
            .is_some();
        {
            let mut observed = READ_SAW_LOCK_FREE.lock().unwrap_or_else(|e| e.into_inner());
            // Start from true so the first read can only clear it.
            *observed = Some(observed.unwrap_or(true) && lock_was_free);
        }

        let start = (offset as usize).min(PROBE_CONTENT.len());
        let end = (start + buffer.len()).min(PROBE_CONTENT.len());
        let count = end - start;
        buffer[..count].copy_from_slice(&PROBE_CONTENT[start..end]);
        Ok(count)
    }
}

impl FlushProbe {
    /// Record one flush, checking that the global lock is not held.
    fn observe(&self, age_ticks: Option<u64>) {
        // `try_lock` is the whole point: if the caller were holding the global
        // filesystem lock across this flush, the attempt would fail.
        let lock_was_free = protofire::kernel::fs::global()
            .and_then(|fs| fs.try_lock())
            .is_some();

        let mut observed = OBSERVED.lock().unwrap_or_else(|e| e.into_inner());
        let entry = observed.get_or_insert_with(FlushObservation::default);
        entry.lock_was_free &= lock_was_free;
        entry.flushes += 1;
        if age_ticks.is_some() {
            entry.last_age_ticks = age_ticks;
        }
    }
}

impl VfsTrait for FlushProbe {
    fn name(&self) -> &str {
        "flush-probe"
    }

    fn lookup(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Ok(Arc::new(ProbeFile))
    }

    fn read_dir(&self, _path: &str, _index: usize) -> Result<DirectoryEntry> {
        Err(Error::NotFound)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::Unsupported)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn sync(&self) -> Result<()> {
        self.observe(None);
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        self.observe(None);
        Ok(())
    }

    fn flush_aged(&self, age_ticks: u64) -> Result<usize> {
        self.observe(Some(age_ticks));
        // Report one written block so the caller's total is exercised too.
        Ok(1)
    }
}

/// A mounted `FlushProbe` plus the global filesystem it lives in.
struct ProbeTree {
    fs: &'static KernelMutex<FileSystem>,
}

impl ProbeTree {
    fn mount() -> Self {
        {
            let mut observed = OBSERVED.lock().unwrap_or_else(|e| e.into_inner());
            *observed = Some(FlushObservation {
                // Start true so the first flush can only clear it.
                lock_was_free: true,
                flushes: 0,
                last_age_ticks: None,
            });
        }
        {
            let mut saw_free = READ_SAW_LOCK_FREE.lock().unwrap_or_else(|e| e.into_inner());
            *saw_free = None;
        }

        // Leaked deliberately: the global keeps the pointer for the life of the
        // test binary, so freeing it would leave the slot dangling.
        let fs = Box::leak(Box::new(KernelMutex::new(FileSystem::new())));
        protofire::kernel::fs::install_global(fs);

        {
            let mut guard = fs.lock();
            guard.register("flush-probe", Arc::new(FlushProbe));
            guard
                .mount("/dev/flush-probe", "/probe", "flush-probe", 0)
                .expect("mount flush probe");
        }

        Self { fs }
    }

    fn observation(&self) -> FlushObservation {
        let observed = OBSERVED.lock().unwrap_or_else(|e| e.into_inner());
        let entry = observed.as_ref().expect("observation initialised");
        FlushObservation {
            lock_was_free: entry.lock_was_free,
            flushes: entry.flushes,
            last_age_ticks: entry.last_age_ticks,
        }
    }
}

impl Drop for ProbeTree {
    fn drop(&mut self) {
        protofire::kernel::fs::uninstall_global(self.fs);
    }
}

#[test]
fn moving_file_bytes_does_not_take_the_namespace_lock() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    // Opening resolves a path, which is a namespace operation and does take the
    // lock — that is expected and fine.
    let mut handle = {
        let fs = tree.fs.lock();
        fs.open("/probe", 0).expect("open probe file")
    };

    // Reading must not.  This is the property that keeps the data path
    // scalable: `FileHandle` holds the vnode, so moving bytes needs no
    // namespace coordination, and a slow device read cannot serialise every
    // other filesystem operation in the kernel.
    let mut buffer = [0_u8; PROBE_CONTENT.len()];
    let count = handle.read(&mut buffer).expect("read probe file");
    assert_eq!(count, PROBE_CONTENT.len());
    assert_eq!(&buffer[..count], PROBE_CONTENT);

    let saw_lock_free = *READ_SAW_LOCK_FREE.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        saw_lock_free,
        Some(true),
        "reading through an open handle must not hold the global namespace lock"
    );
}

#[test]
fn sync_all_flushes_without_holding_the_filesystem_lock() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    protofire::kernel::fs::sync_global_all().expect("sync all");

    let observed = tree.observation();
    assert_eq!(
        observed.flushes, 1,
        "the mounted filesystem should be flushed"
    );
    assert!(
        observed.lock_was_free,
        "the global filesystem lock must not be held while a flush reaches the device"
    );
}

#[test]
fn sync_data_flushes_without_holding_the_filesystem_lock() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    protofire::kernel::fs::sync_global_data().expect("sync data");

    let observed = tree.observation();
    assert_eq!(observed.flushes, 1);
    assert!(observed.lock_was_free);
}

#[test]
fn sync_caches_aged_flushes_without_holding_the_filesystem_lock() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    let written = protofire::kernel::fs::sync_global_caches_aged(600).expect("sync aged caches");

    let observed = tree.observation();
    assert_eq!(observed.flushes, 1);
    assert!(observed.lock_was_free);
    // The age threshold has to reach the filesystem, or the durability path
    // would write back everything instead of only what has aged.
    assert_eq!(observed.last_age_ticks, Some(600));
    assert_eq!(written, 1, "the per-mount block counts should be summed");
}

#[test]
fn every_mounted_filesystem_is_flushed() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    // A second mount of the same probe: both must be visited.
    {
        let mut guard = tree.fs.lock();
        guard
            .mount("/dev/flush-probe", "/probe-again", "flush-probe", 0)
            .expect("mount second flush probe");
    }

    protofire::kernel::fs::sync_global_all().expect("sync all");

    let observed = tree.observation();
    assert_eq!(observed.flushes, 2, "every mount should be flushed");
    assert!(observed.lock_was_free);
}

#[test]
fn a_flush_that_fails_still_releases_the_lock() {
    let _guard = test_lock();
    let tree = ProbeTree::mount();

    // Route the failure through the real path: unmounting between the snapshot
    // and the flush must not leave anything held, because the snapshot holds an
    // `Arc` rather than the lock.
    {
        let mut guard = tree.fs.lock();
        guard.unmount("/probe").expect("unmount probe");
    }

    // Nothing is mounted now, so this is a no-op rather than an error.
    protofire::kernel::fs::sync_global_all().expect("sync with nothing mounted");

    assert!(
        tree.fs.try_lock().is_some(),
        "the filesystem lock must be free after a flush"
    );
}
