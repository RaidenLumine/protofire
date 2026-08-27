//! tests/simplefs/undo_property.rs
//!
//! Property test for SimpleFs transaction rollback (the undo log).
//!
//! Every transaction closure performs a random batch of mutations and then
//! returns `Err` via a guaranteed-failing operation.  The transaction must
//! roll back completely: the filesystem's logical state — root directory
//! listing and seed-file contents — must be byte-identical before and after
//! each failed transaction, and data-integrity checks must still pass.
//!
//! Names are unique per iteration, so any mutation that leaks past a rollback
//! would appear in the root listing and fail the assertion immediately.

mod support;

use std::sync::Arc;

use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::simplefs::SimpleFs;
use protofire::kernel::fs::simplefs::SimpleFsVolume;
use protofire::kernel::fs::vfs::FileSystem as VfsFileSystem;
use protofire::Error;

// ── Deterministic PRNG ─────────────────────────────────────────────────────

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6_364_136_223_846_793_005);
        self.state = self.state.wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next() as usize) % bound
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn open_volume(device: Arc<MemoryBlockDevice>) -> (Arc<SimpleFs>, SimpleFsVolume) {
    let fs = SimpleFs::open(device, true).expect("open writable simplefs");
    let volume = SimpleFsVolume::new(fs.clone());
    (fs, volume)
}

/// Sorted names in the root directory — the primary logical-state fingerprint.
fn root_listing(volume: &SimpleFsVolume) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0;
    while let Ok(entry) = volume.read_dir("/", index) {
        names.push(entry.name.clone());
        index += 1;
    }
    names.sort();
    names
}

fn seed_content(volume: &SimpleFsVolume) -> Vec<u8> {
    let node = volume.lookup("/seed.txt").expect("seed file present");
    support::read_all(&*node)
}

// ── Test ───────────────────────────────────────────────────────────────────

#[test]
fn failed_transactions_leave_no_trace() {
    let image = support::build_seed_image("undo-property", 256, 512, 1024);
    let device = MemoryBlockDevice::new("undo-prop-dev", image, false);
    let (fs, volume) = open_volume(device);

    let baseline_roots = root_listing(&volume);
    let baseline_seed = seed_content(&volume);
    assert!(
        baseline_roots.contains(&"seed.txt".to_string()),
        "seed file must be present in the baseline"
    );

    let mut rng = Lcg::new(0xF0F0_6001);
    for iteration in 0..200usize {
        // Build a transaction that performs a random batch of mutations and
        // then hits a guaranteed failure.  Directory names are unique per
        // iteration so a leaked create_dir is immediately visible.
        let dir_names: Vec<String> = (0..1 + rng.next_usize(4))
            .map(|i| format!("/tx_{iteration}_{i}"))
            .collect();
        let xattr_name = format!("prop_{iteration}");
        let xattr_value = [iteration as u8];

        let result: Result<(), protofire::Error> = fs.transaction(|ctx| {
            for name in &dir_names {
                let _ = ctx.create_dir(name);
            }
            // Mutations before the failing op — must all be undone.
            let _ = ctx.set_xattr("/seed.txt", xattr_name.as_bytes(), &xattr_value);
            // Guaranteed failure: a directory cannot shadow an existing file.
            let _ = ctx.create_dir("/seed.txt");
            Err(Error::AlreadyExists)
        });
        assert!(
            result.is_err(),
            "iteration {iteration}: failing transaction unexpectedly committed"
        );

        assert_eq!(
            root_listing(&volume),
            baseline_roots,
            "iteration {iteration}: a failed transaction leaked a root entry"
        );
        assert_eq!(
            seed_content(&volume),
            baseline_seed,
            "iteration {iteration}: seed-file content changed after a failed \
             transaction"
        );
    }

    // The volume must still be internally consistent after every rollback.
    let (checked, failed) = volume.check_data_integrity();
    assert_eq!(
        failed, 0,
        "{failed}/{checked} files have data checksum failures after rollbacks"
    );
}
