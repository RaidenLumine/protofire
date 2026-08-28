//! tests/simplefs/undo_property.rs
//!
//! Property tests for SimpleFs transaction rollback (the undo log).
//!
//! The first test drives rollback through a guaranteed-failing operation:
//! each transaction closure performs a random batch of mutations and then
//! returns `Err`.  The transaction must roll back completely — root
//! directory listing, seed-file contents, and the in-transaction xattr must
//! all be unchanged — and data-integrity checks must still pass.
//!
//! The second test drives rollback through random device faults: a
//! `FaultingBlockDevice` drops or tears a random write during the metadata
//! flush, and reopening the raw device must yield a consistent filesystem
//! whose directory batch and xattr are all-or-nothing.
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
    // V4 so set_xattr actually persists (V2 has no xattr table and would
    // silently fail the set, masking the rollback under test).
    let image = support::build_v4_seed_image("undo-property", 256, 512, 64, 1024);
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
                // Propagate instead of `let _`-discarding: a mutation that
                // silently fails leaves nothing to roll back, weakening the
                // leak detection below.
                ctx.create_dir(name)?;
            }
            // Mutations before the failing op — must all be undone.
            ctx.set_xattr("/seed.txt", xattr_name.as_bytes(), &xattr_value)?;
            // Guaranteed failure: a directory cannot shadow an existing file.
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
        // The xattr set earlier in the transaction must have been rolled back
        // too — it is invisible to root-listing and seed-content fingerprints,
        // so read it back explicitly.
        let leaked_xattr = volume
            .get_xattr("/seed.txt", xattr_name.as_bytes())
            .expect("read xattr after rollback");
        assert!(
            leaked_xattr.is_none(),
            "iteration {iteration}: set_xattr leaked past rollback: {leaked_xattr:?}"
        );
    }

    // The volume must still be internally consistent after every rollback.
    let (checked, failed) = volume.check_data_integrity();
    assert_eq!(
        failed, 0,
        "{failed}/{checked} files have data checksum failures after rollbacks"
    );
}

/// Random device faults during a mutation transaction must leave the volume
/// recoverable.
///
/// A [`support::FaultingBlockDevice`] drops or tears a random device write
/// issued while the transaction commits.  Reopening the raw device must yield
/// a consistent filesystem whose directory batch and xattr are all-or-nothing:
/// either the whole transaction is visible (clean commit) or none of it is
/// (rollback) — never a torn partial mutation.
#[test]
fn random_device_faults_leave_the_volume_recoverable() {
    // V4 again: the per-iteration xattr must actually be settable.
    let image = support::build_v4_seed_image("undo-fault-prop", 256, 512, 64, 1024);

    let mut rng = Lcg::new(0xF0F0_6002);
    for iteration in 0..160usize {
        let device = MemoryBlockDevice::new("undo-fault-dev", image.clone(), false);
        // Random crash point: fail a device write issued by the transaction's
        // metadata flush, either by dropping it or by tearing part of the
        // block.  Range is sized so both outcomes occur: writes inside the
        // flush trip the fault (rollback), writes past the end never fire
        // (clean commit).
        let fault_write = 1 + rng.next_usize(16);
        let mode = match rng.next_usize(3) {
            0 => support::FaultMode::BeforeWrite,
            _ => support::FaultMode::TornWrite {
                prefix_len: 1 + rng.next_usize(512),
            },
        };
        let failing = support::FaultingBlockDevice::new(device.clone(), fault_write, mode);

        let dir_names: Vec<String> = (0..1 + rng.next_usize(4))
            .map(|i| format!("/fault_{iteration}_{i}"))
            .collect();
        let xattr_name = format!("fault_prop_{iteration}");

        // The fault can fire on any write of the metadata flush, so the
        // transaction either commits cleanly or fails with DeviceError.
        let fs = SimpleFs::open(failing, true).expect("open writable simplefs");
        let outcome: Result<(), protofire::Error> = fs.transaction(|ctx| {
            for name in &dir_names {
                ctx.create_dir(name)?;
            }
            ctx.set_xattr("/seed.txt", xattr_name.as_bytes(), &[iteration as u8])?;
            Ok(())
        });
        // Keep the first mount alive across the reopen: the second mount reads
        // the raw device, which reflects only what the (failed) flush actually
        // wrote before the superblock advanced — not the first mount's cache.
        // Dropping `fs` now would flush that cache into the on-disk view the
        // reopen reads and hide a torn state.

        // Reopen the raw device: the filesystem must recover to a consistent
        // state regardless of where the write was torn or dropped.
        let reopened = SimpleFs::open(device, true).unwrap_or_else(|err| {
            panic!(
                "reopen after device fault: fault_write={fault_write} mode={mode:?} \
                 outcome={outcome:?}: {err:?}"
            )
        });
        let volume = SimpleFsVolume::new(reopened);
        let (checked, failed) = volume.check_data_integrity();
        assert_eq!(
            failed, 0,
            "iteration {iteration}: {failed}/{checked} files fail checksums after \
             fault on write {fault_write}"
        );
        assert_eq!(
            seed_content(&volume),
            b"seed".to_vec(),
            "iteration {iteration}: seed content changed after a device fault"
        );

        // The directory batch is all-or-nothing.
        let roots = root_listing(&volume);
        let present: Vec<&String> = roots
            .iter()
            .filter(|name| name.starts_with(&format!("fault_{iteration}_")))
            .collect();
        let xattr_seen = volume
            .get_xattr("/seed.txt", xattr_name.as_bytes())
            .expect("read xattr after fault");
        match outcome {
            Ok(()) => {
                assert_eq!(
                    present.len(),
                    dir_names.len(),
                    "iteration {iteration}: committed transaction lost a directory \
                     (fault on write {fault_write})"
                );
                assert!(
                    xattr_seen.is_some(),
                    "iteration {iteration}: committed transaction lost its xattr \
                     (fault on write {fault_write})"
                );
            }
            Err(protofire::Error::DeviceError) => {
                // A device fault mid-commit leaves the on-disk state in either
                // of two consistent extremes: the pre-commit state (the fault
                // aborted the flush before any publish landed), or the fully
                // committed state (the fault hit the primary publish after the
                // secondary publish already landed, so the reopened volume
                // reads the newer mirror).  This mirrors the fault-matrix
                // contract: shadow/secondary faults preserve the last stable
                // state while a primary-superblock fault commits.  Anything
                // between — a partial directory batch, or directory and xattr
                // visibility diverging — is a torn commit and a bug.
                assert!(
                    present.is_empty() || present.len() == dir_names.len(),
                    "iteration {iteration}: torn commit leaked {} of {} \
                     directories (fault on write {fault_write})",
                    present.len(),
                    dir_names.len()
                );
                assert_eq!(
                    xattr_seen.is_some(),
                    present.len() == dir_names.len(),
                    "iteration {iteration}: xattr visibility diverged from \
                     directory visibility after a device fault (fault on \
                     write {fault_write})"
                );
            }
            Err(other) => {
                panic!("iteration {iteration}: unexpected transaction outcome {other:?}")
            }
        }
    }
}
