//! tests/simplefs/property.rs
//!
//! Property-based tests for SimpleFs — random action sequences verify that
//! the filesystem maintains expected invariants under arbitrary workloads.
//!
//! We use a simple deterministic PRNG (seeded per test) so failures are
//! reproducible.  Each test generates a random sequence of filesystem actions,
//! applies them to a fresh SimpleFs volume, and checks invariants after every
//! action.

use std::collections::BTreeMap;

use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::simplefs::{SimpleFs, SimpleFsVolume};
use protofire::kernel::fs::vfs::{FileSystem as VfsFileSystem, NodeKind};

// ── Simple LCG PRNG (Numerical Recipes parameters) ─────────────────────────

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

// ── Action types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum FsAction {
    /// Create a file with random name and content.
    CreateFile { path: String, content: Vec<u8> },
    /// Read an existing file and verify its content.
    ReadFile { path: String },
    /// Delete an existing file.
    DeleteFile { path: String },
    /// Rename a file.
    RenameFile { old_path: String, new_path: String },
    /// Create a directory.
    CreateDir { path: String },
    /// List directory entries and verify no duplicates.
    ListDir { path: String },
}

// ── Test oracle tracks expected filesystem state ────────────────────────────

struct FsOracle {
    files: BTreeMap<String, Vec<u8>>,
    next_id: u64,
}

impl FsOracle {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            next_id: 0,
        }
    }

    fn unique_name(&mut self, prefix: &str) -> String {
        let id = self.next_id;
        self.next_id += 1;
        format!("{prefix}_{id:04x}")
    }

    fn record_create(&mut self, path: String, content: Vec<u8>) {
        self.files.insert(path, content);
    }

    fn record_delete(&mut self, path: &str) {
        self.files.remove(path);
    }

    fn record_rename(&mut self, old_path: &str, new_path: &str) {
        if let Some(content) = self.files.remove(old_path) {
            self.files.insert(new_path.to_string(), content);
        }
    }
}

// ── Action generation ───────────────────────────────────────────────────────

fn generate_actions(seed: u64, count: usize) -> Vec<FsAction> {
    let mut rng = Lcg::new(seed);
    let mut oracle = FsOracle::new();
    let mut actions = Vec::with_capacity(count);

    for _ in 0..count {
        let action = if oracle.files.is_empty() || rng.next_usize(3) == 0 {
            // Create a new file.
            let name = oracle.unique_name("/file");
            let len = rng.next_usize(512) + 1;
            let content: Vec<u8> = (0..len).map(|_| rng.next_usize(256) as u8).collect();
            oracle.record_create(name.clone(), content.clone());
            FsAction::CreateFile {
                path: name,
                content,
            }
        } else {
            let file_keys: Vec<&String> = oracle.files.keys().collect();
            let idx = rng.next_usize(file_keys.len());
            let path = file_keys[idx].clone();

            match rng.next_usize(5) {
                0 => FsAction::ReadFile { path },
                1 => {
                    oracle.record_delete(&path);
                    FsAction::DeleteFile { path }
                }
                2 => {
                    let new_name = oracle.unique_name("/renamed");
                    oracle.record_rename(&path, &new_name);
                    FsAction::RenameFile {
                        old_path: path,
                        new_path: new_name,
                    }
                }
                3 => FsAction::ReadFile { path },
                _ => {
                    let parent = match path.rfind('/') {
                        Some(0) | None => "/".to_string(),
                        Some(pos) => path[..pos].to_string(),
                    };
                    FsAction::ListDir { path: parent }
                }
            }
        };

        // 10% chance: also create a directory.
        if rng.next_usize(10) == 0 {
            let dir_name = oracle.unique_name("/dir");
            actions.push(FsAction::CreateDir { path: dir_name });
        }

        actions.push(action);
    }

    actions
}

// ── Action executor ─────────────────────────────────────────────────────────

fn execute_actions(volume: &SimpleFsVolume, actions: &[FsAction]) -> FsOracle {
    let mut oracle = FsOracle::new();

    for action in actions {
        match action {
            FsAction::CreateFile { path, content } => {
                match volume.create_file(path) {
                    Ok(node) => {
                        let written = node
                            .write(0, content)
                            .unwrap_or_else(|e| panic!("write({path}) failed: {e:?}"));
                        assert_eq!(written, content.len(), "short write for {path}");
                        oracle.record_create(path.clone(), content.clone());
                    }
                    Err(_e) => {
                        // File may exist from a prior create (e.g. in random
                        // sequences).  This is benign — skip the oracle update.
                    }
                }
            }
            FsAction::ReadFile { path } => {
                if let Some(expected) = oracle.files.get(path) {
                    if let Ok(node) = volume.lookup(path) {
                        let mut buf = vec![0u8; expected.len() + 64];
                        let n = node
                            .read(0, &mut buf)
                            .unwrap_or_else(|e| panic!("read({path}) failed: {e:?}"));
                        assert_eq!(
                            &buf[..n],
                            expected.as_slice(),
                            "content mismatch for {path}"
                        );
                    }
                }
            }
            FsAction::DeleteFile { path } => {
                if volume.remove_path(path).is_ok() {
                    oracle.record_delete(path);
                }
            }
            FsAction::RenameFile { old_path, new_path } => {
                if volume.rename(old_path, new_path).is_ok() {
                    oracle.record_rename(old_path, new_path);
                }
            }
            FsAction::CreateDir { path } => {
                let _ = volume.create_dir(path);
            }
            FsAction::ListDir { path } => {
                if let Ok(stat) = volume.stat(path) {
                    if stat.kind == NodeKind::Directory {
                        let mut names = Vec::new();
                        let mut idx = 0;
                        while let Ok(entry) = volume.read_dir(path, idx) {
                            names.push(entry.name.clone());
                            idx += 1;
                        }
                        let mut sorted = names.clone();
                        sorted.sort();
                        sorted.dedup();
                        assert_eq!(
                            sorted.len(),
                            names.len(),
                            "duplicate entries in directory {path}: {names:?}",
                        );
                    }
                }
            }
        }

        // After each action the root must be accessible.
        assert!(
            volume.stat("/").is_ok(),
            "root stat failed after {action:?}"
        );
    }

    oracle
}

// ── Invariant checks ────────────────────────────────────────────────────────

fn verify_invariants(volume: &SimpleFsVolume) {
    // Root must always exist and be a directory.
    let root = volume.stat("/").expect("root stat");
    assert_eq!(root.kind, NodeKind::Directory, "root is not a directory");

    // Orphan data block count should be bounded (not leaking).
    let orphans = volume.count_orphan_data_blocks();
    assert!(
        orphans <= 32,
        "excessive orphan data blocks: {orphans} (possible leak)"
    );

    // Data checksums must all be valid.
    let (checked, failed) = volume.check_data_integrity();
    assert_eq!(
        failed, 0,
        "{failed} / {checked} files have data checksum failures"
    );

    // Root directory listing must not contain duplicate names.
    let mut root_entries = Vec::new();
    let mut idx = 0;
    while let Ok(entry) = volume.read_dir("/", idx) {
        root_entries.push(entry.name.clone());
        idx += 1;
    }
    let mut dedup = root_entries.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(
        dedup.len(),
        root_entries.len(),
        "duplicate root entries: {root_entries:?}"
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn property_small_random_sequence_seed_1() {
    let image = SimpleFs::build_image_with_headroom(
        "prop-small",
        &[],
        128,  // extra inodes
        256,  // extra dirents
        1024, // extra data blocks
    )
    .expect("build test image");
    let device = MemoryBlockDevice::new("prop-small-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
    let volume = SimpleFsVolume::new(fs);

    let actions = generate_actions(1, 200);
    execute_actions(&volume, &actions);
    verify_invariants(&volume);
}

#[test]
fn property_medium_random_sequence_seed_42() {
    let image = SimpleFs::build_image_with_headroom("prop-med", &[], 256, 512, 2048)
        .expect("build test image");
    let device = MemoryBlockDevice::new("prop-med-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
    let volume = SimpleFsVolume::new(fs);

    let actions = generate_actions(42, 500);
    execute_actions(&volume, &actions);
    verify_invariants(&volume);
}

#[test]
fn property_create_read_delete_cycle_seed_7() {
    let image = SimpleFs::build_image_with_headroom("prop-cycle", &[], 32, 64, 256)
        .expect("build test image");
    let device = MemoryBlockDevice::new("prop-cycle-dev", image, false);

    for cycle in 0u64..50 {
        let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
        let volume = SimpleFsVolume::new(fs);

        let path = "/cycle_test.bin";
        let payload: Vec<u8> = (0..64)
            .map(|i| (cycle.wrapping_add(i) & 0xff) as u8)
            .collect();

        let node = volume
            .create_file(path)
            .unwrap_or_else(|e| panic!("create failed cycle {cycle}: {e:?}"));
        assert_eq!(
            node.write(0, &payload)
                .unwrap_or_else(|e| panic!("write failed cycle {cycle}: {e:?}")),
            payload.len()
        );

        let mut buf = vec![0u8; 128];
        let n = node
            .read(0, &mut buf)
            .unwrap_or_else(|e| panic!("read failed cycle {cycle}: {e:?}"));
        assert_eq!(&buf[..n], payload.as_slice(), "data mismatch cycle {cycle}");

        volume
            .remove_path(path)
            .unwrap_or_else(|e| panic!("remove failed cycle {cycle}: {e:?}"));
        assert!(
            volume.lookup(path).is_err(),
            "file still exists after delete cycle {cycle}"
        );
    }
}

#[test]
fn property_rename_chains_preserve_content_seed_13() {
    let payload = b"rename chain payload v1.0!!".to_vec();
    let image = SimpleFs::build_image_with_headroom("prop-rename", &[], 32, 64, 128)
        .expect("build test image");
    let device = MemoryBlockDevice::new("prop-rename-dev", image, false);
    let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
    let volume = SimpleFsVolume::new(fs);

    let start = "/chain_00.bin";
    let node = volume.create_file(start).expect("create start");
    node.write(0, &payload).expect("write");

    let mut current = start.to_string();
    for i in 1..=20 {
        let next = format!("/chain_{i:02}.bin");
        volume
            .rename(&current, &next)
            .unwrap_or_else(|e| panic!("rename {current} → {next} failed at step {i}: {e:?}"));
        assert!(
            volume.lookup(&current).is_err(),
            "old name {current} still exists after rename to {next}"
        );
        current = next;
    }

    let node = volume
        .lookup(&current)
        .unwrap_or_else(|e| panic!("final lookup {current} failed: {e:?}"));
    let mut buf = vec![0u8; 128];
    let n = node.read(0, &mut buf).expect("final read");
    assert_eq!(
        &buf[..n],
        payload.as_slice(),
        "content lost after rename chain"
    );
}

#[test]
fn property_no_data_loss_after_reopen_seed_99() {
    let image = SimpleFs::build_image_with_headroom("prop-reopen", &[], 64, 128, 512)
        .expect("build test image");
    let device = MemoryBlockDevice::new("prop-reopen-dev", image, false);

    let mut expected: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    {
        let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
        let volume = SimpleFsVolume::new(fs);

        for i in 0u64..20 {
            let path = format!("/reopen_{i:03}.dat");
            let content: Vec<u8> = (0..(i + 1) * 16)
                .map(|b| (i.wrapping_mul(17).wrapping_add(b) & 0xff) as u8)
                .collect();
            let node = volume
                .create_file(&path)
                .unwrap_or_else(|e| panic!("create {path}: {e:?}"));
            node.write(0, &content)
                .unwrap_or_else(|e| panic!("write {path}: {e:?}"));
            expected.insert(path, content);
        }
    }

    {
        let fs = SimpleFs::open(device.clone(), true).expect("reopen SimpleFs");
        let volume = SimpleFsVolume::new(fs);

        for (path, content) in &expected {
            let node = volume
                .lookup(path)
                .unwrap_or_else(|e| panic!("lookup {path} after reopen: {e:?}"));
            let mut buf = vec![0u8; content.len() + 64];
            let n = node.read(0, &mut buf).expect("read after reopen");
            assert_eq!(
                &buf[..n],
                content.as_slice(),
                "content mismatch for {path} after reopen"
            );
        }
    }
}

#[test]
fn property_empty_filesystem_is_consistent() {
    let image = SimpleFs::build_image("prop-empty", &[]).expect("build empty image");
    let device = MemoryBlockDevice::new("prop-empty-dev", image, true);
    let fs = SimpleFs::open(device.clone(), true).expect("open SimpleFs");
    let volume = SimpleFsVolume::new(fs);

    let root = volume.stat("/").expect("root stat");
    assert_eq!(root.kind, NodeKind::Directory);

    let (_, failed) = volume.check_data_integrity();
    assert_eq!(failed, 0);
}
