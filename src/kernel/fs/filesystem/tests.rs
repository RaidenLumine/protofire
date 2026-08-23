//! src/kernel/fs/filesystem/tests.rs
//! End-to-end FileSystem security-token regression tests: a guest token may
//! create, read, rename, and remove files inside its own data tree
//! (`/data/users/guest/...`) but must be denied mutations of the system tree
//! (`/system/runtime/...`).

use super::super::FileSystem;
use crate::kernel::process::{SecurityToken, HANDLE_RIGHT_READ};
use crate::Error;

/// The non-privileged guest token used by these tests.
fn guest_security_token() -> SecurityToken {
    SecurityToken::guest()
}

#[test]
fn guest_security_token_can_mutate_guest_data_but_not_system_tree() {
    let mut fs = FileSystem::new();
    fs.init();
    let guest = guest_security_token();

    fs.replace_file_contents_normalized_with_security_token(
        "/data/users/guest/downloads/guest-owned.txt",
        b"guest payload",
        guest,
    )
    .expect("guest should create data file");
    let mut file = fs
        .create_file_normalized_with_security_token(
            "/data/users/guest/downloads/guest-owned.txt",
            HANDLE_RIGHT_READ,
            0,
            super::super::OPEN_EXISTING,
            guest,
        )
        .expect("reopen guest data file");
    let mut buffer = [0_u8; 16];
    assert_eq!(
        fs.read(&mut file, &mut buffer).expect("read guest data"),
        b"guest payload".len()
    );
    assert_eq!(&buffer[..b"guest payload".len()], b"guest payload");

    assert_eq!(
        fs.create_dir_normalized_with_security_token("/system/runtime/guest-dir", guest),
        Err(Error::PermissionDenied)
    );
    assert!(matches!(
        fs.replace_file_contents_normalized_with_security_token(
            "/system/runtime/guest-owned.txt",
            b"guest payload",
            guest,
        ),
        Err(Error::PermissionDenied)
    ));
}

#[test]
fn guest_security_token_can_rename_and_remove_within_guest_data_tree() {
    let mut fs = FileSystem::new();
    fs.init();
    let guest = guest_security_token();

    // Create a source file inside the guest data tree.
    fs.replace_file_contents_normalized_with_security_token(
        "/data/users/guest/downloads/move-me.txt",
        b"renamable",
        guest,
    )
    .expect("guest should create source file");

    // Rename within the same mount and tree.
    fs.rename_normalized_paths_with_security_token(
        "/data/users/guest/downloads/move-me.txt",
        "/data/users/guest/downloads/renamed.txt",
        guest,
    )
    .expect("guest should rename within own data tree");

    // Old path must be gone, new path readable.
    let mut file = fs
        .create_file_normalized_with_security_token(
            "/data/users/guest/downloads/renamed.txt",
            HANDLE_RIGHT_READ,
            0,
            super::super::OPEN_EXISTING,
            guest,
        )
        .expect("reopen renamed file");
    let mut buffer = [0_u8; 16];
    let n = fs.read(&mut file, &mut buffer).expect("read renamed file");
    assert_eq!(&buffer[..n], b"renamable");

    // Renaming across into the system tree must still be rejected (while the
    // source file still exists).  The guest data tree and the system tree are
    // separate mounts, so a cross-filesystem move is unsupported at the mount
    // layer — the guest cannot escape its own zone.
    assert!(matches!(
        fs.rename_normalized_paths_with_security_token(
            "/data/users/guest/downloads/renamed.txt",
            "/system/runtime/renamed.txt",
            guest,
        ),
        Err(Error::Unsupported)
    ));

    // Remove within the guest data tree.
    fs.remove_normalized_path_with_security_token("/data/users/guest/downloads/renamed.txt", guest)
        .expect("guest should remove within own data tree");

    // The removed file is no longer openable.
    assert!(matches!(
        fs.create_file_normalized_with_security_token(
            "/data/users/guest/downloads/renamed.txt",
            HANDLE_RIGHT_READ,
            0,
            super::super::OPEN_EXISTING,
            guest,
        ),
        Err(Error::NotFound)
    ));
}
