//! src/fs/filesystem/tests.rs
//!
//! End-to-end FileSystem security-token regression tests: a guest token may
//! create, read, rename, and remove files inside its own data tree
//! (`/data/users/guest/...`) but must be denied mutations of the system tree
//! (`/system/runtime/...`).

use super::super::FileSystem;
use crate::kernel::security::SecurityToken;
use crate::kernel::security::HANDLE_RIGHT_READ;
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
fn the_app_zone_is_writable_by_its_owner_and_not_by_a_guest() {
    // `/apps` is writable at the device and the mount, because an install has
    // to write it; what decides *who* may is the zone's security descriptor.
    // Both halves matter: without the first the install could never run, and
    // without the second any program could install one the machine would then
    // launch.
    let mut fs = FileSystem::new();
    fs.init();
    let guest = guest_security_token();
    let system = SecurityToken::system();

    fs.replace_file_contents_normalized_with_security_token(
        "/apps/installed-by-the-owner.txt",
        b"the zone's owner may write it",
        system,
    )
    .expect("the owner of the app zone may install");

    assert_eq!(
        fs.create_dir_normalized_with_security_token("/apps/guest-dir", guest),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        fs.replace_file_contents_normalized_with_security_token(
            "/apps/guest-owned.txt",
            b"payload",
            guest,
        ),
        Err(Error::PermissionDenied)
    );
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

#[test]
fn creating_a_directory_at_a_mount_point_reports_that_it_exists() {
    let mut fs = FileSystem::new();
    fs.init();

    // `/data` is a mount point, so the directory already exists and `mkdir` on
    // it is the ordinary EEXIST case.  It used to come back as
    // `InvalidArgument`: the path resolves to the mount point itself, and the
    // volume underneath rejects its own root as a name it cannot create.  Any
    // caller that creates a path one component at a time stopped there.
    assert_eq!(fs.create_dir("/data"), Err(Error::AlreadyExists));

    // The same holds for every other zone mount, and for the system token the
    // mkdir-p loop uses.
    assert_eq!(
        fs.create_dir_normalized_with_security_token("/tmp", SecurityToken::system()),
        Err(Error::AlreadyExists)
    );

    // Creating a directory *below* a mount point is unaffected.
    fs.create_dir("/data/etc/regression-accounts")
        .expect("create a directory below the data mount");
    assert!(fs
        .stat_normalized_path("/data/etc/regression-accounts")
        .is_ok());
}

/// A boot disk whose table names no zone of this kernel's is **left alone**:
/// the fixed offsets are not read over it, because its table gave those bytes
/// to whoever the table names ([RFC
/// 0027](../../../../docs/rfcs/0027-never-mount-a-fixed-offset-over-a-table.
/// md)).
///
/// The disk here is the shape that made the change: the demo image's bytes sit
/// at the fixed offsets *underneath* a verified GPT whose one entry belongs to
/// a stranger.  Before the change the boot printed `mounted fixed-zone SimpleFs
/// volumes` for exactly this disk — a vendor's partition read and writable as
/// `/apps` and `/data`.  The assertion is on the report the boot recorded,
/// which is the fact the log line is printed from.
#[test]
fn a_foreign_table_is_not_read_at_the_fixed_offsets() {
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::filesystem::types::StorageInitReport;
    use crate::fs::partition::write_gpt_partitions;
    use alloc::sync::Arc;

    // The demo image's own bytes: a valid MBR disk whose zones are where the
    // fixed offsets say.  On this disk the partition path answers too, so the
    // trap is built by replacing the table while keeping the bytes.
    let mut disk = crate::fs::build_demo_disk_image();

    // A stranger's table: one entry, a Linux filesystem GUID, in the middle of
    // the disk.  Written over the demo MBR by the kernel's own GPT writer, so
    // the bytes are a table this kernel verifies.
    let stranger_type = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];
    // The demo image is small (a few MiB), so the stranger takes a span
    // well inside it — the point is that the entry exists and is not a
    // zone, not how big it is.
    write_gpt_partitions(&mut disk, &[(0, stranger_type, 512, 1024)])
        .expect("write the stranger's table");

    let device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("foreign-gpt", disk, false);
    let mut fs = FileSystem::new();
    fs.init_with_boot_disk(Some(device));

    match fs.storage_init_report() {
        Some(StorageInitReport::BootDiskForeign) => {}
        other => panic!("expected the foreign-table report, saw {other:?}"),
    }

    // And nothing off that disk is mounted: `/apps` is the demo volumes' (the
    // build has them), not a slice of the stranger's partition.
    let apps = fs.mount_points().into_iter().find(|m| m.path == "/apps");
    assert!(
        apps.is_some(),
        "the demo volumes are the fallback and `/apps` comes from them"
    );
}

/// The other half of the same rule: a disk with **no partition information** is
/// still read at the fixed offsets, because they are the only description of
/// where its zones are.  Without this the change would have removed the route
/// instead of narrowing it.
#[test]
fn a_table_less_disk_still_reads_the_fixed_offsets() {
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::filesystem::types::StorageInitReport;
    use alloc::sync::Arc;

    // The demo image with its partition table erased: the zone volumes stay
    // where they are, and nothing on the disk declares them.
    let mut disk = crate::fs::build_demo_disk_image();
    disk[..512].fill(0);
    let device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("table-less", disk, false);
    let mut fs = FileSystem::new();
    fs.init_with_boot_disk(Some(device));

    match fs.storage_init_report() {
        Some(StorageInitReport::BootDiskFixedZoneFallback) => {}
        other => panic!("expected the fixed-zone fallback, saw {other:?}"),
    }
}

/// A zone that carries the LUKS2 magic is not handed to a filesystem parser.
///
/// The wiring this pins is the boot's: `crypt=` names a passphrase, the
/// filesystem asks each zone's device whether it is encrypted, and a device
/// that answers yes goes through `luks2_open` before any filesystem parser
/// sees it.  Without this the unwrap was code with a gate and no caller — the
/// shape `docs/status.md` calls "implemented, not verified".
///
/// What the boot does when the unwrap fails is refuse the boot-disk layout and
/// fall back to the in-memory demo volumes, which is what this asserts: the
/// report carries the error rather than `BootDiskFixedZoneFallback`, so the
/// ciphertext was never read as a volume.  That fallback is older than the
/// encryption and is why a failed unwrap does not stop a machine — it stops
/// the boot *disk*, and the machine runs the demo volumes.
#[test]
fn a_device_with_the_luks2_magic_is_not_read_as_a_filesystem() {
    use crate::fs::block::MemoryBlockDevice;
    use crate::fs::filesystem::types::StorageInitReport;
    use alloc::sync::Arc;

    // A plain device whose first bytes are the LUKS2 magic.  Nothing else has
    // to be a real header: the unwrap fails at the header parse, which is the
    // point — what this pins is that the code took the encrypted path rather
    // than handing the bytes to a filesystem parser.
    let mut disk = alloc::vec![0u8; 1024 * 1024];
    disk[..6].copy_from_slice(&crate::fs::luks2::LUKS2_MAGIC);

    let device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("luks-zone", disk, false);
    let mut fs = FileSystem::new();
    fs.set_crypt_passphrase("a passphrase");
    assert!(
        fs.has_crypt_passphrase(),
        "the setter must record what it was given"
    );
    fs.init_with_boot_disk(Some(device));

    match fs.storage_init_report() {
        Some(StorageInitReport::BootDiskFixedZoneFallback) => panic!(
            "a device with the LUKS2 magic fell through to the fixed-offset \
             layout, which reads ciphertext as a volume"
        ),
        Some(StorageInitReport::MemoryDemo { .. }) => {}
        other => panic!("expected the demo fallback after a failed unwrap, saw {other:?}"),
    }
}

/// With no passphrase, a zone is read exactly as it lies.
///
/// The other half of the same switch, and the one every existing boot is in:
/// an unencrypted disk mounts, and a boot that was never given `crypt=` does
/// not pay for a header probe's answer any differently.
#[test]
fn without_a_passphrase_every_zone_is_read_as_it_lies() {
    use crate::fs::block::MemoryBlockDevice;
    use alloc::sync::Arc;

    let device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("plain-zone", crate::fs::build_demo_disk_image(), false);
    let mut fs = FileSystem::new();
    assert!(!fs.has_crypt_passphrase());
    fs.init_with_boot_disk(Some(device));

    assert!(
        fs.filesystems.contains_key("simplefs-system"),
        "an unencrypted disk must still mount as the SimpleFs system zone"
    );
}

/// A local unit test of the header probe itself.
///
/// The two tests above assert on what a boot did, and neither can separate
/// "the probe said no" from "the probe said yes and the unwrap failed" — both
/// end in the same fallback.  This asks the probe directly, which is what
/// makes the detection itself testable rather than only its consequences.
#[test]
fn the_luks2_probe_answers_from_the_magic_and_nothing_else() {
    use crate::fs::block::MemoryBlockDevice;
    use alloc::sync::Arc;

    let mut plain = alloc::vec![0u8; 4096];
    plain[..8].copy_from_slice(b"PROTOFIR");
    let plain_device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("plain", plain, false);
    assert!(
        !super::layout::carries_luks2_header(plain_device.as_ref()),
        "a device that does not start with the magic is not encrypted"
    );

    let mut magic = alloc::vec![0u8; 4096];
    magic[..6].copy_from_slice(&crate::fs::luks2::LUKS2_MAGIC);
    let magic_device: Arc<dyn crate::fs::block::BlockDevice> =
        MemoryBlockDevice::new("magic", magic, false);
    assert!(
        super::layout::carries_luks2_header(magic_device.as_ref()),
        "a device whose first bytes are the magic is what the unwrap is for"
    );
}
