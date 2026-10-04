//! src/fs/write_locations.rs
//!
//! Where a running machine writes, and why each place is the right one.
//!
//! `/system` and `/apps` are mounted read-only: a running kernel cannot change
//! the code it is running, and neither a system update nor an install writes a
//! *file* into a live zone.  That leaves two places a program writes at
//! runtime, and the difference between them is what a reboot means:
//!
//! | What | Where | Survives |
//! |------|-------|----------|
//! | Scratch — temporary files, a build's intermediate output | `/tmp` | nothing: the volume is built empty on every boot |
//! | Persistent — user data, credentials, caches, logs | `/data` | a reboot *and* a system update |
//!
//! A system update replaces a whole *system volume* — it writes the pair's
//! inactive slot (`crate::fs::system_image`) — so nothing under `/data` is
//! touched by one: the two are different zones, and the switch never names a
//! file inside either.  An install is the one operation that writes the app
//! zone; it is allowed to because installing *is* writing `/apps`, and it is
//! driven deliberately rather than happening behind a program's back.
//!
//! The paths themselves live where they are used — [`VOLATILE_ROOT`],
//! [`PERSISTENT_ROOT`], [`crate::fs::layout::DEFAULT_USER_ROOT`],
//! [`crate::kernel::audit::persist::AUDIT_LOG_PATH`] and the install path's
//! download cache.  This module is where the *policy* is written down, and
//! [`log_write_locations`] is what puts it in the boot log so a reader can see
//! it without reading the source.

/// Scratch space: built empty on every boot, and storage for nothing a later
/// boot needs to find.
pub const VOLATILE_ROOT: &str = crate::fs::TEMP_MOUNT_PATH;

/// Persistent runtime state: user data, credentials, caches and logs.
pub const PERSISTENT_ROOT: &str = crate::fs::layout::StorageZone::Data.zone_root();

/// The zone roots a running machine does not write.
pub const READ_ONLY_ROOTS: [&str; 2] = [
    crate::fs::layout::StorageZone::System.zone_root(),
    crate::fs::layout::StorageZone::Apps.zone_root(),
];

/// Say where a running machine writes, once, after the zone mounts are up.
///
/// Three facts a reader of a boot log should not have to infer: what survives a
/// reboot and what does not, and which two zones are closed to a running
/// machine — which is also what makes a system update unable to lose runtime
/// state, since it replaces a system volume and nothing else.
pub fn log_write_locations() {
    crate::println!(
        "[fs    ] runtime writes: {} (volatile), {} (persistent); {} and {} are read-only",
        VOLATILE_ROOT,
        PERSISTENT_ROOT,
        READ_ONLY_ROOTS[0],
        READ_ONLY_ROOTS[1]
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_roots_are_mounts_and_are_not_each_other() {
        // The policy is only true if both roots exist as the zones they claim
        // to be; the mounts are installed by `install_default_layout` and
        // `install_temp_layout`.
        assert_eq!(VOLATILE_ROOT, "/tmp");
        assert_eq!(PERSISTENT_ROOT, "/data");
        assert_ne!(VOLATILE_ROOT, PERSISTENT_ROOT);

        assert_eq!(READ_ONLY_ROOTS, ["/system", "/apps"]);
        for root in READ_ONLY_ROOTS {
            assert_ne!(root, VOLATILE_ROOT);
            assert_ne!(root, PERSISTENT_ROOT);
        }
    }

    #[test]
    fn every_root_is_a_zone_or_the_temp_mount() {
        // Each write location is the root of a mounted filesystem, not a
        // directory inside one: a reboot (the temp volume) or an update (the
        // system volume) has to be able to treat it as a unit.
        for root in [VOLATILE_ROOT, PERSISTENT_ROOT] {
            assert!(root.starts_with('/'), "{root}");
            assert_eq!(root.matches('/').count(), 1, "{root} is not a root");
        }
    }
}
