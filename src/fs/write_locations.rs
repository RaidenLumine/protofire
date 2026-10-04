//! src/fs/write_locations.rs
//!
//! Where a running machine writes, and why each place is the right one.
//!
//! `/system` is read-only: a running kernel cannot change the code it is
//! running, and a system update does not write a file into it — it replaces a
//! whole system volume by writing the pair's inactive slot
//! ([`crate::fs::system_image`]), which is a different device on purpose.
//!
//! `/apps` is writable, because installing *is* writing it.  Who may is the
//! zone's security descriptor rather than the mount: an install runs under its
//! caller's token, so a program installs exactly where it can write, and a
//! guest reading the same paths is refused by the zone's own rules.
//!
//! Beyond those two, the places a program writes at runtime are these, and the
//! difference between them is what a reboot means:
//!
//! | What | Where | Survives |
//! |------|-------|----------|
//! | Scratch — temporary files, a build's intermediate output | `/tmp` | nothing: the volume is built empty on every boot |
//! | Persistent — user data, credentials, caches, logs | `/data` | a reboot *and* a system update |
//!
//! Nothing under `/data` is touched by a system update: the two are different
//! zones, and the switch never names a file inside either.
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

/// The zone an install writes: the one place a running machine adds programs.
pub const INSTALL_ROOT: &str = crate::fs::layout::StorageZone::Apps.zone_root();

/// The zone root a running machine does not write.
pub const READ_ONLY_ROOT: &str = crate::fs::layout::StorageZone::System.zone_root();

/// Say where a running machine writes, once, after the zone mounts are up.
///
/// Three facts a reader of a boot log should not have to infer: what survives a
/// reboot and what does not, and which two zones are closed to a running
/// machine — which is also what makes a system update unable to lose runtime
/// state, since it replaces a system volume and nothing else.
pub fn log_write_locations() {
    crate::println!(
        "[fs    ] runtime writes: {} (volatile), {} (persistent), {} (installable); {} is read-only",
        VOLATILE_ROOT,
        PERSISTENT_ROOT,
        INSTALL_ROOT,
        READ_ONLY_ROOT
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_root_is_a_mount_of_its_own() {
        // The policy is only true if each root exists as the zone it claims to
        // be; the mounts are installed by `install_default_layout` and
        // `install_temp_layout`.
        assert_eq!(VOLATILE_ROOT, "/tmp");
        assert_eq!(PERSISTENT_ROOT, "/data");
        assert_eq!(INSTALL_ROOT, "/apps");
        assert_eq!(READ_ONLY_ROOT, "/system");

        for (index, root) in [VOLATILE_ROOT, PERSISTENT_ROOT, INSTALL_ROOT, READ_ONLY_ROOT]
            .into_iter()
            .enumerate()
        {
            assert!(root.starts_with('/'), "{root}");
            for other in [VOLATILE_ROOT, PERSISTENT_ROOT, INSTALL_ROOT, READ_ONLY_ROOT]
                .into_iter()
                .skip(index + 1)
            {
                assert_ne!(root, other, "{root} and {other} are the same mount");
            }
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
