//! src/fs/demo/absent.rs
//!
//! The demo volume on a target with no demo payloads: every zone still has to
//! be buildable, because the disk layout is what the boot path reads — so the
//! apps zone gets a placeholder saying why it is empty, and the system zone
//! gets the shared files alone.

use super::*;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
pub(super) fn apps_zone_image(zone: StorageZone) -> Result<Vec<u8>> {
    const PLACEHOLDER_APPS_FILES: &[ImageEntry<'static>] = &[ImageEntry {
        path: "/README.txt",
        data: b"User demo payloads are currently unavailable on this target.\n",
    }];

    SimpleFs::build_image(zone.volume_label(), PLACEHOLDER_APPS_FILES)
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
pub(super) fn system_zone_image() -> Result<Vec<u8>> {
    SimpleFs::build_image(StorageZone::System.volume_label(), SYSTEM_FILES)
}
