//! src/fs/filesystem/layout.rs
//!
//! filesystem/layout — FileSystem zone, layout, and device installation
//! methods.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::device;
use crate::Result;

use super::super::block::BlockDevice;
use super::super::block::BlockSliceDevice;
use super::super::block::MemoryBlockDevice;
use super::super::block::BLOCK_SIZE;
use super::super::devfs;
use super::super::layout::StorageZone;
use super::super::layout::DEFAULT_ZONES;
use super::super::layout::{self};
use super::super::partition::read_partitions;
use super::super::pyrofs::PyroFs;
use super::super::pyrofs::PyroFsVolume;
use super::super::vfs::NodeKind;
use super::super::vfs::StaticFileSystem;
use super::super::FileSystem;
use super::types::BootDiskLayoutSource;
use super::types::ZoneDeviceBindings;

use super::super::DEVFS_FS_NAME;
use super::super::DEVFS_MOUNT_DEVICE;
use super::super::DEVFS_MOUNT_PATH;
use super::super::TEMP_FS_NAME;
use super::super::TEMP_MOUNT_DEVICE;
use super::super::TEMP_MOUNT_PATH;
use super::super::VIRTUAL_DEVICE_FS_NAME;
use super::super::VIRTUAL_DEVICE_MOUNT_DEVICE;
use super::super::VIRTUAL_DEVICE_MOUNT_PATH;

impl FileSystem {
    pub(crate) fn install_default_layout(&mut self) {
        for zone in DEFAULT_ZONES {
            self.mount_zone(zone);
        }

        // Mount a memory-backed writable /tmp volume so user-space programs,
        // shell pipelines, and temporary file operations have a well-known
        // scratch directory that is automatically cleaned on reboot.
        let _ = self.install_temp_layout();

        self.install_virtual_device_layout();
        self.install_devfs_layout();
    }

    pub(crate) fn mount_zone(&mut self, zone: StorageZone) {
        let _ = self.mount(
            zone.device(),
            zone.zone_root(),
            zone.fs_name(),
            zone.flags(),
        );
    }

    pub(crate) fn install_virtual_device_layout(&mut self) {
        let mut devices =
            StaticFileSystem::with_entries("virtual devices", &[("/", NodeKind::Directory, &[])]);
        for node in device::virtual_device_nodes() {
            if node.visible_in_directory() {
                devices.insert(node.mount_path, NodeKind::Device, &[]);
            }
        }

        self.register(VIRTUAL_DEVICE_FS_NAME, Arc::new(devices));
        let _ = self.mount(
            VIRTUAL_DEVICE_MOUNT_DEVICE,
            VIRTUAL_DEVICE_MOUNT_PATH,
            VIRTUAL_DEVICE_FS_NAME,
            layout::MOUNT_READ_ONLY,
        );
    }

    /// Register and mount devfs at `/dev`.
    ///
    /// Registered and mounted on `self` rather than through
    /// `crate::fs::global()`: this runs while the filesystem is being
    /// initialised, before anything has installed it as the global, and a
    /// helper that looks the global up fails silently here.  That is exactly
    /// what happened — `/dev`, `/service` and `/proc` were all missing from a
    /// boot that reported no error, because every one of those mounts went
    /// through a global that did not exist yet.
    pub(crate) fn install_devfs_layout(&mut self) {
        self.register(DEVFS_FS_NAME, Arc::new(devfs::DevFs));
        let _ = self.mount(DEVFS_MOUNT_DEVICE, DEVFS_MOUNT_PATH, DEVFS_FS_NAME, 0);
    }

    /// Mount a memory-backed writable PyroFs volume at `/tmp`.
    ///
    /// The volume is built from an empty image so every boot starts with a
    /// clean scratch space.  Runtime writes stay in the [`MemoryBlockDevice`]
    /// and are discarded on reboot — no persistent storage is involved.
    pub(crate) fn install_temp_layout(&mut self) -> Result<()> {
        // Build a fresh empty image.  Fall back to a minimal zero-filled
        // block if the image builder itself fails (should not happen with
        // an empty entry list, but degrade gracefully).
        let temp_image = PyroFs::build_image("pyrofs:temp", &[])
            .unwrap_or_else(|_| vec![0_u8; layout::DEMO_DISK_TEMP_BLOCKS as usize * BLOCK_SIZE]);

        let temp_device = crate::kernel::block::counting_device(MemoryBlockDevice::new(
            "xiu-temp0",
            temp_image,
            /* read_only */ false,
        ));
        let temp_fs = PyroFs::open(temp_device.clone(), /* case_sensitive */ true)?;

        self.register_block_device(TEMP_MOUNT_DEVICE, temp_device);
        self.register(TEMP_FS_NAME, Arc::new(PyroFsVolume::new(temp_fs)));
        let _ = self.mount(
            TEMP_MOUNT_DEVICE,
            TEMP_MOUNT_PATH,
            TEMP_FS_NAME,
            layout::MOUNT_USER_DATA,
        );

        Ok(())
    }

    #[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
    pub(crate) fn install_demo_memory_layout(&mut self) -> Result<()> {
        // The demo disk is a real MBR-partitioned image, so the in-memory demo
        // mounts it the way a boot disk is mounted: the same partition walk and
        // the same system-slot selection.  Two layouts would be two things to
        // keep in step — and the A/B pair would be exercised by neither.
        let disk: Arc<dyn BlockDevice> =
            crate::kernel::block::counting_device(crate::fs::block::MemoryBlockDevice::new(
                "xiu-demo0",
                crate::fs::demo::build_demo_disk_image(),
                false,
            ));

        match self.boot_disk_zone_devices_from_partitions(disk)? {
            Some((devices, _)) => self.install_zone_devices(devices),
            None => Err(crate::Error::InvalidArgument),
        }
    }

    pub(crate) fn install_boot_disk_layout(
        &mut self,
        boot_disk: Arc<dyn BlockDevice>,
    ) -> Result<BootDiskLayoutSource> {
        // One wrap per device, at the point it enters the filesystem: every
        // read after this — the partition walk, the system-slot scan, and the
        // filesystem's own reads through its slice of the disk — passes
        // through it, and each of them is counted once because a slice hands
        // its parent's wrapped device down.  See
        // `crate::kernel::block::counting_device`.
        let boot_disk = crate::kernel::block::counting_device(boot_disk);
        // The partition path first: a table that names this kernel's zones is
        // the disk's own answer about where they are.
        if let Some((zone_devices, gpt)) =
            self.boot_disk_zone_devices_from_partitions(boot_disk.clone())?
        {
            self.install_zone_devices(zone_devices)?;
            return Ok(BootDiskLayoutSource::Partitions { gpt });
        }

        // The partition path did not answer, and *why* decides what runs next.
        // A disk that carries partition information — entries, a GPT header at
        // either end, verified or damaged — is a disk something partitioned,
        // and its table gave those bytes to someone: reading the fixed offsets
        // over it would mount a stranger's partition as this kernel's own.
        // Only a disk that answers "nothing here" is the shape the fixed
        // offsets describe ([RFC
        // 0027](../../../docs/rfcs/0027-never-mount-a-fixed-offset-over-a-table.md)).
        if crate::fs::partition::carries_partition_information(boot_disk.as_ref())? {
            crate::println!(
                "[fs    ] the boot disk carries a partition table that names no zone of this kernel's; left alone"
            );
            return Ok(BootDiskLayoutSource::Foreign);
        }

        let zone_devices = self.boot_disk_zone_devices_from_fixed_layout(boot_disk);
        self.install_zone_devices(zone_devices)?;
        Ok(BootDiskLayoutSource::FixedZoneFallback)
    }

    pub(crate) fn boot_disk_zone_devices_from_partitions(
        &self,
        boot_disk: Arc<dyn BlockDevice>,
    ) -> Result<Option<(ZoneDeviceBindings, bool)>> {
        let Some(table) = read_partitions(boot_disk.as_ref())? else {
            return Ok(None);
        };
        let gpt = matches!(table, crate::fs::partition::PartitionTable::Gpt(_));

        // The system zone is a *pair* when the disk carries two system volumes:
        // the boot takes the newest committed one, and falls back to the other
        // when that one is torn or was withdrawn.  A disk with one system
        // volume — every disk before the pair existed — is booted from it.
        let slots = crate::fs::system_image::system_slots(&boot_disk, true)?;
        let Some(system) = crate::fs::system_image::select_system_slot(&slots) else {
            return Ok(None);
        };

        // Require every expected zone partition to exist; a partial partition
        // table is refused as a whole instead of mixing layouts.
        let mut zone_devices = Vec::with_capacity(DEFAULT_ZONES.len());

        for zone in DEFAULT_ZONES {
            if zone == StorageZone::System {
                zone_devices.push((zone, system.device.clone()));
                continue;
            }

            let Some((_, partition)) = table.zone_partitions(zone).into_iter().next() else {
                return Ok(None);
            };

            zone_devices.push((
                zone,
                BlockSliceDevice::new(
                    zone.boot_disk_device_name(),
                    boot_disk.clone(),
                    partition.start_block,
                    partition.block_count,
                    zone.device_read_only(),
                ) as Arc<dyn BlockDevice>,
            ));
        }

        // Said only once the whole table has answered: a line about an active
        // slot is a claim that the boot has a system volume, and a table with
        // a system entry but no apps or data is refused below and above —
        // printing it before the loop was a boot that named a slot it then
        // did not use.
        crate::println!(
            "[fs    ] system: slot {} active{}",
            system.name,
            system
                .build
                .map_or_else(alloc::string::String::new, |build| alloc::format!(
                    " (build {})",
                    build.generation
                ))
        );

        Ok(Some((zone_devices, gpt)))
    }

    pub(crate) fn boot_disk_zone_devices_from_fixed_layout(
        &self,
        boot_disk: Arc<dyn BlockDevice>,
    ) -> Vec<(StorageZone, Arc<dyn BlockDevice>)> {
        DEFAULT_ZONES
            .iter()
            .copied()
            .map(|zone| {
                let (start_block, block_count) = zone.disk_range();
                (
                    zone,
                    BlockSliceDevice::new(
                        zone.boot_disk_device_name(),
                        boot_disk.clone(),
                        start_block,
                        block_count,
                        zone.device_read_only(),
                    ) as Arc<dyn BlockDevice>,
                )
            })
            .collect()
    }

    pub(crate) fn install_zone_devices(
        &mut self,
        zone_devices: Vec<(StorageZone, Arc<dyn BlockDevice>)>,
    ) -> Result<()> {
        let zone_devices = self.unlock_encrypted_zones(zone_devices)?;
        let use_ext4 = self.rootfs_type == "ext4";

        if use_ext4 {
            // ext4 path: open as Ext4FsVolume for each zone.
            for (zone, device) in &zone_devices {
                let vol = crate::fs::ext4::Ext4FsVolume::open(device.clone())?;
                self.register_block_device(zone.device(), device.clone());
                self.register(zone.fs_name(), Arc::new(vol));
            }
        } else {
            // PyroFs path (default).
            let mut filesystems = Vec::with_capacity(zone_devices.len());
            for (zone, device) in &zone_devices {
                let fs = PyroFs::open(device.clone(), zone.case_sensitive())?;
                filesystems.push((*zone, device.clone(), fs));
            }
            for (zone, device, fs) in filesystems {
                self.register_block_device(zone.device(), device);
                self.register(zone.fs_name(), Arc::new(PyroFsVolume::new(fs)));
            }
        }

        Ok(())
    }

    /// Replace each zone's device with one that decrypts it, when there is a
    /// passphrase and the zone carries a LUKS2 header.
    ///
    /// Two conditions, and both are answers a boot can give rather than a
    /// policy this function invents:
    ///
    /// * **No passphrase** — every zone stays as it lies on the medium.  That
    ///   is what every boot before this did, and an unencrypted disk needs
    ///   nothing else.
    /// * **A passphrase, and this zone is not encrypted** — the zone is left
    ///   alone rather than refused.  A disk with only `/data` encrypted is a
    ///   shape worth supporting, and a boot that stopped because one zone had
    ///   no header would be refusing the wrong thing.
    ///
    /// The check for "is this encrypted" is the header magic, read once from
    /// the zone's first sector.  A zone that has the magic but does not open
    /// with the passphrase given is a real failure and refuses the *boot-disk
    /// layout*: the alternative is to mount ciphertext as a filesystem and
    /// report whatever the parser makes of it, which is how a wrong passphrase
    /// becomes a corrupt-volume report three subsystems later.  The machine
    /// then falls back to the in-memory demo volumes, which is what every
    /// failed boot disk already did — see `init_with_boot_disk`.
    fn unlock_encrypted_zones(
        &self,
        zone_devices: Vec<(StorageZone, Arc<dyn BlockDevice>)>,
    ) -> Result<Vec<(StorageZone, Arc<dyn BlockDevice>)>> {
        let Some(passphrase) = self.crypt_passphrase.as_deref() else {
            return Ok(zone_devices);
        };

        let mut unlocked = Vec::with_capacity(zone_devices.len());
        for (zone, device) in zone_devices {
            if !carries_luks2_header(device.as_ref()) {
                unlocked.push((zone, device));
                continue;
            }
            // A zone with the header but no key is a boot disk that cannot be
            // used, and this refuses it rather than mounting ciphertext:
            // handing a PyroFs parser an AES-XTS stream produces a
            // corrupt-volume error three subsystems later, which names the
            // wrong problem.
            let encrypted = crate::fs::luks2::luks2_open(device.clone(), passphrase.as_bytes())?;
            crate::println!(
                "[fs    ] zone {} is LUKS2 and opened with the boot's passphrase",
                zone.zone_root()
            );
            unlocked.push((zone, Arc::new(encrypted) as Arc<dyn BlockDevice>));
        }
        Ok(unlocked)
    }
}

/// Whether `device`'s first sector carries the LUKS2 magic.
///
/// The one question that separates "this zone is encrypted" from "this zone is
/// not", asked of the medium rather than of a configuration file: a disk is
/// what it says it is, and a boot that trusted a label instead would try to
/// merge stripes out of a PyroFs superblock.  A read error answers "no" —
/// the caller then reads the zone as it lies and the filesystem's own parser
/// reports whatever is actually wrong with it, which is a better error than
/// this one could give.
pub(crate) fn carries_luks2_header(device: &dyn BlockDevice) -> bool {
    let mut sector = [0u8; crate::fs::block::BLOCK_SIZE];
    if device.read_blocks(0, &mut sector).is_err() {
        return false;
    }
    sector[..6] == crate::fs::luks2::LUKS2_MAGIC
}

/// Whether any zone on `disk` carries a LUKS2 header.
///
/// Asked before the mount so a boot knows whether to ask for a passphrase at
/// all, and answered from the same bytes the mount will read: the partition
/// table's zone extents, each probed at its first sector.  A disk with no
/// partition table is probed at the fixed offsets, because that is where its
/// zones are.
///
/// A read error answers "no" for that zone and the search continues, which is
/// the same answer the mount gives: the zone is then read as it lies and the
/// filesystem's own parser reports what is wrong with it.
pub fn disk_carries_encrypted_zone(disk: &dyn BlockDevice) -> bool {
    let Ok(Some(table)) = read_partitions(disk) else {
        // No table: the fixed offsets are the disk's zones.
        return DEFAULT_ZONES
            .iter()
            .any(|zone| zone_carries_luks2(disk, zone.disk_range()));
    };

    DEFAULT_ZONES.iter().any(|zone| {
        let mut found = false;
        for (_, partition) in table.zone_partitions(*zone) {
            if zone_carries_luks2(disk, (partition.start_block, partition.block_count)) {
                found = true;
            }
        }
        found
    })
}

/// Whether the extent at `(start_block, _)` starts with the LUKS2 magic.
fn zone_carries_luks2(disk: &dyn BlockDevice, (start_block, _): (u64, u64)) -> bool {
    let mut sector = [0u8; crate::fs::block::BLOCK_SIZE];
    if disk.read_blocks(start_block, &mut sector).is_err() {
        return false;
    }
    sector[..6] == crate::fs::luks2::LUKS2_MAGIC
}
