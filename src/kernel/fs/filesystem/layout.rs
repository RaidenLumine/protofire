//! src/kernel/fs/filesystem/layout.rs
//!
//! filesystem/layout — FileSystem zone, layout, and device installation methods.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::device;
use crate::kernel::kernel_log::KernelLogFileSystem;
use crate::Result;

use super::super::block::{BlockDevice, BlockSliceDevice, MemoryBlockDevice, BLOCK_SIZE};
use super::super::layout::{self, StorageZone, DEFAULT_ZONES};
use super::super::partition::read_mbr_partitions;
use super::super::simplefs::{SimpleFs, SimpleFsVolume};
use super::super::vfs::{NodeKind, StaticFileSystem};
use super::super::FileSystem;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
use super::path_helpers::build_demo_memory_device;
use super::types::{BootDiskLayoutSource, ZoneDeviceBindings};

use super::super::{
    DEVFS_MOUNT_PATH, KERNEL_LOGS_FS_NAME, KERNEL_LOGS_MOUNT_DEVICE, KERNEL_LOGS_MOUNT_PATH,
    PROCFS_MOUNT_PATH, TEMP_FS_NAME, TEMP_MOUNT_DEVICE, TEMP_MOUNT_PATH, VIRTUAL_DEVICE_FS_NAME,
    VIRTUAL_DEVICE_MOUNT_DEVICE, VIRTUAL_DEVICE_MOUNT_PATH,
};

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
        self.install_kernel_logs_layout();
        self.install_procfs_layout();
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

    pub(crate) fn install_kernel_logs_layout(&mut self) {
        let logs_fs = KernelLogFileSystem;
        self.register(KERNEL_LOGS_FS_NAME, Arc::new(logs_fs));
        let _ = self.mount(
            KERNEL_LOGS_MOUNT_DEVICE,
            KERNEL_LOGS_MOUNT_PATH,
            KERNEL_LOGS_FS_NAME,
            layout::MOUNT_READ_ONLY,
        );
    }

    /// Register and mount procfs at `/proc`.
    pub(crate) fn install_procfs_layout(&mut self) {
        let _ = crate::kernel::fs::procfs::mount_procfs(PROCFS_MOUNT_PATH);
    }

    /// Register and mount devfs at `/dev`.
    pub(crate) fn install_devfs_layout(&mut self) {
        let _ = crate::kernel::fs::devfs::mount_devfs(DEVFS_MOUNT_PATH);
    }

    /// Mount a memory-backed writable SimpleFs volume at `/tmp`.
    ///
    /// The volume is built from an empty image so every boot starts with a
    /// clean scratch space.  Runtime writes stay in the [`MemoryBlockDevice`]
    /// and are discarded on reboot — no persistent storage is involved.
    pub(crate) fn install_temp_layout(&mut self) -> Result<()> {
        // Build a fresh empty image.  Fall back to a minimal zero-filled
        // block if the image builder itself fails (should not happen with
        // an empty entry list, but degrade gracefully).
        let temp_image = SimpleFs::build_image("simplefs:temp", &[])
            .unwrap_or_else(|_| vec![0_u8; layout::DEMO_DISK_TEMP_BLOCKS as usize * BLOCK_SIZE]);

        let temp_device =
            MemoryBlockDevice::new("xiu-temp0", temp_image, /* read_only */ false);
        let temp_fs = SimpleFs::open(temp_device.clone(), /* case_sensitive */ true)?;

        self.register_block_device(TEMP_MOUNT_DEVICE, temp_device);
        self.register(TEMP_FS_NAME, Arc::new(SimpleFsVolume::new(temp_fs)));
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
        let demo_devices: Vec<(StorageZone, Arc<dyn BlockDevice>)> = vec![
            build_demo_memory_device(StorageZone::System, "xiu-system0"),
            build_demo_memory_device(StorageZone::Apps, "xiu-apps0"),
            build_demo_memory_device(StorageZone::Data, "xiu-data0"),
        ];

        self.install_zone_devices(demo_devices)
    }

    pub(crate) fn install_boot_disk_layout(
        &mut self,
        boot_disk: Arc<dyn BlockDevice>,
    ) -> Result<BootDiskLayoutSource> {
        // Prefer explicit partition discovery first, then fall back to the
        // legacy fixed zone layout for older disk images.
        if let Some(zone_devices) = self.boot_disk_zone_devices_from_mbr(boot_disk.clone())? {
            self.install_zone_devices(zone_devices)?;
            return Ok(BootDiskLayoutSource::MbrPartitions);
        }

        let zone_devices = self.boot_disk_zone_devices_from_fixed_layout(boot_disk);
        self.install_zone_devices(zone_devices)?;
        Ok(BootDiskLayoutSource::FixedZoneFallback)
    }

    pub(crate) fn boot_disk_zone_devices_from_mbr(
        &self,
        boot_disk: Arc<dyn BlockDevice>,
    ) -> Result<Option<ZoneDeviceBindings>> {
        let Some(partitions) = read_mbr_partitions(boot_disk.as_ref())? else {
            return Ok(None);
        };

        // Require every expected zone partition to exist; a partial partition
        // table should fall back as a whole instead of mixing layouts.
        let mut zone_devices = Vec::with_capacity(DEFAULT_ZONES.len());

        for zone in DEFAULT_ZONES {
            let Some(partition) = partitions[zone.partition_slot()] else {
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

        Ok(Some(zone_devices))
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
        let use_ext4 = self.rootfs_type == "ext4";

        if use_ext4 {
            // ext4 path: open as Ext4FsVolume for each zone.
            for (zone, device) in &zone_devices {
                let vol = crate::kernel::fs::ext4::Ext4FsVolume::open(device.clone())?;
                self.register_block_device(zone.device(), device.clone());
                self.register(zone.fs_name(), Arc::new(vol));
            }
        } else {
            // SimpleFs path (default).
            let mut filesystems = Vec::with_capacity(zone_devices.len());
            for (zone, device) in &zone_devices {
                let fs = SimpleFs::open(device.clone(), zone.case_sensitive())?;
                filesystems.push((*zone, device.clone(), fs));
            }
            for (zone, device, fs) in filesystems {
                self.register_block_device(zone.device(), device);
                self.register(zone.fs_name(), Arc::new(SimpleFsVolume::new(fs)));
            }
        }

        Ok(())
    }
}
