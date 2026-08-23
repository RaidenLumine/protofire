//! src/kernel/fs/layout.rs
//! Disk and zone layout constants plus mount policy for system/apps/data areas.

pub const MOUNT_READ_ONLY: u32 = 1 << 0;
pub const MOUNT_EXECUTABLE: u32 = 1 << 1;
pub const MOUNT_USER_DATA: u32 = 1 << 2;
pub const MOUNT_KNOWN_FLAGS: u32 = MOUNT_READ_ONLY | MOUNT_EXECUTABLE | MOUNT_USER_DATA;

pub const DEFAULT_USER_ROOT: &str = "/data/users/guest";
// Keep system/data compact for fast tests, but give /apps extra room so the
// demo software catalog can grow without silently overflowing the fixed image.
pub const DEMO_DISK_SYSTEM_BLOCKS: u64 = 256;
pub const DEMO_DISK_APPS_BLOCKS: u64 = 512;
pub const DEMO_DISK_DATA_BLOCKS: u64 = 256;
pub const DEMO_DISK_TEMP_BLOCKS: u64 = 128;
pub const DEMO_DISK_SYSTEM_START_BLOCK: u64 = 2048;
pub const DEMO_DISK_APPS_START_BLOCK: u64 = DEMO_DISK_SYSTEM_START_BLOCK + DEMO_DISK_SYSTEM_BLOCKS;
pub const DEMO_DISK_DATA_START_BLOCK: u64 = DEMO_DISK_APPS_START_BLOCK + DEMO_DISK_APPS_BLOCKS;
pub const DEMO_DISK_TOTAL_BLOCKS: u64 = DEMO_DISK_DATA_START_BLOCK + DEMO_DISK_DATA_BLOCKS;

pub const DEMO_MBR_SYSTEM_PARTITION_TYPE: u8 = 0xa1;
pub const DEMO_MBR_APPS_PARTITION_TYPE: u8 = 0xa2;
pub const DEMO_MBR_DATA_PARTITION_TYPE: u8 = 0xa3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageZone {
    System,
    Apps,
    Data,
}

pub const DEFAULT_ZONES: [StorageZone; 3] =
    [StorageZone::System, StorageZone::Apps, StorageZone::Data];

impl StorageZone {
    pub const fn zone_root(self) -> &'static str {
        match self {
            Self::System => "/system",
            Self::Apps => "/apps",
            Self::Data => "/data",
        }
    }

    pub const fn fs_name(self) -> &'static str {
        match self {
            Self::System => "simplefs-system",
            Self::Apps => "simplefs-apps",
            Self::Data => "simplefs-data",
        }
    }

    pub const fn volume_label(self) -> &'static str {
        match self {
            Self::System => "simplefs:system",
            Self::Apps => "simplefs:apps",
            Self::Data => "simplefs:data",
        }
    }

    pub const fn device(self) -> &'static str {
        match self {
            Self::System => "/dev/adastra-system",
            Self::Apps => "/dev/adastra-apps",
            Self::Data => "/dev/adastra-data",
        }
    }

    pub const fn boot_disk_device_name(self) -> &'static str {
        match self {
            Self::System => "ata0.system",
            Self::Apps => "ata0.apps",
            Self::Data => "ata0.data",
        }
    }

    pub const fn flags(self) -> u32 {
        match self {
            Self::System => MOUNT_READ_ONLY,
            Self::Apps => MOUNT_READ_ONLY | MOUNT_EXECUTABLE,
            Self::Data => MOUNT_USER_DATA,
        }
    }

    pub const fn case_sensitive(self) -> bool {
        match self {
            Self::System | Self::Apps => true,
            Self::Data => false,
        }
    }

    pub const fn device_read_only(self) -> bool {
        match self {
            Self::System | Self::Apps => true,
            Self::Data => false,
        }
    }

    pub const fn partition_slot(self) -> usize {
        match self {
            Self::System => 0,
            Self::Apps => 1,
            Self::Data => 2,
        }
    }

    pub const fn mbr_partition_type(self) -> u8 {
        match self {
            Self::System => DEMO_MBR_SYSTEM_PARTITION_TYPE,
            Self::Apps => DEMO_MBR_APPS_PARTITION_TYPE,
            Self::Data => DEMO_MBR_DATA_PARTITION_TYPE,
        }
    }

    pub const fn disk_range(self) -> (u64, u64) {
        match self {
            Self::System => (DEMO_DISK_SYSTEM_START_BLOCK, DEMO_DISK_SYSTEM_BLOCKS),
            Self::Apps => (DEMO_DISK_APPS_START_BLOCK, DEMO_DISK_APPS_BLOCKS),
            Self::Data => (DEMO_DISK_DATA_START_BLOCK, DEMO_DISK_DATA_BLOCKS),
        }
    }
}
