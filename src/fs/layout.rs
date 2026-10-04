//! src/fs/layout.rs
//!
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
/// The data partition has to be larger than the image the builder writes for
/// it, which carries `DATA_ZONE_EXTRA_DATA_BLOCKS` of headroom.  256 blocks was
/// smaller than that image, so the disk path substituted its fallback zone and
/// the demo's data files were only ever present on the in-memory layout.
pub const DEMO_DISK_DATA_BLOCKS: u64 = 512;
pub const DEMO_DISK_TEMP_BLOCKS: u64 = 128;
pub const DEMO_DISK_SYSTEM_START_BLOCK: u64 = 2048;
pub const DEMO_DISK_APPS_START_BLOCK: u64 = DEMO_DISK_SYSTEM_START_BLOCK + DEMO_DISK_SYSTEM_BLOCKS;
pub const DEMO_DISK_DATA_START_BLOCK: u64 = DEMO_DISK_APPS_START_BLOCK + DEMO_DISK_APPS_BLOCKS;
pub const DEMO_DISK_TOTAL_BLOCKS: u64 = DEMO_DISK_DATA_START_BLOCK + DEMO_DISK_DATA_BLOCKS;

/// The second system slot, after the three zones so their offsets — and every
/// disk built before the pair existed — stay where they were.
pub const DEMO_DISK_SYSTEM_B_START_BLOCK: u64 = DEMO_DISK_DATA_START_BLOCK + DEMO_DISK_DATA_BLOCKS;
pub const DEMO_DISK_SYSTEM_B_BLOCKS: u64 = DEMO_DISK_SYSTEM_BLOCKS;
pub const DEMO_DISK_TOTAL_BLOCKS_WITH_SYSTEM_PAIR: u64 =
    DEMO_DISK_SYSTEM_B_START_BLOCK + DEMO_DISK_SYSTEM_B_BLOCKS;

/// The disk range of the second system slot, as `(start_block, block_count)`.
pub const SYSTEM_SLOT_B_DISK_RANGE: (u64, u64) =
    (DEMO_DISK_SYSTEM_B_START_BLOCK, DEMO_DISK_SYSTEM_B_BLOCKS);

/// The builds the demo disk's two system slots are committed as.  B is newer,
/// so a demo boot takes it: the pair is exercised where a machine boots, not
/// only in tests.  Put back into the base total once the pair is everywhere:
/// `DEMO_DISK_TOTAL_BLOCKS` stays the size of a single-slot disk.
pub const DEMO_SYSTEM_SLOT_A_GENERATION: u64 = 1;
pub const DEMO_SYSTEM_SLOT_B_GENERATION: u64 = 2;

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

#[cfg(test)]
mod tests {
    use super::StorageZone;

    #[test]
    fn only_the_data_zone_is_writable() {
        // Where a machine writes is a property of the zone, and it is the one
        // every zone device is cut with (see
        // `crate::fs::filesystem::layout`): `/system` and `/apps` are read-only
        // at the block device, so no token and no code path can write them at
        // runtime — the install path writes its own zone through the
        // *filesystem*, under the caller's token, and that is the exception
        // the zone exists for.
        assert!(StorageZone::System.device_read_only());
        assert!(StorageZone::Apps.device_read_only());
        assert!(!StorageZone::Data.device_read_only());
    }
}
