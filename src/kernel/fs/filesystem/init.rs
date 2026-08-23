//! src/kernel/fs/filesystem/init.rs
//! FileSystem construction, initialization, and boot-disk layout.
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::kernel::sync::Mutex;
use crate::println;

use super::super::block::BlockDevice;
use super::super::layout::DEFAULT_USER_ROOT;
use super::super::vfs::directory_node;
use super::super::FileSystem;
use super::types::{BootDiskLayoutSource, StorageInitReport};

impl FileSystem {
    pub fn new() -> Self {
        Self {
            root: directory_node("/"),
            filesystems: BTreeMap::new(),
            block_devices: BTreeMap::new(),
            mounted_fs: BTreeMap::new(),
            current_working_dir: Mutex::new("/".to_string()),
            next_handle: Mutex::new(4),
            storage_init_report: Mutex::new(None),
            rootfs_type: String::new(),
        }
    }

    /// Atomically allocate `count` consecutive handle numbers.
    ///
    /// Returns the first handle number in the allocated range.
    /// The handle counter is advanced by `count`.
    pub fn alloc_handles(&self, count: u64) -> u64 {
        let mut next = self.next_handle.lock();
        let first = *next;
        *next = next.wrapping_add(count);
        first
    }

    pub fn init(&mut self) {
        self.init_with_boot_disk(None);
    }

    /// Set the root filesystem type for the next [`init_with_boot_disk`] call.
    ///
    /// Supported values: `"simplefs"` (default) and `"ext4"`.
    pub fn set_rootfs_type(&mut self, fs_type: &str) {
        self.rootfs_type = fs_type.to_string();
    }

    pub fn init_with_boot_disk(&mut self, boot_disk: Option<Arc<dyn BlockDevice>>) {
        let rootfs_type = self.rootfs_type.clone();
        let fs_label = if rootfs_type == "ext4" {
            "ext4"
        } else {
            "SimpleFs"
        };
        let mut boot_disk_error = None;
        let boot_layout = match boot_disk {
            Some(disk) => match self.install_boot_disk_layout(disk) {
                Ok(layout) => Some(layout),
                Err(error) => {
                    boot_disk_error = Some(error);
                    crate::print!(
                        "[fs    ] failed to mount {} volumes from ATA boot disk: {}\n",
                        fs_label,
                        error.as_str()
                    );
                    None
                }
            },
            None => None,
        };

        // Prefer a real boot disk layout when available, but keep the kernel
        // usable by falling back to the in-memory demo volumes.
        let report = match boot_layout {
            Some(BootDiskLayoutSource::MbrPartitions) => {
                crate::print!(
                    "[fs    ] mounted MBR-partitioned {} volumes from ATA boot disk\n",
                    fs_label
                );
                StorageInitReport::BootDiskMbrPartitions
            }
            Some(BootDiskLayoutSource::FixedZoneFallback) => {
                crate::print!(
                    "[fs    ] mounted fixed-zone {} volumes from ATA boot disk\n",
                    fs_label
                );
                StorageInitReport::BootDiskFixedZoneFallback
            }
            None => {
                #[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
                {
                    match self.install_demo_memory_layout() {
                        Ok(()) => {
                            println!("[fs    ] mounted in-memory demo SimpleFs volumes");
                            StorageInitReport::MemoryDemo { boot_disk_error }
                        }
                        Err(error) => {
                            println!(
                                "[fs    ] failed to mount in-memory demo SimpleFs volumes: {}",
                                error.as_str()
                            );
                            StorageInitReport::Failed {
                                boot_disk_error,
                                memory_demo_error: error,
                            }
                        }
                    }
                }
                #[cfg(not(any(feature = "demo-disk", test, not(target_os = "none"))))]
                {
                    println!("[fs    ] no boot disk found and demo-disk feature is disabled");
                    StorageInitReport::Failed {
                        boot_disk_error,
                        memory_demo_error: crate::Error::NotFound,
                    }
                }
            }
        };
        *self.storage_init_report.lock() = Some(report);

        self.install_default_layout();
        let _ = self.set_current_working_dir(DEFAULT_USER_ROOT);
    }
}
