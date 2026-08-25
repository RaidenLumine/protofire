//! src/kernel/drivers/virtio_pci_modern.rs
//!
//! VirtIO PCI modern transport layer.
//! VirtIO modern (1.0) PCI transport via the device's MMIO BAR.
//!
//! QEMU 8.2's transitional `virtio-net-pci` device exposes the legacy
//! IO-port BAR (BAR0) with a read-only `QueueSize` register (writing
//! to offset 0x0C is rejected).  The modern PCI interface (BAR4) allows
//! the driver to write `queue_size` via the common config structure,
//! which is required for queue sizes > 227 that don't fit the legacy
//! two-page layout.
//!
//! This module provides [`PciModernTransport`], a drop-in replacement
//! for [`VirtIoMmio`] that uses the modern PCI register set through a
//! memory-mapped BAR.

use crate::kernel::drivers::virtio::MmioRegion;
use crate::kernel::drivers::virtio::MAGIC_VALUE;
use crate::kernel::drivers::virtio::REG_CONFIG_GENERATION;
use crate::kernel::drivers::virtio::REG_DEVICE_FEATURES;
use crate::kernel::drivers::virtio::REG_DEVICE_FEATURES_SEL;
use crate::kernel::drivers::virtio::REG_DEVICE_ID;
use crate::kernel::drivers::virtio::REG_DRIVER_FEATURES;
use crate::kernel::drivers::virtio::REG_DRIVER_FEATURES_SEL;
use crate::kernel::drivers::virtio::REG_MAGIC_VALUE;
use crate::kernel::drivers::virtio::REG_QUEUE_DESC_HIGH;
use crate::kernel::drivers::virtio::REG_QUEUE_DESC_LOW;
use crate::kernel::drivers::virtio::REG_QUEUE_DEVICE_HIGH;
use crate::kernel::drivers::virtio::REG_QUEUE_DEVICE_LOW;
use crate::kernel::drivers::virtio::REG_QUEUE_DRIVER_HIGH;
use crate::kernel::drivers::virtio::REG_QUEUE_DRIVER_LOW;
use crate::kernel::drivers::virtio::REG_QUEUE_NOTIFY;
use crate::kernel::drivers::virtio::REG_QUEUE_NUM;
use crate::kernel::drivers::virtio::REG_QUEUE_NUM_MAX;
use crate::kernel::drivers::virtio::REG_QUEUE_READY;
use crate::kernel::drivers::virtio::REG_QUEUE_SEL;
use crate::kernel::drivers::virtio::REG_STATUS;
use crate::kernel::drivers::virtio::REG_VENDOR_ID;
use crate::kernel::drivers::virtio::REG_VERSION;
use crate::kernel::drivers::virtio::VIRTIO_VERSION;

// ─── Modern PCI BAR layout (QEMU) ───────────────────────────────

/// Offset of the common config structure within the MMIO BAR.
const COMMON_CFG_OFFSET: u64 = 0x0000;
/// Offset of the device-specific config within the MMIO BAR.
const DEVICE_CFG_OFFSET: u64 = 0x2000;
/// Offset of the notification area within the MMIO BAR.
const NOTIFY_OFFSET: u64 = 0x3000;
/// Multiplier applied to `queue_notify_off` to produce a byte offset
/// within the notification area.
const NOTIFY_OFF_MULTIPLIER: u64 = 4;

/// Maximum number of queues tracked in the per-queue notification-offset
/// cache.  VirtIO devices typically expose a handful of queues (2 for net);
/// the cache is indexed by queue index and consulted on every doorbell kick.
const MAX_QUEUES: usize = 64;

// ─── Common config field offsets (VirtIO 1.0 §4.1.4) ────────────

const CFG_DEVICE_FEATURE_SELECT: u64 = 0x00; // le32
const CFG_DEVICE_FEATURE: u64 = 0x04; // le32, read-only
const CFG_DRIVER_FEATURE_SELECT: u64 = 0x08; // le32
const CFG_DRIVER_FEATURE: u64 = 0x0C; // le32
const CFG_DEVICE_STATUS: u64 = 0x14; // u8
const CFG_CONFIG_GENERATION: u64 = 0x15; // u8
const CFG_QUEUE_SELECT: u64 = 0x16; // le16
const CFG_QUEUE_SIZE: u64 = 0x18; // le16
const CFG_QUEUE_ENABLE: u64 = 0x1C; // le16
const CFG_QUEUE_NOTIFY_OFF: u64 = 0x1E; // le16
const CFG_QUEUE_DESC: u64 = 0x20; // le64
const CFG_QUEUE_DRIVER: u64 = 0x28; // le64
const CFG_QUEUE_DEVICE: u64 = 0x30; // le64

// ─── Transport ───────────────────────────────────────────────────

/// Modern (VirtIO 1.0) PCI transport wrapping a memory-mapped BAR.
///
/// Unlike the legacy IO-port transport, the modern interface uses a
/// structured common config block where `queue_size` is writeable.
/// This transport implements [`MmioRegion`] so it can be passed
/// directly to [`VirtIoMmio`] — the register translation is done
/// inside `read32` / `write32`.
///
/// # Register translation
///
/// | MMIO register        | Modern PCI action                  |
/// |----------------------|-------------------------------------|
/// | MAGIC_VALUE          | fabricated constant                 |
/// | VERSION              | fabricated constant                 |
/// | DEVICE_ID            | translated from PCI device ID       |
/// | VENDOR_ID            | from PCI enumeration                |
/// | DEVICE_FEATURES      | write sel@0x00, read feature@0x04   |
/// | DRIVER_FEATURES      | write sel@0x08, write feature@0x0C  |
/// | QUEUE_SEL            | write queue_select@0x16             |
/// | QUEUE_NUM_MAX        | read queue_size@0x18                |
/// | QUEUE_NUM            | write queue_size@0x18               |
/// | QUEUE_READY          | write queue_enable@0x1C             |
/// | QUEUE_NOTIFY         | compute notify addr, write idx      |
/// | STATUS               | read/write device_status@0x14       |
/// | QUEUE_DESC_LOW/HIGH  | write queue_desc@0x20               |
/// | QUEUE_DRIVER_L/H     | write queue_driver@0x28             |
/// | QUEUE_DEVICE_L/H     | write queue_device@0x30             |
/// | CONFIG_GENERATION    | read config_generation@0x15         |
/// | Config space (≥0x100)| read from device_cfg area           |
pub struct PciModernRegion {
    /// Virtual address of the MMIO BAR (BAR4).
    bar_base: usize,
    /// VirtIO device type ID (e.g. 1 for network).
    device_id: u32,
    /// Vendor ID from PCI enumeration.
    vendor_id: u32,
    /// Index of the queue most recently selected via REG_QUEUE_SEL.
    selected_queue: core::cell::Cell<u16>,
    /// Per-queue cached queue_notify_off values, indexed by queue index.
    notify_offs: [core::cell::Cell<u16>; MAX_QUEUES],
}

unsafe impl Send for PciModernRegion {}
unsafe impl Sync for PciModernRegion {}

impl PciModernRegion {
    /// Create a new modern PCI transport adapter.
    ///
    /// `bar_base` is the virtual address of the MMIO BAR (already mapped
    /// in the kernel page tables).
    /// `pci_device_id` is the PCI device ID (e.g. 0x1000 for network).
    pub fn new(bar_base: usize, pci_device_id: u16, vendor_id: u16) -> Self {
        let virtio_device_id = if (0x1000..=0x103F).contains(&pci_device_id) {
            (pci_device_id - 0x0FFF) as u32
        } else {
            pci_device_id as u32
        };

        Self {
            bar_base,
            device_id: virtio_device_id,
            vendor_id: vendor_id as u32,
            selected_queue: core::cell::Cell::new(0),
            notify_offs: [const { core::cell::Cell::new(0) }; MAX_QUEUES],
        }
    }

    // ── Low-level MMIO helpers ──────────────────────────────────

    unsafe fn mmio_read32(&self, offset: u64) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.bar_base as *const u8).add(offset as usize) as *const u32)
        }
    }

    unsafe fn mmio_write32(&self, offset: u64, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.bar_base as *mut u8).add(offset as usize) as *mut u32,
                value,
            );
        }
    }

    /// Read a 16-bit little-endian field from a 32-bit aligned address,
    /// performing read-modify-write for non-aligned fields.
    unsafe fn cfg_read16(&self, offset: u64) -> u16 {
        let aligned = offset & !3u64;
        let shift = ((offset & 3) * 8) as u32;
        let dword = unsafe { self.mmio_read32(aligned) };
        ((dword >> shift) & 0xFFFF) as u16
    }

    unsafe fn cfg_write16(&self, offset: u64, value: u16) {
        let aligned = offset & !3u64;
        let shift = ((offset & 3) * 8) as u32;
        let dword = unsafe { self.mmio_read32(aligned) };
        let mask = !(0xFFFFu32 << shift);
        let new_dword = (dword & mask) | ((value as u32) << shift);
        unsafe { self.mmio_write32(aligned, new_dword) };
    }

    unsafe fn cfg_read8(&self, offset: u64) -> u8 {
        let aligned = offset & !3u64;
        let shift = ((offset & 3) * 8) as u32;
        let dword = unsafe { self.mmio_read32(aligned) };
        ((dword >> shift) & 0xFF) as u8
    }

    unsafe fn cfg_write8(&self, offset: u64, value: u8) {
        let aligned = offset & !3u64;
        let shift = ((offset & 3) * 8) as u32;
        let dword = unsafe { self.mmio_read32(aligned) };
        let mask = !(0xFFu32 << shift);
        let new_dword = (dword & mask) | ((value as u32) << shift);
        unsafe { self.mmio_write32(aligned, new_dword) };
    }

    /// Compute the notification address and kick the given queue.
    unsafe fn notify(&self, queue_index: u16) {
        let qi = queue_index as usize;
        let off = if qi < MAX_QUEUES {
            self.notify_offs[qi].get()
        } else {
            crate::println!(
                "[virtio-pci-modern] notify: queue {} out of range (MAX_QUEUES={}), skipping kick",
                queue_index,
                MAX_QUEUES
            );
            return;
        };
        let addr = self.bar_base as u64 + NOTIFY_OFFSET + (off as u64) * NOTIFY_OFF_MULTIPLIER;
        crate::println!(
            "[virtio-pci-modern] notify q{} at 0x{:x} (off={} mult={})",
            queue_index,
            addr,
            off,
            NOTIFY_OFF_MULTIPLIER
        );
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, queue_index as u32);
        }
    }
}

impl MmioRegion for PciModernRegion {
    fn read32(&self, offset: u64) -> u32 {
        match offset {
            // Fabricated — modern PCI has no magic/version at fixed offsets.
            REG_MAGIC_VALUE => MAGIC_VALUE,
            REG_VERSION => VIRTIO_VERSION,
            REG_DEVICE_ID => self.device_id,
            REG_VENDOR_ID => self.vendor_id,

            // DeviceFeatures: select page, then read.
            REG_DEVICE_FEATURES => {
                // feature_sel was written by REG_DEVICE_FEATURES_SEL handler.
                // Read the selected page's features.
                let cfg_off = COMMON_CFG_OFFSET + CFG_DEVICE_FEATURE;
                unsafe { self.mmio_read32(cfg_off) }
            }

            // DeviceFeaturesSel — no-op read (selection is tracked by device).
            REG_DEVICE_FEATURES_SEL => 0,

            // QueueNumMax: the device's maximum queue size.
            REG_QUEUE_NUM_MAX => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_QUEUE_SIZE;
                // queue_size returns the maximum when no size has been written.
                unsafe { self.cfg_read16(cfg_off) as u32 }
            }

            // Status: 8-bit device_status field.
            REG_STATUS => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_DEVICE_STATUS;
                unsafe { self.cfg_read8(cfg_off) as u32 }
            }

            // ConfigGeneration.
            REG_CONFIG_GENERATION => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_CONFIG_GENERATION;
                unsafe { self.cfg_read8(cfg_off) as u32 }
            }

            // Device-specific config space (offset ≥ 0x100).
            _ if offset >= 0x100 => {
                let cfg_off = DEVICE_CFG_OFFSET + (offset - 0x100);
                unsafe { self.mmio_read32(cfg_off) }
            }

            // Unknown offset.
            _ => 0,
        }
    }

    fn write32(&self, offset: u64, value: u32) {
        match offset {
            // DeviceFeaturesSel: select which 32-bit page of device features.
            REG_DEVICE_FEATURES_SEL => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_DEVICE_FEATURE_SELECT;
                unsafe { self.mmio_write32(cfg_off, value) };
            }

            // DriverFeaturesSel: select page, then write feature bits.
            REG_DRIVER_FEATURES_SEL => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_DRIVER_FEATURE_SELECT;
                unsafe { self.mmio_write32(cfg_off, value) };
            }

            // DriverFeatures: write after selecting the page.
            REG_DRIVER_FEATURES => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_DRIVER_FEATURE;
                unsafe { self.mmio_write32(cfg_off, value) };
                let readback = unsafe { self.mmio_read32(cfg_off) };
                crate::println!(
                    "[virtio-pci-modern] write DriverFeatures=0x{:08x} readback=0x{:08x}",
                    value,
                    readback
                );
            }

            // QueueSel: select which queue to configure.
            REG_QUEUE_SEL => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_QUEUE_SELECT;
                unsafe { self.cfg_write16(cfg_off, value as u16) };
                self.selected_queue.set(value as u16);
            }

            // QueueNum: set the queue size for the selected queue.
            REG_QUEUE_NUM => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_QUEUE_SIZE;
                unsafe { self.cfg_write16(cfg_off, value as u16) };
            }

            // QueueReady → enable the queue and cache its notify offset.
            REG_QUEUE_READY => {
                // Write queue_enable (1 = enable).
                let enable_off = COMMON_CFG_OFFSET + CFG_QUEUE_ENABLE;
                unsafe { self.cfg_write16(enable_off, if value != 0 { 1 } else { 0 }) };

                if value != 0 {
                    // Cache the queue_notify_off of the currently selected
                    // queue so later kicks use that queue's doorbell offset.
                    let notify_off_off = COMMON_CFG_OFFSET + CFG_QUEUE_NOTIFY_OFF;
                    let nf = unsafe { self.cfg_read16(notify_off_off) };
                    let q = self.selected_queue.get() as usize;
                    if q < MAX_QUEUES {
                        self.notify_offs[q].set(nf);
                    }
                    crate::println!("[virtio-pci-modern] queue {} enabled, notify_off={}", q, nf);
                }
            }

            // QueueNotify: kick the device.
            REG_QUEUE_NOTIFY => {
                unsafe { self.notify(value as u16) };
            }

            // Status: 8-bit device_status field.
            REG_STATUS => {
                let cfg_off = COMMON_CFG_OFFSET + CFG_DEVICE_STATUS;
                let old = unsafe { self.cfg_read8(cfg_off) };
                unsafe { self.cfg_write8(cfg_off, value as u8) };
                let new = unsafe { self.cfg_read8(cfg_off) };
                crate::println!(
                    "[virtio-pci-modern] write Status=0x{:02x}->0x{:02x} (req=0x{:02x})",
                    old,
                    new,
                    value as u8
                );
            }

            // Queue descriptor address (64-bit).  The device accumulates
            // the full 64-bit value across the low/high writes, so each half
            // is written directly (mirrors the queue driver/device handlers).
            REG_QUEUE_DESC_LOW => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DESC, value);
            },
            REG_QUEUE_DESC_HIGH => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DESC + 4, value);
            },

            // Queue driver (avail) address (64-bit).  The device accumulates
            // the full 64-bit value across the low/high writes, so each half
            // is written directly (mirrors the queue device handlers below).
            REG_QUEUE_DRIVER_LOW => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DRIVER, value);
            },
            REG_QUEUE_DRIVER_HIGH => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DRIVER + 4, value);
            },

            // Queue device (used) address (64-bit).
            REG_QUEUE_DEVICE_LOW => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DEVICE, value);
            },
            REG_QUEUE_DEVICE_HIGH => unsafe {
                self.mmio_write32(COMMON_CFG_OFFSET + CFG_QUEUE_DEVICE + 4, value);
            },

            // Config space writes: silently ignored.
            _ if offset >= 0x100 => {}

            // Unknown offset — silently ignored.
            _ => {}
        }
    }
}
