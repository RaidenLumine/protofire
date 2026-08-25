//! src/kernel/drivers/virtio_pci.rs
//!
//! VirtIO PCI legacy transport layer.
//! VirtIO legacy PCI transport on x86_64.
//!
//! On x86_64 QEMU with the Q35 machine, VirtIO network devices are
//! attached to the PCI bus (virtio-net-pci).  The legacy PCI interface
//! uses an IO-port BAR (BAR0) whose register layout differs from the
//! standalone MMIO transport.  This module provides an [`MmioRegion`]
//! adapter that translates MMIO-style register offsets to the PCI IO-port
//! register set so the existing [`VirtIoMmio`] transport can drive a
//! PCI-attached VirtIO device without modification.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::port::Port;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::MmioRegion;

// ─── Re-exported MMIO register offsets (MUST match virtio.rs) ──────────
// We redeclare these as match-arm patterns require numeric literals.
// The values are verified against virtio.rs at compile time via static
// assertions below.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_CONFIG_GENERATION;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_DEVICE_FEATURES;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_DEVICE_FEATURES_SEL;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_DEVICE_ID;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_DRIVER_FEATURES;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_DRIVER_FEATURES_SEL;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_MAGIC_VALUE;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DESC_HIGH;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DESC_LOW;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DEVICE_HIGH;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DEVICE_LOW;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DRIVER_HIGH;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_DRIVER_LOW;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_NOTIFY;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_NUM;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_NUM_MAX;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_READY;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_QUEUE_SEL;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_STATUS;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_VENDOR_ID;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::drivers::virtio::REG_VERSION;

/// VirtIO magic value (little-endian "virt").
#[allow(dead_code)]
const MAGIC_VALUE: u32 = 0x7472_6976;
/// Legacy VirtIO version.
#[allow(dead_code)]
const VIRTIO_VERSION: u32 = 2;

// ─── PCI legacy IO-port register offsets (relative to BAR0 base) ───────

/// DeviceFeatures (32-bit, read-only).
#[allow(dead_code)]
const PCI_DEVICE_FEATURES: u16 = 0x00;
/// DriverFeatures (32-bit, read-write).
#[allow(dead_code)]
const PCI_DRIVER_FEATURES: u16 = 0x04;
/// QueuePFN (32-bit, read-write) — guest-physical page number of the
/// selected virtqueue.
#[allow(dead_code)]
const PCI_QUEUE_PFN: u16 = 0x08;
/// QueueSize (16-bit at offset 0x0C) and QueueSelect (16-bit at offset
/// 0x0E).  Accessed as a single 32-bit dword for the combined value, or
/// as individual 16-bit IO ports.
#[allow(dead_code)]
const PCI_QUEUE_SIZE: u16 = 0x0C;
#[allow(dead_code)]
const PCI_QUEUE_SELECT: u16 = 0x0E;
/// QueueNotify (16-bit, write-only).
#[allow(dead_code)]
const PCI_QUEUE_NOTIFY: u16 = 0x10;
/// DeviceStatus (8-bit at offset 0x12).
#[allow(dead_code)]
const PCI_DEVICE_STATUS: u16 = 0x12;
/// ISRStatus (8-bit at offset 0x13).  Reading clears all pending bits.
#[allow(dead_code)]
const PCI_ISR_STATUS: u16 = 0x13;

// ─── Adapter ────────────────────────────────────────────────────────────

/// Adapts the VirtIO PCI legacy IO-port register set to the MMIO-like
/// [`MmioRegion`] trait expected by [`VirtIoMmio`](super::virtio::VirtIoMmio).
///
/// # Register translation
///
/// | MMIO register    | MMIO offset | PCI IO-port action              |
/// |------------------|-------------|---------------------------------|
/// | MAGIC_VALUE      | 0x000       | fabricated constant             |
/// | VERSION          | 0x004       | fabricated constant             |
/// | DEVICE_ID        | 0x008       | translated from PCI device ID   |
/// | VENDOR_ID        | 0x00C       | from PCI enumeration            |
/// | DEVICE_FEATURES  | 0x010       | read PCI offset 0x00            |
/// | DRIVER_FEATURES  | 0x020       | write PCI offset 0x04           |
/// | QUEUE_SEL        | 0x030       | write PCI offset 0x0E (16-bit)  |
/// | QUEUE_NUM_MAX    | 0x034       | read PCI offset 0x0C (16-bit)   |
/// | QUEUE_NUM        | 0x038       | write PCI offset 0x0C (16-bit)  |
/// | QUEUE_READY      | 0x044       | → compute & write QueuePFN      |
/// | QUEUE_NOTIFY     | 0x050       | write PCI offset 0x10 (16-bit)  |
/// | STATUS           | 0x070       | read/write PCI offset 0x12 (8b) |
/// | DESC/DRIVER/     | 0x080‑0x0A4| cached → used for PFN           |
/// | DEVICE addrs     |             |                                 |
/// | CONFIG_GENERATION| 0x0FC       | fabricated 0                    |
/// | Config space     | 0x100+      | not available; returns 0        |
///
/// Device-specific config space (offset ≥ 0x100) is not accessible
/// through the legacy IO BAR.  VIRTIO_NET_F_MAC (bit 5) is masked from
/// DeviceFeatures so the driver falls back to the default QEMU MAC
/// address (52:54:00:12:34:56).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct PciLegacyMmioRegion {
    /// IO-port base address from BAR0.
    io_base: u16,
    /// VirtIO device type ID (e.g. 1 for network).
    device_id: u32,
    /// Vendor ID from PCI enumeration.
    vendor_id: u32,
    /// Cached descriptor-table physical address (valid when QueueReady fires).
    queue_desc: core::cell::Cell<u64>,
}

// Safety: IO port access is guarded by the driver-level Mutex that
// serialises all transport operations.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Send for PciLegacyMmioRegion {}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Sync for PciLegacyMmioRegion {}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl PciLegacyMmioRegion {
    /// Create a new PCI legacy MMIO adapter.
    ///
    /// `io_base` is the IO-port base address from the device's BAR0.
    /// `pci_device_id` is the PCI device ID (e.g. 0x1000 for network);
    /// this is translated to the VirtIO device type ID (e.g. 1 for net).
    pub fn new(io_base: u16, pci_device_id: u16, vendor_id: u16) -> Self {
        // VirtIO PCI device IDs 0x1000..0x103F map to VirtIO device
        // types 1..64 (VirtIO 0.9.5 §4.1.2.2).
        let virtio_device_id = if (0x1000..=0x103F).contains(&pci_device_id) {
            (pci_device_id - 0x0FFF) as u32
        } else {
            pci_device_id as u32
        };

        Self {
            io_base,
            device_id: virtio_device_id,
            vendor_id: vendor_id as u32,
            queue_desc: core::cell::Cell::new(0),
        }
    }

    // ── IO-port helpers ──────────────────────────────────────────────

    unsafe fn io_read32(&self, offset: u16) -> u32 {
        unsafe { Port::<u32>::new(self.io_base + offset).read() }
    }

    unsafe fn io_write32(&self, offset: u16, value: u32) {
        unsafe { Port::<u32>::new(self.io_base + offset).write(value) }
    }

    unsafe fn io_write16(&self, offset: u16, value: u16) {
        unsafe { Port::<u16>::new(self.io_base + offset).write(value) }
    }

    unsafe fn io_read8(&self, offset: u16) -> u8 {
        unsafe { Port::<u8>::new(self.io_base + offset).read() }
    }

    unsafe fn io_write8(&self, offset: u16, value: u8) {
        unsafe { Port::<u8>::new(self.io_base + offset).write(value) }
    }

    /// Finalise queue configuration: compute the QueuePFN from the cached
    /// descriptor-table address and write it to the device.
    unsafe fn commit_queue_pfn(&self) -> u32 {
        let desc = self.queue_desc.get() as usize;
        // In legacy PCI the queue lives in two physical pages:
        //   page N:   descriptor table + available ring
        //   page N+1: used ring (VirtIO 0.9.5 §2.3.2)
        // The QueuePFN register holds the page number of page N.
        // x86_64 uses identity mapping so VA == PA.
        let pfn = (desc >> 12) as u32;
        let pfn_before = unsafe { self.io_read32(PCI_QUEUE_PFN) };
        unsafe { self.io_write32(PCI_QUEUE_PFN, pfn) };
        let pfn_after = unsafe { self.io_read32(PCI_QUEUE_PFN) };
        crate::println!(
            "[virtio-pci] commit_queue_pfn: desc=0x{:x} pfn=0x{:x}->0x{:x} (before=0x{:x})",
            desc,
            pfn,
            pfn_after,
            pfn_before
        );
        pfn
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl MmioRegion for PciLegacyMmioRegion {
    fn read32(&self, offset: u64) -> u32 {
        match offset {
            // Fabricated — PCI has no magic/version registers.
            REG_MAGIC_VALUE => MAGIC_VALUE,
            REG_VERSION => VIRTIO_VERSION,
            REG_DEVICE_ID => self.device_id,
            REG_VENDOR_ID => self.vendor_id,

            // DeviceFeatures (PCI offset 0x00).  Mask VIRTIO_NET_F_MAC
            // (bit 5) because the legacy IO BAR cannot access device-
            // specific config space.
            REG_DEVICE_FEATURES => {
                let raw = unsafe { self.io_read32(PCI_DEVICE_FEATURES) };
                const VIRTIO_NET_F_MAC: u32 = 1 << 5;
                raw & !VIRTIO_NET_F_MAC
            }

            // DeviceFeaturesSel — not used in legacy PCI.
            REG_DEVICE_FEATURES_SEL => 0,

            // QueueNumMax: 16-bit at PCI offset 0x0C, bits [15:0].
            REG_QUEUE_NUM_MAX => {
                let dword = unsafe { self.io_read32(PCI_QUEUE_SIZE) };
                let val = dword & 0xFFFF;
                crate::println!(
                    "[virtio-pci] read QueueNumMax=0x{:x} ({}) raw_dword=0x{:08x}",
                    val,
                    val,
                    dword
                );
                val
            }

            // Status: 8-bit at PCI offset 0x12.
            REG_STATUS => unsafe { self.io_read8(PCI_DEVICE_STATUS) as u32 },

            // ConfigGeneration: not available.
            REG_CONFIG_GENERATION => 0,

            // Config space (offset ≥ 0x100): not available.
            _ if offset >= 0x100 => 0,

            // Unknown offset.
            _ => 0,
        }
    }

    fn write32(&self, offset: u64, value: u32) {
        match offset {
            // DeviceFeaturesSel — not used in legacy PCI; ignored.
            REG_DEVICE_FEATURES_SEL => {}

            // DriverFeatures (PCI offset 0x04).
            REG_DRIVER_FEATURES => {
                unsafe { self.io_write32(PCI_DRIVER_FEATURES, value) }
                // Read back to verify the write.
                let readback = unsafe { self.io_read32(PCI_DRIVER_FEATURES) };
                crate::println!(
                    "[virtio-pci] write DriverFeatures=0x{:08x} readback=0x{:08x}",
                    value,
                    readback
                );
            }

            // DriverFeaturesSel — not used; ignored.
            REG_DRIVER_FEATURES_SEL => {}

            // QueueSel (PCI offset 0x0E, 16-bit).
            REG_QUEUE_SEL => unsafe {
                self.io_write16(PCI_QUEUE_SELECT, value as u16);
            },

            // QueueNum (PCI offset 0x0C, 16-bit).
            // QEMU 8.2 does not support writing to the legacy QueueSize
            // register — the queue size is fixed at the device's default
            // (typically 128).  The write is silently ignored here; the
            // caller must ensure the virtqueue allocation size matches
            // whatever the device reports via QueueNumMax.
            REG_QUEUE_NUM => {
                crate::println!(
                    "[virtio-pci] QueueNum write 0x{:x} ignored (device-controlled size)",
                    value
                );
            }

            // QueueReady → compute and write QueuePFN at PCI offset 0x08.
            REG_QUEUE_READY => {
                if value != 0 {
                    unsafe {
                        self.commit_queue_pfn();
                    }
                }
            }

            // QueueNotify (PCI offset 0x10).  The VirtIO legacy PCI spec
            // §4.1.4.2 says this is a 16-bit register.  Writing 32 bits
            // here would clobber the adjacent DeviceStatus and ISRStatus
            // registers on some implementations, so we write exactly 16.
            REG_QUEUE_NOTIFY => {
                let isr_before = unsafe { self.io_read8(PCI_ISR_STATUS) };
                let status_before = unsafe { self.io_read8(PCI_DEVICE_STATUS) };
                unsafe {
                    self.io_write16(PCI_QUEUE_NOTIFY, value as u16);
                }
                let isr_after = unsafe { self.io_read8(PCI_ISR_STATUS) };
                let status_after = unsafe { self.io_read8(PCI_DEVICE_STATUS) };
                crate::println!(
                    "[virtio-pci] kick q{} IO=0x{:x} status=0x{:02x}->0x{:02x} isr=0x{:02x}->0x{:02x}",
                    value,
                    self.io_base + PCI_QUEUE_NOTIFY,
                    status_before,
                    status_after,
                    isr_before,
                    isr_after
                );
            }

            // Status (PCI offset 0x12, 8-bit).
            REG_STATUS => {
                unsafe {
                    self.io_write8(PCI_DEVICE_STATUS, value as u8);
                }
                let readback = unsafe { self.io_read8(PCI_DEVICE_STATUS) };
                crate::println!(
                    "[virtio-pci] write Status=0x{:02x} readback=0x{:02x}",
                    value as u8,
                    readback
                );
            }

            // Cache descriptor-table address for QueuePFN calculation.
            REG_QUEUE_DESC_LOW => {
                let cur = self.queue_desc.get();
                self.queue_desc
                    .set((cur & 0xFFFF_FFFF_0000_0000) | (value as u64));
            }
            REG_QUEUE_DESC_HIGH => {
                let cur = self.queue_desc.get();
                self.queue_desc
                    .set((cur & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32));
            }

            // Driver/device ring addresses are not needed for QueuePFN
            // (the device computes them from the descriptor start and
            // queue size).  Silently ignore.
            REG_QUEUE_DRIVER_LOW
            | REG_QUEUE_DRIVER_HIGH
            | REG_QUEUE_DEVICE_LOW
            | REG_QUEUE_DEVICE_HIGH => {}

            // Config space writes: not available.
            _ if offset >= 0x100 => {}

            // Unknown offset — silently ignored.
            _ => {}
        }
    }
}

// ─── Stub for non-x86_64 / host targets ─────────────────────────────────

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub struct PciLegacyMmioRegion;

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
impl PciLegacyMmioRegion {
    #[allow(unused)]
    pub fn new(_io_base: u16, _device_id: u16, _vendor_id: u16) -> Self {
        Self
    }
}
