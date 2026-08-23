//! src/kernel/drivers/virtio_pci_msix.rs
//! MSI-X capability driver for VirtIO PCI devices.
//!
//! QEMU's `virtio-net-pci` (transitional) device exposes an MSI-X
//! capability with two vectors: one for config-space change notifications
//! and one for virtqueue interrupts.  This module discovers the MSI-X
//! capability, maps the MSI-X table BAR, allocates vector numbers, and
//! programs the table entries.
//!
//! MSI-X is optional: if the capability is absent or has fewer than two
//! vectors, drivers should fall back to line-based INTx interrupts.
//!
//! ```text
//! let mut msix = VirtIoMsix::from_device_info(&dev_info)?;
//! let cfg_vec = msix.alloc_vector()?;
//! let q_vec   = msix.alloc_vector()?;
//!
//! let dest = msix.current_destination();
//! msix.program_vector(cfg_vec, &VirtIoMsix::compose_entry(dest, VEC_CFG));
//! msix.program_vector(q_vec,   &VirtIoMsix::compose_entry(dest, VEC_QUEUE));
//!
//! msix.enable();
//! msix.unmask_vector(cfg_vec);
//! msix.unmask_vector(q_vec);
//!
//! // Write vector numbers to the VirtIO common config registers
//! transport.regs().write32(REG_CONFIG_MSIX_VECTOR, cfg_vec as u32);
//! transport.select_queue(RX_QUEUE);
//! transport.regs().write32(REG_QUEUE_MSIX_VECTOR, q_vec as u32);
//! transport.select_queue(TX_QUEUE);
//! transport.regs().write32(REG_QUEUE_MSIX_VECTOR, q_vec as u32);
//! ```
//!
//! ## Reference
//!
//! - VirtIO 1.0 Specification, Section 4.1.4.3 (MSI-X Vector Configuration)
//! - PCI Local Bus Specification, Revision 3.0, Section 6.8 (MSI-X Capability)

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::mmu::map_device_mmio;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::{
    enumeration::{pci_capability_find, pci_capability_msix, MsixCapability, PciDeviceInfo},
    raw::{self, PciAddress},
};
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::Result;

// ─── Shared constants ───────────────────────────────────────────────────

/// MSI-X NO_VECTOR value — writing this to `config_msix_vector` or
/// `queue_msix_vector` disables MSI-X interrupts for that vector.
pub const MSIX_NO_VECTOR: u16 = 0xFFFF;

/// PCI capability ID for MSI-X (PCI 3.0 §6.8.2).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const CAPABILITY_ID_MSIX: u8 = 0x11;

/// Message Control register: MSI-X enable (bit 15).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MSIX_CTRL_ENABLE: u16 = 1 << 15;
/// Message Control register: function mask (bit 14).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;
/// Message Control register: table size mask (bits 0-10, value = N-1).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MSIX_CTRL_TABLE_SIZE_MASK: u16 = 0x7FF;

/// Vector Control register: per-vector mask (bit 0).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MSIX_VECTOR_MASKED: u32 = 1;

/// Size of a single MSI-X table entry in bytes.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const MSIX_ENTRY_BYTES: usize = 16;
/// Offset of the Message Address field within an entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ENTRY_ADDRESS: usize = 0;
/// Offset of the Message Data field within an entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ENTRY_DATA: usize = 8;
/// Offset of the Vector Control field within an entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const ENTRY_VECTOR_CONTROL: usize = 12;

/// x86_64 local APIC MMIO base used as the MSI message address (bits 31:20).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const APIC_MMIO_BASE: u32 = 0xFEE0_0000;

// ─── MSI-X manager ─────────────────────────────────────────────────────

/// MSI-X manager for a single PCI device.
///
/// Wraps the device's MSI-X capability and a mapping of its MSI-X table
/// BAR.  Vector numbers are allocated sequentially from the table; each
/// vector's 16-byte entry is programmed via [`Self::program_vector`].
/// MSI-X is enabled (with the function mask set) only after all entries
/// are programmed, so no spurious interrupts fire during setup.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct VirtIoMsix {
    addr: PciAddress,
    capability_offset: u8,
    /// Mapped MSI-X table base.
    table: *mut u8,
    /// Number of table entries (Table Size + 1).
    entry_count: u16,
    /// Next free vector number.
    next_vector: u16,
    /// `true` once the MSI-X enable bit has been set.
    enabled: bool,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Send for VirtIoMsix {}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl VirtIoMsix {
    /// Locate the device's MSI-X capability and map its table BAR.
    ///
    /// Returns `Err` when the device has no MSI-X capability, the table
    /// BAR is missing, or the table cannot be mapped.
    pub fn from_device_info(dev_info: &PciDeviceInfo) -> Result<Self> {
        let addr = dev_info.address();
        let Some(cap_offset) = pci_capability_find(addr, CAPABILITY_ID_MSIX) else {
            return Err(crate::Error::Unsupported);
        };
        let cap = unsafe { pci_capability_msix(addr, cap_offset) };

        let (bir, table_offset) = decode_table_bir(&cap);
        let Some(bar) = dev_info.bars.get(bir as usize) else {
            return Err(crate::Error::NotFound);
        };
        if bar.base_address == 0 {
            return Err(crate::Error::NotFound);
        }

        let table_phys = bar.base_address + table_offset;
        let entry_count = (cap.message_control & MSIX_CTRL_TABLE_SIZE_MASK) as u16 + 1;
        let table_bytes = (entry_count as usize) * MSIX_ENTRY_BYTES;

        let table =
            unsafe { map_device_mmio(table_phys, table_bytes) }.ok_or(crate::Error::OutOfMemory)?;

        Ok(Self {
            addr,
            capability_offset: cap.offset,
            table,
            entry_count,
            next_vector: 0,
            enabled: false,
        })
    }

    /// Number of usable vectors in the table.
    pub fn available(&self) -> usize {
        self.entry_count as usize
    }

    /// Allocate the next free vector number.
    ///
    /// Returns `Err` when the table is exhausted.
    pub fn alloc_vector(&mut self) -> Result<u16> {
        if self.next_vector >= self.entry_count {
            return Err(crate::Error::Unsupported);
        }
        let vector = self.next_vector;
        self.next_vector += 1;
        Ok(vector)
    }

    /// Destination (local APIC ID) used for MSI delivery on this CPU.
    pub fn current_destination(&self) -> u32 {
        crate::arch::x86_64::apic::lapic_id()
    }

    /// Compose a masked MSI-X table entry delivering `vector` to `dest`.
    ///
    /// The entry is created masked (Vector Control bit 0 set) so it does
    /// not fire until [`Self::unmask_vector`] is called.
    pub fn compose_entry(dest: u32, vector: u8) -> MsixTableEntry {
        MsixTableEntry {
            address_low: APIC_MMIO_BASE | ((dest & 0xFF) << 12),
            address_high: 0,
            data: vector as u32,
            vector_control: MSIX_VECTOR_MASKED,
        }
    }

    /// Write a 16-byte table entry for `vector`.
    pub fn program_vector(&mut self, vector: u16, entry: &MsixTableEntry) {
        let base = unsafe { self.table.add(vector as usize * MSIX_ENTRY_BYTES) };
        unsafe {
            base.cast::<u32>().write_volatile(entry.address_low);
            base.add(4).cast::<u32>().write_volatile(entry.address_high);
            base.add(8).cast::<u32>().write_volatile(entry.data);
            base.add(12)
                .cast::<u32>()
                .write_volatile(entry.vector_control);
        }
    }

    /// Read the current 16-byte table entry for `vector`.
    pub fn read_vector(&self, vector: u16) -> MsixTableEntry {
        let base = unsafe { self.table.add(vector as usize * MSIX_ENTRY_BYTES) };
        unsafe {
            MsixTableEntry {
                address_low: base.cast::<u32>().read_volatile(),
                address_high: base.add(4).cast::<u32>().read_volatile(),
                data: base.add(8).cast::<u32>().read_volatile(),
                vector_control: base.add(12).cast::<u32>().read_volatile(),
            }
        }
    }

    /// Enable MSI-X, keeping the function mask set so no interrupt fires
    /// until the driver has finished programming all vectors.
    pub fn enable(&mut self) {
        let ctrl = self.read_message_control();
        let ctrl = ctrl | MSIX_CTRL_ENABLE | MSIX_CTRL_FUNCTION_MASK;
        self.write_message_control(ctrl);
        self.enabled = true;
    }

    /// Clear the function mask, allowing unmasked vectors to deliver.
    pub fn clear_function_mask(&mut self) {
        let ctrl = self.read_message_control();
        self.write_message_control(ctrl & !MSIX_CTRL_FUNCTION_MASK);
    }

    /// Unmask (enable delivery of) a single vector.
    pub fn unmask_vector(&mut self, vector: u16) {
        let base = unsafe {
            self.table
                .add(vector as usize * MSIX_ENTRY_BYTES + ENTRY_VECTOR_CONTROL)
        };
        unsafe {
            base.cast::<u32>().write_volatile(0);
        }
    }

    /// Mask (disable delivery of) a single vector.
    pub fn mask_vector(&mut self, vector: u16) {
        let base = unsafe {
            self.table
                .add(vector as usize * MSIX_ENTRY_BYTES + ENTRY_VECTOR_CONTROL)
        };
        unsafe {
            base.cast::<u32>().write_volatile(MSIX_VECTOR_MASKED);
        }
    }

    /// Disable MSI-X entirely (clears the enable bit).  No further vectors
    /// fire until MSI-X is re-enabled.
    pub fn disable(&mut self) {
        let ctrl = self.read_message_control();
        self.write_message_control(ctrl & !MSIX_CTRL_ENABLE);
        self.enabled = false;
    }

    /// Returns `true` if MSI-X has been enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn read_message_control(&self) -> u16 {
        unsafe { raw::pci_config_read_u16(self.addr, self.capability_offset + 2) }
    }

    fn write_message_control(&self, value: u16) {
        unsafe { raw::pci_config_write_u16(self.addr, self.capability_offset + 2, value) };
    }
}

/// A single 16-byte MSI-X table entry.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    /// Message Address — low 32 bits.
    pub address_low: u32,
    /// Message Address — high 32 bits.
    pub address_high: u32,
    /// Message Data (vector number in bits 0-7 for local APIC delivery).
    pub data: u32,
    /// Vector Control (bit 0 = masked).
    pub vector_control: u32,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn decode_table_bir(cap: &MsixCapability) -> (u8, u64) {
    let bir = (cap.table_bir_and_offset & 0x7) as u8;
    let offset = (cap.table_bir_and_offset & 0xFFFF_FFF8) as u64;
    (bir, offset)
}

// ─── Host / non-x86_64 stub ─────────────────────────────────────────────

/// MSI-X manager for a single PCI device.
///
/// On non-x86_64 targets (and host test builds) the MSI-X capability is
/// not exercised: the constructor always returns [`None`] and every
/// method is a no-op, mirroring the bare-metal contract so callers stay
/// architecture-agnostic.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtIoMsix;

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
impl VirtIoMsix {
    /// Locate the device's MSI-X capability and map its table BAR.
    ///
    /// The parameter is intentionally generic: each architecture exposes its
    /// own PCI device-info type, and this stub never inspects it.
    pub fn from_device_info<T>(_dev_info: &T) -> crate::Result<Self> {
        Err(crate::Error::Unsupported)
    }

    /// Number of usable vectors in the table.
    pub fn available(&self) -> usize {
        0
    }

    /// Allocate the next free vector number.
    pub fn alloc_vector(&mut self) -> crate::Result<u16> {
        Err(crate::Error::Unsupported)
    }

    /// Destination (local APIC ID) used for MSI delivery on this CPU.
    pub fn current_destination(&self) -> u32 {
        0
    }

    /// Compose a masked MSI-X table entry delivering `vector` to `dest`.
    pub fn compose_entry(_dest: u32, _vector: u8) -> MsixTableEntry {
        MsixTableEntry {
            address_low: 0,
            address_high: 0,
            data: 0,
            vector_control: MSIX_VECTOR_MASKED,
        }
    }

    /// Write a 16-byte table entry for `vector`.
    pub fn program_vector(&mut self, _vector: u16, _entry: &MsixTableEntry) {}

    /// Read the current 16-byte table entry for `vector`.
    pub fn read_vector(&self, _vector: u16) -> MsixTableEntry {
        MsixTableEntry {
            address_low: 0,
            address_high: 0,
            data: 0,
            vector_control: 0,
        }
    }

    /// Enable MSI-X, keeping the function mask set.
    pub fn enable(&mut self) {}

    /// Clear the function mask, allowing unmasked vectors to deliver.
    pub fn clear_function_mask(&mut self) {}

    /// Unmask (enable delivery of) a single vector.
    pub fn unmask_vector(&mut self, _vector: u16) {}

    /// Mask (disable delivery of) a single vector.
    pub fn mask_vector(&mut self, _vector: u16) {}

    /// Disable MSI-X entirely.
    pub fn disable(&mut self) {}

    /// Returns `true` if MSI-X has been enabled.
    pub fn is_enabled(&self) -> bool {
        false
    }
}

/// A single 16-byte MSI-X table entry.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    /// Message Address — low 32 bits.
    pub address_low: u32,
    /// Message Address — high 32 bits.
    pub address_high: u32,
    /// Message Data (vector number in bits 0-7 for local APIC delivery).
    pub data: u32,
    /// Vector Control (bit 0 = masked).
    pub vector_control: u32,
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
const MSIX_VECTOR_MASKED: u32 = 1;

#[cfg(all(test, target_arch = "x86_64", target_os = "none"))]
mod tests {
    use super::*;

    #[test]
    fn no_vector_disables_msix() {
        assert_eq!(MSIX_NO_VECTOR, 0xFFFF);
    }

    #[test]
    fn compose_entry_masks_and_targets_dest() {
        let entry = VirtIoMsix::compose_entry(1, 46);
        assert_eq!(entry.address_low & 0x0FF0_0000, 1 << 12);
        assert_eq!(entry.address_high, 0);
        assert_eq!(entry.data, 46);
        assert_eq!(entry.vector_control, 1);
    }
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::MSIX_NO_VECTOR;

    #[test]
    fn no_vector_disables_msix() {
        assert_eq!(MSIX_NO_VECTOR, 0xFFFF);
    }
}
