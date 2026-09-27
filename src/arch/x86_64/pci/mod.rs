//! src/arch/x86_64/pci/mod.rs
//!
//! PCI/PCIe on x86_64.
//!
//! The architecture offers two ways to reach configuration space, and this
//! module is where that choice is written down:
//!
//! - [`raw`] — the legacy port pair at `0xCF8`/`0xCFC`.  Every x86_64 machine
//!   has it, it needs no mapping, and it is what the walk runs on here.
//! - The memory window QEMU's q35 machine describes through
//!   [`Q35_MMCONFIG_BASE`].  It covers bus 0 and reaches the extended PCIe
//!   registers the ports cannot address.
//!
//! The walk itself is not here.  It is architecture-neutral, it lives once in
//! [`crate::arch::pci`], and this module supplies the port-I/O backend for it —
//! so an x86_64 machine that reads through a window reads through exactly the
//! code aarch64 and riscv64 read through.

pub mod enumeration;
pub mod raw;

// The walk's vocabulary, re-exported so a caller naming this machine finds it.
pub use crate::arch::pci::cap_id;
pub use crate::arch::pci::EcamRegion;
pub use crate::arch::pci::MsiCapability;
pub use crate::arch::pci::MsixCapability;
pub use crate::arch::pci::PciBarInfo;
pub use crate::arch::pci::PciDeviceInfo;
pub use crate::arch::pci::PcieCapability;
pub use crate::arch::pci::PcieSlotCapabilities;

// The legacy port-I/O mechanism: its address type and register offsets are
// meaningful on every target (they are numbers), its port access is not.
pub use raw::PciAddress;
pub use raw::BAR0;
pub use raw::BAR1;
pub use raw::BAR2;
pub use raw::BAR3;
pub use raw::BAR4;
pub use raw::BAR5;
pub use raw::CAP_PTR;
pub use raw::CLASS;
pub use raw::COMMAND;
pub use raw::DEVICE_ID;
pub use raw::HEADER_TYPE;
pub use raw::INTERRUPT_LINE;
pub use raw::REVISION_ID;
pub use raw::STATUS;
pub use raw::VENDOR_ID;
pub use raw::VENDOR_ID_NONE;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_read_u16;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_read_u32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_read_u8;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_write_u16;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_write_u32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_config_write_u8;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::pci_device_exists;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::LegacyConfig;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::log_pci_devices;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pci_capability_find;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pci_capability_msi;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pci_capability_msix;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pci_capability_pcie;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pci_enumerate_buses;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pcie_check_hotplug_event;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::pcie_read_slot_status;

/// Base of the q35 root complex's memory-mapped configuration window.
///
/// It is a fixed address rather than a discovered one: q35 describes it in
/// its ACPI tables, and this kernel does not read those for it.
pub const Q35_MMCONFIG_BASE: usize = 0xB000_0000;

/// The q35 window, covering the bus its root complex puts devices on.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn ecam_discover() -> EcamRegion {
    EcamRegion::new(Q35_MMCONFIG_BASE, 0, 0)
}
