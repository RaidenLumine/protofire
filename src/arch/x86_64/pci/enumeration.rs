//! src/arch/x86_64/pci/enumeration.rs
//!
//! The x86_64 binding of the shared configuration-space walk.
//!
//! The walk — presence probe, BAR sizing, capability chain, bus scan — is the
//! same on every mechanism and lives once in
//! [`crate::arch::pci::walk`].  What is left here is this machine's spelling
//! of its entry points: the configuration space an x86_64 scan reads is the
//! legacy port pair, so every function below supplies [`LegacyConfig`] and the
//! [`PciAddress`] the port primitives take.
//!
//! It used to hold a second copy of the walk, written against those
//! primitives.  The copy had drifted: it masked the multifunction bit out of
//! the header type it stored, so `is_multifunction()` was always false on this
//! architecture and the enumeration report never marked a multi-function
//! device.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::vec::Vec;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::raw::LegacyConfig;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use super::raw::PciAddress;

pub use crate::arch::pci::PciBarInfo;
pub use crate::arch::pci::PciDeviceInfo;

// The layouts are the specification's, not this machine's: one definition
// lives in `crate::arch::pci`, and this module re-exports it so that callers
// keep naming the machine they asked.
pub use crate::arch::pci::cap_id;
pub use crate::arch::pci::MsiCapability;
pub use crate::arch::pci::MsixCapability;
pub use crate::arch::pci::PcieCapability;
pub use crate::arch::pci::PcieSlotCapabilities;

/// Enumerate every function on every bus the port mechanism addresses.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pci_enumerate_buses() -> Vec<PciDeviceInfo> {
    crate::arch::pci::pci_enumerate_buses(&LegacyConfig, 0..=255)
}

/// Print a summary of an enumeration.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn log_pci_devices(devices: &[PciDeviceInfo]) {
    crate::arch::pci::log_pci_devices(&LegacyConfig, devices)
}

/// Offset of the first capability of `cap_id` on this function, if any.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pci_capability_find(addr: PciAddress, cap_id: u8) -> Option<u8> {
    crate::arch::pci::pci_capability_find(
        &LegacyConfig,
        addr.bus,
        addr.device,
        addr.function,
        cap_id,
    )
}

/// Parse the MSI capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid MSI capability of this function, as
/// [`pci_capability_find`] returns.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_msi(addr: PciAddress, offset: u8) -> MsiCapability {
    // SAFETY: the caller's contract is the shared function's — `offset` names
    // a valid MSI capability — and the configuration space is this machine's.
    unsafe {
        crate::arch::pci::pci_capability_msi(
            &LegacyConfig,
            addr.bus,
            addr.device,
            addr.function,
            offset,
        )
    }
}

/// Parse the MSI-X capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid MSI-X capability of this function,
/// as [`pci_capability_find`] returns.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_msix(addr: PciAddress, offset: u8) -> MsixCapability {
    // SAFETY: as `pci_capability_msi` above, for the MSI-X layout.
    unsafe {
        crate::arch::pci::pci_capability_msix(
            &LegacyConfig,
            addr.bus,
            addr.device,
            addr.function,
            offset,
        )
    }
}

/// Parse the PCI Express capability at `offset`.
///
/// # Safety
///
/// `offset` must be the offset of a valid PCIe capability of this function,
/// as [`pci_capability_find`] returns.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn pci_capability_pcie(addr: PciAddress, offset: u8) -> PcieCapability {
    // SAFETY: as `pci_capability_msi` above, for the PCIe layout.
    unsafe {
        crate::arch::pci::pci_capability_pcie(
            &LegacyConfig,
            addr.bus,
            addr.device,
            addr.function,
            offset,
        )
    }
}

/// Read the slot capabilities and status of a PCIe port.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pcie_read_slot_status(addr: PciAddress) -> Option<PcieSlotCapabilities> {
    crate::arch::pci::pcie_read_slot_status(&LegacyConfig, addr.bus, addr.device, addr.function)
}

/// Check a PCIe slot for a hotplug event.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn pcie_check_hotplug_event(addr: PciAddress) -> Option<bool> {
    crate::arch::pci::pcie_check_hotplug_event(&LegacyConfig, addr.bus, addr.device, addr.function)
}
