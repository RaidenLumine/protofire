//! PCI/PCIe subsystem: raw config-space access, bus enumeration,
//! capability walking, and ECAM (MMCONFIG) support.
//!
//! ## Submodules
//!
//! - `raw` — Legacy IO-port config-space access (0xCF8/0xCFC).
//! - `enumeration` — Bus scan, BAR probing, capability traversal.
//! - `ecam` — PCI Express memory-mapped configuration (MMCONFIG).

pub mod ecam;
pub mod enumeration;
pub mod raw;

// Re-export types and constants (always available).
pub use raw::{
    PciAddress, BAR0, BAR1, BAR2, BAR3, BAR4, BAR5, CAP_PTR, CLASS, COMMAND, DEVICE_ID,
    HEADER_TYPE, INTERRUPT_LINE, REVISION_ID, STATUS, VENDOR_ID, VENDOR_ID_NONE,
};

pub use enumeration::{
    cap_id, MsiCapability, MsixCapability, PciBarInfo, PciDeviceInfo, PcieCapability,
};

pub use ecam::{EcamRegion, Q35_MMCONFIG_BASE};

// Re-export bare-metal functions (only available on x86_64 bare-metal).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use raw::{
    pci_config_read_u16, pci_config_read_u32, pci_config_read_u8, pci_config_write_u16,
    pci_config_write_u32, pci_config_write_u8, pci_device_exists,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use enumeration::{
    log_pci_devices, pci_capability_find, pci_capability_msi, pci_capability_msix,
    pci_capability_pcie, pci_enumerate_buses,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::{
    ecam_discover, ecam_read_u16, ecam_read_u32, ecam_read_u8, ecam_write_u16, ecam_write_u32,
    ecam_write_u8,
};
