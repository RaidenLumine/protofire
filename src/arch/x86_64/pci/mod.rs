//! src/arch/x86_64/pci/mod.rs
//!
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

pub use enumeration::cap_id;
pub use enumeration::MsiCapability;
pub use enumeration::MsixCapability;
pub use enumeration::PciBarInfo;
pub use enumeration::PciDeviceInfo;
pub use enumeration::PcieCapability;

pub use ecam::EcamRegion;
pub use ecam::Q35_MMCONFIG_BASE;

// Re-export bare-metal functions (only available on x86_64 bare-metal).
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
pub use ecam::ecam_discover;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_read_u16;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_read_u32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_read_u8;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_write_u16;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_write_u32;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use ecam::ecam_write_u8;
