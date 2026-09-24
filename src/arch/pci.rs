//! src/arch/pci.rs
//!
//! The parts of PCI that are the same on every machine.
//!
//! A capability structure is a layout the specification defines, not
//! something an implementation chooses: `MsiCapability` is eight fields in a
//! fixed order on a machine that walks configuration space through `0xCF8`
//! and on one that maps it through an ECAM window.  What differs between the
//! architectures is only how a byte of configuration space is *read*, and
//! that stays in each `arch/<arch>/pci` module — as the walkers that return
//! these types do.
//!
//! The layouts used to be written out once per architecture.  They were
//! byte-identical, which is the best case for a copy: nothing had drifted
//! yet.  They live here now so that there is one place for the next field the
//! specification adds, and one place for a fourth architecture to look.

/// Configuration-space capability IDs (PCI Local Bus § 6.7).
pub mod cap_id {
    pub const MSI: u8 = 0x05;
    pub const MSI_X: u8 = 0x11;
    pub const PCI_EXPRESS: u8 = 0x10;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const POWER_MANAGEMENT: u8 = 0x01;
}

/// A parsed MSI capability structure.
#[derive(Debug, Clone, Copy)]
pub struct MsiCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// Message Control register (16-bit).
    pub message_control: u16,
    /// Message Address register (32-bit, low).
    pub message_address: u32,
    /// Message Upper Address (32-bit, only if 64-bit capable).
    pub message_upper_address: Option<u32>,
    /// Message Data register (16-bit).
    pub message_data: u16,
    /// Mask Bits register (32-bit, if per-vector masking).
    pub mask_bits: Option<u32>,
    /// Pending Bits register (32-bit, if per-vector masking).
    pub pending_bits: Option<u32>,
}

/// A parsed MSI-X capability structure.
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// Message Control register (16-bit).
    pub message_control: u16,
    /// BAR indicator (bits 2:0) and offset (bits 31:3) for the MSI-X Table.
    pub table_bir_and_offset: u32,
    /// BAR indicator (bits 2:0) and offset (bits 31:3) for the Pending Bit
    /// Array.
    pub pba_bir_and_offset: u32,
}

/// A parsed PCI Express capability structure.
#[derive(Debug, Clone, Copy)]
pub struct PcieCapability {
    /// Offset of the capability in config space.
    pub offset: u8,
    /// PCI Express Capabilities register (16-bit).
    pub pcie_caps: u16,
    /// Device Capabilities register (32-bit).
    pub device_caps: u32,
    /// Device Control register (16-bit).
    pub device_control: u16,
    /// Link Capabilities register (32-bit).
    pub link_caps: u32,
    /// Link Status register (16-bit).
    pub link_status: u16,
}

/// Information about the hotplug capabilities of a PCIe slot.
#[derive(Debug, Clone, Copy)]
pub struct PcieSlotCapabilities {
    /// Slot Capabilities register.
    pub slot_caps: u32,
    /// Slot Control register.
    pub slot_control: u16,
    /// Slot Status register.
    pub slot_status: u16,
    /// True if this port supports hotplug.
    pub hotplug_capable: bool,
    /// True if a card is currently present in the slot.
    pub presence_detect_state: bool,
}
