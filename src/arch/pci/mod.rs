//! src/arch/pci/mod.rs
//!
//! The parts of PCI that are the same on every machine.
//!
//! A capability structure is a layout the specification defines, not
//! something an implementation chooses: `MsiCapability` is eight fields in a
//! fixed order on a machine that walks configuration space through `0xCF8`
//! and on one that maps it through an ECAM window.  What differs between the
//! architectures is only how a byte of configuration space is *read*, and
//! that is the one thing a backend here answers.
//!
//! The layouts used to be written out once per architecture.  They were
//! byte-identical, which is the best case for a copy: nothing had drifted
//! yet.  They live here now so that there is one place for the next field the
//! specification adds, and one place for a fourth architecture to look.
//!
//! The *walk* is the same story one level up.  Finding the functions on a
//! bus, probing their BARs, following the capability chain — none of that
//! depends on the mechanism that fetches a register, and it had been written
//! three times: once over the legacy port pair for x86_64, and once over ECAM
//! for each of aarch64 and riscv64, the last two near-identical.  It is one
//! copy now, in [`walk`], written against [`ConfigSpace`]: a backend answers
//! "what is in this register", and the walk knows what the answer means.
//!
//! What stays per-architecture is the part that really is the machine's: which
//! window holds configuration space and how it gets mapped.  That is
//! [`ecam::EcamRegion`] on aarch64 and riscv64 (discovered from the device
//! tree), the legacy port pair on x86_64, and a fixed `Q35_MMCONFIG_BASE`
//! window for the machine that has one.

pub mod ecam;
pub mod walk;

pub use ecam::EcamRegion;
pub use walk::find_device;
pub use walk::log_pci_devices;
pub use walk::pci_capability_find;
pub use walk::pci_capability_msi;
pub use walk::pci_capability_msix;
pub use walk::pci_capability_pcie;
pub use walk::pci_device_exists;
pub use walk::pci_enable_memory_and_bus_master;
pub use walk::pci_enumerate_buses;
pub use walk::pci_program_bar_64;
pub use walk::pci_read_bar_64;
pub use walk::pcie_check_hotplug_event;
pub use walk::pcie_read_slot_status;
pub use walk::probe_bar_size;
pub use walk::PciBarInfo;
pub use walk::PciDeviceInfo;

/// Configuration-space register offsets of the standard header (PCI Local Bus
/// § 6.1), in the width the ECAM arithmetic wants.
///
/// The legacy port-I/O backend is byte-addressed and declares its own offsets
/// for that API, but it narrows *these* — so a register the specification
/// moves is a register that moves in one place.
pub mod reg {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const CLASS: u16 = 0x0B;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BAR0: u16 = 0x10;
    pub const BAR1: u16 = 0x14;
    pub const BAR2: u16 = 0x18;
    pub const BAR3: u16 = 0x1C;
    pub const BAR4: u16 = 0x20;
    pub const BAR5: u16 = 0x24;
    pub const CAP_PTR: u16 = 0x34;
    pub const INTERRUPT_LINE: u16 = 0x3C;

    /// Vendor ID an absent function answers with.
    pub const VENDOR_ID_NONE: u16 = 0xFFFF;

    /// COMMAND bit 1: respond to memory space.
    pub const COMMAND_MEMORY: u16 = 1 << 1;
    /// COMMAND bit 2: act as a bus master.
    pub const COMMAND_BUS_MASTER: u16 = 1 << 2;
}

/// One function's configuration space.
///
/// The walk is written against this rather than against a mechanism: what a
/// register *means* is the specification's business, and how a byte of it is
/// fetched is the machine's.
///
/// # Safety
///
/// Every method is `unsafe` for one reason: forming an address is not the
/// same as having something live behind it.  What "live" means is the
/// backend's to say — an ECAM window has to be mapped before it can be read,
/// while the legacy port pair is fixed by the architecture and present on
/// every machine that has one — and it is that precondition, not the address
/// arithmetic, that a caller owes.
///
/// `bus`/`device`/`function` do *not* have to name a function that exists — a
/// read of an absent one answers all-ones on both backends, and that is what
/// the walk's presence probe reads.  `offset` must lie inside the
/// configuration space the backend describes; the dword-aligned forms require
/// `offset & 0x3 == 0`.
pub trait ConfigSpace: Copy {
    /// Read one byte.
    ///
    /// # Safety
    ///
    /// See the trait documentation.
    unsafe fn read_u8(&self, bus: u8, device: u8, function: u8, offset: u16) -> u8;

    /// Read two bytes.
    ///
    /// # Safety
    ///
    /// See the trait documentation.
    unsafe fn read_u16(&self, bus: u8, device: u8, function: u8, offset: u16) -> u16;

    /// Read four bytes.
    ///
    /// # Safety
    ///
    /// See the trait documentation.
    unsafe fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32;

    /// Write one byte.
    ///
    /// # Safety
    ///
    /// See the trait documentation, and: the caller must know what the
    /// register holds, because a write is not recoverable by reading.
    unsafe fn write_u8(&self, bus: u8, device: u8, function: u8, offset: u16, value: u8);

    /// Write two bytes.
    ///
    /// # Safety
    ///
    /// See [`ConfigSpace::write_u8`].
    unsafe fn write_u16(&self, bus: u8, device: u8, function: u8, offset: u16, value: u16);

    /// Write four bytes.
    ///
    /// # Safety
    ///
    /// See [`ConfigSpace::write_u8`].
    unsafe fn write_u32(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32);
}

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
