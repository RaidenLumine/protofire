//! MSI/MSI-X interrupt composition and programming helpers for x86_64.
//!
//! Message Signalled Interrupts (MSI) allow PCI/PCIe devices to deliver
//! interrupts by writing to a special address range in the LAPIC MMIO
//! space, bypassing the IOAPIC entirely.
//!
//! ## MSI Address Format (x86_64)
//!
//! Bits 31:20 — 0xFEE (fixed)
//! Bits 19:12 — Destination ID (APIC ID << 4 for physical mode)
//! Bits 11:4  — Reserved (0)
//! Bits 3     — Redirection Hint (0)
//! Bits 2     — Destination Mode (0 = physical, 1 = logical)
//! Bits 1:0   — 0
//!
//! ## MSI Data Format (x86_64)
//!
//! Bits 15    — Extended Interrupt (0)
//! Bits 14    — Level (0 for edge-triggered on FSB interrupts)
//! Bits 13    — Reserved (0)
//! Bits 12    — Delivery Status (0)
//! Bits 10:8  — Delivery Mode (000 = Fixed, 001 = Lowest, 010 = SMI, 100 = NMI)
//! Bits 7:0   — Vector

// ---------------------------------------------------------------------------
// MSI composition
// ---------------------------------------------------------------------------

/// Delivery mode: Fixed.
pub const MSI_DELIVERY_FIXED: u32 = 0x00;
/// Delivery mode: Lowest Priority.
pub const MSI_DELIVERY_LOWEST: u32 = 0x01;

/// Compose the MSI message address for a given destination LAPIC ID.
///
/// Physical destination mode, no redirection.
pub fn msi_compose_address(dest_apic_id: u8) -> u32 {
    let dest = (dest_apic_id as u32 & 0xFF) << 12;
    0xFEE0_0000u32 | dest
}

/// Compose the MSI message data for a given vector and delivery mode.
///
/// Edge-triggered, no level.
pub fn msi_compose_data(vector: u8, delivery_mode: u32) -> u32 {
    (vector as u32 & 0xFF) | ((delivery_mode & 0x07) << 8)
}

// ---------------------------------------------------------------------------
// MSI-X BAR access helpers
// ---------------------------------------------------------------------------

/// An MSI-X table entry (16 bytes in device MMIO or memory).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MsixTableEntry {
    pub message_address_low: u32,
    pub message_address_high: u32,
    pub message_data: u32,
    pub vector_control: u32,
}

impl MsixTableEntry {
    /// Mask bit in the Vector Control field (bit 0).
    pub const MASK_BIT: u32 = 1;

    /// Returns `true` if the entry is masked.
    pub fn is_masked(&self) -> bool {
        self.vector_control & Self::MASK_BIT != 0
    }

    /// Construct a new masked entry (all zeros, masked).
    pub fn masked() -> Self {
        Self {
            message_address_low: 0,
            message_address_high: 0,
            message_data: 0,
            vector_control: Self::MASK_BIT,
        }
    }
}

/// Set up an MSI-X table entry for a given vector and destination.
pub fn msix_compose_entry(dest_apic_id: u8, vector: u8, delivery_mode: u32) -> MsixTableEntry {
    MsixTableEntry {
        message_address_low: msi_compose_address(dest_apic_id),
        message_address_high: 0,
        message_data: msi_compose_data(vector, delivery_mode),
        vector_control: 0, // unmasked
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_address_for_lapic_id_0() {
        assert_eq!(msi_compose_address(0), 0xFEE0_0000);
    }

    #[test]
    fn msi_address_for_lapic_id_1() {
        assert_eq!(msi_compose_address(1), 0xFEE0_1000);
    }

    #[test]
    fn msi_data_vector_32_fixed() {
        let data = msi_compose_data(32, MSI_DELIVERY_FIXED);
        assert_eq!(data & 0xFF, 32);
        assert_eq!((data >> 8) & 0x07, MSI_DELIVERY_FIXED);
    }

    #[test]
    fn msix_entry_is_masked() {
        let entry = MsixTableEntry::masked();
        assert!(entry.is_masked());
    }

    #[test]
    fn msix_entry_compose() {
        let entry = msix_compose_entry(0, 44, MSI_DELIVERY_FIXED);
        assert!(!entry.is_masked());
        assert_eq!(entry.message_address_low, 0xFEE0_0000);
        assert_eq!(entry.message_data & 0xFF, 44);
    }
}
