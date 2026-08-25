//! src/kernel/network/link/ethernet.rs
//!
//! Ethernet II frame parse / build and MAC address helpers.

use alloc::vec::Vec;

use crate::Error;
use crate::Result;

/// Size of a 48-bit MAC address in bytes.
pub const MAC_ADDRESS_SIZE: usize = 6;
/// Size of the Ethernet II header (destination + source + EtherType).
pub const ETHERNET_HEADER_SIZE: usize = 14;

/// A 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The all-zeroes MAC address.
    pub const ZERO: Self = Self([0; 6]);
    /// The Ethernet broadcast address (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// Create a MAC address from a raw byte array.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Ethernet II EtherType values (IEEE 802.3 EtherType field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtherType {
    /// Internet Protocol version 4 (`0x0800`).
    Ipv4,
    /// Address Resolution Protocol (`0x0806`).
    Arp,
    /// Internet Protocol version 6 (`0x86DD`).
    Ipv6,
    /// VLAN-tagged frame (`0x8100`).
    Vlan,
    /// Any other EtherType value.
    Other(u16),
}

impl EtherType {
    /// The 16-bit EtherType value as it appears on the wire.
    pub const fn value(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86DD,
            Self::Vlan => 0x8100,
            Self::Other(value) => value,
        }
    }

    /// Map a raw 16-bit EtherType value to an [`EtherType`].
    pub const fn from_value(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            0x8100 => Self::Vlan,
            other => Self::Other(other),
        }
    }
}

/// An Ethernet II frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Create a new Ethernet frame with the given fields.
    pub fn new(
        destination: MacAddress,
        source: MacAddress,
        ethertype: EtherType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            destination,
            source,
            ethertype,
            payload,
        }
    }
}

// ─── Parse / build ───

/// Parse a raw byte slice into an `EthernetFrame`.
///
/// Returns an error if the slice is shorter than [`ETHERNET_HEADER_SIZE`]
/// bytes.
pub fn parse_frame(data: &[u8]) -> Result<EthernetFrame> {
    if data.len() < ETHERNET_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let destination = MacAddress([data[0], data[1], data[2], data[3], data[4], data[5]]);
    let source = MacAddress([data[6], data[7], data[8], data[9], data[10], data[11]]);
    let ethertype = EtherType::from_value(u16::from_be_bytes([data[12], data[13]]));
    Ok(EthernetFrame {
        destination,
        source,
        ethertype,
        payload: data[ETHERNET_HEADER_SIZE..].to_vec(),
    })
}

/// Serialize an `EthernetFrame` into its raw byte representation.
///
/// Returns an error if the payload is too large to fit in a single
/// Ethernet frame.
pub fn build_frame(frame: &EthernetFrame) -> Result<Vec<u8>> {
    // Standard Ethernet MTU is 1500 bytes of payload; accept jumbo frames
    // up to the 16-bit length limit.
    if frame.payload.len() > u16::MAX as usize - ETHERNET_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let mut buf = Vec::with_capacity(ETHERNET_HEADER_SIZE + frame.payload.len());
    buf.extend_from_slice(&frame.destination.0);
    buf.extend_from_slice(&frame.source.0);
    buf.extend_from_slice(&frame.ethertype.value().to_be_bytes());
    buf.extend_from_slice(&frame.payload);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_build_round_trips() {
        let frame = EthernetFrame::new(
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            EtherType::Ipv4,
            vec![0x45, 0x00, 0x00, 0x14],
        );
        let raw = build_frame(&frame).expect("build");
        assert_eq!(raw.len(), ETHERNET_HEADER_SIZE + 4);
        let parsed = parse_frame(&raw).expect("parse");
        assert_eq!(parsed.destination, frame.destination);
        assert_eq!(parsed.source, frame.source);
        assert_eq!(parsed.ethertype, EtherType::Ipv4);
        assert_eq!(parsed.payload, frame.payload);
    }

    #[test]
    fn parse_rejects_short_frame() {
        assert_eq!(parse_frame(&[0; 13]), Err(Error::InvalidArgument));
    }

    #[test]
    fn ethertype_maps_values() {
        assert_eq!(EtherType::Ipv4.value(), 0x0800);
        assert_eq!(EtherType::Arp.value(), 0x0806);
        assert_eq!(EtherType::Ipv6.value(), 0x86DD);
        assert_eq!(EtherType::from_value(0x0800), EtherType::Ipv4);
        assert_eq!(EtherType::from_value(0x1234), EtherType::Other(0x1234));
    }
}
