//! src/kernel/network/internet/ip.rs
//! Common IP address types for dual-stack (IPv4 / IPv6) networking.
//!
//! `IpAddress` is the canonical address representation used across the
//! public network API.  Protocol-layer modules (`ipv4`, `ipv6`) may also
//! use their native `[u8; 4]` / `[u8; 16]` types internally for wire-format
//! operations.

use core::fmt;

// ─── IpAddress ──────────────────────────────────────────────────────────

/// An IP address, either version 4 or version 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddress {
    /// A 32-bit IPv4 address in network byte order.
    V4([u8; 4]),
    /// A 128-bit IPv6 address in network byte order.
    V6([u8; 16]),
}

impl IpAddress {
    // ── well-known addresses ─────────────────────────────────────────

    /// IPv4 broadcast address `255.255.255.255`.
    pub const IPV4_BROADCAST: Self = IpAddress::V4([255, 255, 255, 255]);

    /// IPv4 unspecified address `0.0.0.0`.
    pub const IPV4_UNSPECIFIED: Self = IpAddress::V4([0u8; 4]);

    /// IPv6 unspecified address `::`.
    pub const IPV6_UNSPECIFIED: Self = IpAddress::V6([0u8; 16]);

    /// IPv6 link-local all-nodes multicast `ff02::1`.
    pub const IPV6_ALL_NODES_MULTICAST: Self = IpAddress::V6([
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    /// IPv6 link-local all-routers multicast `ff02::2`.
    pub const IPV6_ALL_ROUTERS_MULTICAST: Self = IpAddress::V6([
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    // ── predicates ───────────────────────────────────────────────────

    /// Returns `true` if this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddress::V4(_))
    }

    /// Returns `true` if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpAddress::V6(_))
    }

    /// Returns `true` if this is the unspecified address (`0.0.0.0` or `::`).
    pub fn is_unspecified(&self) -> bool {
        match self {
            IpAddress::V4(addr) => *addr == [0u8; 4],
            IpAddress::V6(addr) => *addr == [0u8; 16],
        }
    }

    /// Returns `true` if this is a multicast address.
    ///
    /// IPv4 multicast: first octet 224–239 (class D).
    /// IPv6 multicast: first octet is `0xff`.
    pub fn is_multicast(&self) -> bool {
        match self {
            IpAddress::V4(addr) => addr[0] >= 224 && addr[0] <= 239,
            IpAddress::V6(addr) => addr[0] == 0xff,
        }
    }

    /// Returns `true` if this is an IPv6 link-local address (`fe80::/10`).
    pub fn is_link_local_v6(&self) -> bool {
        match self {
            IpAddress::V6(addr) => addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80,
            _ => false,
        }
    }

    /// Returns `true` if this is an IPv6 solicited-node multicast address
    /// (`ff02::1:ffXX:XXXX`).
    pub fn is_solicited_node_multicast(&self) -> bool {
        match self {
            IpAddress::V6(addr) => {
                addr[0] == 0xff
                    && addr[1] == 0x02
                    && addr[2] == 0x00
                    && addr[3] == 0x00
                    && addr[4] == 0x00
                    && addr[5] == 0x00
                    && addr[6] == 0x00
                    && addr[7] == 0x00
                    && addr[8] == 0x00
                    && addr[9] == 0x00
                    && addr[10] == 0x00
                    && addr[11] == 0x01
                    && addr[12] == 0xff
            }
            _ => false,
        }
    }

    /// Return the IPv4 bytes, or `None` if this is an IPv6 address.
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        match self {
            IpAddress::V4(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Return the IPv6 bytes, or `None` if this is an IPv4 address.
    pub fn as_ipv6(&self) -> Option<[u8; 16]> {
        match self {
            IpAddress::V6(addr) => Some(*addr),
            _ => None,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(addr) => {
                write!(f, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            IpAddress::V6(addr) => {
                // RFC 5952 compressed format
                write!(
                    f,
                    "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                    u16::from_be_bytes([addr[0], addr[1]]),
                    u16::from_be_bytes([addr[2], addr[3]]),
                    u16::from_be_bytes([addr[4], addr[5]]),
                    u16::from_be_bytes([addr[6], addr[7]]),
                    u16::from_be_bytes([addr[8], addr[9]]),
                    u16::from_be_bytes([addr[10], addr[11]]),
                    u16::from_be_bytes([addr[12], addr[13]]),
                    u16::from_be_bytes([addr[14], addr[15]]),
                )
            }
        }
    }
}

impl From<[u8; 4]> for IpAddress {
    fn from(addr: [u8; 4]) -> Self {
        IpAddress::V4(addr)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(addr: [u8; 16]) -> Self {
        IpAddress::V6(addr)
    }
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_address_v4_is_ipv4() {
        let addr = IpAddress::V4([10, 0, 2, 15]);
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.as_ipv4(), Some([10, 0, 2, 15]));
        assert_eq!(addr.as_ipv6(), None);
    }

    #[test]
    fn ip_address_v6_is_ipv6() {
        let addr = IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.as_ipv4(), None);
    }

    #[test]
    fn ip_address_display_v4() {
        let addr = IpAddress::V4([192, 168, 1, 1]);
        assert_eq!(alloc::format!("{}", addr), "192.168.1.1");
    }

    #[test]
    fn ip_address_display_v6() {
        let addr = IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            alloc::format!("{}", addr),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn ip_address_unspecified_detection() {
        assert!(IpAddress::V4([0, 0, 0, 0]).is_unspecified());
        assert!(IpAddress::V6([0u8; 16]).is_unspecified());
        assert!(!IpAddress::V4([10, 0, 2, 15]).is_unspecified());
        assert!(
            !IpAddress::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_unspecified()
        );
    }

    #[test]
    fn ip_address_multicast_detection() {
        // IPv4 multicast (224.0.0.0 - 239.255.255.255)
        assert!(IpAddress::V4([224, 0, 0, 1]).is_multicast());
        assert!(IpAddress::V4([239, 255, 255, 255]).is_multicast());
        assert!(!IpAddress::V4([10, 0, 2, 15]).is_multicast());
        assert!(!IpAddress::V4([223, 255, 255, 255]).is_multicast());
        assert!(!IpAddress::V4([240, 0, 0, 0]).is_multicast());

        // IPv6 multicast (ff00::/8)
        assert!(
            IpAddress::V6([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_multicast()
        );
        assert!(
            !IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_multicast()
        );
    }

    #[test]
    fn ip_address_link_local_v6_detection() {
        // fe80::1
        let ll = IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(ll.is_link_local_v6());
        // febf::1 (still fe80::/10)
        let ll2 = IpAddress::V6([0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(ll2.is_link_local_v6());
        // 2001:db8::1 (not link-local)
        let global = IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!global.is_link_local_v6());
    }

    #[test]
    fn ip_address_solicited_node_multicast_detection() {
        // ff02::1:ff00:0001
        let sn = IpAddress::V6([
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0x00, 0x00, 0x01,
        ]);
        assert!(sn.is_solicited_node_multicast());
        // ff02::2 (all-routers, not solicited-node)
        assert!(!IpAddress::IPV6_ALL_ROUTERS_MULTICAST.is_solicited_node_multicast());
    }

    #[test]
    fn ip_address_from_conversions() {
        let v4: IpAddress = [10, 0, 2, 15].into();
        assert_eq!(v4, IpAddress::V4([10, 0, 2, 15]));

        let v6: IpAddress = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into();
        assert_eq!(
            v6,
            IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn ip_address_well_known_constants() {
        assert_eq!(
            IpAddress::IPV4_BROADCAST,
            IpAddress::V4([255, 255, 255, 255])
        );
        assert_eq!(IpAddress::IPV4_UNSPECIFIED, IpAddress::V4([0, 0, 0, 0]));
        assert_eq!(IpAddress::IPV6_UNSPECIFIED, IpAddress::V6([0u8; 16]));
    }

    #[test]
    fn ip_address_eq_and_clone() {
        let a = IpAddress::V4([10, 0, 2, 1]);
        let b = a;
        assert_eq!(a, b);
        let c = a;
        assert_eq!(a, c);
        assert_ne!(a, IpAddress::V4([10, 0, 2, 2]));
        assert_ne!(IpAddress::V4([10, 0, 2, 1]), IpAddress::V6([0u8; 16]));
    }
}
