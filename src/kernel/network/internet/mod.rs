//! src/kernel/network/internet/mod.rs
//!
//! Internet-layer modules: IP, ARP, ICMP, IGMP, MLD, ICMPv6/NDP, and
//! educational protocol modules (IPv4 options, Mobile IP, RSVP).
pub mod arp;
pub mod fragments;
pub mod icmp;
pub mod icmpv6;
pub mod igmp;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod mld;
pub mod nat;
pub mod pmtu;

// Educational networking modules — see individual files for pedagogical
// context.
#[cfg(any(test, feature = "educational_networking"))]
pub mod ip_options;
#[cfg(any(test, feature = "educational_networking"))]
pub mod mobile_ip;
#[cfg(any(test, feature = "educational_networking"))]
pub mod rsvp;
