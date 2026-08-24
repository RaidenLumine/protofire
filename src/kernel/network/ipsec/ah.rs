//! src/kernel/network/ipsec/ah.rs
//!
//! AH (RFC 4302) with HMAC-SHA256-128 (RFC 4868).
//!
//! Wire layout (28 bytes):
//! ```text
//! [ Next Header(1) ][ Payload Len(1) ][ Reserved(2) ][ SPI(4) ][ Seq(4) ][ ICV(16) ]
//! ```
//! The ICV is `HMAC-SHA256(key, msg)[..16]` where `msg` is the IP header
//! with its mutable fields zeroed, followed by the AH header with its ICV
//! zeroed, followed by the protected payload.

use alloc::vec::Vec;

use crate::kernel::crypto::hmac_sha256;
use crate::{Error, Result};

use super::IpsecSa;

/// AH header size with a 16-byte ICV.
pub const AH_HEADER_SIZE: usize = 28;
/// ICV size (truncated HMAC-SHA256).
pub const AH_ICV_SIZE: usize = 16;

/// Zero the mutable IPv4 header fields that are excluded from the AH ICV
/// (RFC 4302 §3.3.2.2): TOS, flags/fragment-offset, TTL, and the header
/// checksum.
pub fn ipv4_mutable_zeroed(header: &[u8]) -> Vec<u8> {
    let mut copy = header.to_vec();
    if copy.len() >= 12 {
        copy[1] = 0; // TOS
        copy[6] = 0; // flags high
        copy[7] = 0; // fragment offset low
        copy[8] = 0; // TTL
        copy[10] = 0; // checksum high
        copy[11] = 0; // checksum low
    }
    copy
}

/// Zero the mutable IPv6 header field excluded from the AH ICV: the hop
/// limit.  (Routing header Segments Left would also be zeroed if present.)
pub fn ipv6_mutable_zeroed(header: &[u8]) -> Vec<u8> {
    let mut copy = header.to_vec();
    if copy.len() >= 8 {
        copy[7] = 0; // hop limit
    }
    copy
}

/// Build an AH header for sequence `seq`, protecting `inner` with the given
/// `next_header`.  `ip_header_mutable_zeroed` is the outer IP header with
/// mutable fields zeroed (see the `*_mutable_zeroed` helpers).
pub fn build_ah(
    sa: &IpsecSa,
    seq: u64,
    next_header: u8,
    ip_header_mutable_zeroed: &[u8],
    inner: &[u8],
) -> Result<Vec<u8>> {
    let mut ah = Vec::with_capacity(AH_HEADER_SIZE);
    ah.push(next_header);
    // Payload length = (AH length in 32-bit words) - 2 = 28/4 - 2 = 5.
    ah.push(5);
    ah.extend_from_slice(&[0u8; 2]); // reserved
    ah.extend_from_slice(&sa.spi.to_be_bytes());
    ah.extend_from_slice(&(seq as u32).to_be_bytes());
    ah.extend_from_slice(&[0u8; AH_ICV_SIZE]); // ICV placeholder

    let mut mac_input = Vec::with_capacity(ip_header_mutable_zeroed.len() + ah.len() + inner.len());
    mac_input.extend_from_slice(ip_header_mutable_zeroed);
    mac_input.extend_from_slice(&ah);
    mac_input.extend_from_slice(inner);
    let mac = hmac_sha256(&sa.auth_key, &mac_input);
    ah[AH_HEADER_SIZE - AH_ICV_SIZE..].copy_from_slice(&mac[..AH_ICV_SIZE]);
    Ok(ah)
}

/// Verify the ICV of a received AH header.  `ah_with_icv` is the 28-byte AH
/// header as received.
pub fn verify_ah(
    sa: &IpsecSa,
    ip_header_mutable_zeroed: &[u8],
    ah_with_icv: &[u8],
    inner: &[u8],
) -> Result<()> {
    if ah_with_icv.len() < AH_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let mut ah_zeroed = ah_with_icv[..AH_HEADER_SIZE].to_vec();
    ah_zeroed[AH_HEADER_SIZE - AH_ICV_SIZE..].fill(0);

    let mut mac_input =
        Vec::with_capacity(ip_header_mutable_zeroed.len() + ah_zeroed.len() + inner.len());
    mac_input.extend_from_slice(ip_header_mutable_zeroed);
    mac_input.extend_from_slice(&ah_zeroed);
    mac_input.extend_from_slice(inner);
    let mac = hmac_sha256(&sa.auth_key, &mac_input);

    let received = &ah_with_icv[AH_HEADER_SIZE - AH_ICV_SIZE..AH_HEADER_SIZE];
    if constant_time_bytes_eq(received, &mac[..AH_ICV_SIZE]) {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Constant-time byte comparison (works for any equal-length buffers).
fn constant_time_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sa(spi: u32, key: Vec<u8>) -> IpsecSa {
        IpsecSa {
            id: 1,
            spi,
            mode: super::super::IpsecMode::Transport,
            proto: super::super::IpsecProto::Ah,
            aead: None,
            auth: Some(super::super::AuthAlgo::HmacSha256),
            enc_key: Vec::new(),
            salt: Vec::new(),
            auth_key: key,
            tunnel_src: None,
            tunnel_dst: None,
            seq_counter: 0,
            replay_window: 0,
            replay_last: 0,
            packets_in: 0,
            packets_out: 0,
            bytes_in: 0,
            bytes_out: 0,
            lifetime_bytes: 0,
            lifetime_ticks: 0,
        }
    }

    #[test]
    fn build_and_verify_round_trip() {
        let sa = make_sa(0x01020304, (0x10u8..0x30).collect());
        // A minimal 20-byte IPv4 header.
        let mut ip_header = [0u8; 20];
        ip_header[0] = 0x45;
        ip_header[8] = 64; // TTL (mutable, must not affect the ICV)
        let zeroed = ipv4_mutable_zeroed(&ip_header);
        assert_eq!(zeroed[8], 0);

        let inner = b"ah protected payload";
        let ah = build_ah(&sa, 7, 17, &zeroed, inner).expect("build");
        assert_eq!(ah.len(), AH_HEADER_SIZE);
        assert_eq!(ah[0], 17); // next header

        // Verify with the same mutable-zeroed header.
        verify_ah(&sa, &zeroed, &ah, inner).expect("verify");

        // Tamper the ICV → rejected.
        let mut bad = ah.clone();
        bad[AH_HEADER_SIZE - 1] ^= 0xFF;
        assert_eq!(
            verify_ah(&sa, &zeroed, &bad, inner),
            Err(Error::PermissionDenied)
        );

        // A different mutable field value (TTL) must not break verification.
        let mut different_ttl = ip_header;
        different_ttl[8] = 128;
        let zeroed2 = ipv4_mutable_zeroed(&different_ttl);
        verify_ah(&sa, &zeroed2, &ah, inner).expect("mutable field ignored");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let sa = make_sa(9, (0x10u8..0x30).collect());
        let zeroed = ipv4_mutable_zeroed(&[
            0x45u8, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let ah = build_ah(&sa, 1, 6, &zeroed, b"data").expect("build");
        assert!(verify_ah(&sa, &zeroed, &ah, b"data!").is_err());
    }
}
