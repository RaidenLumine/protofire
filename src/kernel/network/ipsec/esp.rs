//! src/kernel/network/ipsec/esp.rs
//!
//! ESP (RFC 4303) with AEAD integrity (RFC 4106 AES-GCM / RFC 7634
//! ChaCha20-Poly1305).
//!
//! Wire layout:
//! ```text
//! [ SPI(4) ][ Seq(4) ][ Encrypted payload ][ ICV (16, covered by AEAD) ]
//! ```
//! The AEAD covers `SPI || Seq` as AAD and encrypts
//! `inner || pad || pad_len || next_header` (padded to a multiple of 4
//! bytes).  The 96-bit AEAD nonce is derived from the 4-byte salt and the
//! 32-bit sequence number.

use alloc::vec::Vec;

use crate::kernel::crypto::aes128_gcm_decrypt;
use crate::kernel::crypto::aes128_gcm_encrypt;
use crate::kernel::crypto::chacha20_poly1305_decrypt;
use crate::kernel::crypto::chacha20_poly1305_encrypt;
use crate::Error;
use crate::Result;

use super::AeadAlgo;
use super::IpsecSa;

/// ESP header size (SPI + Seq).
pub const ESP_HEADER_SIZE: usize = 8;
/// AEAD tag/ICV size.
pub const ESP_ICV_SIZE: usize = 16;

/// Build the 96-bit AEAD nonce for `seq`.
fn build_nonce(salt: &[u8], algo: AeadAlgo, seq: u32) -> Result<[u8; 12]> {
    let mut nonce = [0u8; 12];
    match algo {
        AeadAlgo::Aes128Gcm => {
            // RFC 4106: salt(4) || 32 zero bits || 32-bit sequence number.
            if salt.len() < 4 {
                return Err(Error::InvalidArgument);
            }
            nonce[..4].copy_from_slice(&salt[..4]);
            nonce[8..12].copy_from_slice(&seq.to_be_bytes());
        }
        AeadAlgo::ChaCha20Poly1305 => {
            // RFC 7634: salt(4) || 8-byte big-endian counter derived from
            // the 32-bit sequence number (high word = 1).
            if salt.len() < 4 {
                return Err(Error::InvalidArgument);
            }
            nonce[..4].copy_from_slice(&salt[..4]);
            nonce[4..8].copy_from_slice(&1u32.to_be_bytes());
            nonce[8..12].copy_from_slice(&seq.to_be_bytes());
        }
    }
    Ok(nonce)
}

/// Encrypt `inner` into a complete ESP payload (header + ciphertext + ICV).
pub fn build_esp_payload(sa: &IpsecSa, seq: u64, inner: &[u8], next_header: u8) -> Result<Vec<u8>> {
    let algo = sa.aead.ok_or(Error::InvalidArgument)?;
    let seq32 = seq as u32;

    // Plaintext = inner || pad || pad_len || next_header, 4-byte aligned.
    let pad_len = (4 - ((inner.len() + 2) % 4)) % 4;
    let mut plaintext = Vec::with_capacity(inner.len() + pad_len + 2);
    plaintext.extend_from_slice(inner);
    plaintext.extend_from_slice(&[0u8; 4][..pad_len]);
    plaintext.push(pad_len as u8);
    plaintext.push(next_header);

    // AAD = SPI || Seq (RFC 4106/7634 combined mode).
    let mut aad = Vec::with_capacity(8);
    aad.extend_from_slice(&sa.spi.to_be_bytes());
    aad.extend_from_slice(&seq32.to_be_bytes());
    let nonce = build_nonce(&sa.salt, algo, seq32)?;

    let (ciphertext, tag) = match algo {
        AeadAlgo::Aes128Gcm => {
            let mut key = [0u8; 16];
            if sa.enc_key.len() != 16 {
                return Err(Error::InvalidArgument);
            }
            key.copy_from_slice(&sa.enc_key);
            aes128_gcm_encrypt(&key, &nonce, &aad, &plaintext)
        }
        AeadAlgo::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            if sa.enc_key.len() != 32 {
                return Err(Error::InvalidArgument);
            }
            key.copy_from_slice(&sa.enc_key);
            chacha20_poly1305_encrypt(&key, &nonce, &aad, &plaintext)
        }
    };

    let mut payload = Vec::with_capacity(ESP_HEADER_SIZE + ciphertext.len() + ESP_ICV_SIZE);
    payload.extend_from_slice(&sa.spi.to_be_bytes());
    payload.extend_from_slice(&seq32.to_be_bytes());
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Decrypt and verify an ESP payload.  Returns `(inner, next_header)`.
pub fn parse_esp_payload(sa: &IpsecSa, data: &[u8]) -> Result<(Vec<u8>, u8)> {
    let algo = sa.aead.ok_or(Error::InvalidArgument)?;
    if data.len() < ESP_HEADER_SIZE + ESP_ICV_SIZE {
        return Err(Error::InvalidArgument);
    }
    let seq32 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let nonce = build_nonce(&sa.salt, algo, seq32)?;

    let mut aad = Vec::with_capacity(8);
    aad.extend_from_slice(&data[..4]); // SPI
    aad.extend_from_slice(&data[4..8]); // Seq
    let ciphertext = &data[ESP_HEADER_SIZE..data.len() - ESP_ICV_SIZE];
    let tag: [u8; 16] = data[data.len() - ESP_ICV_SIZE..]
        .try_into()
        .map_err(|_| Error::InvalidArgument)?;

    // Map the AEAD verification failure to a caller-visible integrity
    // error.  The crypto layer reports a failed tag check as
    // `InvalidCredential`; ESP treats that as an integrity failure of the
    // received datagram (`PermissionDenied`).
    fn verify_decrypt<F>(decrypt: F) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Result<Vec<u8>>,
    {
        decrypt().map_err(|e| match e {
            Error::InvalidCredential => Error::PermissionDenied,
            other => other,
        })
    }

    let plaintext = match algo {
        AeadAlgo::Aes128Gcm => {
            let mut key = [0u8; 16];
            if sa.enc_key.len() != 16 {
                return Err(Error::InvalidArgument);
            }
            key.copy_from_slice(&sa.enc_key);
            verify_decrypt(|| aes128_gcm_decrypt(&key, &nonce, &aad, ciphertext, &tag))?
        }
        AeadAlgo::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            if sa.enc_key.len() != 32 {
                return Err(Error::InvalidArgument);
            }
            key.copy_from_slice(&sa.enc_key);
            verify_decrypt(|| chacha20_poly1305_decrypt(&key, &nonce, &aad, ciphertext, &tag))?
        }
    };

    if plaintext.len() < 2 {
        return Err(Error::InvalidArgument);
    }
    let next_header = *plaintext.last().ok_or(Error::InvalidArgument)?;
    let pad_len = plaintext[plaintext.len() - 2] as usize;
    if pad_len + 2 > plaintext.len() {
        return Err(Error::InvalidArgument);
    }
    let inner = plaintext[..plaintext.len() - 2 - pad_len].to_vec();
    Ok((inner, next_header))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sa(spi: u32, aead: AeadAlgo, key: Vec<u8>, salt: Vec<u8>) -> IpsecSa {
        IpsecSa {
            id: 1,
            spi,
            mode: super::super::IpsecMode::Transport,
            proto: super::super::IpsecProto::Esp,
            aead: Some(aead),
            auth: None,
            enc_key: key,
            salt,
            auth_key: Vec::new(),
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
    fn aes128_gcm_round_trip() {
        let sa = make_sa(
            0x01020304,
            AeadAlgo::Aes128Gcm,
            (0u8..16).collect(),
            [0xAA; 4].to_vec(),
        );
        let inner = b"hello esp transport";
        let payload = build_esp_payload(&sa, 5, inner, 17).expect("build");
        let (decoded, nh) = parse_esp_payload(&sa, &payload).expect("parse");
        assert_eq!(decoded, inner);
        assert_eq!(nh, 17);
    }

    #[test]
    fn chacha20_poly1305_round_trip() {
        let sa = make_sa(
            0x05060708,
            AeadAlgo::ChaCha20Poly1305,
            (0u8..32).collect(),
            [0xBB; 12].to_vec(),
        );
        let inner = b"chacha esp payload data";
        let payload = build_esp_payload(&sa, 9, inner, 132).expect("build");
        let (decoded, nh) = parse_esp_payload(&sa, &payload).expect("parse");
        assert_eq!(decoded, inner);
        assert_eq!(nh, 132);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let sa = make_sa(
            0x01020304,
            AeadAlgo::Aes128Gcm,
            (0u8..16).collect(),
            [0xAA; 4].to_vec(),
        );
        let payload = build_esp_payload(&sa, 5, b"secret", 6).expect("build");
        let mut tampered = payload.clone();
        let idx = tampered.len() - ESP_ICV_SIZE - 1;
        tampered[idx] ^= 0xFF;
        assert_eq!(
            parse_esp_payload(&sa, &tampered),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sa = make_sa(
            0x01020304,
            AeadAlgo::Aes128Gcm,
            (0u8..16).collect(),
            [0xAA; 4].to_vec(),
        );
        // Different key, same SPI — decryption must fail AEAD verification.
        let wrong = make_sa(
            0x01020304,
            AeadAlgo::Aes128Gcm,
            [0xFF; 16].to_vec(),
            [0xAA; 4].to_vec(),
        );
        let payload = build_esp_payload(&sa, 1, b"x", 17).expect("build");
        assert!(parse_esp_payload(&wrong, &payload).is_err());
    }

    #[test]
    fn empty_inner_round_trips() {
        let sa = make_sa(
            1,
            AeadAlgo::Aes128Gcm,
            (0u8..16).collect(),
            [0u8; 4].to_vec(),
        );
        let payload = build_esp_payload(&sa, 1, &[], 59).expect("build");
        let (decoded, nh) = parse_esp_payload(&sa, &payload).expect("parse");
        assert!(decoded.is_empty());
        assert_eq!(nh, 59);
    }
}
