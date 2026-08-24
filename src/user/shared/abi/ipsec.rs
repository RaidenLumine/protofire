//! src/user/shared/abi/ipsec.rs
//!
//! src/abi/ipsec.rs
//! Shared ABI definitions for IPsec Security Policy Database (SPD) and
//! Security Association Database (SAD) management syscalls.

/// IPsec modes.
pub const IPSEC_MODE_TRANSPORT: u32 = 0;
pub const IPSEC_MODE_TUNNEL: u32 = 1;

/// IPsec protocols.
pub const IPSEC_PROTO_ESP: u32 = 50;
pub const IPSEC_PROTO_AH: u32 = 51;

/// ESP AEAD algorithms.
pub const IPSEC_AEAD_AES128_GCM: u32 = 1;
pub const IPSEC_AEAD_CHACHA20_POLY1305: u32 = 2;

/// AH authentication algorithms.
pub const IPSEC_AUTH_HMAC_SHA256: u32 = 1;

/// SPD actions.
pub const IPSEC_ACTION_BYPASS: u32 = 0;
pub const IPSEC_ACTION_DISCARD: u32 = 1;
pub const IPSEC_ACTION_PROTECT: u32 = 2;

/// SPD directions.
pub const IPSEC_DIR_INBOUND: u32 = 1;
pub const IPSEC_DIR_OUTBOUND: u32 = 2;
pub const IPSEC_DIR_BOTH: u32 = 3;

/// Fixed sizes of the wire ABI structs.
pub const IPSEC_SP_DEF_SIZE: usize = 48;
pub const IPSEC_SA_DEF_SIZE: usize = 144;
pub const IPSEC_STATS_SIZE: usize = 48;

/// A Security Policy Database entry definition (order matters — first
/// match wins).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsecSpDef {
    pub flags: u32,
    /// `IPSEC_ACTION_*`.
    pub action: u32,
    /// `IPSEC_DIR_*`.
    pub direction: u32,
    /// IP protocol number to match (0 = any).
    pub protocol: u32,
    pub src_addr: [u8; 4],
    pub src_prefix: u32,
    pub dst_addr: [u8; 4],
    pub dst_prefix: u32,
    pub src_port: u32,
    pub dst_port: u32,
    /// SAD id of the SA to apply when `action == PROTECT`.
    pub sa_id: u32,
    pub reserved: u32,
}

/// A Security Association definition.
///
/// Keys are inlined fixed-size buffers so the struct can be copied in one
/// flat `read_user_value`; only `enc_key_len`/`auth_key_len` bytes of each
/// are meaningful.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsecSaDef {
    pub flags: u32,
    /// Security Parameters Index (identifies the SA on the wire).
    pub spi: u32,
    /// `IPSEC_MODE_*`.
    pub mode: u32,
    /// `IPSEC_PROTO_*`.
    pub proto: u32,
    /// `IPSEC_AEAD_*` (ESP only).
    pub aead_algo: u32,
    /// `IPSEC_AUTH_*` (AH only).
    pub auth_algo: u32,
    /// Length of the encryption key in `enc_key` (16 for AES-128, 32 for
    /// ChaCha20).
    pub enc_key_len: u32,
    /// Length of the authentication key in `auth_key`.
    pub auth_key_len: u32,
    pub enc_key: [u8; 32],
    pub auth_key: [u8; 32],
    /// AEAD salt (4 bytes for AES-GCM, 12 bytes for ChaCha20-Poly1305).
    pub salt: [u8; 12],
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub tunnel_src: [u8; 4],
    pub tunnel_dst: [u8; 4],
    pub lifetime_bytes: u64,
    pub lifetime_ticks: u64,
}

/// Global IPsec statistics snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpsecStats {
    pub enabled: u32,
    pub sp_count: u32,
    pub sa_count: u32,
    pub esp_encrypted: u64,
    pub esp_decrypted: u64,
    pub auth_failures: u64,
    pub replay_drops: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn abi_struct_sizes_are_stable() {
        assert_eq!(size_of::<IpsecSpDef>(), IPSEC_SP_DEF_SIZE);
        assert_eq!(size_of::<IpsecSaDef>(), IPSEC_SA_DEF_SIZE);
        assert_eq!(size_of::<IpsecStats>(), IPSEC_STATS_SIZE);
    }

    #[test]
    fn constants_match_protocol_numbers() {
        assert_eq!(IPSEC_PROTO_ESP, 50);
        assert_eq!(IPSEC_PROTO_AH, 51);
        assert_eq!(IPSEC_MODE_TRANSPORT, 0);
        assert_eq!(IPSEC_MODE_TUNNEL, 1);
    }
}
