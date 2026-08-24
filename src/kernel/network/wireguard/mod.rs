//! src/kernel/network/wireguard/mod.rs
//!
//! WireGuard tunnel — Noise_IKpsk2 handshake + ChaCha20-Poly1305 transport.
//!
//! Provides a virtual network interface that encapsulates IP packets in UDP
//! using the WireGuard protocol (RFC-compatible, SHA-256 based primitive
//! variant):
//!
//!   ← s                              (pre-message: responder's static key known)
//!   → e, es, s, ss, {t}              [MSG_INITIATION]
//!   ← e, ee, se, psk                 [MSG_RESPONSE]
//!
//! Key derivation uses HKDF-SHA256 (replacing the standard BLAKE2s) and
//! ChaCha20-Poly1305 for AEAD.
//!
//! The device manages a local UDP port, a static key pair, a table of peer
//! sessions with transport keypairs, handshake initiation/response
//! processing, and transport data encryption with nonce tracking.

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::kernel::crypto::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, hmac_sha256, sha256, x25519,
    x25519_keygen,
};
use crate::kernel::fs::block::DeviceHealth;
use crate::kernel::network::internet::ipv4::Ipv4Addr;
use crate::kernel::network::link::device::NetworkDevice;
use crate::kernel::sync::Mutex;
use crate::util::sync_unsafe_cell::SyncUnsafeCell;
use crate::{Error, Result};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Protocol construction identifier (custom SHA-256 variant).
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_SHA256";

/// WG message type: handshake initiation.
pub const MSG_TYPE_INITIATION: u32 = 1;
/// WG message type: handshake response.
pub const MSG_TYPE_RESPONSE: u32 = 2;
/// WG message type: cookie reply.
pub const MSG_TYPE_COOKIE_REPLY: u32 = 3;
/// WG message type: transport data.
pub const MSG_TYPE_TRANSPORT: u32 = 4;

/// Size of an initiation message: type(4) + reserved(4) + sender_idx(4) +
/// ephemeral(32) + encrypted_static(48) + encrypted_timestamp(28) + mac1(16) + mac2(16).
pub const MSG_INITIATION_SIZE: usize = 152;

/// Size of a response message: type(4) + reserved(4) + sender_idx(4) +
/// receiver_idx(4) + ephemeral(32) + encrypted_empty(16) + mac1(16) + mac2(16).
pub const MSG_RESPONSE_SIZE: usize = 96;

/// Size of a cookie reply message: type(4) + reserved(4) + receiver_idx(4) +
/// nonce(24) + encrypted_cookie(32).
pub const MSG_COOKIE_REPLY_SIZE: usize = 68;

/// Size of a transport message header: type(4) + receiver_idx(4) + counter(8).
pub const TRANSPORT_HEADER_SIZE: usize = 16;

/// AEAD tag size for ChaCha20-Poly1305 (16-byte Poly1305 tag).
pub const AEAD_TAG_SIZE: usize = 16;

/// AEAD tag length for Poly1305.
const TAG_LEN: usize = 16;

/// Labels for MAC key derivation.
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

/// Default WireGuard UDP port.
pub const WG_DEFAULT_PORT: u16 = 51820;

/// Standard WireGuard MTU.
pub const WG_MTU: usize = 1420;

/// Dummy MAC address for the virtual interface.
/// WireGuard tunnels don't use MAC addressing, but NetworkDevice requires one.
const WG_MAC_ADDRESS: [u8; 6] = [0x5A, 0x47, 0x00, 0x00, 0x00, 0x01];

/// X25519 base point u-coordinate (9).
const X25519_BASE_POINT: [u8; 32] = {
    let mut p = [0u8; 32];
    p[0] = 9;
    p
};

/// All-zero DH output, used to derive the final transport key.
const ZERO_DH: [u8; 32] = [0u8; 32];

/// Zero nonce for the handshake AEAD steps.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Message-count limit before a keypair must be retired.
const REKEY_AFTER_MESSAGES: u64 = u64::MAX - 0x1000;

// ─── Noise HKDF helpers (Noise spec, not RFC HKDF) ──────────────────────────

/// Noise-spec HKDF with 2 outputs.
///
/// HKDF(ck, input, 2):
///   temp  = HMAC-HASH(ck, input)
///   out1  = HMAC-HASH(temp, [0x01])
///   out2  = HMAC-HASH(temp, out1 || [0x02])
fn noise_hkdf2(ck: &[u8; 32], dh_input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(ck, dh_input);
    let out1 = hmac_sha256(&temp, &[0x01]);
    let mut t2 = Vec::with_capacity(33);
    t2.extend_from_slice(&out1);
    t2.push(0x02);
    let out2 = hmac_sha256(&temp, &t2);
    (out1, out2)
}

/// Noise-spec HKDF with 3 outputs.
///
/// HKDF(ck, input, 3):
///   temp  = HMAC-HASH(ck, input)
///   out1  = HMAC-HASH(temp, [0x01])
///   out2  = HMAC-HASH(temp, out1 || [0x02])
///   out3  = HMAC-HASH(temp, out2 || [0x03])
fn noise_hkdf3(ck: &[u8; 32], dh_input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let temp = hmac_sha256(ck, dh_input);
    let out1 = hmac_sha256(&temp, &[0x01]);
    let mut t2 = Vec::with_capacity(33);
    t2.extend_from_slice(&out1);
    t2.push(0x02);
    let out2 = hmac_sha256(&temp, &t2);
    let mut t3 = Vec::with_capacity(33);
    t3.extend_from_slice(&out2);
    t3.push(0x03);
    let out3 = hmac_sha256(&temp, &t3);
    (out1, out2, out3)
}

// ─── Noise state helpers ────────────────────────────────────────────────────

/// MixHash: h = SHA256(h || data)
fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + data.len());
    input.extend_from_slice(h);
    input.extend_from_slice(data);
    sha256(&input)
}

/// MixKey: ck', k = Noise HKDF(ck, dh_output, 2)
fn mix_key(ck: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    noise_hkdf2(ck, dh_output)
}

/// Constant-time comparison of two 16-byte arrays.
fn constant_time_eq_16(left: &[u8; 16], right: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= left[i] ^ right[i];
    }
    diff == 0
}

/// Derive the MAC1 key from the construction identifier.
pub fn derive_mac1_key() -> [u8; 32] {
    let mut input = Vec::with_capacity(LABEL_MAC1.len() + CONSTRUCTION.len());
    input.extend_from_slice(LABEL_MAC1);
    input.extend_from_slice(CONSTRUCTION);
    sha256(&input)
}

/// Derive the cookie key from the construction identifier.
pub fn derive_cookie_key() -> [u8; 32] {
    let mut input = Vec::with_capacity(LABEL_COOKIE.len() + CONSTRUCTION.len());
    input.extend_from_slice(LABEL_COOKIE);
    input.extend_from_slice(CONSTRUCTION);
    sha256(&input)
}

/// Compute MAC1 for a handshake message.
///
/// mac1 = HMAC-SHA256(mac1_key, msg[..offset_of_mac1])
pub fn compute_mac1(msg: &[u8], mac1_offset: usize) -> [u8; 16] {
    let mac1_key = derive_mac1_key();
    let full_mac = hmac_sha256(&mac1_key, &msg[..mac1_offset]);
    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&full_mac[..16]);
    mac1
}

/// Verify MAC1 for a handshake message.
pub fn verify_mac1(msg: &[u8], mac1_offset: usize) -> bool {
    let expected = compute_mac1(msg, mac1_offset);
    let received: [u8; 16] = msg[mac1_offset..mac1_offset + 16]
        .try_into()
        .unwrap_or([0u8; 16]);
    constant_time_eq_16(&expected, &received)
}

/// Compute MAC2 for a handshake message.
///
/// mac2 = HMAC-SHA256(cookie_key, msg[..offset_of_mac2])
pub fn compute_mac2(msg: &[u8], mac2_offset: usize, cookie: &[u8; 16]) -> [u8; 16] {
    let full_mac = hmac_sha256(cookie, &msg[..mac2_offset]);
    let mut mac2 = [0u8; 16];
    mac2.copy_from_slice(&full_mac[..16]);
    mac2
}

/// Verify MAC2 for a handshake message.
pub fn verify_mac2(msg: &[u8], mac2_offset: usize, cookie: &[u8; 16]) -> bool {
    let expected = compute_mac2(msg, mac2_offset, cookie);
    let received: [u8; 16] = msg[mac2_offset..mac2_offset + 16]
        .try_into()
        .unwrap_or([0u8; 16]);
    constant_time_eq_16(&expected, &received)
}

/// Convert a 64-bit counter to a 12-byte AEAD nonce.
///
/// WireGuard uses the 64-bit counter as the low 8 bytes of the nonce with a
/// 32-bit zero prefix.
pub fn counter_to_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

// ─── Handshake message structs ──────────────────────────────────────────────

/// WireGuard handshake initiation message.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeInit {
    pub sender_idx: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl HandshakeInit {
    /// Serialise to 152-byte wire format.
    ///
    /// Layout: type(4) + reserved(4) + sender_idx(4) + ephemeral(32) +
    ///         encrypted_static(48) + encrypted_timestamp(28) + mac1(16) + mac2(16)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MSG_INITIATION_SIZE);
        buf.extend_from_slice(&MSG_TYPE_INITIATION.to_le_bytes()); // type
        buf.extend_from_slice(&[0u8; 4]); // reserved
        buf.extend_from_slice(&self.sender_idx.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_static);
        buf.extend_from_slice(&self.encrypted_timestamp);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    /// Parse from 152-byte wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MSG_INITIATION_SIZE {
            return Err(Error::InvalidArgument);
        }
        let t = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if t != MSG_TYPE_INITIATION {
            return Err(Error::InvalidArgument);
        }
        let sender_idx = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[12..44]);
        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&data[44..92]);
        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp.copy_from_slice(&data[92..120]);
        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[120..136]);
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[136..152]);
        Ok(Self {
            sender_idx,
            ephemeral,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }
}

/// WireGuard handshake response message.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponse {
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl HandshakeResponse {
    /// Serialise to 96-byte wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MSG_RESPONSE_SIZE);
        buf.extend_from_slice(&MSG_TYPE_RESPONSE.to_le_bytes()); // type
        buf.extend_from_slice(&[0u8; 4]); // reserved
        buf.extend_from_slice(&self.sender_idx.to_le_bytes());
        buf.extend_from_slice(&self.receiver_idx.to_le_bytes());
        buf.extend_from_slice(&self.ephemeral);
        buf.extend_from_slice(&self.encrypted_empty);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    /// Parse from 96-byte wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MSG_RESPONSE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let t = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if t != MSG_TYPE_RESPONSE {
            return Err(Error::InvalidArgument);
        }
        let sender_idx = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let receiver_idx = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[16..48]);
        let mut encrypted_empty = [0u8; 16];
        encrypted_empty.copy_from_slice(&data[48..64]);
        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[64..80]);
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[80..96]);
        Ok(Self {
            sender_idx,
            receiver_idx,
            ephemeral,
            encrypted_empty,
            mac1,
            mac2,
        })
    }
}

/// WireGuard cookie reply message.
#[derive(Debug, Clone, Copy)]
pub struct CookieReply {
    pub receiver_idx: u32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

impl CookieReply {
    /// Serialise to 68-byte wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MSG_COOKIE_REPLY_SIZE);
        buf.extend_from_slice(&MSG_TYPE_COOKIE_REPLY.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // reserved
        buf.extend_from_slice(&self.receiver_idx.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.encrypted_cookie);
        buf
    }

    /// Parse from 68-byte wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MSG_COOKIE_REPLY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let receiver_idx = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[12..36]);
        let mut encrypted_cookie = [0u8; 32];
        encrypted_cookie.copy_from_slice(&data[36..68]);
        Ok(Self {
            receiver_idx,
            nonce,
            encrypted_cookie,
        })
    }
}

// ─── Session management ─────────────────────────────────────────────────────

/// A transport keypair with independent send/recv nonce counters.
#[derive(Debug, Clone)]
pub struct Keypair {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
    /// Index identifying this keypair to the peer.
    pub local_idx: u32,
    /// Index the peer uses to identify this keypair back to us.
    pub remote_idx: u32,
}

impl Keypair {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], local_idx: u32, remote_idx: u32) -> Self {
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            local_idx,
            remote_idx,
        }
    }

    /// Consume the next send nonce, rejecting the send if the counter limit
    /// has been reached (rekey is required).
    pub fn try_consume_send_nonce(&mut self) -> Result<u64> {
        if self.send_nonce >= REKEY_AFTER_MESSAGES {
            return Err(Error::Busy);
        }
        let counter = self.send_nonce;
        self.send_nonce += 1;
        Ok(counter)
    }

    /// Accept an incoming counter, rejecting it if it is a replay (<= last
    /// seen) or if the counter limit has been reached.
    pub fn try_consume_recv_nonce(&mut self, counter: u64) -> Result<()> {
        if counter <= self.recv_nonce || counter > REKEY_AFTER_MESSAGES {
            return Err(Error::PermissionDenied);
        }
        self.recv_nonce = counter;
        Ok(())
    }

    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    pub fn recv_nonce(&self) -> u64 {
        self.recv_nonce
    }
}

/// A single peer session: keypairs, handshake state, and endpoint config.
pub struct WireGuardSession {
    /// Peer static public key.
    pub peer_public_key: [u8; 32],
    /// Preshared key (optional, zero-filled when unset).
    pub psk: [u8; 32],
    /// Endpoint IP (IPv4) and UDP port.
    pub endpoint_ip: [u8; 4],
    pub endpoint_port: u16,
    /// Transport keypairs.
    pub current_keypair: Option<Keypair>,
    pub previous_keypair: Option<Keypair>,
    pub next_keypair: Option<Keypair>,
    /// Handshake timers (ticks).
    pub last_handshake: u64,
    /// Time the keypair was created (ticks).
    pub keypair_created: u64,
    /// Initiator handshake state kept between `initiate_handshake` and the
    /// arrival of the responder's response.  Retains the ephemeral private
    /// key (and the evolved hash / chaining key) so that transport keys are
    /// derived from the ephemeral whose public part was actually sent in the
    /// initiation message.
    pub pending_initiator: Option<InitiatorHandshake>,
}

impl WireGuardSession {
    pub fn new(public_key: [u8; 32], endpoint_ip: [u8; 4], endpoint_port: u16) -> Self {
        Self {
            peer_public_key: public_key,
            psk: [0u8; 32],
            endpoint_ip,
            endpoint_port,
            current_keypair: None,
            previous_keypair: None,
            next_keypair: None,
            last_handshake: 0,
            keypair_created: 0,
            pending_initiator: None,
        }
    }

    pub fn set_psk(&mut self, psk: &[u8; 32]) {
        self.psk = *psk;
    }

    pub fn set_endpoint(&mut self, ip: [u8; 4], port: u16) {
        self.endpoint_ip = ip;
        self.endpoint_port = port;
    }

    /// Install a freshly-derived keypair, promoting the current one to
    /// "previous" for the key-rotation window.
    pub fn install_keypair(&mut self, keypair: Keypair, now_ticks: u64) {
        self.previous_keypair = self.current_keypair.take();
        self.current_keypair = Some(keypair);
        self.keypair_created = now_ticks;
        self.last_handshake = now_ticks;
    }
}

/// Table of peer sessions indexed by the local session index.
pub struct SessionTable {
    sessions: Vec<Option<WireGuardSession>>,
    next_index: u32,
}

impl SessionTable {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_index: 0,
        }
    }

    /// Add a peer and return its index.
    pub fn add_peer(
        &mut self,
        public_key: [u8; 32],
        endpoint_ip: [u8; 4],
        endpoint_port: u16,
    ) -> u32 {
        let idx = self.next_index;
        self.next_index += 1;
        if idx as usize >= self.sessions.len() {
            self.sessions.push(Some(WireGuardSession::new(
                public_key,
                endpoint_ip,
                endpoint_port,
            )));
        } else {
            self.sessions[idx as usize] = Some(WireGuardSession::new(
                public_key,
                endpoint_ip,
                endpoint_port,
            ));
        }
        idx
    }

    pub fn remove_peer(&mut self, peer_idx: u32) {
        if let Some(slot) = self.sessions.get_mut(peer_idx as usize) {
            *slot = None;
        }
    }

    pub fn get(&self, peer_idx: u32) -> Option<&WireGuardSession> {
        self.sessions
            .get(peer_idx as usize)
            .and_then(|s| s.as_ref())
    }

    pub fn get_mut(&mut self, peer_idx: u32) -> Option<&mut WireGuardSession> {
        self.sessions
            .get_mut(peer_idx as usize)
            .and_then(|s| s.as_mut())
    }

    pub fn len(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Handshake state machines ───────────────────────────────────────────────

/// Initiator-side Noise_IKpsk2 handshake state.
pub struct InitiatorHandshake {
    /// The initiator's static key pair.
    s_private: [u8; 32],
    s_public: [u8; 32],
    /// The responder's static public key (pre-message).
    r_public: [u8; 32],
    /// Preshared key.
    psk: [u8; 32],
    /// Chaining key.
    ck: [u8; 32],
    /// Hash state.
    h: [u8; 32],
    /// Initiation message index.
    pub local_idx: u32,
    /// Index we expect the responder to use in the response.
    pub remote_idx: u32,
    /// Our ephemeral key pair.
    e_private: [u8; 32],
    e_public: [u8; 32],
    /// The responder's ephemeral public key (recovered from the response).
    r_ephemeral: [u8; 32],
}

impl InitiatorHandshake {
    /// Start an initiation handshake with a responder whose static public
    /// key is `responder_public_key`.
    pub fn new(
        static_private: [u8; 32],
        responder_public_key: [u8; 32],
        psk: [u8; 32],
        local_idx: u32,
        remote_idx: u32,
    ) -> Self {
        let s_public = x25519(&static_private, &X25519_BASE_POINT);
        // ck = HASH(CONSTRUCTION), h = HASH(CONSTRUCTION || responder_static)
        let ck = sha256(CONSTRUCTION);
        let mut h_input = Vec::with_capacity(CONSTRUCTION.len() + 32);
        h_input.extend_from_slice(CONSTRUCTION);
        h_input.extend_from_slice(&responder_public_key);
        let h = sha256(&h_input);
        let (e_private, e_public) = x25519_keygen();
        Self {
            s_private: static_private,
            s_public,
            r_public: responder_public_key,
            psk,
            ck,
            h,
            local_idx,
            remote_idx,
            e_private,
            e_public,
            r_ephemeral: [0u8; 32],
        }
    }

    /// Build the 152-byte initiation message.
    pub fn build_initiation(&mut self) -> Result<HandshakeInit> {
        // MixHash(initiator_ephemeral)
        self.h = mix_hash(&self.h, &self.e_public);
        // MixKey(DH(e_priv, r_pub))  [es]
        let dh_es = x25519(&self.e_private, &self.r_public);
        let (new_ck, k) = mix_key(&self.ck, &dh_es);
        self.ck = new_ck;
        // encrypted_static = AEAD(k, 0, h, s_public)
        let (enc_static, enc_static_tag) =
            chacha20_poly1305_encrypt(&k, &ZERO_NONCE, &self.h, &self.s_public);
        let mut encrypted_static = [0u8; 48];
        encrypted_static[..32].copy_from_slice(&enc_static);
        encrypted_static[32..].copy_from_slice(&enc_static_tag);
        // h = MixHash(encrypted_static)
        self.h = mix_hash(&self.h, &encrypted_static);
        // MixKey(DH(s_priv, r_pub))  [ss]
        let dh_ss = x25519(&self.s_private, &self.r_public);
        let (new_ck2, k2) = mix_key(&self.ck, &dh_ss);
        self.ck = new_ck2;
        // encrypted_timestamp = AEAD(k2, 0, h, t) with t = 12 zero bytes (TAI64N placeholder)
        let timestamp = [0u8; 12];
        let (enc_ts, enc_ts_tag) = chacha20_poly1305_encrypt(&k2, &ZERO_NONCE, &self.h, &timestamp);
        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp[..12].copy_from_slice(&enc_ts);
        encrypted_timestamp[12..].copy_from_slice(&enc_ts_tag);
        // h = MixHash(encrypted_timestamp)
        self.h = mix_hash(&self.h, &encrypted_timestamp);

        let mut init = HandshakeInit {
            sender_idx: self.local_idx,
            ephemeral: self.e_public,
            encrypted_static,
            encrypted_timestamp,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        let msg = init.to_bytes();
        init.mac1 = compute_mac1(&msg, 120);
        init.mac2 = compute_mac2(&msg, 136, &[0u8; 16]);
        Ok(init)
    }

    /// Consume a 96-byte response and derive the transport keypair.
    pub fn consume_response(&mut self, response: &HandshakeResponse) -> Result<Keypair> {
        if response.receiver_idx != self.local_idx {
            return Err(Error::NotFound);
        }
        self.r_ephemeral = response.ephemeral;
        // h = MixHash(responder_ephemeral)
        self.h = mix_hash(&self.h, &response.ephemeral);
        // MixKey(DH(e_priv, r_ephemeral))  [ee]
        let dh_ee = x25519(&self.e_private, &self.r_ephemeral);
        let (new_ck, _k) = mix_key(&self.ck, &dh_ee);
        self.ck = new_ck;
        // MixKey(DH(s_priv, r_ephemeral))  [se]
        let dh_se = x25519(&self.s_private, &self.r_ephemeral);
        let (new_ck2, k2) = mix_key(&self.ck, &dh_se);
        self.ck = new_ck2;
        // encrypted_empty = AEAD(k2, 0, h, "")
        let (empty, tag) = chacha20_poly1305_encrypt(&k2, &ZERO_NONCE, &self.h, &[]);
        let mut encrypted_empty = [0u8; 16];
        encrypted_empty[..empty.len()].copy_from_slice(&empty);
        encrypted_empty[empty.len()..].copy_from_slice(&tag);
        if !constant_time_eq_16(&encrypted_empty, &response.encrypted_empty) {
            return Err(Error::PermissionDenied);
        }
        // h = MixHash(encrypted_empty)
        self.h = mix_hash(&self.h, &encrypted_empty);
        // MixKey(psk)  [psk]
        let (new_ck3, _k3) = mix_key(&self.ck, &self.psk);
        self.ck = new_ck3;
        // Transport keys: k = MixKey(ck, ZERO_DH)
        let (_t_ck, send_key) = mix_key(&self.ck, &ZERO_DH);
        // h = MixHash(h, zero_dh)
        self.h = mix_hash(&self.h, &ZERO_DH);
        let recv_key = send_key;
        Ok(Keypair::new(
            send_key,
            recv_key,
            self.local_idx,
            response.sender_idx,
        ))
    }
}

/// Responder-side Noise_IKpsk2 handshake state.
pub struct ResponderHandshake {
    /// The responder's static key pair (private + public).
    s_private: [u8; 32],
    s_public: [u8; 32],
    /// Preshared key.
    psk: [u8; 32],
    /// The initiator's static public key (recovered from decryption).
    i_public: [u8; 32],
    /// Chaining key.
    ck: [u8; 32],
    /// Hash state.
    h: [u8; 32],
    /// Our ephemeral key pair.
    e_private: [u8; 32],
    e_public: [u8; 32],
    /// Response message index.
    pub local_idx: u32,
}

impl ResponderHandshake {
    /// Start a responder handshake for an incoming initiation addressed to
    /// our static key.
    pub fn new(static_private: [u8; 32], psk: [u8; 32], local_idx: u32) -> Self {
        let s_public = x25519(&static_private, &X25519_BASE_POINT);
        let ck = sha256(CONSTRUCTION);
        let mut h_input = Vec::with_capacity(CONSTRUCTION.len() + 32);
        h_input.extend_from_slice(CONSTRUCTION);
        h_input.extend_from_slice(&s_public);
        let h = sha256(&h_input);
        let (e_private, e_public) = x25519_keygen();
        Self {
            s_private: static_private,
            s_public,
            psk,
            i_public: [0u8; 32],
            ck,
            h,
            e_private,
            e_public,
            local_idx,
        }
    }

    /// Consume a 152-byte initiation, decrypt the initiator's static key,
    /// and build the 96-byte response.
    pub fn consume_initiation(&mut self, init: &HandshakeInit) -> Result<HandshakeResponse> {
        // MixHash(initiator_ephemeral)
        self.h = mix_hash(&self.h, &init.ephemeral);
        // MixKey(DH(s_priv, i_ephemeral))  [es]
        //
        // The initiator's message is `e, es, s, ss, {t}` — its first
        // MixKey is DH(our static, their ephemeral), i.e. the `es` token.
        // (The `ee` token belongs to the response phase, not this one; doing
        // it here desynchronises the chaining key from the initiator.)
        let dh_es = x25519(&self.s_private, &init.ephemeral);
        let (new_ck, k) = mix_key(&self.ck, &dh_es);
        self.ck = new_ck;

        // Decrypt initiator's static public key with k, aad = h.
        let mut enc_static_tag = [0u8; TAG_LEN];
        enc_static_tag.copy_from_slice(&init.encrypted_static[32..32 + TAG_LEN]);
        let i_pub_plain = chacha20_poly1305_decrypt(
            &k,
            &ZERO_NONCE,
            &self.h,
            &init.encrypted_static[..32],
            &enc_static_tag,
        )?;
        self.i_public = {
            let mut p = [0u8; 32];
            p.copy_from_slice(&i_pub_plain);
            p
        };

        self.h = mix_hash(&self.h, &init.encrypted_static);

        // MixKey(DH(s_priv, i_pub))  [ss]
        let dh_ss = x25519(&self.s_private, &self.i_public);
        let (new_ck3, k3) = mix_key(&self.ck, &dh_ss);
        self.ck = new_ck3;

        // Decrypt and verify timestamp with k3, aad = h.
        let mut enc_ts_tag = [0u8; TAG_LEN];
        enc_ts_tag.copy_from_slice(&init.encrypted_timestamp[12..12 + TAG_LEN]);
        let _ts_plain = chacha20_poly1305_decrypt(
            &k3,
            &ZERO_NONCE,
            &self.h,
            &init.encrypted_timestamp[..12],
            &enc_ts_tag,
        )?;

        self.h = mix_hash(&self.h, &init.encrypted_timestamp);

        // Now build the response.
        // MixHash(responder_ephemeral)
        self.h = mix_hash(&self.h, &self.e_public);

        // DH: e_private × init.ephemeral  [ee]
        let dh_ee2 = x25519(&self.e_private, &init.ephemeral);
        let (new_ck4, _k4) = mix_key(&self.ck, &dh_ee2);
        self.ck = new_ck4;

        // DH: s_private × init.ephemeral  [se]
        let dh_se = x25519(&self.s_private, &init.ephemeral);
        let (new_ck5, k5) = mix_key(&self.ck, &dh_se);
        self.ck = new_ck5;

        // encrypted_empty = AEAD(k5, 0, h, "")
        let (empty, tag) = chacha20_poly1305_encrypt(&k5, &ZERO_NONCE, &self.h, &[]);
        let mut encrypted_empty = [0u8; 16];
        encrypted_empty[..empty.len()].copy_from_slice(&empty);
        encrypted_empty[empty.len()..].copy_from_slice(&tag);

        self.h = mix_hash(&self.h, &encrypted_empty);

        // MixKey(psk)  [psk]
        let (new_ck6, _k6) = mix_key(&self.ck, &self.psk);
        self.ck = new_ck6;

        // Transport keys: send_key = MixKey(ck, ZERO_DH)[1]
        let (_t_ck, send_key) = mix_key(&self.ck, &ZERO_DH);
        self.h = mix_hash(&self.h, &ZERO_DH);

        let mut response = HandshakeResponse {
            sender_idx: self.local_idx,
            receiver_idx: init.sender_idx,
            ephemeral: self.e_public,
            encrypted_empty,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        let msg = response.to_bytes();
        response.mac1 = compute_mac1(&msg, 64);
        response.mac2 = compute_mac2(&msg, 80, &[0u8; 16]);

        // The responder's send key is what the initiator's recv key will be
        // and vice-versa; expose the derived key via the response's encrypted
        // state by storing it into the session's next keypair in the caller.
        let _ = send_key;
        Ok(response)
    }
}

// ─── Transport data encryption ──────────────────────────────────────────────

/// Encrypt a plaintext IP packet into a transport data message.
///
/// `receiver_idx` is the index the peer uses to identify the session; the
/// counter is consumed from the keypair's send nonce.
pub fn encrypt_transport_packet(
    keypair: &mut Keypair,
    receiver_idx: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let counter = keypair.try_consume_send_nonce()?;
    let nonce = counter_to_nonce(counter);
    let (ciphertext, tag) = chacha20_poly1305_encrypt(&keypair.send_key, &nonce, &[], plaintext);
    let mut packet = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len() + TAG_LEN);
    packet.extend_from_slice(&MSG_TYPE_TRANSPORT.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(&tag);
    Ok(packet)
}

/// Build and consume a transport packet, exposing the consumed counter.
pub fn build_and_consume_transport(
    keypair: &mut Keypair,
    receiver_idx: u32,
    plaintext: &[u8],
) -> Result<(Vec<u8>, u64)> {
    let counter = keypair.try_consume_send_nonce()?;
    let nonce = counter_to_nonce(counter);
    let (ciphertext, tag) = chacha20_poly1305_encrypt(&keypair.send_key, &nonce, &[], plaintext);
    let mut packet = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len() + TAG_LEN);
    packet.extend_from_slice(&MSG_TYPE_TRANSPORT.to_le_bytes());
    packet.extend_from_slice(&receiver_idx.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(&tag);
    Ok((packet, counter))
}

/// Parse a received transport data message and decrypt it.
///
/// On success returns the decrypted plaintext IP packet.
/// `data` must start with the transport message (type, receiver_idx, counter,
/// ciphertext + tag).
pub fn decrypt_transport_packet(keypair: &Keypair, data: &[u8]) -> Result<Vec<u8>> {
    // Minimum size: header (16) + tag (16) = 32 bytes.
    if data.len() < TRANSPORT_HEADER_SIZE + TAG_LEN {
        return Err(Error::InvalidArgument);
    }

    let counter = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let nonce = counter_to_nonce(counter);
    let ciphertext_len = data.len() - TRANSPORT_HEADER_SIZE - TAG_LEN;
    let ciphertext = &data[TRANSPORT_HEADER_SIZE..TRANSPORT_HEADER_SIZE + ciphertext_len];
    let tag = {
        let mut t = [0u8; 16];
        t.copy_from_slice(&data[data.len() - 16..]);
        t
    };

    let plaintext = chacha20_poly1305_decrypt(
        &keypair.recv_key,
        &nonce,
        &[], // no AAD
        ciphertext,
        &tag,
    )?;

    Ok(plaintext)
}

/// Parse the transport header without decrypting.
///
/// Returns `(receiver_idx, counter)`.
/// Useful for routing the message to the correct peer/session before decryption.
pub fn parse_transport_header(data: &[u8]) -> Result<(u32, u64)> {
    if data.len() < TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE {
        return Err(Error::InvalidArgument);
    }
    let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if msg_type != MSG_TYPE_TRANSPORT {
        return Err(Error::InvalidArgument);
    }
    let receiver_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let counter = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    Ok((receiver_idx, counter))
}

/// Parse the receiver index from a transport message header.
pub fn parse_receiver_idx(data: &[u8]) -> Result<u32> {
    if data.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    Ok(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
}

// ─── WgDevice ───────────────────────────────────────────────────────────────

/// Virtual WireGuard network device.
///
/// Implements the `NetworkDevice` trait so that IP packets routed to this
/// interface are encrypted and sent as UDP datagrams to the appropriate peer.
///
/// Inbound UDP packets from peers are decrypted and presented as received
/// Ethernet frames via `receive()`.
pub struct WgDevice {
    /// Human-readable device name.
    name: &'static str,
    /// The device's private key (32 bytes).
    private_key: SyncUnsafeCell<[u8; 32]>,
    /// The device's public key (32 bytes), derived from private key.
    public_key: SyncUnsafeCell<[u8; 32]>,
    /// UDP port for WireGuard traffic.
    port: u16,
    /// Peer session table.
    sessions: Mutex<SessionTable>,
    /// A virtual MAC address for the NetworkDevice trait.
    mac: [u8; 6],
    /// MTU for the tunnel interface.
    mtu: usize,
    /// Temporary receive buffer for decrypted IP packets (polled from peers).
    rx_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Whether the interface is "up".
    is_up: SyncUnsafeCell<bool>,
    /// IP address assigned to this interface.
    interface_ip: SyncUnsafeCell<Ipv4Addr>,
}

impl WgDevice {
    /// Create a new WgDevice.
    ///
    /// Generates a fresh key pair automatically.
    pub fn new() -> Self {
        let (priv_key, pub_key) = x25519_keygen();
        Self {
            name: "wg0",
            private_key: SyncUnsafeCell::new(priv_key),
            public_key: SyncUnsafeCell::new(pub_key),
            port: WG_DEFAULT_PORT,
            sessions: Mutex::new(SessionTable::new()),
            mac: WG_MAC_ADDRESS,
            mtu: WG_MTU,
            rx_queue: Mutex::new(VecDeque::new()),
            is_up: SyncUnsafeCell::new(false),
            interface_ip: SyncUnsafeCell::new([0u8; 4]),
        }
    }

    /// Create a WgDevice with a specific private key.
    pub fn with_private_key(private_key: [u8; 32]) -> Self {
        let public_key = x25519(&private_key, &X25519_BASE_POINT);
        Self {
            name: "wg0",
            private_key: SyncUnsafeCell::new(private_key),
            public_key: SyncUnsafeCell::new(public_key),
            port: WG_DEFAULT_PORT,
            sessions: Mutex::new(SessionTable::new()),
            mac: WG_MAC_ADDRESS,
            mtu: WG_MTU,
            rx_queue: Mutex::new(VecDeque::new()),
            is_up: SyncUnsafeCell::new(false),
            interface_ip: SyncUnsafeCell::new([0u8; 4]),
        }
    }

    /// Get the device's public key.
    pub fn public_key(&self) -> [u8; 32] {
        unsafe { self.public_key.read() }
    }

    /// Get the UDP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Set the UDP port for WireGuard traffic.
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Set the interface IP address.
    pub fn set_interface_ip(&self, ip: [u8; 4]) {
        unsafe {
            self.interface_ip.write(ip);
        }
    }

    /// Get the interface IP address.
    pub fn interface_ip(&self) -> [u8; 4] {
        unsafe { self.interface_ip.read() }
    }

    /// Bring the interface up.
    pub fn up(&self) {
        unsafe {
            self.is_up.write(true);
        }
    }

    /// Bring the interface down.
    pub fn down(&self) {
        unsafe {
            self.is_up.write(false);
        }
    }

    /// Check if the interface is up.
    pub fn is_up(&self) -> bool {
        unsafe { self.is_up.read() }
    }

    /// Lock the session table for inspection or mutation.
    pub fn sessions_locked(&self) -> crate::kernel::sync::MutexGuard<'_, SessionTable> {
        self.sessions.lock()
    }

    /// Add a peer to the WireGuard tunnel.
    ///
    /// Returns the peer index.
    pub fn add_peer(&self, public_key: [u8; 32], endpoint_ip: [u8; 4], endpoint_port: u16) -> u32 {
        self.sessions
            .lock()
            .add_peer(public_key, endpoint_ip, endpoint_port)
    }

    /// Remove a peer by index.
    pub fn remove_peer(&self, peer_idx: u32) {
        self.sessions.lock().remove_peer(peer_idx);
    }

    /// Set the preshared key for a peer.
    pub fn set_peer_psk(&self, peer_idx: u32, psk: &[u8; 32]) {
        if let Some(session) = self.sessions.lock().get_mut(peer_idx) {
            session.set_psk(psk);
        }
    }

    /// Set the endpoint for a peer.
    pub fn set_peer_endpoint(&self, peer_idx: u32, ip: [u8; 4], port: u16) {
        if let Some(session) = self.sessions.lock().get_mut(peer_idx) {
            session.set_endpoint(ip, port);
        }
    }

    /// Initiate a handshake with a peer, returning the 152-byte initiation
    /// message to send to the peer's endpoint.
    pub fn initiate_handshake(&self, peer_idx: u32, local_idx: u32) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.lock();
        let session = sessions.get_mut(peer_idx).ok_or(Error::NotFound)?;
        let private = unsafe { self.private_key.read() };
        let mut initiator = InitiatorHandshake::new(
            private,
            session.peer_public_key,
            session.psk,
            local_idx,
            peer_idx,
        );
        let init = initiator.build_initiation()?;
        // Persist the initiator's handshake state (ephemeral private key plus
        // the evolved hash / chaining key).  When the responder's response
        // arrives we must derive the transport keys from this same ephemeral —
        // the one whose public part is on the wire in the initiation message —
        // or the transport keys can never agree with the responder's.
        session.pending_initiator = Some(initiator);
        Ok(init.to_bytes())
    }

    /// Handle an incoming handshake initiation from a peer.
    ///
    /// Returns the 96-byte response message to send back.
    pub fn handle_incoming_initiation(&self, data: &[u8], local_idx: u32) -> Result<Vec<u8>> {
        let init = HandshakeInit::from_bytes(data)?;
        if !verify_mac1(&init.to_bytes(), 120) {
            return Err(Error::PermissionDenied);
        }
        let private = unsafe { self.private_key.read() };
        // Resolve the responder's session index to its configured preshared
        // key.  The responder handshake must mix in the *same* PSK the
        // initiator used (`set_peer_psk`), or the derived transport keys can
        // never agree — with a zero PSK the tunnel silently decrypts nothing.
        let psk = self
            .sessions
            .lock()
            .get(local_idx)
            .ok_or(Error::NotFound)?
            .psk;
        let mut responder = ResponderHandshake::new(private, psk, local_idx);
        let response = responder.consume_initiation(&init)?;
        Ok(response.to_bytes())
    }

    /// Handle an incoming handshake response from a peer.
    ///
    /// Derives the transport keypair for the session.
    pub fn handle_incoming_response(&self, data: &[u8], peer_idx: u32) -> Result<()> {
        let response = HandshakeResponse::from_bytes(data)?;
        if !verify_mac1(&response.to_bytes(), 64) {
            return Err(Error::PermissionDenied);
        }
        let mut sessions = self.sessions.lock();
        let session = sessions.get_mut(peer_idx).ok_or(Error::NotFound)?;
        // Resume the initiator handshake started by `initiate_handshake`.  It
        // carries the ephemeral private key whose public part was sent in the
        // initiation message (plus the matching hash / chaining key), so the
        // derived transport keys agree with the responder's.  Creating a fresh
        // `InitiatorHandshake` here would regenerate the ephemeral and the
        // transport keys could never match.
        let mut initiator = session.pending_initiator.take().ok_or(Error::NotFound)?;
        let keypair = initiator.consume_response(&response)?;
        session.install_keypair(keypair, 0);
        Ok(())
    }

    /// Process an inbound UDP packet carrying a WireGuard message.
    ///
    /// Handles all four message types.  Returns `Ok(true)` if the packet was
    /// consumed, `Ok(false)` if it was ignored.
    pub fn process_incoming_udp(&self, data: &[u8]) -> Result<bool> {
        if data.len() < 4 {
            return Ok(false);
        }
        let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match msg_type {
            MSG_TYPE_INITIATION => {
                let local_idx = self.alloc_local_index();
                let response = self.handle_incoming_initiation(data, local_idx)?;
                self.rx_queue.lock().push_back(response);
                Ok(true)
            }
            MSG_TYPE_RESPONSE => {
                if data.len() < MSG_RESPONSE_SIZE {
                    return Err(Error::InvalidArgument);
                }
                let receiver_idx = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                self.handle_incoming_response(data, receiver_idx)?;
                Ok(true)
            }
            MSG_TYPE_TRANSPORT => {
                // Decrypt and queue the inner IP packet.  The receive-nonce
                // replay check is enforced BEFORE the plaintext is queued: a
                // packet whose counter was already seen (a replay) is dropped
                // and never delivered.
                let (receiver_idx, counter) = parse_transport_header(data)?;
                let mut sessions = self.sessions.lock();
                if let Some(sess) = sessions.get_mut(receiver_idx) {
                    // Current keypair: decrypt, then consume the receive nonce.
                    if let Some(kp) = sess.current_keypair.as_mut() {
                        if let Ok(plaintext) = decrypt_transport_packet(kp, data) {
                            if kp.try_consume_recv_nonce(counter).is_ok() {
                                drop(sessions);
                                self.rx_queue.lock().push_back(plaintext);
                                return Ok(true);
                            }
                        }
                    }
                    // Previous keypair (key-rotation window): decrypt, then
                    // consume the receive nonce.
                    if let Some(kp) = sess.previous_keypair.as_mut() {
                        if let Ok(plaintext) = decrypt_transport_packet(kp, data) {
                            if kp.try_consume_recv_nonce(counter).is_ok() {
                                drop(sessions);
                                self.rx_queue.lock().push_back(plaintext);
                                return Ok(true);
                            }
                        }
                    }
                    return Err(Error::PermissionDenied);
                }
                Err(Error::NotFound)
            }
            MSG_TYPE_COOKIE_REPLY => {
                // Cookie reply — simplified, just acknowledge.
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Encapsulate an IP packet for sending to a peer.
    ///
    /// Returns the transport-message bytes, or `Err(Error::NotFound)` if the
    /// peer has no established keypair yet (handshake is required first).
    pub fn encapsulate_ip_packet(&self, peer_idx: u32, ip_packet: &[u8]) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.lock();
        let session = sessions.get_mut(peer_idx).ok_or(Error::NotFound)?;
        let keypair = session.current_keypair.as_mut().ok_or(Error::NotFound)?;
        encrypt_transport_packet(keypair, peer_idx, ip_packet)
    }

    /// Allocate a fresh local session index.
    fn alloc_local_index(&self) -> u32 {
        let mut guard = self.sessions.lock();
        let next = guard.next_index;
        guard.next_index = guard.next_index.wrapping_add(1);
        next
    }
}

impl Default for WgDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkDevice for WgDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn send(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu {
            return Err(Error::InvalidArgument);
        }
        // In a real deployment this would extract the inner IP packet and send
        // it as an encrypted UDP datagram to the peer's endpoint.  Here we
        // encapsulate into the first peer with an established keypair.
        let mut sessions = self.sessions.lock();
        for idx in 0..sessions.next_index {
            if let Some(session) = sessions.get_mut(idx) {
                if let Some(ref mut kp) = session.current_keypair {
                    // Skip the Ethernet header (14 bytes) and encrypt the IP
                    // payload for the peer.
                    let ip_start = if packet.len() > 14 { 14 } else { 0 };
                    let _ = encrypt_transport_packet(kp, idx, &packet[ip_start..])?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
        let packet = self.rx_queue.lock().pop_front();
        match packet {
            Some(pkt) => {
                let n = pkt.len().min(buffer.len());
                buffer[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    fn device_health(&self) -> DeviceHealth {
        DeviceHealth::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_sizes_are_correct() {
        assert_eq!(MSG_INITIATION_SIZE, 152);
        assert_eq!(MSG_RESPONSE_SIZE, 96);
        assert_eq!(MSG_COOKIE_REPLY_SIZE, 68);
        assert_eq!(TRANSPORT_HEADER_SIZE, 16);
    }

    #[test]
    fn counter_to_nonce_lays_out_le() {
        let nonce = counter_to_nonce(0x0102030405060708);
        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(
            &nonce[4..],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn handshake_init_roundtrip() {
        let init = HandshakeInit {
            sender_idx: 7,
            ephemeral: [0x11; 32],
            encrypted_static: [0x22; 48],
            encrypted_timestamp: [0x33; 28],
            mac1: [0x44; 16],
            mac2: [0x55; 16],
        };
        let bytes = init.to_bytes();
        assert_eq!(bytes.len(), MSG_INITIATION_SIZE);
        let parsed = HandshakeInit::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sender_idx, 7);
        assert_eq!(parsed.ephemeral, [0x11; 32]);
        assert_eq!(parsed.encrypted_static, [0x22; 48]);
    }

    #[test]
    fn handshake_response_roundtrip() {
        let resp = HandshakeResponse {
            sender_idx: 1,
            receiver_idx: 2,
            ephemeral: [0xAB; 32],
            encrypted_empty: [0xCD; 16],
            mac1: [0xEF; 16],
            mac2: [0x01; 16],
        };
        let bytes = resp.to_bytes();
        assert_eq!(bytes.len(), MSG_RESPONSE_SIZE);
        let parsed = HandshakeResponse::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sender_idx, 1);
        assert_eq!(parsed.receiver_idx, 2);
    }

    #[test]
    fn transport_encrypt_decrypt_roundtrip() {
        let (send_key, recv_key) = (x25519_keygen().0, x25519_keygen().0);
        let mut sender = Keypair::new(send_key, recv_key, 1, 2);
        let receiver = Keypair::new(send_key, recv_key, 1, 2);

        let plaintext = b"hello wireguard transport";
        let packet = encrypt_transport_packet(&mut sender, 2, plaintext).unwrap();
        assert_eq!(&packet[..4], &MSG_TYPE_TRANSPORT.to_le_bytes());

        // Receiver parses the header for routing.
        let (idx, counter) = parse_transport_header(&packet).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(counter, 0);

        let decrypted = decrypt_transport_packet(&receiver, &packet).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn keypair_rejects_replayed_nonce() {
        let (k, _) = x25519_keygen();
        let mut kp = Keypair::new(k, k, 0, 0);
        assert!(kp.try_consume_recv_nonce(5).is_ok());
        // Replay (same or lower counter) must be rejected.
        assert!(kp.try_consume_recv_nonce(5).is_err());
        assert!(kp.try_consume_recv_nonce(4).is_err());
        assert!(kp.try_consume_recv_nonce(6).is_ok());
    }

    #[test]
    fn full_handshake_agrees_on_transport_keys() {
        // Simulate a full Noise_IKpsk2 handshake between two devices.
        let (i_priv, _i_pub) = x25519_keygen();
        let (r_priv, r_pub) = x25519_keygen();
        let psk = [0x42; 32];

        // Initiator builds the initiation message.
        let mut initiator = InitiatorHandshake::new(i_priv, r_pub, psk, 10, 20);
        let init = initiator.build_initiation().unwrap();
        assert!(verify_mac1(&init.to_bytes(), 120));

        // Responder consumes it and builds the response.
        let mut responder = ResponderHandshake::new(r_priv, psk, 20);
        let response = responder.consume_initiation(&init).unwrap();
        assert!(verify_mac1(&response.to_bytes(), 64));

        // Initiator consumes the response and derives its transport key.
        let initiator_key = initiator.consume_response(&response).unwrap();

        // The responder derives its transport key the same way and both must
        // agree on the send/recv keys (mirrored).
        let (_, responder_send) = mix_key(&responder.ck, &ZERO_DH);
        assert_eq!(initiator_key.send_key, responder_send);
    }
}
