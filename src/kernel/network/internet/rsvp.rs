//! src/kernel/network/internet/rsvp.rs
//! RSVP TSPEC — token-bucket traffic specification (RFC 2210).
//!
//! ## Educational purpose
//!
//! RSVP (Resource ReSerVation Protocol) lets a receiver ask the routers
//! along a path to reserve resources for a flow.  The request travels in a
//! TSPEC (traffic spec) carried by PATH messages.  The core idea is the
//! *token bucket*: the sender commits to transmitting at most `token_rate`
//! tokens per second, with bursts up to `bucket_size` tokens.  A policer
//! admits a packet only when enough tokens remain, so the long-term rate is
//! bounded no matter how bursty the source is.
//!
//! ## Why not production?
//!
//! - RSVP is receiver-oriented and needs a signalling path end-to-end;
//!   most modern networks use DiffServ marking or per-flow queues instead.
//! - Token-bucket policing here is a pure rate simulation — real shapers
//!   account for packet overhead, scheduler latency, and per-class queues.
//! - The wire format omits the RSVP object header (class, class-type,
//!   length) that frames the TSPEC inside a PATH message.

use alloc::vec::Vec;

// ─── Token bucket ──────────────────────────────────────────────────────────

/// A token-bucket traffic spec, matching the parameters of an RSVP TSPEC.
///
/// Tokens accumulate at `token_rate` per second up to a ceiling of
/// `bucket_size`.  A well-behaved flow never sends more than it has tokens
/// for; bursts are tolerated up to the bucket depth.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenBucket {
    /// Tokens added per second (committed rate, CIR).
    pub token_rate: f32,
    /// Maximum number of tokens the bucket can hold (committed burst, CBS).
    pub bucket_size: f32,
    /// Peak rate the sender is allowed to emit (PIR).
    pub peak_rate: f32,
    /// Minimum policed unit, in bytes (smallest packet counted against the
    /// bucket; RFC 2210 uses 0 to mean "don't police to a floor").
    pub min_policed_unit: u32,
    /// Maximum IP packet size the sender will generate, in bytes.
    pub max_packet_size: u32,
}

impl TokenBucket {
    /// Create a token bucket from a rate and a depth.  The peak rate starts
    /// equal to the token rate and the packet-size parameters default to 0.
    pub fn new(token_rate: f32, bucket_size: f32) -> Self {
        Self {
            token_rate,
            bucket_size,
            peak_rate: token_rate,
            min_policed_unit: 0,
            max_packet_size: 0,
        }
    }

    /// Add `seconds` worth of tokens to the bucket, clamped to the bucket
    /// depth so the bucket can never over-fill.
    pub fn replenish(&self, tokens: &mut f32, seconds: f32) {
        let add = self.token_rate * seconds;
        if add > 0.0 {
            *tokens = (*tokens + add).min(self.bucket_size);
        }
    }

    /// Consume `amount` tokens.  Returns `true` when the request is
    /// admitted and the tokens are removed; `false` leaves the bucket
    /// untouched (the policer rejects the burst).
    pub fn take(&self, tokens: &mut f32, amount: f32) -> bool {
        if *tokens >= amount {
            *tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Alias for [`TokenBucket::take`] used when shaping a packet of
    /// `bytes` through the bucket.
    pub fn send(&self, tokens: &mut f32, bytes: f32) -> bool {
        self.take(tokens, bytes)
    }

    /// Serialize the five TSPEC parameters as big-endian 32-bit words
    /// (20 bytes).  Rates use the IEEE 754 single-precision encoding RSVP
    /// uses on the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        for v in [self.token_rate, self.bucket_size, self.peak_rate] {
            buf.extend_from_slice(&v.to_bits().to_be_bytes());
        }
        for v in [self.min_policed_unit, self.max_packet_size] {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        buf
    }

    /// Parse a TSPEC from its 20-byte wire representation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let word = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        Some(Self {
            token_rate: f32::from_bits(word(0)),
            bucket_size: f32::from_bits(word(4)),
            peak_rate: f32::from_bits(word(8)),
            min_policed_unit: word(12),
            max_packet_size: word(16),
        })
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replenish_accumulates_at_token_rate() {
        let tspec = TokenBucket::new(1000.0, 2000.0);

        let mut tokens = 0.0f32;
        tspec.replenish(&mut tokens, 1.5); // 1.5 seconds
        assert!(
            (1400.0..=1500.01).contains(&tokens),
            "Should have ~1500 tokens, got {tokens}"
        );

        // Bucket should not exceed bucket_size.
        tspec.replenish(&mut tokens, 10.0);
        assert!(
            tokens <= tspec.bucket_size + 0.001,
            "bucket must not exceed capacity, got {tokens}"
        );
        assert_eq!(tokens, tspec.bucket_size);
    }

    #[test]
    fn take_admits_and_rejects_bursts() {
        let tspec = TokenBucket::new(1000.0, 2000.0);
        let mut tokens = 2000.0;

        assert!(tspec.take(&mut tokens, 600.0), "within bucket");
        assert_eq!(tokens, 1400.0);

        assert!(!tspec.take(&mut tokens, 5000.0), "burst exceeds bucket");
        assert_eq!(tokens, 1400.0, "rejected take must not remove tokens");
    }

    #[test]
    fn send_is_take() {
        let tspec = TokenBucket::new(1000.0, 2000.0);
        let mut tokens = 1500.0;
        assert!(tspec.send(&mut tokens, 1500.0));
        assert_eq!(tokens, 0.0);
        assert!(!tspec.send(&mut tokens, 1.0));
    }

    #[test]
    fn wire_format_round_trip() {
        let mut tspec = TokenBucket::new(1000.0, 2000.0);
        tspec.peak_rate = 4000.0;
        tspec.min_policed_unit = 60;
        tspec.max_packet_size = 1500;

        let bytes = tspec.to_bytes();
        assert_eq!(bytes.len(), 20);
        let parsed = TokenBucket::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, tspec);
    }

    #[test]
    fn rejects_truncated_tspec() {
        assert!(TokenBucket::from_bytes(&[0u8; 19]).is_none());
    }
}
