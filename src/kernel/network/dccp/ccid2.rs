//! src/kernel/network/dccp/ccid2.rs
//!
//! CCID 2 — TCP-like congestion control (RFC 4341), simplified.
//!
//! The congestion control state is per-connection: a congestion window
//! (`cwnd`, in packets), a slow-start threshold (`ssthresh`), an in-flight
//! counter, and a short history of per-sequence ack/loss outcomes used to
//! emit Ack Vector options (RFC 4341 §11).
//!
//! Ack Vector run-length encoding used here: each value byte is
//! `[ack state bit 7][run length bits 6-0]`, where state 0 = acked and
//! state 1 = lost, and the run length counts how many consecutive packets
//! share that state (most-recent sequence first).  The encoder caps runs at
//! 127 and emits at most 48 sequence numbers per vector.

use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;

/// Maximum number of sequence numbers covered by one Ack Vector.
const ACK_VECTOR_MAX_ENTRIES: usize = 48;

/// CCID 2 per-connection congestion-control state.
#[derive(Debug, Clone)]
pub struct Ccid2State {
    /// Congestion window in packets (start in slow start at 2).
    pub cwnd: u32,
    /// Slow-start threshold.  `u32::MAX` means "in slow start".
    pub ssthresh: u32,
    /// Number of packets sent but not yet acknowledged.
    pub in_flight: u32,
    /// Last sequence number sent.
    pub last_seq: u64,
    /// Per-sequence ack/loss outcomes for Ack Vector generation
    /// (`true` = acked, `false` = lost), oldest first.
    pub acked_window: VecDeque<bool>,
}

impl Default for Ccid2State {
    fn default() -> Self {
        Self::new()
    }
}

impl Ccid2State {
    pub fn new() -> Self {
        Self {
            cwnd: 2,
            ssthresh: u32::MAX,
            in_flight: 0,
            last_seq: 0,
            acked_window: VecDeque::new(),
        }
    }

    /// Record that a packet with sequence number `seq` was sent.
    pub fn on_packet_sent(&mut self, seq: u64) {
        self.last_seq = seq;
        self.in_flight = self.in_flight.saturating_add(1);
    }

    /// Whether a new packet may be sent (window gate).
    pub fn can_send(&self) -> bool {
        self.in_flight < self.cwnd
    }

    /// Record a locally observed ack outcome for `seq` (used both by the
    /// sender processing remote Ack Vectors and by the receiver building its
    /// own Ack Vector).
    pub fn record_outcome(&mut self, seq: u64, acked: bool) {
        if self.acked_window.len() >= ACK_VECTOR_MAX_ENTRIES {
            self.acked_window.pop_front();
        }
        self.acked_window.push_back(acked);
        let _ = seq;
    }

    /// Process an acknowledgment: `acked` packets reduced `in_flight`;
    /// `lost` packets halve the window (fast recovery).  Grow `cwnd` in slow
    /// start, else AIMD.
    pub fn on_ack(&mut self, num_acked: u32, num_lost: u32) {
        self.in_flight = self.in_flight.saturating_sub(num_acked);

        if num_lost > 0 {
            // Loss: halve the window and drop into congestion avoidance.
            self.ssthresh = (self.cwnd / 2).max(1);
            self.cwnd = self.ssthresh;
            return;
        }

        if self.cwnd < self.ssthresh {
            // Slow start: one packet per acknowledgment.
            self.cwnd = self.cwnd.saturating_add(num_acked);
        } else {
            // Congestion avoidance (AIMD): one packet per window of acks.
            let full_windows = num_acked / self.cwnd;
            self.cwnd = self
                .cwnd
                .saturating_add(full_windows.max(1).min(num_acked).min(1));
        }
        self.cwnd = self.cwnd.min(64); // cap
    }

    /// Emit the Ack Vector option value bytes (without the `[type][len]`
    /// prefix): run-lengths of ack/loss state, most-recent sequence first.
    pub fn build_ack_vector_value(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let iter = self.acked_window.iter().rev(); // newest first
        let mut count = 0usize;
        let mut state = false;
        for &acked in iter {
            if count == 0 {
                state = acked;
                count = 1;
            } else if acked == state && count < 127 {
                count += 1;
            } else {
                // Bit 7 set means LOST; clear means ACKED (matches
                // `decode_ack_vector_value`).
                out.push(if !state {
                    0x80 | (count as u8)
                } else {
                    count as u8
                });
                state = acked;
                count = 1;
            }
        }
        if count > 0 {
            out.push(if !state {
                0x80 | (count as u8)
            } else {
                count as u8
            });
        }
        out
    }

    /// Build the complete Ack Vector option (`[type 12][len][value]`).
    pub fn build_ack_vector_option(&self) -> Vec<u8> {
        let value = self.build_ack_vector_value();
        let mut option = Vec::with_capacity(2 + value.len());
        option.push(12);
        option.push(2 + value.len() as u8);
        option.extend_from_slice(&value);
        option
    }
}

/// Decode an Ack Vector value into (acked, lost) packet counts
/// (RFC 4341 §11, using this kernel's run-length encoding).
pub fn decode_ack_vector_value(value: &[u8]) -> (u32, u32) {
    let mut acked = 0u32;
    let mut lost = 0u32;
    for &byte in value {
        let is_lost = byte & 0x80 != 0;
        let run = (byte & 0x7F) as u32;
        if is_lost {
            lost = lost.saturating_add(run);
        } else {
            acked = acked.saturating_add(run);
        }
    }
    (acked, lost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn new_starts_in_slow_start_with_window_two() {
        let state = Ccid2State::new();
        assert_eq!(state.cwnd, 2);
        assert_eq!(state.ssthresh, u32::MAX);
        assert_eq!(state.in_flight, 0);
        assert!(state.can_send());
    }

    #[test]
    fn can_send_respects_window() {
        let mut state = Ccid2State::new();
        state.on_packet_sent(1);
        state.on_packet_sent(2);
        assert!(!state.can_send(), "window of 2 filled");
        state.on_ack(1, 0);
        assert!(state.can_send());
    }

    #[test]
    fn slow_start_grows_window() {
        let mut state = Ccid2State::new();
        state.on_ack(1, 0);
        assert_eq!(state.cwnd, 3);
        state.on_ack(1, 0);
        assert_eq!(state.cwnd, 4);
    }

    #[test]
    fn loss_halves_window() {
        let mut state = Ccid2State::new();
        // Grow past the threshold into congestion avoidance.
        state.cwnd = 10;
        state.ssthresh = 6;
        state.on_ack(1, 1);
        assert_eq!(state.cwnd, 5);
        assert_eq!(state.ssthresh, 5);
    }

    #[test]
    fn ack_vector_run_length_encoding() {
        let mut state = Ccid2State::new();
        // Three acked, then one lost, then two acked.
        state.record_outcome(1, true);
        state.record_outcome(2, true);
        state.record_outcome(3, true);
        state.record_outcome(4, false);
        state.record_outcome(5, true);
        state.record_outcome(6, true);
        let value = state.build_ack_vector_value();
        // Newest first: two acked (0x02), one lost (0x81), three acked (0x03).
        assert_eq!(value, vec![0x02, 0x81, 0x03]);

        let option = state.build_ack_vector_option();
        assert_eq!(option[0], 12);
        assert_eq!(option[1] as usize, option.len());
    }

    #[test]
    fn ack_vector_decode_counts_acked_and_lost() {
        let value = [0x02, 0x81, 0x03];
        let (acked, lost) = decode_ack_vector_value(&value);
        assert_eq!(acked, 2 + 3);
        assert_eq!(lost, 1);
    }
}
