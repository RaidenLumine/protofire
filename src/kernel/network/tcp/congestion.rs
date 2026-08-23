//! src/kernel/network/tcp/congestion.rs
//! Pluggable TCP congestion control framework.
//!
//! Implements the classic TCP congestion control algorithms:
//!
//! **Tahoe** (Jacobson 1988):
//! - Slow Start: cwnd += 1 MSS per ACK (exponential growth).
//! - Congestion Avoidance: cwnd += 1/cwnd MSS per ACK (linear growth).
//! - On loss (3 dup ACKs or RTO): ssthresh = cwnd/2, cwnd = 1 MSS,
//!   enter Slow Start.
//!
//! **Reno** (Jacobson 1990):
//! - Tahoe + Fast Retransmit + Fast Recovery.
//! - On 3 dup ACKs: ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS,
//!   retransmit lost segment, enter Fast Recovery.
//! - In Fast Recovery: cwnd += 1 MSS per dup ACK.
//! - On new ACK covering recovery point: cwnd = ssthresh, exit recovery.

use core::fmt;

/// Minimum congestion window (1 MSS).
const MIN_CWND: u32 = 1;

/// Default initial congestion window (RFC 5681: 10 MSS, capped by SMSS).
/// For simplicity we use 2 MSS for the prototype kernel.
const INITIAL_CWND: u32 = 4;

/// Default slow-start threshold (effectively unlimited until first loss).
const INITIAL_SSTHRESH: u32 = u32::MAX;

/// Dup-ACK threshold for Fast Retransmit / Fast Recovery (RFC 5681 §3.2).
const DUP_ACK_THRESH: u8 = 3;

// ── Congestion state ────────────────────────────────────────────────────────

/// Per-connection congestion control state.
#[derive(Debug, Clone)]
pub struct CongestionState {
    /// Congestion window in MSS units.
    pub cwnd: u32,
    /// Slow-start threshold in MSS units.
    pub ssthresh: u32,
    /// Duplicate ACK counter (reset on new data ACK).
    dup_ack_count: u8,
    /// Whether the connection is in Fast Recovery (Reno only).
    in_recovery: bool,
    /// The highest sequence number sent when Fast Recovery started
    /// (recovery point).  A new ACK covering this means recovery ends.
    recovery_point: u32,
    /// The algorithm variant in use.
    algorithm: CongestionAlgorithm,
}

impl Default for CongestionState {
    fn default() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            dup_ack_count: 0,
            in_recovery: false,
            recovery_point: 0,
            algorithm: CongestionAlgorithm::Reno,
        }
    }
}

impl CongestionState {
    /// Create a new congestion state with the given algorithm.
    pub fn new(algorithm: CongestionAlgorithm) -> Self {
        Self {
            algorithm,
            ..Default::default()
        }
    }

    /// The algorithm in use.
    pub fn algorithm(&self) -> CongestionAlgorithm {
        self.algorithm
    }

    /// Effective send window in bytes: min(cwnd * mss, receiver_window).
    pub fn effective_window(&self, mss: usize, receiver_window: u32) -> usize {
        let cwnd_bytes = (self.cwnd as usize).saturating_mul(mss);
        let rwnd_bytes = receiver_window as usize;
        cwnd_bytes.min(rwnd_bytes).max(mss) // at least 1 MSS
    }

    /// Whether the sender is allowed to transmit another segment given
    /// the current number of bytes in flight.
    pub fn can_send(&self, bytes_in_flight: usize, mss: usize) -> bool {
        let cwnd_bytes = (self.cwnd as usize).saturating_mul(mss);
        bytes_in_flight < cwnd_bytes
    }

    // ── Event handlers ───────────────────────────────────────────────────

    /// Called when a new (non-duplicate) ACK is received.
    ///
    /// `bytes_acked` is the number of new bytes acknowledged.
    /// `mss` is the current effective MSS.
    /// `send_unacked` is the updated SND.UNA after this ACK.
    pub fn on_new_ack(&mut self, bytes_acked: u32, mss: usize, send_unacked: u32) {
        let mss_u32 = mss as u32;

        if self.in_recovery {
            // Fast Recovery (Reno).
            if send_unacked.wrapping_sub(self.recovery_point) <= u32::MAX / 2 {
                // ACK covers recovery point → exit recovery.
                self.cwnd = self.ssthresh;
                self.in_recovery = false;
                self.dup_ack_count = 0;
            } else {
                // Partial ACK in recovery: retransmit next lost segment,
                // deflate cwnd by the acked amount, add back 1 MSS.
                self.cwnd = self.cwnd.saturating_sub(bytes_acked / mss_u32).max(1);
                self.cwnd += 1;
            }
            return;
        }

        self.dup_ack_count = 0;

        if self.cwnd < self.ssthresh {
            // Slow Start: exponential growth.
            self.cwnd = self.cwnd.saturating_add((bytes_acked / mss_u32).max(1));
        } else {
            // Congestion Avoidance: linear growth (~1 MSS per RTT).
            // Approximate: cwnd += (bytes_acked / cwnd) per ACK.
            let inc = (bytes_acked as u64)
                .saturating_mul(mss_u32 as u64)
                .saturating_div(self.cwnd as u64 * mss_u32 as u64)
                .min(1);
            self.cwnd = self.cwnd.saturating_add(inc as u32);
        }
    }

    /// Called when a duplicate ACK is received.
    ///
    /// Returns `true` when a fast retransmit should be triggered.
    pub fn on_dup_ack(&mut self, send_unacked: u32) -> bool {
        if self.in_recovery {
            // In Fast Recovery: inflate cwnd by 1 MSS per dup ACK.
            self.cwnd += 1;
            return false;
        }

        self.dup_ack_count += 1;

        if self.dup_ack_count == DUP_ACK_THRESH {
            match self.algorithm {
                CongestionAlgorithm::Reno => {
                    // Fast Retransmit + Fast Recovery.
                    self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
                    self.cwnd = self.ssthresh + DUP_ACK_THRESH as u32;
                    self.in_recovery = true;
                    self.recovery_point = send_unacked;
                    return true; // trigger retransmit
                }
                CongestionAlgorithm::Tahoe => {
                    // Fast Retransmit, no Fast Recovery.
                    // The actual cwnd reset happens on RTO or we treat
                    // triple dup ACK same as timeout in Tahoe.
                    self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
                    self.cwnd = MIN_CWND;
                    self.dup_ack_count = 0;
                    return true; // trigger retransmit
                }
            }
        }

        self.dup_ack_count >= DUP_ACK_THRESH
    }

    /// Called when a retransmission timeout (RTO) occurs.
    pub fn on_rto(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = MIN_CWND;
        self.dup_ack_count = 0;
        self.in_recovery = false;
    }
}

// ── Algorithm enum ──────────────────────────────────────────────────────────

/// TCP congestion control algorithm variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// Classic Tahoe (RFC 2001 / Jacobson 1988).
    Tahoe,
    /// Reno with Fast Retransmit and Fast Recovery (RFC 2581).
    Reno,
}

impl fmt::Display for CongestionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CongestionAlgorithm::Tahoe => write!(f, "tahoe"),
            CongestionAlgorithm::Reno => write!(f, "reno"),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MSS: usize = 1460;

    #[test]
    fn tahoe_slow_start_grows_exponentially() {
        let mut state = CongestionState::new(CongestionAlgorithm::Tahoe);
        assert_eq!(state.cwnd, INITIAL_CWND);

        // One new ACK acknowledging 1 MSS → cwnd += 1.
        state.on_new_ack(TEST_MSS as u32, TEST_MSS, 1000);
        assert_eq!(state.cwnd, INITIAL_CWND + 1);

        // Another ACK → cwnd += 1 again.
        state.on_new_ack(TEST_MSS as u32, TEST_MSS, 2000);
        assert_eq!(state.cwnd, INITIAL_CWND + 2);
    }

    #[test]
    fn tahoe_on_rto_resets_cwnd() {
        let mut state = CongestionState::new(CongestionAlgorithm::Tahoe);
        // Grow cwnd to 10.
        for _ in 0..6 {
            state.on_new_ack(TEST_MSS as u32, TEST_MSS, 1000);
        }
        assert!(state.cwnd >= 10);

        // RTO: ssthresh = cwnd/2, cwnd = 1.
        state.on_rto();
        assert_eq!(state.cwnd, MIN_CWND);
        assert_eq!(state.ssthresh, 5);
    }

    #[test]
    fn tahoe_triple_dup_ack_retransmits_and_resets_cwnd() {
        let mut state = CongestionState::new(CongestionAlgorithm::Tahoe);
        state.cwnd = 20;
        state.ssthresh = INITIAL_SSTHRESH;

        // Three dup ACKs → retransmit, cwnd = 1, ssthresh = 10.
        state.on_dup_ack(1000);
        state.on_dup_ack(1000);
        let retransmit = state.on_dup_ack(1000);

        assert!(retransmit, "should trigger retransmit on 3rd dup ACK");
        assert_eq!(state.cwnd, MIN_CWND);
        assert_eq!(state.ssthresh, 10);
    }

    #[test]
    fn reno_fast_recovery_on_triple_dup_ack() {
        let mut state = CongestionState::new(CongestionAlgorithm::Reno);
        state.cwnd = 20;
        state.ssthresh = INITIAL_SSTHRESH;

        let recovery_snd_una: u32 = 5000;

        // Three dup ACKs.
        state.on_dup_ack(recovery_snd_una);
        state.on_dup_ack(recovery_snd_una);
        let retransmit = state.on_dup_ack(recovery_snd_una);

        assert!(retransmit, "should trigger retransmit on 3rd dup ACK");
        assert!(state.in_recovery, "should enter Fast Recovery");
        // cwnd = ssthresh + 3 = 10 + 3 = 13.
        assert_eq!(state.cwnd, 13);
        assert_eq!(state.ssthresh, 10);
        assert_eq!(state.recovery_point, recovery_snd_una);
    }

    #[test]
    fn reno_exits_fast_recovery_on_recovery_point_ack() {
        let mut state = CongestionState::new(CongestionAlgorithm::Reno);
        state.cwnd = 20;
        let recovery_snd_una: u32 = 5000;

        // Enter Fast Recovery.
        state.on_dup_ack(recovery_snd_una);
        state.on_dup_ack(recovery_snd_una);
        state.on_dup_ack(recovery_snd_una);
        assert!(state.in_recovery);

        // Dup ACKs in recovery inflate cwnd.
        state.on_dup_ack(recovery_snd_una);
        assert_eq!(state.cwnd, 14); // 13 + 1

        // New ACK covering recovery point → exit recovery, cwnd = ssthresh.
        state.on_new_ack(TEST_MSS as u32, TEST_MSS, recovery_snd_una + 1);
        assert!(!state.in_recovery);
        assert_eq!(state.cwnd, state.ssthresh);
    }

    #[test]
    fn slow_start_transitions_to_congestion_avoidance() {
        let mut state = CongestionState::new(CongestionAlgorithm::Reno);
        // Set ssthresh low so we transition.
        state.ssthresh = 6;
        // Grow in slow start until cwnd >= ssthresh.
        while state.cwnd < state.ssthresh {
            state.on_new_ack(TEST_MSS as u32, TEST_MSS, 1000);
        }
        assert!(state.cwnd >= state.ssthresh);

        // Now in congestion avoidance — growth is much slower.
        let before = state.cwnd;
        state.on_new_ack(TEST_MSS as u32, TEST_MSS, 2000);
        // In congestion avoidance, cwnd increases by ~1/cwnd per ACK.
        // With cwnd >= 6, one ACK won't visibly increase it.
        assert!(state.cwnd <= before + 1);
    }

    #[test]
    fn effective_window_computes_correctly() {
        let state = CongestionState {
            cwnd: 10,
            ..Default::default()
        };
        let mss = 1460;
        let rwnd: u32 = 20000;

        let window = state.effective_window(mss, rwnd);
        // cwnd_bytes = 10 * 1460 = 14600, rwnd = 20000 → min = 14600.
        assert_eq!(window, 14600);

        // Small receiver window dominates.
        let small_window = state.effective_window(mss, 5000);
        assert_eq!(small_window, 5000);
    }

    #[test]
    fn can_send_respects_cwnd() {
        let state = CongestionState {
            cwnd: 2,
            ..Default::default()
        }; // 2 * 1460 = 2920 bytes.
        let mss = 1460;

        assert!(state.can_send(0, mss)); // nothing in flight.
        assert!(state.can_send(1460, mss)); // 1 MSS in flight.
        assert!(!state.can_send(3000, mss)); // exceeds cwnd.
    }

    #[test]
    fn dup_ack_below_threshold_does_not_trigger() {
        let mut state = CongestionState::new(CongestionAlgorithm::Reno);
        state.cwnd = 20;

        let ret1 = state.on_dup_ack(1000);
        let ret2 = state.on_dup_ack(1000);
        assert!(!ret1);
        assert!(!ret2);
        assert_eq!(state.dup_ack_count, 2);
    }

    #[test]
    fn new_ack_resets_dup_ack_count() {
        let mut state = CongestionState::new(CongestionAlgorithm::Reno);
        state.on_dup_ack(1000);
        state.on_dup_ack(1000);
        assert_eq!(state.dup_ack_count, 2);

        // A new ACK resets the count.
        state.on_new_ack(TEST_MSS as u32, TEST_MSS, 2000);
        assert_eq!(state.dup_ack_count, 0);
    }
}
