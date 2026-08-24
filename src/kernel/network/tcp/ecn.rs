//! src/kernel/network/tcp/ecn.rs
//!
//! TCP Explicit Congestion Notification (RFC 3168).
//!
//! ECN allows routers to signal impending congestion by marking IP packets
//! instead of dropping them, enabling TCP to react before loss occurs.
//!
//! ## Handshake negotiation
//! - Client sets ECE + CWR on SYN.
//! - Server sets ECE on SYN-ACK, clears CWR.
//! - Client clears ECE on ACK of SYN.
//!   After this, both endpoints know ECN is active.
//!
//! ## Data phase
//! - Receiver: on receiving CE-marked IP packet, sets ECE on all subsequent
//!   ACKs until a data segment with CWR arrives (RFC 3168 §6.1.2).
//! - Sender: on receiving ACK with ECE set, reduces cwnd/ssthresh by half,
//!   sets CWR on next outgoing segment.  At most once per RTT (RFC 3168 §6.1.1).

/// ECN field values from the IP header (2 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    /// Not ECN-capable transport (00).
    NotEct = 0,
    /// ECN-capable transport, codepoint 0 (10).
    Ect0 = 2,
    /// ECN-capable transport, codepoint 1 (01).
    Ect1 = 1,
    /// Congestion experienced (11).
    Ce = 3,
}

impl EcnCodepoint {
    /// Extract the 2-bit ECN field from an IPv4 TOS byte.
    pub fn from_ipv4_tos(tos: u8) -> Self {
        match tos & 0x03 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// Extract the 2-bit ECN field from an IPv6 Traffic Class byte.
    pub fn from_ipv6_tc(tc: u8) -> Self {
        Self::from_ipv4_tos(tc)
    }
}

// ─── TCP flags for ECN ──────────────────────────────────────────────────────

/// TCP ECE flag (ECN-Echo, bit 6 of flags byte).
pub const TCP_FLAG_ECE: u8 = 0x40;
/// TCP CWR flag (Congestion Window Reduced, bit 7 of flags byte).
pub const TCP_FLAG_CWR: u8 = 0x80;

// ─── Per-connection ECN state ───────────────────────────────────────────────

/// ECN negotiation and reaction state for a single TCP connection.
#[derive(Debug, Clone, Default)]
pub struct EcnState {
    /// Whether ECN is enabled for this connection (negotiated during handshake).
    pub enabled: bool,
    /// Whether we are the active opener (client).  Used to determine the
    /// precise ECN handshake flag pattern.
    is_active: bool,
    /// Whether ECN handshake is in progress (SYN sent, waiting for SYN-ACK).
    handshake_pending: bool,
    /// When the receiver saw a CE-marked packet and has not yet seen a
    /// CWR-bearing segment from the sender, we keep echoing ECE on ACKs.
    receiver_saw_ce: bool,
    /// When true, the next outgoing data segment should carry the CWR flag
    /// (in response to an ECE-bearing ACK).  Cleared after sending.
    sender_must_cwr: bool,
    /// Whether a congestion reaction has been performed in the current
    /// RTT window (to avoid multiple reactions, per RFC 3168 §6.1.1).
    reacted_this_rtt: bool,
}

impl EcnState {
    /// Create a new ECN state for an active opener (client).
    pub fn new_active() -> Self {
        Self {
            enabled: true,
            is_active: true,
            handshake_pending: true,
            ..Default::default()
        }
    }

    /// Create a new ECN state for a passive opener (server / listener).
    pub fn new_passive() -> Self {
        Self {
            enabled: false, // enabled only after receiving ECN-setup SYN
            is_active: false,
            handshake_pending: false,
            ..Default::default()
        }
    }

    /// ECN flags to set on the SYN segment (active opener).
    /// RFC 3168: SYN sets ECE and CWR (ECN-setup SYN).
    pub fn syn_flags(&self) -> u8 {
        if self.enabled && self.is_active {
            TCP_FLAG_ECE | TCP_FLAG_CWR
        } else {
            0
        }
    }

    /// ECN flags to set on the SYN-ACK segment (passive opener).
    /// RFC 3168: SYN-ACK sets ECE, clears CWR.
    pub fn syn_ack_flags(&self) -> u8 {
        if self.enabled {
            TCP_FLAG_ECE
        } else {
            0
        }
    }

    /// Process the receipt of a SYN segment.  If it has ECE+CWR, enable ECN
    /// for the passive side.
    pub fn on_recv_syn(&mut self, flags: u8) {
        if flags & TCP_FLAG_ECE != 0 && flags & TCP_FLAG_CWR != 0 {
            self.enabled = true; // peer supports ECN
        }
    }

    /// Process the receipt of a SYN-ACK segment.  If ECN was requested,
    /// verify the server responded correctly (ECE set, CWR clear).
    pub fn on_recv_syn_ack(&mut self, flags: u8) {
        if self.handshake_pending {
            if flags & TCP_FLAG_ECE != 0 {
                self.handshake_pending = false; // ECN confirmed
            } else {
                self.enabled = false; // server didn't support ECN
                self.handshake_pending = false;
            }
        }
    }

    /// Called when an IP packet with CE codepoint is received.
    /// Sets `receiver_saw_ce` so that subsequent ACKs carry the ECE flag.
    pub fn on_ce_received(&mut self) {
        if self.enabled {
            self.receiver_saw_ce = true;
        }
    }

    /// Determine the ECN flags to set on an outgoing ACK segment.
    pub fn ack_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.enabled && self.receiver_saw_ce {
            flags |= TCP_FLAG_ECE;
        }
        if self.sender_must_cwr {
            flags |= TCP_FLAG_CWR;
        }
        flags
    }

    /// Called after sending a segment (to clear transient flags).
    pub fn on_segment_sent(&mut self, flags: u8) {
        if flags & TCP_FLAG_CWR != 0 {
            self.sender_must_cwr = false;
            // After sending CWR, the receiver stops echoing ECE.
            // We don't reset `receiver_saw_ce` here — it's reset when CWR
            // ACK arrives.
        }
    }

    /// Called when an ACK with ECE is received (as sender).
    /// Triggers congestion reaction (once per RTT).
    pub fn on_ece_ack(&mut self) -> bool {
        if !self.enabled || self.reacted_this_rtt {
            return false;
        }
        self.reacted_this_rtt = true;
        self.sender_must_cwr = true;
        true // caller should reduce cwnd/ssthresh
    }

    /// Called when a data segment with CWR is received (as receiver).
    /// Stops echoing ECE until the next CE-marked packet.
    pub fn on_cwr_received(&mut self) {
        self.receiver_saw_ce = false;
    }

    /// Called at the start of a new RTT (e.g. when a new ACK advances
    /// SND.UNA significantly).  Resets the "reacted this RTT" flag.
    pub fn on_new_rtt(&mut self) {
        self.reacted_this_rtt = false;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecn_codepoint_from_tos() {
        assert_eq!(EcnCodepoint::from_ipv4_tos(0x00), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_ipv4_tos(0x02), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_ipv4_tos(0x01), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_ipv4_tos(0x03), EcnCodepoint::Ce);
        // Upper bits are ignored.
        assert_eq!(EcnCodepoint::from_ipv4_tos(0xFF), EcnCodepoint::Ce);
    }

    #[test]
    fn active_opener_sets_ecn_syn_flags() {
        let ecn = EcnState::new_active();
        let flags = ecn.syn_flags();
        assert!(flags & TCP_FLAG_ECE != 0);
        assert!(flags & TCP_FLAG_CWR != 0);
    }

    #[test]
    fn passive_opener_enables_ecn_on_ecn_syn() {
        let mut ecn = EcnState::new_passive();
        assert!(!ecn.enabled);

        ecn.on_recv_syn(TCP_FLAG_ECE | TCP_FLAG_CWR);
        assert!(ecn.enabled);
        assert!(ecn.syn_ack_flags() & TCP_FLAG_ECE != 0);
    }

    #[test]
    fn active_opener_confirms_ecn_on_syn_ack() {
        let mut ecn = EcnState::new_active();
        ecn.on_recv_syn_ack(TCP_FLAG_ECE);
        assert!(ecn.enabled);
        assert!(!ecn.handshake_pending);
    }

    #[test]
    fn active_opener_disables_ecn_when_server_no_ecn() {
        let mut ecn = EcnState::new_active();
        ecn.on_recv_syn_ack(0); // No ECE → no ECN support
        assert!(!ecn.enabled);
    }

    #[test]
    fn receiver_echoes_ece_after_ce_packet() {
        let mut ecn = EcnState::new_active();
        ecn.handshake_pending = false;
        ecn.enabled = true;

        // Receive CE-marked packet.
        ecn.on_ce_received();
        assert!(ecn.receiver_saw_ce);
        assert!(ecn.ack_flags() & TCP_FLAG_ECE != 0);
    }

    #[test]
    fn receiver_stops_ece_on_cwr() {
        let mut ecn = EcnState::new_active();
        ecn.handshake_pending = false;
        ecn.enabled = true;
        ecn.receiver_saw_ce = true;

        ecn.on_cwr_received();
        assert!(!ecn.receiver_saw_ce);
        assert_eq!(ecn.ack_flags() & TCP_FLAG_ECE, 0);
    }

    #[test]
    fn sender_reacts_to_ece_ack_once_per_rtt() {
        let mut ecn = EcnState::new_active();
        ecn.handshake_pending = false;
        ecn.enabled = true;

        // First ECE ACK → react.
        assert!(ecn.on_ece_ack());
        assert!(ecn.sender_must_cwr);

        // Second ECE ACK in same RTT → no reaction.
        assert!(!ecn.on_ece_ack());

        // New RTT → can react again.
        ecn.on_new_rtt();
        assert!(ecn.on_ece_ack());
    }

    #[test]
    fn sender_clears_cwr_after_sending() {
        let mut ecn = EcnState::new_active();
        ecn.handshake_pending = false;
        ecn.enabled = true;
        ecn.on_ece_ack();
        assert!(ecn.sender_must_cwr);

        ecn.on_segment_sent(TCP_FLAG_CWR);
        assert!(!ecn.sender_must_cwr);
    }
}
