//! src/kernel/network/link/csma_ca.rs
//!
//! CSMA/CA — Carrier Sense Multiple Access with Collision Avoidance
//! (IEEE 802.11 DCF).
//!
//! ## Educational purpose
//!
//! A wireless station cannot listen while it transmits, so it cannot detect
//! collisions the way Ethernet does.  Instead 802.11 *avoids* them: a
//! station performs a Clear Channel Assessment (CCA), then runs a random
//! backoff chosen from an exponentially-growing contention window, and
//! exchanges short control frames (RTS/CTS) to reserve the medium before
//! sending DATA.  Every non-participating station sets a Network Allocation
//! Vector (NAV) from the announced frame durations and stays silent until
//! it expires.
//!
//! ## Why not production?
//!
//! - Real DCF is continuous-time and heavily randomised; this model is a
//!   deterministic, tick-based simulation for pedagogy.
//! - Frames are exchanged in the clear via `deliver()` — no signal propagation,
//!   capture effect, or frame aggregation.
//! - DIFS / SIFS are folded into single one-tick phase transitions.

use alloc::vec::Vec;

// ── Constants ──────────────────────────────────────────────────────────────

/// One backoff slot in ticks.
pub const SLOT_TICKS: u32 = 1;
/// Short Inter-Frame Space — the turnaround gap between control frames
/// (represented here as a single one-tick phase transition).
pub const SIFS_TICKS: u32 = 1;
/// DIFS — the gap a station must sense idle before starting a backoff.
pub const DIFS_TICKS: u32 = 2;
/// Minimum contention window (CWmin): the slot range after a clean send.
pub const CW_MIN: u32 = 15;
/// Maximum contention window (CWmax): the slot range after many collisions.
pub const CW_MAX: u32 = 1023;
/// Collisions before a frame is discarded.
pub const MAX_ATTEMPTS: u32 = 6;
/// Ticks without a CTS before an RTS is treated as lost.
pub const CTS_TIMEOUT_TICKS: u32 = 5;
/// Ticks without an ACK before DATA is treated as lost.
pub const ACK_TIMEOUT_TICKS: u32 = 5;
/// NAV duration set by a CTS (ticks).
pub const NAV_CTS_TICKS: u32 = 4;
/// NAV duration set by a DATA frame (ticks).
pub const NAV_DATA_TICKS: u32 = 8;
/// NAV duration set by an ACK (ticks).
pub const NAV_ACK_TICKS: u32 = 4;

// ── Frame kinds and events ─────────────────────────────────────────────────

/// The kinds of frame that appear on the medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Request to Send — reserves the medium.
    Rts,
    /// Clear to Send — the receiver approves the reservation.
    Cts,
    /// The data payload itself.
    Data,
    /// Acknowledgment.
    Ack,
    /// A jam pattern observed after a collision.
    Jam,
}

/// What happened during one station tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeEvent {
    /// The station transmitted a frame onto the medium.
    Transmitted(FrameKind),
    /// The exchange completed: DATA was acknowledged.
    Acknowledged,
    /// No CTS/ACK arrived — the station doubled its CW and backed off.
    CollisionRetry,
    /// The medium was busy (NAV active) and the station deferred.
    Deferred,
}

// ── Exchange state machine ─────────────────────────────────────────────────

/// The phase of the RTS/CTS/DATA/ACK handshake a station is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeState {
    /// Not participating in an exchange.
    Idle,
    /// Waiting out a contention-window backoff before sending RTS.
    Backoff,
    /// RTS sent, waiting for CTS.
    WaitingCts,
    /// An RTS was received; about to reply with CTS.
    RespondingCts,
    /// CTS received, sending DATA.
    SendingData,
    /// DATA sent, waiting for ACK.
    WaitingAck,
    /// DATA was received; about to reply with ACK.
    RespondingAck,
    /// The medium is reserved (NAV active); deferring.
    Deferring,
}

// ── Shared medium ──────────────────────────────────────────────────────────

/// The shared wireless medium: NAV, the current transmitter, and a record
/// of the last frame broadcast (so a test harness can "overhear" it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bus {
    /// Remaining ticks the medium is reserved for an announced exchange.
    pub nav_remaining: u32,
    /// Id of the station currently holding the medium, if any.
    pub transmitter: Option<u32>,
    /// True when two stations transmitted in the same slot.
    pub collision: bool,
    /// The last frame broadcast on the medium.
    pub last_frame: Option<(FrameKind, Vec<u8>)>,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    /// Create an idle medium.
    pub fn new() -> Self {
        Self {
            nav_remaining: 0,
            transmitter: None,
            collision: false,
            last_frame: None,
        }
    }

    /// True when the medium is free: no transmitter, no NAV, no collision.
    pub fn is_idle(&self) -> bool {
        self.transmitter.is_none() && self.nav_remaining == 0 && !self.collision
    }

    /// Reserve the medium for `ticks` (used to set the NAV for other
    /// stations from the duration announced in a CTS/DATA/ACK).
    pub fn set_nav(&mut self, ticks: u32) {
        if ticks > self.nav_remaining {
            self.nav_remaining = ticks;
        }
    }

    /// A station begins transmitting.  Returns `false` (and flags a
    /// collision) if another station already holds the medium.
    pub fn start_transmit(&mut self, station: u32) -> bool {
        match self.transmitter {
            Some(other) if other != station => {
                self.collision = true;
                false
            }
            Some(_) => true,
            None => {
                self.transmitter = Some(station);
                true
            }
        }
    }

    /// Release the medium.
    pub fn end_transmit(&mut self) {
        self.transmitter = None;
    }

    /// Broadcast a frame on the medium, recording it as the last seen.
    pub fn broadcast(&mut self, kind: FrameKind, payload: Vec<u8>) {
        self.last_frame = Some((kind, payload));
    }

    /// Advance the medium one tick: NAV countdown and collision clear.
    pub fn tick(&mut self) {
        if self.nav_remaining > 0 {
            self.nav_remaining -= 1;
        }
        self.collision = false;
    }
}

// ── Station ────────────────────────────────────────────────────────────────

/// A CSMA/CA station running the 802.11 DCF exchange state machine.
#[derive(Debug, Clone)]
pub struct Station {
    /// Stable identifier used as the backoff randomisation seed.
    pub id: u32,
    /// Current phase of the RTS/CTS/DATA/ACK exchange.
    pub state: ExchangeState,
    /// Current contention window (slot range).
    pub cw: u32,
    /// Backoff slots remaining before the station may transmit.
    pub backoff_remaining: u32,
    /// Station-local NAV: ticks to stay silent.
    pub nav_remaining: u32,
    /// Number of failed transmission attempts for the current frame.
    pub attempts: u32,
    /// The DATA payload queued for transmission, if any.
    pub data: Option<Vec<u8>>,
    /// The DATA payload received most recently, if any.
    pub received_data: Option<Vec<u8>>,
    /// Last control frame received (CTS/ACK).
    last_rx: Option<FrameKind>,
    /// Ticks spent in the current state (drives timeouts).
    ticks_in_state: u32,
}

impl Station {
    /// Create a station with an empty CW and no data pending.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            state: ExchangeState::Idle,
            cw: CW_MIN,
            backoff_remaining: 0,
            nav_remaining: 0,
            attempts: 0,
            data: None,
            received_data: None,
            last_rx: None,
            ticks_in_state: 0,
        }
    }

    /// Queue a DATA payload for transmission.
    pub fn enqueue(&mut self, data: Vec<u8>) {
        self.data = Some(data);
    }

    /// Hand a frame received from the medium to the station.  Control
    /// frames that target this station drive it into the appropriate
    /// response state.
    pub fn deliver(&mut self, kind: FrameKind, payload: &[u8]) {
        match kind {
            FrameKind::Rts => {
                if self.state == ExchangeState::Idle {
                    self.state = ExchangeState::RespondingCts;
                    self.ticks_in_state = 0;
                }
            }
            FrameKind::Cts => self.last_rx = Some(FrameKind::Cts),
            FrameKind::Data => {
                if self.state == ExchangeState::Idle {
                    self.received_data = Some(payload.to_vec());
                    self.state = ExchangeState::RespondingAck;
                    self.ticks_in_state = 0;
                }
            }
            FrameKind::Ack => self.last_rx = Some(FrameKind::Ack),
            FrameKind::Jam => {}
        }
    }

    /// Advance the station one tick and report what, if anything, happened.
    pub fn step(&mut self, bus: &mut Bus) -> Option<ExchangeEvent> {
        if self.nav_remaining > 0 {
            self.nav_remaining -= 1;
        }
        self.ticks_in_state += 1;

        match self.state {
            ExchangeState::Idle => {
                if self.data.is_some() {
                    if bus.is_idle() {
                        self.enter_backoff();
                    } else {
                        self.state = ExchangeState::Deferring;
                        return Some(ExchangeEvent::Deferred);
                    }
                }
                None
            }
            ExchangeState::Deferring => {
                if bus.is_idle() {
                    self.state = ExchangeState::Backoff;
                    self.enter_backoff();
                }
                Some(ExchangeEvent::Deferred)
            }
            ExchangeState::Backoff => {
                if !bus.is_idle() {
                    return Some(ExchangeEvent::Deferred);
                }
                if self.backoff_remaining > 0 {
                    self.backoff_remaining -= 1;
                    None
                } else {
                    self.transmit_rts(bus)
                }
            }
            ExchangeState::WaitingCts => {
                if self.last_rx.take() == Some(FrameKind::Cts) {
                    // CTS received — SIFS passes, then DATA goes out.
                    self.state = ExchangeState::SendingData;
                    self.ticks_in_state = 0;
                    None
                } else if self.ticks_in_state >= CTS_TIMEOUT_TICKS {
                    self.on_collision();
                    Some(ExchangeEvent::CollisionRetry)
                } else {
                    None
                }
            }
            ExchangeState::SendingData => self.transmit_data(bus),
            ExchangeState::WaitingAck => {
                if self.last_rx.take() == Some(FrameKind::Ack) {
                    self.state = ExchangeState::Idle;
                    self.data = None;
                    self.cw = CW_MIN;
                    self.attempts = 0;
                    self.ticks_in_state = 0;
                    Some(ExchangeEvent::Acknowledged)
                } else if self.ticks_in_state >= ACK_TIMEOUT_TICKS {
                    self.on_collision();
                    Some(ExchangeEvent::CollisionRetry)
                } else {
                    None
                }
            }
            ExchangeState::RespondingCts => self.transmit_cts(bus),
            ExchangeState::RespondingAck => self.transmit_ack(bus),
        }
    }

    // ── internal helpers ──────────────────────────────────────────────

    /// Pick a deterministic backoff slot and enter the Backoff state.
    fn enter_backoff(&mut self) {
        self.state = ExchangeState::Backoff;
        self.ticks_in_state = 0;
        let max_slots = self.cw as u64;
        let slot = (self.id as u64 * 17 + self.attempts as u64 * 31) % (max_slots + 1);
        self.backoff_remaining = DIFS_TICKS + (slot as u32) * SLOT_TICKS;
    }

    /// Send an RTS, entering WaitingCts.
    fn transmit_rts(&mut self, bus: &mut Bus) -> Option<ExchangeEvent> {
        if !bus.start_transmit(self.id) {
            // Another station won the same slot — treat as a collision.
            self.on_collision();
            return Some(ExchangeEvent::CollisionRetry);
        }
        bus.broadcast(FrameKind::Rts, self.data.clone().unwrap_or_default());
        bus.end_transmit();
        self.state = ExchangeState::WaitingCts;
        self.ticks_in_state = 0;
        Some(ExchangeEvent::Transmitted(FrameKind::Rts))
    }

    /// Reply to a received RTS with a CTS and return to Idle.
    fn transmit_cts(&mut self, bus: &mut Bus) -> Option<ExchangeEvent> {
        bus.broadcast(FrameKind::Cts, alloc::vec![]);
        bus.end_transmit();
        bus.set_nav(NAV_CTS_TICKS);
        self.state = ExchangeState::Idle;
        self.ticks_in_state = 0;
        Some(ExchangeEvent::Transmitted(FrameKind::Cts))
    }

    /// Transmit the queued DATA payload, entering WaitingAck.
    fn transmit_data(&mut self, bus: &mut Bus) -> Option<ExchangeEvent> {
        let payload = self.data.clone().unwrap_or_default();
        bus.broadcast(FrameKind::Data, payload);
        bus.end_transmit();
        bus.set_nav(NAV_DATA_TICKS);
        self.state = ExchangeState::WaitingAck;
        self.ticks_in_state = 0;
        Some(ExchangeEvent::Transmitted(FrameKind::Data))
    }

    /// Reply to received DATA with an ACK and return to Idle.
    fn transmit_ack(&mut self, bus: &mut Bus) -> Option<ExchangeEvent> {
        bus.broadcast(FrameKind::Ack, alloc::vec![]);
        bus.end_transmit();
        bus.set_nav(NAV_ACK_TICKS);
        self.state = ExchangeState::Idle;
        self.ticks_in_state = 0;
        Some(ExchangeEvent::Transmitted(FrameKind::Ack))
    }

    /// React to a lost CTS/ACK (a collision): double the contention window
    /// and back off, or discard the frame after too many attempts.
    fn on_collision(&mut self) {
        self.attempts += 1;
        if self.attempts >= MAX_ATTEMPTS {
            self.discard_current();
            return;
        }
        self.cw = (self.cw * 2 + 1).min(CW_MAX);
        self.state = ExchangeState::Backoff;
        self.ticks_in_state = 0;
        let max_slots = self.cw as u64;
        let slot = (self.id as u64 * 17 + self.attempts as u64 * 31) % (max_slots + 1);
        self.backoff_remaining = DIFS_TICKS + (slot as u32) * SLOT_TICKS;
    }

    /// Drop the current frame and reset to a fresh contention state.
    fn discard_current(&mut self) {
        self.data = None;
        self.state = ExchangeState::Idle;
        self.cw = CW_MIN;
        self.backoff_remaining = 0;
        self.attempts = 0;
        self.ticks_in_state = 0;
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rts_cts_data_ack_happy_path() {
        let mut bus = Bus::new();
        let mut alice = Station::new(1);
        let mut bob = Station::new(2);

        let payload = vec![0xAB; 8];
        alice.enqueue(payload.clone());

        // Alice contends for the medium and transmits RTS after backoff.
        let mut rts = false;
        for _ in 0..128 {
            if matches!(
                alice.step(&mut bus),
                Some(ExchangeEvent::Transmitted(FrameKind::Rts))
            ) {
                rts = true;
                break;
            }
        }
        assert!(rts, "Alice should transmit RTS");
        assert_eq!(alice.state, ExchangeState::WaitingCts);
        assert!(matches!(bus.last_frame, Some((FrameKind::Rts, _))));

        // Bob receives the RTS and replies with CTS.
        bob.deliver(FrameKind::Rts, &[]);
        let ev = bob.step(&mut bus);
        assert!(matches!(
            ev,
            Some(ExchangeEvent::Transmitted(FrameKind::Cts))
        ));

        // Alice receives the CTS, then transmits DATA.
        alice.deliver(FrameKind::Cts, &[]);
        assert!(
            alice.step(&mut bus).is_none(),
            "one tick of SIFS before DATA"
        );
        assert_eq!(alice.state, ExchangeState::SendingData);
        let ev = alice.step(&mut bus);
        assert!(matches!(
            ev,
            Some(ExchangeEvent::Transmitted(FrameKind::Data))
        ));
        assert!(matches!(
            bus.last_frame,
            Some((FrameKind::Data, ref d)) if *d == payload
        ));

        // Bob receives the DATA and replies with ACK.
        bob.deliver(FrameKind::Data, &payload);
        let ev = bob.step(&mut bus);
        assert!(matches!(
            ev,
            Some(ExchangeEvent::Transmitted(FrameKind::Ack))
        ));

        // Alice receives the ACK and completes the exchange.
        alice.deliver(FrameKind::Ack, &[]);
        let ev = alice.step(&mut bus);
        assert!(matches!(ev, Some(ExchangeEvent::Acknowledged)));
        assert_eq!(alice.state, ExchangeState::Idle);
        assert_eq!(alice.cw, CW_MIN, "CW resets after a clean exchange");
    }

    #[test]
    fn missing_cts_times_out_and_doubles_backoff() {
        let mut bus = Bus::new();
        let mut alice = Station::new(1);
        let mut bob = Station::new(2);
        alice.enqueue(vec![0xAA; 4]);
        bob.enqueue(vec![0xBB; 4]);

        // Both stations transmit an RTS in the same slot...
        let mut alice_rts = false;
        let mut bob_rts = false;
        for _ in 0..128 {
            if matches!(
                alice.step(&mut bus),
                Some(ExchangeEvent::Transmitted(FrameKind::Rts))
            ) {
                alice_rts = true;
                break;
            }
        }
        for _ in 0..128 {
            if matches!(
                bob.step(&mut bus),
                Some(ExchangeEvent::Transmitted(FrameKind::Rts))
            ) {
                bob_rts = true;
                break;
            }
        }
        assert!(alice_rts && bob_rts, "both stations should transmit RTS");
        assert_eq!(alice.state, ExchangeState::WaitingCts);
        assert_eq!(bob.state, ExchangeState::WaitingCts);

        // ...but neither receives a CTS, so both time out and back off.
        let mut alice_retry = false;
        let mut bob_retry = false;
        for _ in 0..64 {
            if matches!(alice.step(&mut bus), Some(ExchangeEvent::CollisionRetry)) {
                alice_retry = true;
                break;
            }
        }
        for _ in 0..64 {
            if matches!(bob.step(&mut bus), Some(ExchangeEvent::CollisionRetry)) {
                bob_retry = true;
                break;
            }
        }
        assert!(alice_retry && bob_retry, "both stations should back off");
        assert_eq!(alice.cw, CW_MIN * 2 + 1, "CW doubles after a collision");
        assert_eq!(bob.cw, CW_MIN * 2 + 1);
        assert_eq!(alice.state, ExchangeState::Backoff);
        assert_eq!(bob.state, ExchangeState::Backoff);
    }

    #[test]
    fn nav_deferral_blocks_transmission() {
        let mut bus = Bus::new();
        let mut alice = Station::new(1);
        alice.enqueue(vec![0xAA; 4]);

        // Another station reserves the medium for 3 ticks.
        bus.set_nav(3);

        // While the NAV is active Alice must not transmit anything.
        for _ in 0..3 {
            let ev = alice.step(&mut bus);
            assert!(matches!(ev, Some(ExchangeEvent::Deferred)));
            bus.tick();
        }

        // After the NAV expires Alice may begin her backoff and RTS.
        let mut rts = false;
        for _ in 0..128 {
            if matches!(
                alice.step(&mut bus),
                Some(ExchangeEvent::Transmitted(FrameKind::Rts))
            ) {
                rts = true;
                break;
            }
        }
        assert!(rts, "Alice should transmit RTS once the NAV expires");
    }
}
