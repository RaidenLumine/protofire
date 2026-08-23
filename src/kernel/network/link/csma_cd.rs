//! src/kernel/network/link/csma_cd.rs
//! CSMA/CD — Carrier Sense Multiple Access with Collision Detection
//! (IEEE 802.3 classic Ethernet).
//!
//! ## Educational purpose
//!
//! Ethernet shared a single coaxial medium: every station heard everything,
//! and only one station could transmit at a time.  A station "carrier
//! senses" the wire, waits until it is idle, and transmits its frame one
//! byte at a time.  If two stations transmit in the same slot the signals
//! interfere — a collision.  Because a station can listen while sending,
//! it *detects* the collision, aborts, jams the medium, and retries after a
//! randomly-chosen backoff (the truncated binary exponential backoff).
//!
//! ## Why not production?
//!
//! - Modern Ethernet is switched and full-duplex; CSMA/CD lives on only in
//!   half-duplex compat mode on old hubs.
//! - Real MACs use a hardware LFSR for backoff slots; this model seeds its
//!   "random" backoff deterministically for reproducible tests.
//! - The medium is modelled tick-by-tick with one byte per tick, a
//!   simplification of the bit-serial signalling on 10BASE-T.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

// ── Constants ──────────────────────────────────────────────────────────────

/// Transmit attempts (including the first) before a frame is discarded.
pub const MAX_ATTEMPTS: u32 = 16;
/// Exponent cap for the binary exponential backoff (slots ≤ 2^10 − 1).
pub const MAX_BACKOFF_EXPONENT: u32 = 10;
/// Length of one backoff slot in ticks.
pub const SLOT_TIME_TICKS: u32 = 1;
/// Number of preamble bytes (7 × `10101010`) before the SFD.
pub const PREAMBLE_BYTES: usize = 7;
/// The preamble byte: `10101010`.
pub const PREAMBLE_BYTE: u8 = 0x55;
/// Start Frame Delimiter: `10101011`.
pub const SFD: u8 = 0xD5;
/// Jam byte emitted after a detected collision (all ones).
pub const JAM_BYTE: u8 = 0xFF;

// ── Shared medium ──────────────────────────────────────────────────────────

/// The shared coaxial medium: who holds the wire, and whether a collision
/// was just detected.
#[derive(Debug, Clone, Default)]
pub struct Bus {
    /// True while a station holds the medium.
    transmitting: bool,
    /// True when a collision was detected in the current slot.
    collision: bool,
}

impl Bus {
    /// Create an idle medium.
    pub fn new() -> Self {
        Self {
            transmitting: false,
            collision: false,
        }
    }

    /// True when the wire is free for a new transmission.
    pub fn is_idle(&self) -> bool {
        !self.transmitting
    }

    /// A station seizes the medium.
    pub fn start_transmit(&mut self) {
        self.transmitting = true;
    }

    /// A station releases the medium.
    pub fn end_transmit(&mut self) {
        self.transmitting = false;
    }

    /// Whether a collision is currently reported on the medium.
    pub fn collision(&self) -> bool {
        self.collision
    }

    /// Report a collision (the simulation harness sets this when two
    /// stations transmit in the same tick).
    pub fn detect_collision(&mut self) {
        self.collision = true;
    }

    /// Clear the collision flag once the jam period has passed.
    pub fn clear_collision(&mut self) {
        self.collision = false;
    }
}

// ── Station ────────────────────────────────────────────────────────────────

/// A CSMA/CD station: a FIFO of pending frames plus per-frame transmission
/// and backoff state.
#[derive(Debug, Clone)]
pub struct Station {
    /// Stable identifier used as the backoff randomisation seed.
    pub id: u32,
    /// Frames (preamble + SFD + payload) waiting to be sent.
    pub tx_queue: VecDeque<Vec<u8>>,
    /// True while a frame is being clocked onto the medium.
    pub transmitting: bool,
    /// Byte offset of the next byte to emit from the current frame.
    pub tx_byte_offset: usize,
    /// Number of collisions suffered by the current frame.
    pub collision_count: u32,
    /// Backoff ticks remaining before the station may transmit.
    pub backoff_remaining: u32,
}

impl Station {
    /// Create a station with the given id and no pending frames.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            tx_queue: VecDeque::new(),
            transmitting: false,
            tx_byte_offset: 0,
            collision_count: 0,
            backoff_remaining: 0,
        }
    }

    /// Queue a frame (already carrying preamble + SFD) for transmission.
    pub fn send_frame(&mut self, frame: Vec<u8>) {
        self.tx_queue.push_back(frame);
    }

    /// Whether any frame is queued or still being transmitted.
    pub fn has_pending(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Advance the station one tick on the medium and return the byte to
    /// place on the wire, if any.
    ///
    /// Exactly one byte is emitted per tick, matching the byte-clock
    /// serial line of 10BASE-T.
    pub fn transmit_tick(&mut self, bus: &mut Bus) -> Option<Vec<u8>> {
        // 1. Backoff — count down; nothing is transmitted.
        if self.backoff_remaining > 0 {
            self.backoff_remaining -= 1;
            return None;
        }

        // 2. Collision — a collision was detected on the medium.
        if bus.collision() {
            if self.transmitting {
                // Abort the current frame, jam, and schedule a retry.  The
                // medium is released so that a deferred station can seize the
                // wire again once the jam/backoff period has elapsed.
                self.transmitting = false;
                bus.end_transmit();
                self.tx_byte_offset = 0;
                self.collision_count += 1;
                self.start_backoff();
                return Some(alloc::vec![JAM_BYTE]);
            }
            return None;
        }

        // 3. Transmitting — emit the next byte of the current frame.
        if self.transmitting {
            return self.emit_next_byte(bus);
        }

        // 4. Carrier sense — another station holds the medium; defer.
        if !bus.is_idle() {
            return None;
        }

        // 5. Idle — try to start transmitting the next frame.
        if !self.tx_queue.is_empty() && bus.is_idle() {
            // Start transmission.
            bus.start_transmit();
            self.transmitting = true;
            self.tx_byte_offset = 0;
            // Send first byte.
            if let Some(frame) = self.tx_queue.front() {
                let byte = frame[0];
                self.tx_byte_offset = 1;
                return Some(alloc::vec![byte]);
            }
        }

        None
    }

    /// Emit the next byte of the current frame, releasing the medium once
    /// the frame is complete.
    fn emit_next_byte(&mut self, bus: &mut Bus) -> Option<Vec<u8>> {
        let (byte, done) = match self.tx_queue.front() {
            Some(frame) if self.tx_byte_offset < frame.len() => {
                let b = frame[self.tx_byte_offset];
                self.tx_byte_offset += 1;
                (b, self.tx_byte_offset >= frame.len())
            }
            _ => (0x00, true),
        };

        if done {
            // Frame finished — release the medium and reset for the next.
            self.transmitting = false;
            bus.end_transmit();
            self.tx_queue.pop_front();
            self.tx_byte_offset = 0;
            self.collision_count = 0;
        }
        Some(alloc::vec![byte])
    }

    /// Compute a random backoff after a collision.
    /// Uses the truncated binary exponential backoff algorithm.
    fn start_backoff(&mut self) {
        if self.collision_count >= MAX_ATTEMPTS {
            // Give up — discard frame (caller should handle this).
            self.discard_current();
            return;
        }

        let k = self.collision_count.min(MAX_BACKOFF_EXPONENT);
        let max_slots = (1u64 << k) - 1;
        // Deterministic "random" based on station id + collision count
        // for reproducibility in tests.  Real hardware uses a true LFSR.
        let slot = (self.id as u64 * 17 + self.collision_count as u64 * 31) % (max_slots + 1);
        self.backoff_remaining = (slot * SLOT_TIME_TICKS as u64) as u32;
    }

    /// Drop the current frame and reset all per-frame state.
    fn discard_current(&mut self) {
        self.tx_queue.pop_front();
        self.transmitting = false;
        self.tx_byte_offset = 0;
        self.collision_count = 0;
        self.backoff_remaining = 0;
    }
}

// ── Helper: build a CSMA/CD frame with preamble and SFD ────────────────────

/// Build an Ethernet frame: 7 bytes of preamble (`10101010`), the start
/// frame delimiter (`10101011`), then the payload.
pub fn build_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(PREAMBLE_BYTES + 1 + payload.len());
    frame.extend_from_slice(&[PREAMBLE_BYTE; PREAMBLE_BYTES]);
    frame.push(SFD);
    frame.extend_from_slice(payload);
    frame
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn build_frame_adds_preamble_and_sfd() {
        let payload = vec![0x00, 0x01, 0x02, 0x03];
        let frame = build_frame(&payload);

        assert_eq!(frame.len(), PREAMBLE_BYTES + 1 + payload.len());
        assert!(frame[..PREAMBLE_BYTES].iter().all(|&b| b == PREAMBLE_BYTE));
        assert_eq!(frame[PREAMBLE_BYTES], SFD);
        assert_eq!(&frame[PREAMBLE_BYTES + 1..], &payload[..]);
    }

    #[test]
    fn successful_single_frame_transmission() {
        let mut bus = Bus::new();
        let mut station = Station::new(1);

        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = build_frame(&payload);
        station.send_frame(frame.clone());

        // Clock the medium until the frame is fully transmitted.
        let mut transmitted = Vec::new();
        let mut ticks = 0;
        while station.has_pending() || station.transmitting {
            if let Some(bytes) = station.transmit_tick(&mut bus) {
                transmitted.extend_from_slice(&bytes);
            }
            ticks += 1;
            assert!(ticks < 64, "frame should finish within 64 ticks");
        }

        assert_eq!(transmitted, frame, "every frame byte reaches the wire");
        assert!(bus.is_idle(), "the medium is released after the frame");
        assert_eq!(station.collision_count, 0);
        assert_eq!(station.tx_byte_offset, 0);
    }

    #[test]
    fn collision_then_backoff_then_retry() {
        let mut bus = Bus::new();
        // Station 2 picks a nonzero backoff slot after the first collision.
        let mut station = Station::new(2);

        let payload = vec![0x11, 0x22, 0x33, 0x44];
        let frame = build_frame(&payload);
        station.send_frame(frame);

        // The first preamble byte goes out.
        let b = station.transmit_tick(&mut bus).expect("first byte");
        assert_eq!(b, vec![PREAMBLE_BYTE]);
        assert!(station.transmitting);

        // A second station transmits in the same slot → collision.
        bus.detect_collision();
        let jam = station.transmit_tick(&mut bus).expect("jam byte");
        assert_eq!(jam, vec![JAM_BYTE]);
        assert!(!station.transmitting, "frame aborted on collision");
        assert_eq!(station.collision_count, 1);
        bus.clear_collision();

        // The station is backing off.
        assert!(
            station.backoff_remaining > 0,
            "station should be backing off after the collision"
        );
        while station.backoff_remaining > 0 {
            assert!(
                station.transmit_tick(&mut bus).is_none(),
                "nothing is transmitted during backoff"
            );
        }

        // After the backoff the frame is retransmitted from the start.
        let b = station
            .transmit_tick(&mut bus)
            .expect("retransmit first byte");
        assert_eq!(b, vec![PREAMBLE_BYTE]);
        assert_eq!(station.tx_byte_offset, 1);
        assert_eq!(station.collision_count, 1, "count persists until success");
    }

    #[test]
    fn defers_while_medium_busy() {
        let mut bus = Bus::new();
        let mut a = Station::new(1);
        let mut b = Station::new(2);

        let frame = build_frame(&[0x10, 0x20, 0x30]);
        a.send_frame(frame.clone());

        // A starts transmitting.
        assert_eq!(
            a.transmit_tick(&mut bus).expect("A starts")[0],
            PREAMBLE_BYTE
        );
        assert!(a.transmitting);

        // B defers — the medium is no longer idle.
        b.send_frame(frame);
        assert!(b.transmit_tick(&mut bus).is_none(), "B must defer");
        assert!(!b.transmitting);

        // A finishes its frame, releasing the medium.
        let mut ticks = 0;
        while a.has_pending() || a.transmitting {
            a.transmit_tick(&mut bus);
            ticks += 1;
            assert!(ticks < 64);
        }
        assert!(bus.is_idle(), "medium released after A finishes");

        // Only now does B begin transmitting.
        assert_eq!(
            b.transmit_tick(&mut bus).expect("B starts")[0],
            PREAMBLE_BYTE
        );
        assert!(b.transmitting);
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let mut bus = Bus::new();
        let mut station = Station::new(2);

        station.send_frame(build_frame(&[0xAA, 0xBB]));
        station.transmit_tick(&mut bus);

        // Force the collision count to the limit and collide once more.
        station.collision_count = MAX_ATTEMPTS;
        bus.detect_collision();
        let jam = station.transmit_tick(&mut bus).expect("jam byte");
        assert_eq!(jam, vec![JAM_BYTE]);
        bus.clear_collision();

        // The frame was discarded after the maximum number of attempts.
        assert!(!station.has_pending(), "frame must be discarded");
        assert!(!station.transmitting);
        assert_eq!(station.collision_count, 0);
        assert_eq!(station.backoff_remaining, 0);
    }
}
