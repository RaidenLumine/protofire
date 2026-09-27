//! src/network/stack/slaac.rs
//!
//! Stateless-address autoconfiguration, driven by the tick path.
//!
//! SLAAC is two things a host does, and neither has to happen at boot: it
//! sends Router Solicitations until a Router Advertisement answers, and it
//! checks an address formed from that advertisement before using it (DAD,
//! RFC 4862 §5.4).  Both used to be written as a loop that waited on ticks —
//! `icmpv6::run_slaac`, which the boot could not call because the timer starts
//! later than the network, so it printed "skipped" and left a TODO.
//!
//! The same work is expressible as a step per tick, which is what this module
//! does: the boot arms it, the scheduler's tick drives it, and a boot with no
//! IPv6 router costs nothing but a lock the tick path already takes for the
//! other tables.

use super::NetworkStack;
use crate::network::internet::icmpv6;
use crate::network::internet::ipv6::Ipv6Addr;

/// How many Router Solicitations one attempt sends before it stops asking and
/// waits for an unsolicited advertisement.
///
/// Three, one second apart, is the RFC 4861 §6.3.7 retransmission count that
/// the blocking attempt this replaced hard-coded in its loop.
const MAX_SOLICITS: u32 = 3;

/// Ticks between Router Solicitations, and the window an address is watched
/// for a duplicate before it is used.  The kernel's timer runs at 100 Hz, so
/// both are one second.
const SOLICIT_INTERVAL_TICKS: u64 = 100;
const DAD_WINDOW_TICKS: u64 = 100;

/// The one SLAAC attempt a boot makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlaacState {
    /// Set by [`NetworkStack::start_slaac`]; cleared once an address has been
    /// solicited, formed and checked.
    pub(crate) armed: bool,
    /// How many solicitations this attempt has sent.
    pub(crate) solicits_sent: u32,
    /// The tick the next solicitation is due at.
    pub(crate) next_solicit_tick: u64,
    /// The address formed from an advertisement and waiting out its DAD
    /// window.
    pub(crate) dad_target: Option<Ipv6Addr>,
    /// The tick the DAD window closes at.
    pub(crate) dad_deadline_tick: u64,
}

impl SlaacState {
    pub(crate) const fn new() -> Self {
        Self {
            armed: false,
            solicits_sent: 0,
            next_solicit_tick: 0,
            dad_target: None,
            dad_deadline_tick: 0,
        }
    }
}

impl NetworkStack {
    /// Arm SLAAC.  The tick path does the work; this only says "try".
    ///
    /// Called by the boot once the timer is live.  It is not an error to arm
    /// twice; the second call is a no-op.
    pub fn start_slaac(&self) {
        let mut state = self.slaac.lock();
        if state.armed {
            return;
        }
        state.armed = true;
        state.solicits_sent = 0;
        // The first solicitation goes out on the next tick.
        state.next_solicit_tick = self.current_tick();
    }

    /// One tick's worth of SLAAC work.
    ///
    /// Called from [`NetworkStack::advance_tick`].  The order is the
    /// protocol's: an address that an advertisement formed is watched for a
    /// duplicate before anything else happens, and solicitations continue
    /// while there is no address yet.
    pub(crate) fn drive_slaac(&self, tick: u64) {
        let mut state = self.slaac.lock();
        if !state.armed {
            return;
        }

        if state.dad_target.is_some() {
            // The neighbour-advertisement path sets this when somebody else
            // claims an address we hold; until now nothing ever set it, which
            // made DAD a one-second wait that always passed.
            if self.dad_conflict_detected() {
                self.clear_global_ip_v6();
                state.dad_target = None;
                state.solicits_sent = 0;
                state.next_solicit_tick = tick + SOLICIT_INTERVAL_TICKS;
                crate::println!("[net   ] SLAAC: address is already in use; asking again");
                return;
            }
            // A *deadline* is compared, not an elapsed gap: `wrapping_sub`
            // would turn "the window is still open" into a huge number and read
            // as "past due".
            if tick < state.dad_deadline_tick {
                return;
            }
            state.dad_target = None;
            state.armed = false;
            crate::println!("[net   ] SLAAC: address confirmed");
            return;
        }

        // An advertisement may arrive at any time, including long after the
        // solicitations below stop; whatever forms an address gets checked.
        if self.global_ip_v6().is_some() {
            if let Some(address) = self.global_ip_v6() {
                icmpv6::send_dad_probe(self, address);
                state.dad_target = Some(address);
                state.dad_deadline_tick = tick + DAD_WINDOW_TICKS;
            }
            return;
        }

        if state.solicits_sent >= MAX_SOLICITS {
            return;
        }
        // The first solicitation goes out as soon as the attempt is armed; the
        // rest are one interval apart.  Both deadlines below are absolute ticks,
        // so they are compared rather than subtracted.
        let due = state.solicits_sent == 0 || tick >= state.next_solicit_tick;
        if !due {
            return;
        }
        let _ = icmpv6::send_router_solicitation(self);
        state.solicits_sent += 1;
        state.next_solicit_tick = tick + SOLICIT_INTERVAL_TICKS;
    }
}

/// The RFC 4861 §6.3.7 retransmission count and interval, for the test that
/// drives this without a router.
#[cfg(test)]
pub(crate) const TEST_MAX_SOLICITS: u32 = MAX_SOLICITS;
#[cfg(test)]
pub(crate) const TEST_SOLICIT_INTERVAL_TICKS: u64 = SOLICIT_INTERVAL_TICKS;
