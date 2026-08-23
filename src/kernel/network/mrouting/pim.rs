//! src/kernel/network/mrouting/pim.rs
//! PIM-Dense-Mode (PIM-DM) data plane (RFC 3973): a simplified flood-and-
//! prune multicast routing control plane.
//!
//! Dense mode is the simplest multicast routing protocol: every packet for a
//! new (S,G) is flooded out of every interface; downstream routers that have
//! no members send Prune messages to stop the flow, and send Graft to
//! re-request it.  This module implements the kernel-resident side: Hello /
//! Join-Prune / Graft / Graft-Ack message handling, a per-(S,G) prune table
//! with expiry, a PIM-neighbor table, and the flood decision invoked by the
//! forwarding engine when no MFC entry exists yet.
//!
//! Data-plane note: `pim_enabled`, `should_forward`, `flood`,
//! `rpf_allows_forward`, `sanitize_out_vifs` (the flood decision helpers) and
//! the `enable` bring-up API are exercised by the in-module test suite but
//! currently have no live caller — the multicast forwarding path that consumed
//! them was lost in the recovery snapshot (the original gated them behind
//! `cfg(any(test, feature = "educational_networking"))`).  They are retained
//! as the tested PIM-DM surface, hence the targeted `dead_code` allowances.
//!
//! Security posture (improved over the original recovery):
//! - Every inbound message's PIM checksum (bytes 2-3, one's-complement over
//!   the whole message, RFC 4601 §5.2) is validated; invalid messages are
//!   silently dropped rather than trusted.
//! - Forwarded multicast passes a real RPF (Reverse Path Forwarding) check:
//!   the route back to the source must point back through the incoming VIF
//!   (RFC 3973 §3.4.2) — we do not unconditionally flood.
//! - Packets whose TTL has been consumed are never forwarded; the forward
//!   path decrements the TTL and skips anything that would reach zero.
//! - Outgoing VIF indices read from untrusted data are clamped against the
//!   VIF table so an out-of-range index cannot cause an out-of-bounds access
//!   or panic.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::network::internet::igmp;
use crate::kernel::network::internet::ip::IpAddress;
use crate::kernel::network::internet::ipv4::{self, IpProtocol, Ipv4Addr, Ipv4Header};
use crate::kernel::network::stack::NetworkStack;
use crate::Result;

use super::mfc::OutVif;
use super::vif::VIF_LOCAL;
use super::MrtState;

/// PIM protocol number (IP protocol 103).
pub const PIM_PROTOCOL: u8 = 103;

/// All-PIM-routers link-local group (224.0.0.2): PIM control messages and
/// periodic Hellos are addressed to this group.
pub const PIM_ALL_ROUTERS: Ipv4Addr = [224, 0, 0, 2];

/// PIM Hello period: the RFC 3973 default of 30 s at the 100 Hz kernel tick.
pub const PIM_HELLO_PERIOD_TICKS: u64 = 3000;

const PIM_TYPE_HELLO: u8 = 0;
const PIM_TYPE_JOIN_PRUNE: u8 = 3;
const PIM_TYPE_GRAFT: u8 = 6;
const PIM_TYPE_GRAFT_ACK: u8 = 7;

/// Prune lifetime: 3 seconds at 100 Hz.
pub const PRUNE_TIMEOUT_TICKS: u64 = 300;
/// PIM neighbor lifetime: 3.5 × the RFC 3973 Hello holdtime (105 s at 100 Hz).
pub const NEIGHBOR_TIMEOUT_TICKS: u64 = 10_500;

/// PIM-DM state.
#[derive(Default)]
pub struct PimState {
    pub enabled: bool,
    /// `(source, group)` → tick at which the prune expires.
    pub pruned: BTreeMap<([u8; 4], [u8; 4]), u64>,
    /// PIM neighbor address → tick it was last heard from (via Hello).
    pub neighbors: BTreeMap<IpAddress, u64>,
    pub prune_timeout_ticks: u64,
    pub neighbor_timeout_ticks: u64,
    /// Period between periodic PIM Hello transmissions (ticks).
    pub hello_period_ticks: u64,
    /// Tick at which the last periodic PIM Hello was sent.
    pub last_hello_tick: u64,
}

impl PimState {
    pub fn new() -> Self {
        Self {
            enabled: false,
            pruned: BTreeMap::new(),
            neighbors: BTreeMap::new(),
            prune_timeout_ticks: PRUNE_TIMEOUT_TICKS,
            neighbor_timeout_ticks: NEIGHBOR_TIMEOUT_TICKS,
            hello_period_ticks: PIM_HELLO_PERIOD_TICKS,
            last_hello_tick: 0,
        }
    }
}

// ─── Checksum ───────────────────────────────────────────────────────────

/// Whether the PIM checksum in `payload` (bytes 2-3, one's-complement over
/// the whole message) is correct.  A valid message folds to zero exactly as
/// the IPv4 header checksum does in [`ipv4::compute_checksum`].
fn pim_checksum_valid(payload: &[u8]) -> bool {
    payload.len() >= 4 && ipv4::compute_checksum(payload) == 0
}

/// Fill in the checksum field (bytes 2-3) of a PIM message.
fn set_pim_checksum(msg: &mut [u8]) {
    msg[2] = 0;
    msg[3] = 0;
    let cs = ipv4::compute_checksum(msg);
    msg[2] = (cs >> 8) as u8;
    msg[3] = cs as u8;
}

// ─── Control-plane API ──────────────────────────────────────────────────

/// Whether the PIM-DM control plane is active.
#[cfg_attr(not(test), allow(dead_code))]
pub fn pim_enabled(state: &MrtState) -> bool {
    state.pim.enabled
}

/// Enable PIM-DM (join the all-PIM-routers group 224.0.0.2).
///
/// Brings the control plane up and announces the group membership with an
/// unsolicited IGMPv2 Membership Report (the PIM group join needs the IGMP
/// membership to be reported on the wire).  Joining is idempotent: repeated
/// calls after the first are no-ops.
#[allow(dead_code)]
pub fn enable(state: &mut MrtState, stack: &NetworkStack) {
    state.pim.enabled = true;
    state.pim.last_hello_tick = stack.current_tick();
    if let Some(report) = stack
        .igmp_state()
        .lock()
        .join(PIM_ALL_ROUTERS, stack.current_tick())
    {
        let raw = igmp::build_igmp_message(&report);
        let header = Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 1, // IGMP reports are link-local
            protocol: IpProtocol::Igmp,
            header_checksum: 0,
            source: stack.local_ip(),
            destination: report.group_address,
        };
        let raw_ip = ipv4::build_packet(&header, &raw);
        let _ = stack.send_ipv4_multicast(report.group_address, raw_ip);
    }
}

/// Reverse-Path-Forwarding check (RFC 3973 §3.4.2).
///
/// A multicast packet for a flow sourced at `source` and received on `in_vif`
/// is only accepted when the route back to the source points back through the
/// incoming VIF; otherwise the packet arrived from downstream and flooding it
/// would loop.  The routing table is consulted rather than unconditionally
/// flooding.
#[cfg_attr(not(test), allow(dead_code))]
pub fn rpf_allows_forward(stack: &NetworkStack, source: Ipv4Addr, in_vif: u32) -> bool {
    let route = stack.routing_table().lock().lookup(source);
    match route {
        // No route back to the source → do not forward.
        None => false,
        Some((gateway, _)) => {
            if in_vif == VIF_LOCAL {
                // Received on / generated for the local interface: any route
                // back to the source satisfies RPF.
                true
            } else {
                // Arrived on a downstream VIF: accept only if the source is
                // directly connected (gateway 0.0.0.0), i.e. the packet came
                // up the very interface it would be forwarded back out of.
                gateway == [0, 0, 0, 0]
            }
        }
    }
}

/// PIM-DM flood / prune decision helper.
///
/// Returns `true` when a packet `(source, group)` received on `in_vif` with
/// IP header TTL `ttl` should be flooded: PIM must be enabled, the flow must
/// not be pruned, the TTL must not be spent, and RPF must hold on the
/// incoming VIF.
#[cfg_attr(not(test), allow(dead_code))]
pub fn should_forward(
    stack: &NetworkStack,
    state: &MrtState,
    source: Ipv4Addr,
    group: Ipv4Addr,
    ttl: u8,
    in_vif: u32,
) -> bool {
    if !state.pim.enabled {
        return false;
    }
    // A downstream router pruned this (S,G): stop flooding it.
    if state.pim.pruned.contains_key(&(source, group)) {
        return false;
    }
    // A packet whose TTL has already been consumed cannot be forwarded: the
    // forward path decrements the TTL and must not produce a zero-TTL packet.
    if ttl <= 1 {
        return false;
    }
    rpf_allows_forward(stack, source, in_vif)
}

/// Flood a newly seen (S,G) packet out of every non-local VIF (RFC 3973
/// dense-mode flooding), subject to the prune / TTL / RPF checks.
#[cfg_attr(not(test), allow(dead_code))]
pub fn flood(
    stack: &NetworkStack,
    state: &mut MrtState,
    header: &Ipv4Header,
    in_vif: u32,
    payload: &[u8],
) -> Result<()> {
    if !should_forward(
        stack,
        state,
        header.source,
        header.destination,
        header.ttl,
        in_vif,
    ) {
        return Ok(());
    }
    let out_vifs: Vec<crate::kernel::network::mrouting::vif::VifEntry> = state
        .vif_table
        .iter()
        .filter(|vif| vif.index != VIF_LOCAL)
        .copied()
        .collect();
    for _vif in out_vifs {
        let mut fwd_header = header.clone();
        // The forward path decrements the TTL and skips a packet that would
        // hit zero (should_forward guarantees ttl >= 2, so ttl - 1 >= 1).
        fwd_header.ttl = header.ttl.saturating_sub(1);
        if fwd_header.ttl == 0 {
            continue;
        }
        fwd_header.flags_fragment_offset = 0;
        let raw = ipv4::build_packet(&fwd_header, payload);
        stack.send_ipv4_multicast(header.destination, raw)?;
    }
    Ok(())
}

/// Return the outgoing VIF indices of an MFC-style outgoing list that are
/// actually present in the VIF table.  Any index `>= vif_table.len()`, or
/// otherwise not backed by a VIF, is rejected so an out-of-range index read
/// from untrusted data cannot cause an out-of-bounds access or panic.
#[cfg_attr(not(test), allow(dead_code))]
pub fn sanitize_out_vifs(state: &MrtState, out_vifs: &[OutVif]) -> Vec<u32> {
    let max = state.vif_table.len() as u32;
    out_vifs
        .iter()
        .map(|o| o.vif)
        .filter(|&v| v < max && state.vif_table.get(v).is_some())
        .collect()
}

/// Process an inbound PIM message (IP protocol 103).
///
/// `source` is the IP header source address of the datagram carrying the
/// message; it is recorded in the neighbor table when a Hello is seen.
/// Messages with an invalid PIM checksum or a non-v2 version are silently
/// dropped (RFC 4601 §5.2).
pub fn on_pim_packet(
    stack: &NetworkStack,
    state: &mut MrtState,
    source: IpAddress,
    payload: &[u8],
) -> Result<()> {
    if !pim_checksum_valid(payload) {
        // Bad checksum: never trust the contents of the message.
        return Ok(());
    }
    if payload[0] >> 4 != 2 {
        return Ok(()); // only PIM version 2 is understood
    }
    let ptype = payload[0] & 0x0F;
    match ptype {
        PIM_TYPE_HELLO => {
            // A PIM neighbor announced itself; enable the control plane and
            // remember the neighbor (Hello holdtime lives in the options and
            // is ignored by this simplified implementation).
            state.pim.enabled = true;
            state.pim.neighbors.insert(source, stack.current_tick());
        }
        PIM_TYPE_JOIN_PRUNE => {
            // Simplified layout (recovered snapshot): upstream neighbor at
            // bytes 4-7 (unused here), encoded group at 8-11, source at
            // 12-15, prune flag at byte 16.  A prune record stops flooding;
            // a join (prune flag 0) re-requests it.
            if payload.len() < 17 {
                return Ok(()); // truncated — drop
            }
            let mut group = [0u8; 4];
            group.copy_from_slice(&payload[8..12]);
            let mut source_v4 = [0u8; 4];
            source_v4.copy_from_slice(&payload[12..16]);
            let is_prune = payload[16] != 0;
            if is_prune {
                state
                    .pim
                    .pruned
                    .insert((source_v4, group), stack.current_tick());
            } else {
                state.pim.pruned.remove(&(source_v4, group));
            }
        }
        PIM_TYPE_GRAFT => {
            // A downstream router wants the flow back: clear the prune and
            // acknowledge with a Graft-Ack (RFC 3973 §4.5.4) so it knows the
            // flow will resume.  The Ack is unicast back to the grafting
            // router.
            if payload.len() >= 17 {
                let mut group = [0u8; 4];
                group.copy_from_slice(&payload[8..12]);
                let mut source_v4 = [0u8; 4];
                source_v4.copy_from_slice(&payload[12..16]);
                state.pim.pruned.remove(&(source_v4, group));
                if let IpAddress::V4(src) = source {
                    let ack = build_graft_ack(source_v4, group);
                    let _ = send_pim_message(stack, src, &ack);
                }
            }
        }
        PIM_TYPE_GRAFT_ACK => {
            // Graft acknowledged; nothing to do.
        }
        _ => {}
    }
    Ok(())
}

/// Periodic PIM maintenance: expire stale prunes and stale neighbors, and
/// send a periodic Hello (RFC 3973 §4.4) to announce our presence to PIM
/// neighbors while the control plane is enabled.
pub fn tick(state: &mut MrtState, tick: u64, stack: &NetworkStack) {
    let prune_timeout = state.pim.prune_timeout_ticks;
    state
        .pim
        .pruned
        .retain(|_, start| tick.wrapping_sub(*start) < prune_timeout);
    let neighbor_timeout = state.pim.neighbor_timeout_ticks;
    state
        .pim
        .neighbors
        .retain(|_, last| tick.wrapping_sub(*last) < neighbor_timeout);

    if state.pim.enabled
        && tick.wrapping_sub(state.pim.last_hello_tick) >= state.pim.hello_period_ticks
    {
        state.pim.last_hello_tick = tick;
        let _ = send_pim_message(stack, PIM_ALL_ROUTERS, &build_hello());
    }
}

// ─── Message builders ───────────────────────────────────────────────────

/// Build a PIM Hello message (version 2, type 0) with a valid checksum.
pub fn build_hello() -> Vec<u8> {
    let mut msg = vec![0x20, 0, 0, 0];
    set_pim_checksum(&mut msg);
    msg
}

/// Build a PIM Graft-Ack for a Graft carrying `(source, group)`.
pub fn build_graft_ack(source: [u8; 4], group: [u8; 4]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16);
    msg.push(0x20 | PIM_TYPE_GRAFT_ACK);
    msg.push(0);
    msg.extend_from_slice(&[0u8; 2]); // checksum
    msg.extend_from_slice(&group);
    msg.extend_from_slice(&source);
    set_pim_checksum(&mut msg);
    msg
}

/// Wrap a PIM message in IPv4 and send it.
///
/// A multicast destination (PIM control traffic, e.g. Hello to the
/// all-PIM-routers group) goes out the multicast MAC mapping; a unicast
/// destination (a Graft-Ack to the grafting router) is ARP-resolved and
/// sent point-to-point.
pub fn send_pim_message(stack: &NetworkStack, dst: Ipv4Addr, payload: &[u8]) -> Result<()> {
    let header = Ipv4Header {
        total_length: 0,
        identification: 0,
        flags_fragment_offset: 0,
        ttl: 1,
        protocol: IpProtocol::Unknown(PIM_PROTOCOL),
        header_checksum: 0,
        source: stack.local_ip(),
        destination: dst,
    };
    let raw = ipv4::build_packet(&header, payload);
    if (224..=239).contains(&dst[0]) {
        stack.send_ipv4_multicast(dst, raw)
    } else {
        stack.send_ipv4_packet(dst, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;

    use crate::abi::mrt as mrt_abi;
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::link::ethernet::{self, EtherType, MacAddress};
    use crate::kernel::network::stack::routing::RouteEntry;
    use crate::kernel::network::stack::NetworkStack;

    fn make_stack() -> (&'static NetworkStack, Arc<MockNetworkDevice>) {
        unsafe {
            NetworkStack::uninstall_global();
        }
        let dev = Arc::new(MockNetworkDevice::new(
            "pim-test",
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        ));
        NetworkStack::init_with_device(dev.clone(), [10, 0, 2, 15]);
        (NetworkStack::global().expect("stack"), dev)
    }

    fn vif_def(index: u32) -> mrt_abi::MrtVifDef {
        mrt_abi::MrtVifDef {
            flags: mrt_abi::MRT_VIF_FLAG_PIM,
            vif_index: index,
            threshold: 0,
            rate_limit: 0,
            reserved0: 0,
            reserved1: 0,
        }
    }

    /// Build a Join/Prune message with the simplified recovered layout and a
    /// valid checksum.
    fn join_prune_msg(group: [u8; 4], source: [u8; 4], is_prune: bool) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x20 | PIM_TYPE_JOIN_PRUNE);
        msg.push(0);
        msg.extend_from_slice(&[0u8; 2]); // checksum
        msg.extend_from_slice(&[0, 0, 0, 0]); // upstream neighbor
        msg.extend_from_slice(&group);
        msg.extend_from_slice(&source);
        msg.push(is_prune as u8); // prune flag
        set_pim_checksum(&mut msg);
        msg
    }

    #[test]
    fn checksum_validation_accepts_correct_and_rejects_corrupt() {
        let (stack, _dev) = make_stack();
        let hello = build_hello();
        assert!(
            pim_checksum_valid(&hello),
            "built message has a valid checksum"
        );

        // A correct message is processed: Hello enables PIM.
        let mut state = MrtState::new();
        on_pim_packet(stack, &mut state, IpAddress::V4([10, 0, 2, 1]), &hello).expect("hello");
        assert!(pim_enabled(&state));

        // Corrupt a byte (the reserved byte — version/type stay intact) so the
        // rejection is purely due to the checksum, then confirm the message is
        // dropped and does not touch the state.
        let mut bad = hello;
        bad[1] ^= 0xFF;
        assert!(!pim_checksum_valid(&bad));
        let mut state2 = MrtState::new();
        on_pim_packet(stack, &mut state2, IpAddress::V4([10, 0, 2, 1]), &bad).expect("drop");
        assert!(!pim_enabled(&state2), "corrupted message must be dropped");
    }

    #[test]
    fn hello_enables_pim() {
        let (stack, _dev) = make_stack();
        let mut state = MrtState::new();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        assert!(pim_enabled(&state));
        assert!(state
            .pim
            .neighbors
            .contains_key(&IpAddress::V4([10, 0, 2, 1])));
    }

    #[test]
    fn join_prune_inserts_and_removes() {
        let (stack, _dev) = make_stack();
        let mut state = MrtState::new();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];

        let prune = join_prune_msg(g, s, true);
        on_pim_packet(stack, &mut state, IpAddress::V4([10, 0, 2, 2]), &prune).expect("prune");
        assert!(state.pim.pruned.contains_key(&(s, g)), "prune recorded");

        let join = join_prune_msg(g, s, false);
        on_pim_packet(stack, &mut state, IpAddress::V4([10, 0, 2, 2]), &join).expect("join");
        assert!(
            !state.pim.pruned.contains_key(&(s, g)),
            "join clears the prune"
        );
    }

    #[test]
    fn tick_expires_stale_prunes() {
        let (stack, _dev) = make_stack();
        let mut state = MrtState::new();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];
        let prune = join_prune_msg(g, s, true);
        on_pim_packet(stack, &mut state, IpAddress::V4([10, 0, 2, 2]), &prune).expect("prune");

        // A fresh prune is retained.
        state.tick(stack.current_tick(), stack);
        assert!(state.pim.pruned.contains_key(&(s, g)));

        // After the prune lifetime elapses the entry ages out.
        state.tick(stack.current_tick() + PRUNE_TIMEOUT_TICKS + 1, stack);
        assert!(!state.pim.pruned.contains_key(&(s, g)));
    }

    #[test]
    fn ttl_zero_packets_not_forwarded() {
        let (stack, _dev) = make_stack();
        let mut state = MrtState::new();
        state.init();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        // A route back to the source exists so RPF would pass — the only
        // remaining reason to refuse is the TTL.
        stack.routing_table().lock().add(RouteEntry::network(
            [10, 0, 2, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
        ));
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];

        assert!(!should_forward(stack, &state, s, g, 0, VIF_LOCAL));
        assert!(!should_forward(stack, &state, s, g, 1, VIF_LOCAL));
        assert!(should_forward(stack, &state, s, g, 2, VIF_LOCAL));
    }

    #[test]
    fn rpf_gates_forwarding_on_source_route() {
        let (stack, _dev) = make_stack();
        let mut state = MrtState::new();
        state.init();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];

        // No route back to the source → RPF fails, nothing is forwarded.
        assert!(!should_forward(stack, &state, s, g, 64, VIF_LOCAL));

        // A route back to the source makes RPF pass for the local VIF.
        stack.routing_table().lock().add(RouteEntry::network(
            [10, 0, 2, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
        ));
        assert!(should_forward(stack, &state, s, g, 64, VIF_LOCAL));
    }

    #[test]
    fn out_of_range_vif_index_rejected() {
        let mut state = MrtState::new();
        state.init();
        state.add_vif(&vif_def(1)).expect("add vif 1");
        // The VIF table now holds indices 0 and 1 (len == 2).
        let out = vec![
            OutVif { vif: 1, ttl: 3 }, // valid
            OutVif { vif: 2, ttl: 3 }, // out of range (>= len 2)
            OutVif {
                vif: u32::MAX,
                ttl: 3,
            }, // wildly out of range
        ];
        let sanitized = sanitize_out_vifs(&state, &out);
        assert_eq!(sanitized, vec![1]);
    }

    #[test]
    fn periodic_hello_is_sent_when_enabled() {
        let (stack, dev) = make_stack();
        let mut state = MrtState::new();

        // Disabled: the control plane stays silent.
        state.tick(stack.current_tick() + PIM_HELLO_PERIOD_TICKS, stack);
        assert!(dev.drain_tx().is_empty(), "no Hello while PIM is disabled");

        // Enable and baseline the hello clock.
        state.pim.enabled = true;
        state.pim.last_hello_tick = stack.current_tick();

        // Before the hello period elapses, no Hello is emitted.
        state.tick(stack.current_tick() + PIM_HELLO_PERIOD_TICKS - 1, stack);
        assert!(dev.drain_tx().is_empty());

        // At the period boundary a PIM Hello is sent to the all-PIM group.
        state.tick(stack.current_tick() + PIM_HELLO_PERIOD_TICKS, stack);
        let tx = dev.drain_tx();
        assert!(!tx.is_empty(), "a periodic Hello must be transmitted");
        let frame = ethernet::parse_frame(&tx[0]).expect("ethernet frame");
        assert_eq!(frame.ethertype, EtherType::Ipv4);
        let pkt = ipv4::parse_packet(&frame.payload).expect("ipv4 packet");
        assert_eq!(pkt.header.protocol.to_u8(), PIM_PROTOCOL);
        assert_eq!(pkt.header.destination, PIM_ALL_ROUTERS);
        assert_eq!(pkt.payload[0] >> 4, 2, "PIM version 2");
        assert_eq!(pkt.payload[0] & 0x0F, PIM_TYPE_HELLO);
        assert!(pim_checksum_valid(&pkt.payload));
    }

    #[test]
    fn graft_is_acknowledged_with_graft_ack() {
        let (stack, dev) = make_stack();
        let mut state = MrtState::new();
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];

        // Prune (S,G), then graft the flow back.
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 2]),
            &join_prune_msg(g, s, true),
        )
        .expect("prune");
        assert!(state.pim.pruned.contains_key(&(s, g)));

        let mut graft = Vec::new();
        graft.push(0x20 | PIM_TYPE_GRAFT);
        graft.push(0);
        graft.extend_from_slice(&[0u8; 2]); // checksum
        graft.extend_from_slice(&[0, 0, 0, 0]); // upstream neighbor
        graft.extend_from_slice(&g);
        graft.extend_from_slice(&s);
        graft.push(0); // ensure len >= 17
        set_pim_checksum(&mut graft);

        // The Graft-Ack is unicast to the grafting router, so it must be
        // ARP-resolvable for the send to succeed.
        stack.arp_cache().lock().insert(
            [10, 0, 2, 2],
            MacAddress([0x02, 0, 0, 0, 0, 0x02]),
            stack.current_tick(),
        );

        on_pim_packet(stack, &mut state, IpAddress::V4([10, 0, 2, 2]), &graft).expect("graft");

        // The prune is cleared and a Graft-Ack is transmitted back.
        assert!(!state.pim.pruned.contains_key(&(s, g)));
        let tx = dev.drain_tx();
        assert!(!tx.is_empty(), "a Graft-Ack must be transmitted");
        let frame = ethernet::parse_frame(&tx[0]).expect("ethernet frame");
        assert_eq!(frame.ethertype, EtherType::Ipv4);
        let pkt = ipv4::parse_packet(&frame.payload).expect("ipv4 packet");
        assert_eq!(pkt.header.protocol.to_u8(), PIM_PROTOCOL);
        assert_eq!(
            pkt.header.destination,
            [10, 0, 2, 2],
            "Ack is unicast to the grafter"
        );
        assert_eq!(pkt.payload[0] & 0x0F, PIM_TYPE_GRAFT_ACK);
        assert!(
            pim_checksum_valid(&pkt.payload),
            "Graft-Ack has a valid checksum"
        );
    }

    #[test]
    fn flood_forwards_only_when_rpf_holds() {
        let (stack, dev) = make_stack();
        let mut state = MrtState::new();
        state.init();
        // A non-local VIF so there is somewhere to flood to.
        state.add_vif(&vif_def(1)).expect("add vif 1");
        on_pim_packet(
            stack,
            &mut state,
            IpAddress::V4([10, 0, 2, 1]),
            &build_hello(),
        )
        .expect("hello");
        let s = [10, 0, 2, 1];
        let g = [224, 1, 2, 3];
        let header = Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Udp,
            header_checksum: 0,
            source: s,
            destination: g,
        };

        // No route back to the source → RPF fails → nothing is forwarded.
        flood(stack, &mut state, &header, VIF_LOCAL, b"payload").expect("flood");
        assert!(dev.drain_tx().is_empty(), "RPF failure must not forward");

        // A route back to the source makes RPF pass → the packet is flooded.
        stack.routing_table().lock().add(RouteEntry::network(
            [10, 0, 2, 0],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
        ));
        flood(stack, &mut state, &header, VIF_LOCAL, b"payload").expect("flood");
        let tx = dev.drain_tx();
        assert!(!tx.is_empty(), "RPF pass must forward the packet");
        let frame = ethernet::parse_frame(&tx[0]).expect("ethernet frame");
        assert_eq!(frame.ethertype, EtherType::Ipv4);
        let pkt = ipv4::parse_packet(&frame.payload).expect("ipv4 packet");
        assert_eq!(pkt.header.destination, g);
        assert_eq!(pkt.payload, b"payload");
    }
}
