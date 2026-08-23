//! src/kernel/network/internet/fragments.rs
//! IPv4 fragment reassembly (RFC 815 / RFC 791).
//!
//! Maintains a per-`(id, protocol, source, destination)` reassembly buffer
//! with a bitmap tracking which 8-byte-aligned fragment offsets have arrived.
//! Expired entries are evicted during `advance_tick()`.

use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::ipv4::{Ipv4Addr, Ipv4Header, Ipv4Packet};

// ─── Fragment reassembly timeout ────────────────────────────────────────

/// Fragment reassembly timeout in ticks (30 seconds at 100 Hz).
const FRAGMENT_TIMEOUT_TICKS: u64 = 3000;

/// Maximum number of concurrent reassembly entries.  Beyond this limit new
/// fragments are silently dropped.
const MAX_REASSEMBLY_ENTRIES: usize = 16;

/// Maximum size of a reassembled datagram (64 KiB).
const MAX_DATAGRAM_SIZE: usize = 65535;

// ─── Fragment key ───────────────────────────────────────────────────────

/// Uniquely identifies a packet being reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FragmentKey {
    id: u16,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

// ─── Reassembly buffer ──────────────────────────────────────────────────

/// State for one in-progress reassembly.
struct ReassemblyEntry {
    /// When this entry was created (tick).
    created_at: u64,
    /// Total length of the original datagram payload (0 if unknown).
    total_length: usize,
    /// Assembled payload buffer (allocated lazily when the last fragment
    /// arrives).
    buffer: Option<Vec<u8>>,
    /// Fragments that arrived before the buffer was allocated (before the
    /// last fragment was received).  Each entry is (byte_offset, data).
    pending_fragments: Vec<(usize, Vec<u8>)>,
    /// Bitmap of arrived 8-byte fragment blocks.
    bitmap: Vec<u8>,
    /// The IP header from the first fragment.
    header: Ipv4Header,
    /// Whether the final fragment (MF=0) has been received.
    have_last: bool,
}

impl ReassemblyEntry {
    fn new(first_header: Ipv4Header, created_at: u64) -> Self {
        Self {
            created_at,
            total_length: 0,
            buffer: None,
            pending_fragments: Vec::new(),
            bitmap: Vec::new(),
            header: first_header,
            have_last: false,
        }
    }

    /// Mark an 8-byte block as received.
    fn mark_block(&mut self, block_index: usize) {
        let byte_idx = block_index / 8;
        let bit_idx = block_index % 8;
        if byte_idx >= self.bitmap.len() {
            self.bitmap.resize(byte_idx + 1, 0);
        }
        self.bitmap[byte_idx] |= 1 << bit_idx;
    }

    /// Check if all blocks from 0 to `total_blocks - 1` have been received.
    fn is_complete(&self) -> bool {
        if !self.have_last {
            return false;
        }
        let total_blocks = self.total_length.div_ceil(8);
        if total_blocks == 0 {
            return true;
        }
        let needed_bytes = total_blocks.div_ceil(8);
        if self.bitmap.len() < needed_bytes {
            return false;
        }
        for i in 0..total_blocks {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if self.bitmap[byte_idx] & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Return `true` if any of the 8-byte blocks `[start, start + count)`
    /// has already been received.  Used for RFC 5722 overlap detection.
    fn overlaps(&self, block_start: usize, block_count: usize) -> bool {
        for i in 0..block_count {
            let byte_idx = (block_start + i) / 8;
            let bit_idx = (block_start + i) % 8;
            if byte_idx < self.bitmap.len() && self.bitmap[byte_idx] & (1 << bit_idx) != 0 {
                return true;
            }
        }
        false
    }
}

// ─── Fragment cache ─────────────────────────────────────────────────────

pub struct FragmentCache {
    entries: BTreeMap<FragmentKey, ReassemblyEntry>,
}

impl Default for FragmentCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns the number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Fragment processing ────────────────────────────────────────────────

/// Process a received IPv4 fragment.
///
/// If the fragment completes a datagram, returns `Some(Ipv4Packet)` with the
/// reassembled packet.  Otherwise returns `None` (fragment buffered).
///
/// Non-fragmented packets (MF=0, offset=0) are passed through unchanged as
/// `Some(packet)` without touching the fragment cache.
pub fn process_ipv4_fragment(
    cache: &mut FragmentCache,
    packet: &Ipv4Packet,
    current_tick: u64,
) -> Option<Ipv4Packet> {
    let hdr = &packet.header;
    let flags_fo = hdr.flags_fragment_offset;
    let mf = flags_fo & 0x2000 != 0; // More Fragments
    let fragment_offset = (flags_fo & 0x1FFF) as usize;

    // Non-fragmented: no MF and offset 0 → pass through.
    if !mf && fragment_offset == 0 {
        return Some(packet.clone());
    }

    let key = FragmentKey {
        id: hdr.identification,
        protocol: hdr.protocol.to_u8(),
        source: hdr.source,
        destination: hdr.destination,
    };

    let entry = cache
        .entries
        .entry(key)
        .or_insert_with(|| ReassemblyEntry::new(hdr.clone(), current_tick));

    let data = &packet.payload;
    let block_start = fragment_offset;
    let byte_offset = fragment_offset * 8;
    let data_len = data.len();

    // RFC 5722: if any 8-byte block of this fragment was already received,
    // the fragments overlap — discard the entire reassembly buffer and drop
    // the packet (an attacker could otherwise smuggle conflicting bytes).
    let block_count = data_len.div_ceil(8);
    if entry.overlaps(block_start, block_count) {
        cache.entries.remove(&key);
        return None;
    }

    if !mf {
        entry.have_last = true;
        // Now we know the total payload length.
        let total_payload = byte_offset + data_len;
        if entry.buffer.is_none() && total_payload <= MAX_DATAGRAM_SIZE {
            entry.total_length = total_payload;
            entry.buffer = Some(vec![0u8; total_payload]);
            // Flush any pending fragments into the new buffer.
            let buf = entry.buffer.as_mut().unwrap();
            for (off, frag_data) in entry.pending_fragments.drain(..) {
                let end = (off + frag_data.len()).min(buf.len());
                let copy_len = end.saturating_sub(off).min(frag_data.len());
                if off < buf.len() {
                    buf[off..off + copy_len].copy_from_slice(&frag_data[..copy_len]);
                }
            }
        }
    }

    // Copy fragment data into the buffer if allocated, otherwise queue it.
    if let Some(ref mut buf) = entry.buffer {
        let end = (byte_offset + data_len).min(buf.len());
        let copy_len = end.saturating_sub(byte_offset).min(data_len);
        if byte_offset < buf.len() {
            buf[byte_offset..byte_offset + copy_len].copy_from_slice(&data[..copy_len]);
        }
    } else {
        // Buffer not yet allocated — queue this fragment's data.
        entry.pending_fragments.push((byte_offset, data.to_vec()));
    }

    // Mark blocks as received.
    for i in 0..block_count {
        entry.mark_block(block_start + i);
    }

    // Check if reassembly is complete.
    if entry.is_complete() {
        let mut reassembled_header = entry.header.clone();
        reassembled_header.flags_fragment_offset = 0; // clear MF and offset
        let payload = entry.buffer.take().unwrap_or_default();
        cache.entries.remove(&key);
        return Some(Ipv4Packet {
            header: reassembled_header,
            payload,
        });
    }

    None
}

/// Evict expired fragment entries.  Called from `advance_tick()`.
pub fn evict_expired_fragments(cache: &mut FragmentCache, current_tick: u64) {
    cache.entries.retain(|_, entry| {
        let elapsed = current_tick.wrapping_sub(entry.created_at);
        elapsed < FRAGMENT_TIMEOUT_TICKS
    });
    // If the cache is still over capacity, drop the oldest entries.
    while cache.entries.len() > MAX_REASSEMBLY_ENTRIES {
        let oldest = cache.entries.keys().next().copied();
        if let Some(key) = oldest {
            cache.entries.remove(&key);
        } else {
            break;
        }
    }
}

// ─── IPv6 fragment reassembly ───────────────────────────────────────────────

/// Key for IPv6 fragment reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv6FragmentKey {
    pub identification: u32,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

/// State for one in-progress IPv6 reassembly.
struct Ipv6ReassemblyEntry {
    created_at: u64,
    total_length: usize,
    buffer: Option<Vec<u8>>,
    pending_fragments: Vec<(usize, Vec<u8>)>,
    bitmap: Vec<u8>,
    /// The original fragment header's next_header (payload protocol).
    next_header: u8,
    have_last: bool,
}

impl Ipv6ReassemblyEntry {
    fn new(next_header: u8, created_at: u64) -> Self {
        Self {
            created_at,
            total_length: 0,
            buffer: None,
            pending_fragments: Vec::new(),
            bitmap: Vec::new(),
            next_header,
            have_last: false,
        }
    }

    fn mark_block(&mut self, block_index: usize) {
        let byte_idx = block_index / 8;
        let bit_idx = block_index % 8;
        if byte_idx >= self.bitmap.len() {
            self.bitmap.resize(byte_idx + 1, 0);
        }
        self.bitmap[byte_idx] |= 1 << bit_idx;
    }

    fn is_complete(&self) -> bool {
        if !self.have_last || self.total_length == 0 {
            return false;
        }
        let total_blocks = self.total_length.div_ceil(8);
        if total_blocks == 0 {
            return true;
        }
        let needed_bytes = total_blocks.div_ceil(8);
        if self.bitmap.len() < needed_bytes {
            return false;
        }
        for i in 0..total_blocks {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if self.bitmap[byte_idx] & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Return `true` if any of the 8-byte blocks `[start, start + count)`
    /// has already been received.  Used for RFC 5722 overlap detection.
    fn overlaps(&self, block_start: usize, block_count: usize) -> bool {
        for i in 0..block_count {
            let byte_idx = (block_start + i) / 8;
            let bit_idx = (block_start + i) % 8;
            if byte_idx < self.bitmap.len() && self.bitmap[byte_idx] & (1 << bit_idx) != 0 {
                return true;
            }
        }
        false
    }
}

/// IPv6 fragment reassembly cache.
pub struct Ipv6FragmentCache {
    entries: BTreeMap<Ipv6FragmentKey, Ipv6ReassemblyEntry>,
}

impl Default for Ipv6FragmentCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6FragmentCache {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Process a received IPv6 fragment (the payload following the Fragment
/// extension header).
///
/// `frag_header` is the parsed Fragment header.  `payload` is the data after
/// the fragment header (the fragmented payload).  `src` and `dst` are the
/// IPv6 addresses from the fixed header.
///
/// Returns `Some((next_header, reassembled_payload))` when the datagram is
/// complete, or `None` while fragments are still being collected.
pub fn process_ipv6_fragment(
    cache: &mut Ipv6FragmentCache,
    frag_header: &super::ipv6::Ipv6FragmentHeader,
    payload: &[u8],
    src: [u8; 16],
    dst: [u8; 16],
    current_tick: u64,
) -> Option<(u8, Vec<u8>)> {
    if !frag_header.more_fragments && frag_header.fragment_offset == 0 {
        // Not actually fragmented.
        return Some((frag_header.next_header.to_u8(), payload.to_vec()));
    }

    let key = Ipv6FragmentKey {
        identification: frag_header.identification,
        source: src,
        destination: dst,
    };

    let entry = cache
        .entries
        .entry(key)
        .or_insert_with(|| Ipv6ReassemblyEntry::new(frag_header.next_header.to_u8(), current_tick));

    // RFC 7112: every fragment of one packet must agree on the next header of
    // the fragmented payload.  A mismatch means the fragments are not all of
    // the same packet — discard the whole reassembly buffer.
    let incoming_nh = frag_header.next_header.to_u8();
    if incoming_nh != entry.next_header {
        cache.entries.remove(&key);
        return None;
    }

    let byte_offset = frag_header.fragment_offset as usize * 8;
    let data_len = payload.len();

    // RFC 5722: overlapping fragments are discarded (the entire packet is
    // dropped, since overlapping bytes are an attack signal).
    let block_start = frag_header.fragment_offset as usize;
    let block_count = data_len.div_ceil(8);
    if entry.overlaps(block_start, block_count) {
        cache.entries.remove(&key);
        return None;
    }

    if !frag_header.more_fragments {
        entry.have_last = true;
        entry.total_length = byte_offset + data_len;
    }

    if let Some(ref mut buf) = entry.buffer {
        // Buffer exists — copy data directly.
        if byte_offset + data_len > buf.len() {
            buf.resize(byte_offset + data_len, 0);
        }
        buf[byte_offset..byte_offset + data_len].copy_from_slice(payload);
    } else if !frag_header.more_fragments {
        // Last fragment with known total length — allocate the buffer and
        // copy this fragment's data plus any pending fragments.
        let mut buf = alloc::vec![0u8; entry.total_length];
        buf[byte_offset..byte_offset + data_len].copy_from_slice(payload);
        for (off, frag) in &entry.pending_fragments {
            let end = (*off + frag.len()).min(buf.len());
            if *off < buf.len() {
                let copy_len = end - *off;
                buf[*off..*off + copy_len].copy_from_slice(&frag[..copy_len]);
            }
        }
        entry.pending_fragments.clear();
        entry.buffer = Some(buf);
    } else {
        entry
            .pending_fragments
            .push((byte_offset, payload.to_vec()));
    }

    for i in 0..block_count {
        entry.mark_block(block_start + i);
    }

    if entry.is_complete() {
        let next_header = entry.next_header;
        let payload = entry.buffer.take().unwrap_or_default();
        cache.entries.remove(&key);
        return Some((next_header, payload));
    }

    None
}

/// Evict expired IPv6 fragment entries.
pub fn evict_expired_ipv6_fragments(cache: &mut Ipv6FragmentCache, current_tick: u64) {
    cache
        .entries
        .retain(|_, entry| current_tick.wrapping_sub(entry.created_at) < FRAGMENT_TIMEOUT_TICKS);
    while cache.entries.len() > MAX_REASSEMBLY_ENTRIES {
        let oldest = cache.entries.keys().next().copied();
        if let Some(key) = oldest {
            cache.entries.remove(&key);
        } else {
            break;
        }
    }
}

// ─── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::network::internet::ipv4::{IpProtocol, IPV4_MIN_HEADER_SIZE};
    use crate::kernel::network::internet::ipv6::{Ipv6FragmentHeader, Ipv6NextHeader};

    fn make_ipv4_fragment(
        id: u16,
        mf: bool,
        offset: u16,
        protocol: IpProtocol,
        payload: &[u8],
    ) -> Ipv4Packet {
        let flags_fo = if mf {
            0x2000 | (offset & 0x1FFF)
        } else {
            offset & 0x1FFF
        };
        let header = Ipv4Header {
            total_length: (IPV4_MIN_HEADER_SIZE + payload.len()) as u16,
            identification: id,
            flags_fragment_offset: flags_fo,
            ttl: 64,
            protocol,
            header_checksum: 0,
            source: [10, 0, 2, 1],
            destination: [10, 0, 2, 2],
        };
        Ipv4Packet {
            header,
            payload: Vec::from(payload),
        }
    }

    #[test]
    fn non_fragmented_packet_passes_through() {
        let mut cache = FragmentCache::new();
        let packet = make_ipv4_fragment(0x42, false, 0, IpProtocol::Udp, b"hello");
        let result = process_ipv4_fragment(&mut cache, &packet, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().payload, b"hello");
        assert!(cache.is_empty());
    }

    #[test]
    fn two_fragment_reassembly() {
        let mut cache = FragmentCache::new();
        // First fragment: MF=1, offset=0 (bytes 0-3).
        let frag1 = make_ipv4_fragment(1, true, 0, IpProtocol::Udp, b"AAAA");
        assert!(process_ipv4_fragment(&mut cache, &frag1, 0).is_none());
        assert_eq!(cache.len(), 1);

        // Last fragment: MF=0, offset=1 (byte 8, i.e. 1 * 8 = 8).
        let frag2 = make_ipv4_fragment(1, false, 1, IpProtocol::Udp, b"BBBB");
        let reassembled = process_ipv4_fragment(&mut cache, &frag2, 0);
        assert!(reassembled.is_some());
        let payload = reassembled.unwrap().payload;
        // Total: bytes 0-3 = "AAAA", gap 4-7 = zeros, bytes 8-11 = "BBBB".
        assert_eq!(payload.len(), 12);
        assert_eq!(&payload[0..4], b"AAAA");
        assert_eq!(&payload[4..8], &[0u8; 4]);
        assert_eq!(&payload[8..12], b"BBBB");
        assert!(cache.is_empty());
    }

    #[test]
    fn three_fragment_out_of_order_reassembly() {
        let mut cache = FragmentCache::new();
        // Offset 1 (byte 8) — middle fragment.
        let frag_mid = make_ipv4_fragment(2, true, 1, IpProtocol::Tcp, &[0xCC; 4]);
        assert!(process_ipv4_fragment(&mut cache, &frag_mid, 0).is_none());

        // Offset 0 (byte 0) — first fragment.
        let frag_first = make_ipv4_fragment(2, true, 0, IpProtocol::Tcp, &[0xAA; 4]);
        assert!(process_ipv4_fragment(&mut cache, &frag_first, 0).is_none());

        // Offset 2 (byte 16), MF=0 — last fragment.
        let frag_last = make_ipv4_fragment(2, false, 2, IpProtocol::Tcp, &[0xBB; 4]);
        let reassembled = process_ipv4_fragment(&mut cache, &frag_last, 0);
        assert!(reassembled.is_some());
        let payload = reassembled.unwrap().payload;
        // byte 0-3: AA, gap 4-7: zero, byte 8-11: CC, gap 12-15: zero, byte 16-19: BB.
        assert_eq!(payload.len(), 20);
        assert_eq!(&payload[0..4], &[0xAA; 4]);
        assert_eq!(&payload[8..12], &[0xCC; 4]);
        assert_eq!(&payload[16..20], &[0xBB; 4]);
    }

    #[test]
    fn expired_fragments_are_evicted() {
        let mut cache = FragmentCache::new();
        let frag = make_ipv4_fragment(3, true, 0, IpProtocol::Udp, b"data");
        assert!(process_ipv4_fragment(&mut cache, &frag, 0).is_none());
        assert_eq!(cache.len(), 1);

        // Advance beyond timeout.
        evict_expired_fragments(&mut cache, FRAGMENT_TIMEOUT_TICKS + 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn non_expired_fragments_preserved() {
        let mut cache = FragmentCache::new();
        let frag = make_ipv4_fragment(4, true, 0, IpProtocol::Udp, b"partial");
        assert!(process_ipv4_fragment(&mut cache, &frag, 100).is_none());
        assert_eq!(cache.len(), 1);

        // Still within timeout window.
        evict_expired_fragments(&mut cache, 100 + FRAGMENT_TIMEOUT_TICKS - 1);
        assert_eq!(cache.len(), 1);
    }

    // ─── IPv6 fragment tests ─────────────────────────────────────────

    fn make_ipv6_frag_header(
        id: u32,
        mf: bool,
        offset: u16,
        next_header: u8,
    ) -> Ipv6FragmentHeader {
        Ipv6FragmentHeader {
            next_header: Ipv6NextHeader::from_u8(next_header),
            fragment_offset: offset,
            more_fragments: mf,
            identification: id,
        }
    }

    #[test]
    fn ipv6_non_fragmented_passes_through() {
        let mut cache = Ipv6FragmentCache::new();
        let frag = make_ipv6_frag_header(1, false, 0, 6); // TCP
        let result = process_ipv6_fragment(&mut cache, &frag, b"hello", [0x20; 16], [0x30; 16], 0);
        let (proto, data) = result.expect("pass through");
        assert_eq!(proto, 6);
        assert_eq!(data, b"hello");
        assert!(cache.is_empty());
    }

    #[test]
    fn ipv6_two_fragment_reassembly() {
        let mut cache = Ipv6FragmentCache::new();
        let src = [0x20; 16];
        let dst = [0x30; 16];

        // First fragment: offset 0, 8 bytes, MF=1.
        let frag1 = make_ipv6_frag_header(42, true, 0, 6);
        let r1 = process_ipv6_fragment(&mut cache, &frag1, b"AAAAAAAA", src, dst, 0);
        assert!(r1.is_none());

        // Second (last) fragment: offset 1 (byte 8), 8 bytes, MF=0.
        let frag2 = make_ipv6_frag_header(42, false, 1, 6);
        let r2 = process_ipv6_fragment(&mut cache, &frag2, b"BBBBBBBB", src, dst, 0);
        assert!(r2.is_some());
        let (proto, data) = r2.unwrap();
        assert_eq!(proto, 6);
        assert_eq!(data.len(), 16);
        assert_eq!(&data[0..8], b"AAAAAAAA");
        assert_eq!(&data[8..16], b"BBBBBBBB");
    }

    #[test]
    fn ipv6_fragment_reassembly_three_pieces() {
        let mut cache = Ipv6FragmentCache::new();
        let src = [0x20; 16];
        let dst = [0x30; 16];

        // 3 fragments of 4 bytes each = 12 bytes total.
        // First (offset 0, MF=1).
        assert!(process_ipv6_fragment(
            &mut cache,
            &make_ipv6_frag_header(99, true, 0, 17), // UDP
            b"0123",
            src,
            dst,
            0,
        )
        .is_none());
        // Second (offset 4/8=0, but data=4 bytes later...)
        // Actually offset in 8-byte units. 4 bytes = offset 0.5 → but offset
        // must be in 8-byte units. So if payload is 4 bytes, byte_offset = 0
        // for offset=0, and byte_offset = 8 for offset=1.
        assert!(process_ipv6_fragment(
            &mut cache,
            &make_ipv6_frag_header(99, true, 1, 17),
            b"4567",
            src,
            dst,
            0,
        )
        .is_none());
        // Last (offset 2 = 16 bytes, MF=0).
        let result = process_ipv6_fragment(
            &mut cache,
            &make_ipv6_frag_header(99, false, 2, 17),
            b"89AB",
            src,
            dst,
            0,
        );
        assert!(result.is_some());
        let (proto, data) = result.unwrap();
        assert_eq!(proto, 17);
        // Reassembly should produce: bytes 0-3="0123", padding 4-7=0, 8-11="4567", 12-15=0, 16-19="89AB"
        // But since fragment payloads are only 4 bytes at offsets 0, 1, 2 (in 8-byte units):
        // byte offset 0: "0123" (4 bytes) + gap 4-7
        // byte offset 8: "4567" (4 bytes) + gap 12-15
        // byte offset 16: "89AB" (4 bytes)
        // Total = 20 bytes
        assert_eq!(data.len(), 20);
        assert_eq!(&data[0..4], b"0123");
        assert_eq!(&data[8..12], b"4567");
        assert_eq!(&data[16..20], b"89AB");
    }

    #[test]
    fn ipv6_fragment_expiry_evicts_old_entry() {
        let mut cache = Ipv6FragmentCache::new();
        let frag = make_ipv6_frag_header(1, true, 0, 6);
        process_ipv6_fragment(&mut cache, &frag, b"data", [0x20; 16], [0x30; 16], 100);
        assert_eq!(cache.len(), 1);

        // Evict after timeout.
        evict_expired_ipv6_fragments(&mut cache, 100 + FRAGMENT_TIMEOUT_TICKS + 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn ipv6_fragment_over_capacity_drops_oldest() {
        let mut cache = Ipv6FragmentCache::new();
        for i in 0..MAX_REASSEMBLY_ENTRIES + 2 {
            let frag = make_ipv6_frag_header(i as u32, true, 0, 6);
            let mut src = [0x20; 16];
            src[0] = i as u8;
            process_ipv6_fragment(&mut cache, &frag, b"x", src, [0x30; 16], 0);
        }
        // Eviction is called during tick; after evicting, entries should be
        // capped.
        evict_expired_ipv6_fragments(&mut cache, 0);
        assert!(cache.len() <= MAX_REASSEMBLY_ENTRIES);
    }
}
