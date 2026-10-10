//! src/fs/ntfs/lznt1.rs
//!
//! The decompressor for an NTFS stream whose attribute flags say **compressed**
//! ([RFC 0014](../../docs/rfcs/0014-read-the-ntfs-streams-lznt1-compressed.
//! md)).
//!
//! A compressed `$DATA` is a packed sequence of **units** of at most
//! [`UNIT_SIZE`] bytes, and nothing is carried across a unit boundary: a unit
//! is decompressed on its own, which is what makes a read of one range need
//! only the units that range touches.  Each unit is a sixteen-bit little-endian
//! header and its payload; the header's low twelve bits are the payload's
//! length *less one*, bit 15 says whether the payload was squeezed, and the
//! rest is the format's own shape.
//!
//! A squeezed payload is a byte of eight **flags** — bit 0 first — each of
//! which says whether the item it introduces is a literal byte or a **pair**:
//! sixteen bits, little-endian, whose high half is a distance less one and
//! whose low half is a length less three, with the split between them moving as
//! the unit's output grows (the table below).  An item copies from inside the
//! unit it is in, so a pair that reaches before the unit's start is a stream
//! that does not add up.
//!
//! The shape is Linux's `fs/ntfs3/lznt.c` (`decompress_chunk` and the table it
//! indexes with); the code is this tree's.

use crate::Error;

/// The size of one unit: what the format splits a stream into, and the most a
/// unit's decompressed bytes can be.
pub const UNIT_SIZE: usize = 4096;

/// How far a unit's output has to have grown before the split between a pair's
/// distance and its length moves.  The split is at `12 - index` bits, where
/// `index` is how many of these the output has passed.
const DISTANCES: [usize; 9] = [0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000];

/// What a unit's header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unit {
    /// The unit's own length in the stream, its two header bytes included.
    pub length: usize,
    /// Whether the payload was squeezed, or is literal bytes.
    pub compressed: bool,
}

/// Read a unit's header.
pub fn parse_unit(header: [u8; 2]) -> Unit {
    let header = u16::from_le_bytes(header);
    Unit {
        length: 3 + (header & 0x0FFF) as usize,
        compressed: header & 0x8000 != 0,
    }
}

/// Whether this is the padding an encoder leaves after the last unit, rather
/// than a unit: a stream that ends in the middle of the file is the caller's
/// answer, not this module's.
pub fn is_padding(header: [u8; 2]) -> bool {
    header == [0, 0]
}

/// Decompress one unit's payload into `out`, and answer how many bytes of the
/// unit it held.
///
/// `out` is the unit's room: at most [`UNIT_SIZE`] bytes, and it is where a
/// pair whose length would run past the unit is cut — the reference truncates
/// there too, because a stream's last unit is only as long as the file is.
pub fn expand(unit: &Unit, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let room = out.len().min(UNIT_SIZE);
    if !unit.compressed {
        // A literal unit: its payload is its bytes, and the format writes a
        // whole unit's worth of them.
        let take = payload.len().min(room);
        out[..take].copy_from_slice(&payload[..take]);
        return Ok(take);
    }

    let mut produced = 0usize;
    let mut at = 0usize;
    let mut flags = 0u8;
    let mut bit = 0u32;
    loop {
        if bit == 0 {
            // A byte of flags, or the end of the payload: the reference stops
            // where its input ends, and the unit is then what it wrote.
            let Some(byte) = payload.get(at).copied() else {
                break;
            };
            at += 1;
            flags = byte;
        }
        if flags & (1 << bit) == 0 {
            let Some(byte) = payload.get(at).copied() else {
                break;
            };
            at += 1;
            if produced == room {
                break;
            }
            out[produced] = byte;
            produced += 1;
        } else {
            if at + 2 > payload.len() {
                return Err(Error::InvalidArgument);
            }
            let pair = u16::from_le_bytes([payload[at], payload[at + 1]]);
            at += 2;
            let shift = 12 - index_for(produced);
            let distance = 1 + (pair >> shift) as usize;
            let length = 3 + (pair & ((1u16 << shift) - 1)) as usize;
            if distance > produced {
                return Err(Error::InvalidArgument);
            }
            let mut left = length;
            while left > 0 && produced < room {
                out[produced] = out[produced - distance];
                produced += 1;
                left -= 1;
            }
        }
        bit = (bit + 1) & 7;
    }
    Ok(produced)
}

/// How many of [`DISTANCES`] a unit's output has passed: the index a pair's
/// split is taken from.
fn index_for(produced: usize) -> u32 {
    let mut index = 0usize;
    while index < DISTANCES.len() - 1 && produced > DISTANCES[index] {
        index += 1;
    }
    index as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A unit's bytes as the stream holds them: the header the format writes
    /// for a payload of this length, and the payload.
    fn unit_bytes(payload: &[u8], compressed: bool) -> Vec<u8> {
        let header = (payload.len() - 1) as u16 | if compressed { 0xB000 } else { 0x3000 };
        let mut bytes = header.to_le_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn expand_bytes(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let unit = parse_unit([bytes[0], bytes[1]]);
        assert_eq!(unit.length, bytes.len(), "the header names the unit");
        let mut out = vec![0u8; UNIT_SIZE];
        let produced = expand(&unit, &bytes[2..], &mut out)?;
        out.truncate(produced);
        Ok(out)
    }

    #[test]
    fn a_literal_unit_is_its_payload() {
        let payload: Vec<u8> = (0..UNIT_SIZE).map(|at| (at % 251) as u8).collect();
        let bytes = unit_bytes(&payload, false);
        assert!(!parse_unit([bytes[0], bytes[1]]).compressed);
        assert_eq!(expand_bytes(&bytes).expect("a literal unit"), payload);
    }

    #[test]
    fn a_pair_copies_from_inside_its_unit() {
        // "abc" as three literals, then a pair: distance three, length six.
        // The split is twelve bits at this point (the unit has grown three
        // bytes), so the pair's high half is `distance - 1` and its low half
        // `length - 3`.
        let pair = (2u16 << 12) | 3u16;
        let mut payload = vec![0b0000_1000, b'a', b'b', b'c'];
        payload.extend_from_slice(&pair.to_le_bytes());
        let bytes = unit_bytes(&payload, true);
        assert!(parse_unit([bytes[0], bytes[1]]).compressed);
        assert_eq!(expand_bytes(&bytes).expect("a squeezed unit"), b"abcabcabc");
    }

    #[test]
    fn a_pair_that_reaches_before_its_unit_is_refused() {
        // Distance five with three bytes behind it: there is nothing at that
        // place in the unit, and a reader that answered anyway would answer
        // with bytes from before the file.
        let pair = (4u16 << 12) | 3u16; // distance 5, length 6
        let mut payload = vec![0b0000_1000, b'a', b'b', b'c'];
        payload.extend_from_slice(&pair.to_le_bytes());
        let bytes = unit_bytes(&payload, true);
        assert_eq!(expand_bytes(&bytes), Err(Error::InvalidArgument));
    }

    #[test]
    fn a_payload_that_ends_inside_an_item_is_refused() {
        // One literal, then a flag that claims a pair with one byte left.
        let bytes = unit_bytes(&[0b0000_0010, b'a', 0x2f], true);
        assert_eq!(expand_bytes(&bytes), Err(Error::InvalidArgument));
    }

    #[test]
    fn the_split_widens_as_the_unit_grows() {
        // A thousand and twenty-four literals put the unit's output past 0x400,
        // where the split is six bits: the pair below names distance four and
        // length three *there*, and a reader that used one split throughout
        // would read the same sixteen bits as a two-hundred-byte copy instead.
        let literals: Vec<u8> = (0..1024).map(|at| (at % 251) as u8).collect();
        // The format interleaves: a flag byte of eight zeros, then the eight
        // literals it stands for, again and again.
        let mut payload = Vec::new();
        for group in literals.chunks(8) {
            payload.push(0u8);
            payload.extend_from_slice(group);
        }
        payload.push(0b0000_0001); // the pair's own flag byte
        payload.extend_from_slice(&0x00C0u16.to_le_bytes());
        let bytes = unit_bytes(&payload, true);
        let out = expand_bytes(&bytes).expect("a unit the split moves inside");
        assert_eq!(
            out.len(),
            1027,
            "three bytes from the pair, not one hundred and ninety-five"
        );
        assert_eq!(
            &out[1024..],
            &out[1020..1023],
            "the pair copied four bytes back"
        );
        assert_eq!(&out[..1024], &literals[..]);
    }
}
