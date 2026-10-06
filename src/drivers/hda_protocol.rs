//! src/drivers/hda_protocol.rs
//!
//! The Intel HDA register map and codec protocol.
//!
//! Register offsets, bit fields, and the verb layout a codec answers: these are
//! the specification's, not hardware.  They compile — and their size and
//! offset checks run — everywhere, while the controller that drives them is
//! compiled where the machine has one.

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// HDA class code (Audio device).
pub const HDA_CLASS: u8 = 0x04;
/// HDA subclass (HD Audio Controller).
pub const HDA_SUBCLASS: u8 = 0x03;

// ---------------------------------------------------------------------------
// HDA global registers (offset from BAR0)
// ---------------------------------------------------------------------------

/// Capabilities register (16-bit).
pub const HDA_CAP: usize = 0x00;
/// Version register (16-bit): VMIN [7:0], VMAJ [15:8].
pub const HDA_VERSION: usize = 0x02;
/// Global Control register (32-bit).
pub const HDA_GCTL: usize = 0x08;
/// Wake Enable register (16-bit).
pub const HDA_WAKEEN: usize = 0x0C;
/// State Change Status register (16-bit).
pub const HDA_STATESTS: usize = 0x0E;
/// Global Status register (16-bit).
pub const HDA_GSTS: usize = 0x10;

// GCTL bits.
pub const GCTL_CRST: u32 = 1 << 0; // Controller Reset

// STATESTS bits — bit i signals SDI pin i (codec i).
pub const STATESTS_SDI0: u16 = 1 << 0;

// ---------------------------------------------------------------------------
// CORB registers (BAR0 + 0x40)
// ---------------------------------------------------------------------------

/// CORB Lower Base Address (32-bit).
pub const HDA_CORBLBASE: usize = 0x40;
/// CORB Upper Base Address (32-bit).
pub const HDA_CORBUBASE: usize = 0x44;
/// CORB Write Pointer (16-bit).
pub const HDA_CORBWP: usize = 0x48;
/// CORB Read Pointer (16-bit).
pub const HDA_CORBRP: usize = 0x4A;
/// CORB Control (8-bit).
pub const HDA_CORBCTL: usize = 0x4C;
/// CORB Status (8-bit).
pub const HDA_CORBSTS: usize = 0x4D;
/// CORB Size (8-bit).
pub const HDA_CORBSIZE: usize = 0x4E;

// CORBCTL bits.
pub const CORBCTL_CMEIE: u8 = 1 << 0; // CORB Memory Error Interrupt Enable
pub const CORBCTL_CORBRUN: u8 = 1 << 1; // CORB DMA Engine Run

// CORBSTS bits.
pub const CORBSTS_CMEI: u8 = 1 << 0; // CORB Memory Error Indicator

// CORBSIZE fields.
pub const CORBSIZE_CAP_SHIFT: u8 = 0; // bit 0: size programmable capability
pub const CORBSIZE_SIZE_SHIFT: u8 = 4; // bits 5:4: size mode
pub const CORBSIZE_SIZE_MASK: u8 = 0x30;
pub const CORBSIZE_2: u8 = 0x00;
pub const CORBSIZE_16: u8 = 0x01;
pub const CORBSIZE_256: u8 = 0x02;

// ---------------------------------------------------------------------------
// RIRB registers (BAR0 + 0x50)
// ---------------------------------------------------------------------------

/// RIRB Lower Base Address (32-bit).
pub const HDA_RIRBLBASE: usize = 0x50;
/// RIRB Upper Base Address (32-bit).
pub const HDA_RIRBUBASE: usize = 0x54;
/// RIRB Write Pointer (16-bit).
pub const HDA_RIRBWP: usize = 0x58;
/// Response Interrupt Count (16-bit).
pub const HDA_RINTCNT: usize = 0x5A;
/// RIRB Control (8-bit).
pub const HDA_RIRBCTL: usize = 0x5C;
/// RIRB Status (8-bit).
pub const HDA_RIRBSTS: usize = 0x5D;
/// RIRB Size (8-bit).
pub const HDA_RIRBSIZE: usize = 0x5E;

// RIRBCTL bits.
pub const RIRBCTL_RINTCTL: u8 = 1 << 0; // Response Interrupt Enable
pub const RIRBCTL_DMAEN: u8 = 1 << 1; // RIRB DMA Enable
pub const RIRBCTL_OIC: u8 = 1 << 2; // Overrun Interrupt Control

// RIRBSTS bits.
pub const RIRBSTS_RINTFL: u8 = 1 << 0; // Response Interrupt Flag
pub const RIRBSTS_OIS: u8 = 1 << 2; // Overrun Interrupt Status

// RIRBSIZE fields.
pub const RIRBSIZE_SIZE_SHIFT: u8 = 4; // bits 5:4
pub const RIRBSIZE_SIZE_MASK: u8 = 0x30;
pub const RIRBSIZE_256: u8 = 0x02;

// ---------------------------------------------------------------------------
// DMA Position Buffer (BAR0 + 0x70)
// ---------------------------------------------------------------------------

/// DMA Position Lower Base (32-bit).
pub const HDA_DPLBASE: usize = 0x70;
/// DMA Position Upper Base (32-bit).
pub const HDA_DPUBASE: usize = 0x74;

// ---------------------------------------------------------------------------
// Stream descriptor registers (BAR0 + 0x80, stride 0x20 per stream)
// ---------------------------------------------------------------------------

pub const HDA_SD_BASE: usize = 0x80;
pub const HDA_SD_STRIDE: usize = 0x20;

// Offsets relative to stream base.
pub const HDA_SDCTL: usize = 0x00; // Stream Descriptor Control (32-bit)
pub const HDA_SDSTS: usize = 0x03; // Stream Descriptor Status (8-bit)
pub const HDA_SDLPIB: usize = 0x04; // Link Position in Buffer (32-bit)
pub const HDA_SDCBL: usize = 0x08; // Cyclic Buffer Length (32-bit)
pub const HDA_SDLVI: usize = 0x0C; // Last Valid Index (16-bit)
pub const HDA_SDFIFOD: usize = 0x10; // FIFO Depth (16-bit)
pub const HDA_SDFMT: usize = 0x12; // Format (16-bit)
pub const HDA_SDBDPL: usize = 0x18; // BDL Pointer Low (32-bit)
pub const HDA_SDBDPU: usize = 0x1C; // BDL Pointer High (32-bit)

// Stream Descriptor Control (SDCTL) bits.
//
// The two low bits are reset then run, in that order, and getting them the
// other way round is silent: the "start" writes the reset bit, the controller
// resets a stream it was never running, and a driver that only checks its own
// bookkeeping still reports that it wrote every sample.
pub const SDCTL_SRST: u32 = 1 << 0; // Stream Reset (write 1, wait for 1, write 0)
pub const SDCTL_RUN: u32 = 1 << 1; // Stream Run
/// Where the stream number (tag) lives in SDCTL.
///
/// Bits 23:20 of the descriptor's control register, *not* bits 7:4 — that is
/// the field of the codec's `SET_CONVERTER_STREAM_CHANNEL` payload, and
/// confusing the two is silent in the same way the run/reset swap is: the
/// controller notifies the codec of stream 0, the codec has its converter on
/// the tag the driver meant, and no sample ever reaches the voice.
pub const SDCTL_STRM_TAG_SHIFT: u32 = 20;
pub const SDCTL_STRM_TAG_MASK: u32 = 0x0F << SDCTL_STRM_TAG_SHIFT;
pub const SDCTL_DIR_SHIFT: u32 = 19; // Direction bit (0 = output, 1 = input)
pub const SDCTL_DIR_IN: u32 = 1 << SDCTL_DIR_SHIFT;

/// The stream descriptor a playback stream uses.
///
/// The eight descriptors are not interchangeable by direction: the first four
/// carry capture and the last four playback, and a controller told to play on
/// a capture descriptor resets it instead of routing it to the output
/// converter — which is what QEMU's `intel-hda` does with `stream >= 4` when
/// it decides the direction to hand the codec.
pub const HDA_PLAYBACK_STREAM: usize = 4;

// Stream Descriptor Status (SDSTS) bits.
pub const SDSTS_BCIS: u8 = 1 << 0; // Buffer Completion Interrupt Status
pub const SDSTS_FIFO_READY: u8 = 1 << 3; // FIFO Ready

// ---------------------------------------------------------------------------
// HDA verb definitions
// ---------------------------------------------------------------------------

/// Get Parameter verb (12-bit verb ID).
pub const VERB_GET_PARAMETER: u16 = 0xF00;

/// Set Stream Format verb.
///
/// Its payload is the 16-bit format word [`hda_format`] builds — the same
/// value the stream descriptor's SDFMT holds — so it goes out through
/// [`hda_verb16`], not [`hda_verb`].
pub const VERB_SET_STREAM_FORMAT: u16 = 0x200;
/// Set Power State verb (payload: power state; 0 = D0).
pub const VERB_SET_POWER_STATE: u16 = 0x705;
/// Set Converter Stream Channel verb (payload: stream tag in bits 7:4, the
/// number of the first channel this converter handles in bits 3:0).
///
/// The low nibble is a channel *number*, not a count: the count is a field
/// of the format word, which is why a converter told "one channel" by its
/// stream channel still plays stereo if its format says stereo, and why the
/// reverse is what halves a tone's pitch.
pub const VERB_SET_CONVERTER_STREAM_CHANNEL: u16 = 0x706;

/// Parameter IDs for GET_PARAMETER.
pub mod param_id {
    /// Vendor ID (32-bit: vendor in upper 16 bits, device in lower 16 bits).
    pub const VENDOR_ID: u8 = 0x00;
    /// Revision ID.
    pub const REVISION_ID: u8 = 0x02;
    /// Subordinate Node Count.
    pub const SUBORDINATE_NODE_COUNT: u8 = 0x04;
    /// Function Group Type.
    pub const FUNCTION_GROUP_TYPE: u8 = 0x05;
    /// Audio Function Group capabilities.
    pub const AFG_CAPABILITIES: u8 = 0x08;
    /// Audio Widget capabilities.
    pub const AW_CAPABILITIES: u8 = 0x09;
    /// Supported PCM sizes and rates.
    pub const SUPPORTED_PCM: u8 = 0x0A;
    /// Supported audio formats.
    pub const CONFIG_DEFAULT: u8 = 0x1C;
}

/// AW_CAPABILITIES widget type: bits 20:24 (`0xf << 20`), per the HDA spec
/// and QEMU's intel-hda-defs.h.
pub const AW_WCAP_TYPE_SHIFT: u32 = 20;
pub const AW_WCAP_TYPE_MASK: u32 = 0x0F << AW_WCAP_TYPE_SHIFT;
/// Widget type 0 = audio output converter.
pub const AW_WID_AUDIO_OUTPUT: u32 = 0x00;

/// Build a 32-bit HDA verb value.
///
/// The eight-bit-payload form, per the Intel HDA specification:
///
/// | Bits     | Field           |
/// |----------|-----------------|
/// | 31:28    | Codec Address   |
/// | 27:20    | Node ID         |
/// | 19:8     | Verb ID         |
/// | 7:0      | Payload         |
pub const fn hda_verb(cad: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
    ((cad as u32) << 28) | ((nid as u32) << 20) | ((verb_id as u32) << 8) | (payload as u32)
}

/// Build a verb whose payload is sixteen bits wide.
///
/// A verb's payload width is a property of the verb, not of its caller.  The
/// widget-control and capability verbs — `GET_PARAMETER`, `SET_POWER_STATE`,
/// `SET_CONVERTER_STREAM_CHANNEL`, everything numbered `7xx` and up — carry
/// one byte and use [`hda_verb`].  Everything below `0x700`,
/// `SET_STREAM_FORMAT` among them, carries two, and its word is laid out
/// differently: the verb ID keeps only its *high nibble*, in bits 19:16, and
/// bits 15:0 are the payload.
///
/// Sending a two-byte verb through the one-byte form is silent rather than
/// loud.  Bits 19:16 are still the verb's high nibble, so the codec finds the
/// right verb and answers successfully; what it receives as the payload is
/// the low byte the caller passed, and a format word truncated to its low
/// byte is a *valid* format word for a different stream — one channel
/// narrower than the driver meant.
pub const fn hda_verb16(cad: u8, nid: u8, verb_id: u16, payload: u16) -> u32 {
    ((cad as u32) << 28)
        | ((nid as u32) << 20)
        | (((verb_id as u32) & 0xF00) << 8)
        | (payload as u32)
}

/// Build a GET_PARAMETER verb.
pub const fn get_param(cad: u8, nid: u8, param: u8) -> u32 {
    hda_verb(cad, nid, VERB_GET_PARAMETER, param)
}

// ---------------------------------------------------------------------------
// Playback stream: BDL ring geometry and format encoding
// ---------------------------------------------------------------------------

/// Number of BDL descriptors in the playback ring.
pub const BDL_ENTRIES: usize = 16;
/// Size of a single BDL descriptor on the wire (16 bytes).
pub const BDL_ENTRY_BYTES: usize = 16;
/// Length of each BDL data buffer (4 KiB = one page frame).
pub const BDL_ENTRY_LEN: u32 = 4096;
/// Total playback ring length (BDL_ENTRIES * BDL_ENTRY_LEN).
pub const BDL_TOTAL_LEN: u32 = (BDL_ENTRIES as u32) * BDL_ENTRY_LEN;
/// IOC (Interrupt on Completion) flag within a BDL descriptor's dword 3.
pub const BDL_IOC_BIT: u32 = 1 << 0;
/// PCM stream type (bits 3:0 of the format word).
pub const HDA_STREAM_TYPE_PCM: u16 = 0;
/// Bytes reserved at the ring tail (one interleaved stereo 16-bit frame).
///
/// The reserve keeps a completely full ring distinguishable from an empty
/// one, so `write_pos == read_pos` can only ever mean "empty" and the
/// producer can never overwrite data the DMA has not yet played.
pub const BDL_RESERVED_FRAME: u32 = 4;

/// Encode a PCM format into the SDFMT / SET_STREAM_FORMAT format word.
///
/// Per the Intel HDA specification the 16-bit word is laid out as:
///
/// | Bits  | Field                                        |
/// |-------|----------------------------------------------|
/// | 3:0   | channels - 1                                  |
/// | 6:4   | bits per sample (0=8, 1=16, 2=20, 3=24, 4=32) |
/// | 10:8  | sample rate divisor minus one (0 = /1, 7 = /8) |
/// | 13:11 | sample rate multiplier minus one (0 = 1x, 3 = 4x) |
/// | 14    | base rate (0 = 48 kHz, 1 = 44.1 kHz)          |
/// | 15    | stream type (0 = PCM)                         |
///
/// The rate is not a code point per rate but a base rate times a multiplier
/// over a divisor, and there are only two bases: 32 kHz is 48 kHz * 2 / 3,
/// 22.05 kHz is 44.1 kHz / 2, and so on.  A rate with no such encoding falls
/// back to 48 kHz at 1x, and an unknown depth to 16 bits; the caller is
/// expected to have validated its codec's SUPPORTED_PCM caps.
///
/// The channel *count* lives here, and that is the field that matters: a
/// codec told zero channels reads zero as one channel, plays a stereo
/// stream's two interleaved samples one after the other, and every tone it
/// produces comes out an octave low — with every register read back exactly
/// as it was written.
pub const fn hda_format(rate_hz: u32, channels: u8, bits_per_sample: u8) -> u16 {
    // (base 44.1 kHz?, multiplier minus one, divisor minus one).
    let (base44, mult, div): (u16, u16, u16) = match rate_hz {
        48000 => (0, 0, 0),
        44100 => (1, 0, 0),
        32000 => (0, 1, 2),  // 48 kHz * 2 / 3
        22050 => (1, 0, 1),  // 44.1 kHz / 2
        16000 => (0, 0, 2),  // 48 kHz / 3
        11025 => (1, 0, 3),  // 44.1 kHz / 4
        8000 => (0, 0, 5),   // 48 kHz / 6
        96000 => (0, 1, 0),  // 48 kHz * 2
        192000 => (0, 3, 0), // 48 kHz * 4
        _ => (0, 0, 0),
    };
    let bits: u16 = match bits_per_sample {
        8 => 0,
        16 => 1,
        20 => 2,
        24 => 3,
        32 => 4,
        _ => 1,
    };
    let channels = (channels.saturating_sub(1) as u16) & 0x0F;
    channels
        | ((bits & 0x07) << 4)
        | ((div & 0x07) << 8)
        | ((mult & 0x07) << 11)
        | (base44 << 14)
        | HDA_STREAM_TYPE_PCM
}

/// Serialise a BDL descriptor into its 16-byte on-wire layout.
///
/// dword 0-1 = little-endian 64-bit buffer address, dword 2 = length, and
/// dword 3 bit 0 = IOC.
pub const fn bdl_entry_bytes(address: u64, length: u32, ioc: bool) -> [u8; BDL_ENTRY_BYTES] {
    let mut out = [0u8; BDL_ENTRY_BYTES];
    out[0] = (address & 0xFF) as u8;
    out[1] = ((address >> 8) & 0xFF) as u8;
    out[2] = ((address >> 16) & 0xFF) as u8;
    out[3] = ((address >> 24) & 0xFF) as u8;
    out[4] = ((address >> 32) & 0xFF) as u8;
    out[5] = ((address >> 40) & 0xFF) as u8;
    out[6] = ((address >> 48) & 0xFF) as u8;
    out[7] = ((address >> 56) & 0xFF) as u8;
    out[8] = (length & 0xFF) as u8;
    out[9] = ((length >> 8) & 0xFF) as u8;
    out[10] = ((length >> 16) & 0xFF) as u8;
    out[11] = ((length >> 24) & 0xFF) as u8;
    if ioc {
        out[12] = BDL_IOC_BIT as u8;
    }
    out
}

/// Populate a BDL with `BDL_ENTRIES` descriptors pointing at the data ring
/// whose first buffer is at physical address `data_phys`.
///
/// The descriptors cover the ring in `BDL_ENTRY_LEN`-sized strides, with IOC
/// raised only on the final descriptor so a fully-consumed ring is detectable
/// if interrupt wiring is added later.
pub fn populate_bdl(bdl: &mut [u8], data_phys: u64) -> Option<()> {
    if bdl.len() < BDL_ENTRIES * BDL_ENTRY_BYTES {
        return None;
    }
    for i in 0..BDL_ENTRIES {
        let address = data_phys.wrapping_add((i as u64) * BDL_ENTRY_LEN as u64);
        let ioc = i == BDL_ENTRIES - 1;
        let entry = bdl_entry_bytes(address, BDL_ENTRY_LEN, ioc);
        let off = i * BDL_ENTRY_BYTES;
        bdl[off..off + BDL_ENTRY_BYTES].copy_from_slice(&entry);
    }
    Some(())
}

/// Producer/consumer byte positions of a cyclic playback ring.
///
/// The host's writes advance `write_pos`; the controller's DMA engine
/// advances `read_pos`, which is re-synced from SDLPIB between writes.  Both
/// positions are tracked modulo the ring length so a full wrap round the ring
/// is a no-op.  The ring data buffer in the driver is exactly `BDL_TOTAL_LEN`
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdlRingState {
    /// Producer byte position (bytes written, modulo ring length).
    pub write_pos: u32,
    /// Consumer byte position (bytes played, modulo ring length).
    pub read_pos: u32,
}

impl BdlRingState {
    /// An empty ring.
    pub const fn new() -> Self {
        Self {
            write_pos: 0,
            read_pos: 0,
        }
    }

    /// Bytes ready for the DMA engine to play.
    pub fn available(&self) -> u32 {
        (self.write_pos + BDL_TOTAL_LEN - self.read_pos) % BDL_TOTAL_LEN
    }

    /// Bytes of free space before the producer would catch the consumer.
    ///
    /// One full stereo frame is reserved (see `BDL_RESERVED_FRAME`), so this
    /// can never report enough space for a write that wraps onto the DMA's
    /// play position.
    pub fn free_space(&self) -> u32 {
        let used = self.available() + BDL_RESERVED_FRAME;
        BDL_TOTAL_LEN - core::cmp::min(used, BDL_TOTAL_LEN)
    }

    /// Re-sync the consumer position from the link position in buffer
    /// (SDLPIB), which counts bytes played modulo the cyclic buffer length.
    pub fn sync_read_from_link(&mut self, link_pos: u32) {
        self.read_pos = link_pos % BDL_TOTAL_LEN;
    }

    /// Copy up to `free_space()` bytes from `src` into the ring at the
    /// producer position, wrapping at the ring length.
    ///
    /// `ring` must be exactly `BDL_TOTAL_LEN` bytes.  Returns the number of
    /// bytes copied, which is less than `src.len()` only when the ring is
    /// full.
    pub fn copy_into(&mut self, ring: &mut [u8], src: &[u8]) -> usize {
        debug_assert!(ring.len() as u32 == BDL_TOTAL_LEN);
        let n = core::cmp::min(src.len(), self.free_space() as usize);
        let pos = (self.write_pos as usize) % ring.len();
        let first = core::cmp::min(n, ring.len() - pos);
        ring[pos..pos + first].copy_from_slice(&src[..first]);
        if first < n {
            ring[..n - first].copy_from_slice(&src[first..n]);
        }
        self.write_pos = ((self.write_pos as usize + n) % ring.len()) as u32;
        n
    }
}

impl Default for BdlRingState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CORB / RIRB buffer geometry
// ---------------------------------------------------------------------------

/// Number of CORB entries (256 x 4B = 1024 bytes, fits in one 4 KiB page).
#[allow(dead_code)]
pub(crate) const CORB_ENTRIES: usize = 256;
/// Number of RIRB entries (256 x 8B = 2048 bytes, fits in one 4 KiB page).
#[allow(dead_code)]
pub(crate) const RIRB_ENTRIES: usize = 256;

/// Maximum number of codecs on the HDA link (per the specification).
#[allow(dead_code)]
pub(crate) const MAX_CODECS: usize = 15;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn hda_verb_build_get_param() {
        // GET_PARAMETER VENDOR_ID for codec 0, node 0.
        let v = hda_verb(0, 0, VERB_GET_PARAMETER, 0x00);
        assert_eq!(v, 0x000F0000, "GET_PARAMETER VENDOR_ID verb mismatch");

        // GET_PARAMETER VENDOR_ID for codec 1, node 2.
        let v2 = hda_verb(1, 2, VERB_GET_PARAMETER, 0x00);
        assert_eq!(v2, 0x102F0000, "codec 1 node 2 verb mismatch");
    }

    #[test]
    fn get_param_helper() {
        let v = get_param(0, 0, param_id::VENDOR_ID);
        assert_eq!(v, 0x000F0000);
    }

    #[test]
    fn hda_verb_endian_format() {
        // Verify bit-field placement.
        let v = hda_verb(0x0F, 0xAB, 0x123, 0xCD);
        // CAD=0x0F -> bits 31:28 = 0xF
        // NID=0xAB -> bits 27:20 = 0xAB
        // Verb=0x123 -> bits 19:8 = 0x123
        // Payload=0xCD -> bits 7:0 = 0xCD
        assert_eq!(v, 0xFAB123CDu32, "verb bit layout mismatch");
    }

    #[test]
    fn hda_verb16_places_the_whole_payload() {
        // SET_STREAM_FORMAT for codec 0, node 2, carrying 48 kHz / 16-bit /
        // stereo: the verb's high nibble in bits 19:16, the format word in
        // 15:0.  The one-byte form would have written only 0x11's low byte
        // into bits 7:0 and left bits 15:8 zero — a one-channel format the
        // codec answers just as happily.
        let v = hda_verb16(0, 2, VERB_SET_STREAM_FORMAT, 0x0011);
        assert_eq!(v, 0x0022_0011);
        assert_eq!((v >> 8) & 0xF00, 0x200);
        assert_eq!(v & 0xFFFF, 0x0011);

        // The truncated encoding the driver used to send, for contrast: the
        // verb still decodes, and the payload is one channel narrower.
        let truncated = hda_verb(0, 2, VERB_SET_STREAM_FORMAT, 0x10);
        assert_eq!((truncated >> 8) & 0xF00, 0x200);
        assert_eq!(truncated & 0xFFFF, 0x0010);
    }

    #[test]
    fn register_offsets_non_zero() {
        const {
            assert!(HDA_CAP < 0x100);
            assert!(HDA_GCTL >= 0x08);
            assert!(HDA_CORBLBASE == 0x40);
            assert!(HDA_CORBWP == 0x48);
            assert!(HDA_RIRBLBASE == 0x50);
            assert!(HDA_RIRBWP == 0x58);
        }
    }

    #[test]
    fn gctl_bits_defined() {
        assert_ne!(GCTL_CRST, 0);
    }

    #[test]
    fn corbctl_bits_defined() {
        assert_ne!(CORBCTL_CORBRUN, 0);
    }

    #[test]
    fn rirbctl_bits_defined() {
        assert_ne!(RIRBCTL_DMAEN, 0);
    }

    // -----------------------------------------------------------------------
    // Format encoding
    // -----------------------------------------------------------------------

    #[test]
    fn hda_format_stereo_16bit_48k() {
        // 48 kHz / 16-bit / 2 ch is 0x0011: channels-1 = 1 in bits 3:0, the
        // 16-bit code 1 in bits 6:4, and no multiplier or divisor.  It is
        // also, byte for byte, the format QEMU's hda-codec resets its
        // converters to (`AC_FMT_TYPE_PCM | AC_FMT_BITS_16 | (1 <<
        // AC_FMT_CHAN_SHIFT)`), which is what makes it checkable against
        // something other than this file's own arithmetic.
        assert_eq!(hda_format(48000, 2, 16), 0x0011);
    }

    #[test]
    fn hda_format_rate_fields() {
        // The base rate is one bit (14); the rest is a multiplier in 13:11
        // and a divisor in 10:8, each stored minus one.
        let rate_field = |rate: u32| hda_format(rate, 2, 16) & 0x7F00;
        assert_eq!(rate_field(48000), 0x0000);
        assert_eq!(rate_field(44100), 0x4000);
        assert_eq!(rate_field(32000), 0x0A00); // 48 kHz * 2 / 3
        assert_eq!(rate_field(22050), 0x4100); // 44.1 kHz / 2
        assert_eq!(rate_field(16000), 0x0200); // 48 kHz / 3
        assert_eq!(rate_field(11025), 0x4300); // 44.1 kHz / 4
        assert_eq!(rate_field(8000), 0x0500); // 48 kHz / 6
        assert_eq!(rate_field(96000), 0x0800); // 48 kHz * 2
        assert_eq!(rate_field(192000), 0x1800); // 48 kHz * 4
        assert_eq!(hda_format(44100, 2, 16) & 0x4000, 0x4000);
        assert_eq!(hda_format(48000, 2, 16) & 0x4000, 0x0000);
    }

    #[test]
    fn hda_format_channels() {
        // channels - 1 in bits 3:0 — the field whose zero value is what
        // turns a stereo stream into an octave-low mono one.
        assert_eq!(hda_format(48000, 1, 16) & 0x000F, 0x0000);
        assert_eq!(hda_format(48000, 2, 16) & 0x000F, 0x0001);
        assert_eq!(hda_format(48000, 6, 16) & 0x000F, 0x0005);
    }

    #[test]
    fn hda_format_bit_depth() {
        assert_eq!(hda_format(48000, 2, 8) & 0x0070, 0x0000);
        assert_eq!(hda_format(48000, 2, 16) & 0x0070, 0x0010);
        assert_eq!(hda_format(48000, 2, 20) & 0x0070, 0x0020);
        assert_eq!(hda_format(48000, 2, 24) & 0x0070, 0x0030);
        assert_eq!(hda_format(48000, 2, 32) & 0x0070, 0x0040);
    }

    #[test]
    fn hda_format_falls_back_to_nearest_encoding() {
        // Unsupported rate/depth degrade to 48 kHz / 16-bit.
        assert_eq!(hda_format(12345, 2, 7), 0x0011);
        // A zero channel count still yields a valid PCM word.
        assert_eq!(hda_format(48000, 0, 16) & 0x000F, 0x0000);
    }

    #[test]
    fn hda_format_is_never_non_pcm() {
        // Stream type is bit 15, and PCM is zero there.
        assert_eq!(hda_format(48000, 2, 16) & 0x8000, 0x0000);
    }

    // -----------------------------------------------------------------------
    // BDL serialisation
    // -----------------------------------------------------------------------

    #[test]
    fn bdl_entry_serialises_little_endian() {
        let e = bdl_entry_bytes(0x1234_5678_9ABC_0DEF, 4096, false);
        assert_eq!(e[0..8], [0xEF, 0x0D, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(e[8..12], [0x00, 0x10, 0x00, 0x00]);
        assert_eq!(e[12], 0x00);
        assert_eq!(e[13..16], [0x00, 0x00, 0x00]);
    }

    #[test]
    fn bdl_entry_raises_ioc_flag() {
        assert_eq!(bdl_entry_bytes(0, 4096, true)[12], BDL_IOC_BIT as u8);
        assert_eq!(bdl_entry_bytes(0, 4096, false)[12], 0);
    }

    #[test]
    fn populate_bdl_walks_the_ring() {
        let mut bdl = vec![0u8; BDL_ENTRIES * BDL_ENTRY_BYTES];
        let base = 0x1_0000u64;
        assert_eq!(populate_bdl(&mut bdl, base), Some(()));
        // First entry points at the data base with a full buffer length.
        assert_eq!(
            &bdl[0..BDL_ENTRY_BYTES],
            &bdl_entry_bytes(base, BDL_ENTRY_LEN, false)[..]
        );
        // Each stride advances by exactly one buffer length.
        let mid = base + 7 * BDL_ENTRY_LEN as u64;
        assert_eq!(
            &bdl[7 * BDL_ENTRY_BYTES..8 * BDL_ENTRY_BYTES],
            &bdl_entry_bytes(mid, BDL_ENTRY_LEN, false)[..]
        );
        // The final entry points at the last buffer and raises IOC.
        let last_base = base + (BDL_ENTRIES as u64 - 1) * BDL_ENTRY_LEN as u64;
        let last = &bdl[BDL_ENTRY_BYTES * (BDL_ENTRIES - 1)..BDL_ENTRY_BYTES * BDL_ENTRIES];
        assert_eq!(last, &bdl_entry_bytes(last_base, BDL_ENTRY_LEN, true)[..]);
    }

    #[test]
    fn populate_bdl_rejects_short_buffer() {
        let mut bdl = [0u8; 8];
        assert_eq!(populate_bdl(&mut bdl, 0x1000), None);
    }

    // -----------------------------------------------------------------------
    // BDL ring state
    // -----------------------------------------------------------------------

    #[test]
    fn ring_starts_empty() {
        let ring = BdlRingState::new();
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.free_space(), BDL_TOTAL_LEN - BDL_RESERVED_FRAME);
    }

    #[test]
    fn ring_copy_single_segment() {
        let mut ring_buf = vec![0u8; BDL_TOTAL_LEN as usize];
        let mut ring = BdlRingState::new();
        let src = [1u8, 2, 3, 4];
        assert_eq!(ring.copy_into(&mut ring_buf, &src), 4);
        assert_eq!(ring.write_pos, 4);
        assert_eq!(ring.available(), 4);
        assert_eq!(&ring_buf[..4], &src);
    }

    #[test]
    fn ring_available_tracks_consumer() {
        let mut ring = BdlRingState::new();
        ring.write_pos = 100;
        ring.read_pos = 40;
        assert_eq!(ring.available(), 60);
        assert_eq!(ring.free_space(), BDL_TOTAL_LEN - BDL_RESERVED_FRAME - 60);
    }

    #[test]
    fn ring_sync_read_from_link_wraps() {
        let mut ring = BdlRingState::new();
        ring.write_pos = 0x2000;
        // A link position past a full wrap lands in the same modulo space.
        ring.sync_read_from_link(BDL_TOTAL_LEN + 0x100);
        assert_eq!(ring.read_pos, 0x100);
        assert_eq!(ring.available(), 0x1F00);
    }

    #[test]
    fn ring_copy_clamps_to_free_space() {
        let mut ring_buf = vec![0u8; BDL_TOTAL_LEN as usize];
        let mut ring = BdlRingState::new();
        // Near the reserve boundary only 16 bytes fit before the ring is full.
        ring.write_pos = BDL_TOTAL_LEN - 20;
        assert_eq!(ring.free_space(), 16);
        let src = [7u8; 32];
        assert_eq!(ring.copy_into(&mut ring_buf, &src), 16);
        assert_eq!(ring.write_pos, BDL_TOTAL_LEN - 4);
        let start = (BDL_TOTAL_LEN - 20) as usize;
        let end = (BDL_TOTAL_LEN - 4) as usize;
        assert_eq!(&ring_buf[start..end], &[7u8; 16]);
    }

    #[test]
    fn ring_reserve_prevents_catching_the_consumer() {
        let mut ring_buf = vec![0u8; BDL_TOTAL_LEN as usize];
        let mut ring = BdlRingState::new();
        // Fill to the maximum the reserve allows.
        let n = ring.free_space() as usize;
        assert_eq!(n, (BDL_TOTAL_LEN - BDL_RESERVED_FRAME) as usize);
        let src = vec![0xA5u8; n];
        assert_eq!(ring.copy_into(&mut ring_buf, &src), n);
        // The ring is full: one more copy writes nothing.
        assert_eq!(ring.copy_into(&mut ring_buf, &[1u8, 2, 3, 4]), 0);
        assert_eq!(ring.free_space(), 0);
        // Draining one frame opens exactly one frame of space.
        ring.sync_read_from_link(BDL_RESERVED_FRAME);
        assert_eq!(ring.free_space(), BDL_RESERVED_FRAME);
    }

    #[test]
    fn ring_write_pos_wraps_across_copies() {
        let mut ring_buf = vec![0u8; BDL_TOTAL_LEN as usize];
        let mut ring = BdlRingState::new();
        // Fill to the reserve boundary, then drain one frame and top up —
        // the producer position must cycle round without meeting the consumer.
        let first = ring.free_space() as usize;
        ring.copy_into(&mut ring_buf, &vec![0x11u8; first]);
        ring.sync_read_from_link(BDL_RESERVED_FRAME);
        let second = ring.free_space() as usize;
        assert_eq!(second, BDL_RESERVED_FRAME as usize);
        ring.copy_into(&mut ring_buf, &vec![0x22u8; second]);
        assert_eq!(ring.write_pos, 0); // wrapped cleanly
        assert_eq!(ring.read_pos, BDL_RESERVED_FRAME);
        // The tail bytes just written landed where the DMA will play them.
        assert_eq!(&ring_buf[first..first + second], &vec![0x22u8; second][..]);
    }
}
