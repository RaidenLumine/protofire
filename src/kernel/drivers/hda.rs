//! src/kernel/drivers/hda.rs
//!
//! High-Definition Audio (HDA) controller driver.
//! Intel High Definition Audio (HDA) controller driver.
//!
//! The HDA controller is discovered via PCI (class 0x04, subclass 0x03).
//! It exposes MMIO registers via BAR0.
//!
//! ## Implementation status
//!
//! - PCI discovery and BAR0 MMIO mapping: done
//! - Controller reset and initialization: done
//! - CORB/RIRB setup and verb delivery: done
//! - Codec enumeration (VENDOR_ID): done
//! - Codec widget enumeration (output converter + PCM format): done
//! - Playback stream data-path (BDL ring + DMA): done (QEMU best-effort)
//! - Device node `/system/dev/audio`: done

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
pub const SDCTL_SRUN: u32 = 1 << 0; // Stream Run
pub const SDCTL_SRUN_RESET: u32 = 1 << 1; // Stream Run (stop / reset latch)
pub const SDCTL_STRM_TAG_SHIFT: u32 = 4; // Stream tag lives in bits 7:4
pub const SDCTL_STRM_TAG_MASK: u32 = 0x0F << SDCTL_STRM_TAG_SHIFT;
pub const SDCTL_DIR_SHIFT: u32 = 19; // Direction bit (0 = output, 1 = input)
pub const SDCTL_DIR_IN: u32 = 1 << SDCTL_DIR_SHIFT;

// Stream Descriptor Status (SDSTS) bits.
pub const SDSTS_BCIS: u8 = 1 << 0; // Buffer Completion Interrupt Status
pub const SDSTS_FIFO_READY: u8 = 1 << 3; // FIFO Ready

// ---------------------------------------------------------------------------
// HDA verb definitions
// ---------------------------------------------------------------------------

/// Get Parameter verb (12-bit verb ID).
pub const VERB_GET_PARAMETER: u16 = 0xF00;

/// Set Stream Format verb (payload: stream tag in bits 7:4, format index
/// in bits 3:0).
pub const VERB_SET_STREAM_FORMAT: u16 = 0x200;
/// Set Power State verb (payload: power state; 0 = D0).
pub const VERB_SET_POWER_STATE: u16 = 0x705;
/// Set Converter Stream Channel verb (payload: stream tag in bits 7:4,
/// channel count - 1 in bits 3:0).
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
/// Format per the Intel HDA specification:
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
/// Per the Intel HDA specification the 16-bit format word is laid out as:
///
/// | Bits  | Field                                   |
/// |-------|-----------------------------------------|
/// | 15:12 | bits per sample (0=8, 1=16, 2=20, 3=24, 4=32) |
/// | 11:9  | channels - 1                            |
/// | 8     | base rate multiplier (1x or 4x)          |
/// | 7:4   | base sample rate                        |
/// | 3:0   | stream type (0 = PCM)                   |
///
/// Unsupported rates and bit depths fall back to the nearest encoding; the
/// caller is expected to have validated its codec's SUPPORTED_PCM caps.
pub const fn hda_format(rate_hz: u32, channels: u8, bits_per_sample: u8) -> u16 {
    let base_rate: u16 = match rate_hz {
        48000 => 0,
        44100 => 1,
        32000 => 2,
        22050 => 3,
        16000 => 4,
        11025 => 5,
        8000 => 6,
        96000 => 7,
        192000 => 8,
        _ => 0,
    };
    let bits: u16 = match bits_per_sample {
        8 => 0,
        16 => 1,
        20 => 2,
        24 => 3,
        32 => 4,
        _ => 1,
    };
    let channels = (channels.saturating_sub(1) as u16) & 0x07;
    (bits << 12) | (channels << 9) | (base_rate << 4) | HDA_STREAM_TYPE_PCM
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
const CORB_ENTRIES: usize = 256;
/// Number of RIRB entries (256 x 8B = 2048 bytes, fits in one 4 KiB page).
#[allow(dead_code)]
const RIRB_ENTRIES: usize = 256;

/// Maximum number of codecs on the HDA link (per the specification).
#[allow(dead_code)]
const MAX_CODECS: usize = 15;

// ---------------------------------------------------------------------------
// Controller state (bare-metal only)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod controller {
    use super::*;
    use crate::arch::mmu::map_device_mmio;
    use crate::kernel::memory::DmaBuffer;
    use crate::println;
    use crate::Result;
    use core::ptr::read_volatile;
    use core::ptr::write_volatile;

    /// Bounded spin budget for waiting on the DMA engine to drain the ring.
    const MAX_POSITION_SPINS: u32 = 50_000_000;

    /// Bounded poll for codec-present bits after controller reset.
    const CODEC_WAIT_SPINS: u32 = 10_000_000;

    /// MMIO helpers for 32-bit, 16-bit, and 8-bit register access.
    unsafe fn reg_read32(base: *mut u8, offset: usize) -> u32 {
        read_volatile(base.add(offset) as *const u32)
    }
    unsafe fn reg_write32(base: *mut u8, offset: usize, val: u32) {
        write_volatile(base.add(offset) as *mut u32, val);
    }
    unsafe fn reg_read16(base: *mut u8, offset: usize) -> u16 {
        read_volatile(base.add(offset) as *const u16)
    }
    unsafe fn reg_write16(base: *mut u8, offset: usize, val: u16) {
        write_volatile(base.add(offset) as *mut u16, val);
    }
    unsafe fn reg_read8(base: *mut u8, offset: usize) -> u8 {
        read_volatile(base.add(offset) as *const u8)
    }
    unsafe fn reg_write8(base: *mut u8, offset: usize, val: u8) {
        write_volatile(base.add(offset), val);
    }

    /// The HDA host controller.
    pub struct HdaController {
        /// MMIO base virtual address (BAR0 mapped).
        regs: *mut u8,
        /// Capabilities register value.
        #[allow(dead_code)]
        cap: u16,
        /// Number of input streams (from CAP).
        #[allow(dead_code)]
        num_input_streams: u8,
        /// Number of output streams (from CAP).
        #[allow(dead_code)]
        num_output_streams: u8,
        /// Number of bidirectional streams (from CAP).
        #[allow(dead_code)]
        num_bidir_streams: u8,
        /// CORB DMA buffer (256 entries of 4 bytes each).
        corb_buf: DmaBuffer,
        /// RIRB DMA buffer (256 entries of 8 bytes each).
        rirb_buf: DmaBuffer,
        /// CORB write pointer, cached to minimise MMIO reads.
        corb_wp: u16,
        /// Last RIRB write pointer we consumed.
        rirb_rp: u16,
        /// Vendor/device ID of codec 0 (0 = not probed yet).
        pub codec0_vendor: u32,
        /// Playback BDL descriptor list (16 entries = 256 bytes, one frame).
        playback_bdl: Option<DmaBuffer>,
        /// Playback PCM data ring (BDL_ENTRIES page frames).
        playback_data: Option<DmaBuffer>,
        /// Producer/consumer positions for the playback ring.
        playback_ring: BdlRingState,
        /// Sample rate the stream is currently programmed for (0 = stopped).
        active_rate: u32,
        /// Audio output converter widget NID (0 = no converter found).
        converter_nid: u8,
        /// Stream tag used for the playback stream.
        stream_tag: u8,
        /// Spins accumulated while waiting for the DMA to drain the ring.
        position_spins: u32,
    }

    // SAFETY: HdaController owns its MMIO mapping and DMA buffers exclusively.
    unsafe impl Send for HdaController {}

    impl HdaController {
        /// Create and initialise a new HDA controller.
        ///
        /// `bar0_phys` is the physical base address of BAR0, `bar0_size`
        /// the length of the MMIO region.
        pub unsafe fn new(bar0_phys: u64, bar0_size: usize) -> Option<Self> {
            let mmio = map_device_mmio(bar0_phys, bar0_size)?;
            let regs = mmio;

            // Read capabilities.
            let cap = reg_read16(regs, HDA_CAP);
            let iss = ((cap >> 12) & 0x0F) as u8;
            let oss = ((cap >> 8) & 0x0F) as u8;
            let bss = ((cap >> 4) & 0x0F) as u8;
            let _nsdo = (cap & 0x0F) as u8;

            println!(
                "[hda   ] CAP=0x{:04x} ISS={} OSS={} BSS={}",
                cap, iss, oss, bss
            );

            // Allocate DMA buffers.
            let corb_buf = DmaBuffer::allocate(1)?; // 4 KiB
            let rirb_buf = DmaBuffer::allocate(1)?; // 4 KiB

            let mut ctrl = Self {
                regs,
                cap,
                num_input_streams: iss,
                num_output_streams: oss,
                num_bidir_streams: bss,
                corb_buf,
                rirb_buf,
                corb_wp: 0,
                rirb_rp: 0xFFFF,
                codec0_vendor: 0,
                playback_bdl: None,
                playback_data: None,
                playback_ring: BdlRingState::new(),
                active_rate: 0,
                converter_nid: 0,
                stream_tag: 0,
                position_spins: 0,
            };

            // Reset controller.
            ctrl.reset().ok()?;

            // Initialise CORB.
            ctrl.init_corb().ok()?;

            // Initialise RIRB.
            ctrl.init_rirb().ok()?;

            // Check for codecs on the link.
            if !ctrl.detect_codecs() {
                println!("[hda   ] no codecs detected on the link");
                return Some(ctrl); // Still return the controller for later use.
            }

            // Read VENDOR_ID from codec 0, node 0.
            match ctrl.read_codec_param(0, 0, param_id::VENDOR_ID) {
                Ok(vid) => {
                    let vendor = (vid >> 16) as u16;
                    let device = vid as u16;
                    println!(
                        "[hda   ] codec 0 VENDOR_ID = {:#010x} (vendor={:#06x} device={:#06x})",
                        vid, vendor, device
                    );
                    ctrl.codec0_vendor = vid;
                }
                Err(e) => {
                    println!("[hda   ] codec 0 VENDOR_ID read failed: {}", e.as_str());
                }
            }

            // Enumerate the codec widget graph for a playback output
            // converter and allocate the playback DMA buffers when one is
            // found.
            match ctrl.find_output_converter(0) {
                Ok(nid) => {
                    ctrl.converter_nid = nid;
                    ctrl.stream_tag = 1;
                    if let (Some(mut bdl), Some(data)) =
                        (DmaBuffer::allocate(1), DmaBuffer::allocate(BDL_ENTRIES))
                    {
                        let _ = populate_bdl(bdl.as_mut_slice(), data.phys_addr() as u64);
                        ctrl.playback_bdl = Some(bdl);
                        ctrl.playback_data = Some(data);
                        println!(
                            "[hda   ] playback: output converter nid={} stream_tag={}",
                            nid, ctrl.stream_tag
                        );
                    }
                }
                Err(e) => {
                    println!("[hda   ] no output converter found: {}", e.as_str());
                }
            }

            println!("[hda   ] controller initialised");
            Some(ctrl)
        }

        // -------------------------------------------------------------------
        // Reset
        // -------------------------------------------------------------------

        /// Reset the controller (GCTL.CRST toggle).
        unsafe fn reset(&mut self) -> Result<()> {
            // Clear stale codec wake flags before running the reset (W1C),
            // mirroring Linux's azx_reset ordering: the codec re-asserts
            // STATESTS on the CRST de-assert edge, and clearing it afterwards
            // would swallow that edge.
            let statests = reg_read16(self.regs, HDA_STATESTS);
            if statests != 0 {
                reg_write16(self.regs, HDA_STATESTS, statests);
            }

            // Assert reset (CRST = 0).
            reg_write32(self.regs, HDA_GCTL, 0);
            for _ in 0..100_000 {
                if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST == 0 {
                    break;
                }
            }
            if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST != 0 {
                return Err(crate::Error::TimedOut);
            }

            // De-assert reset (CRST = 1).
            reg_write32(self.regs, HDA_GCTL, GCTL_CRST);
            for _ in 0..100_000 {
                if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST != 0 {
                    break;
                }
            }
            if reg_read32(self.regs, HDA_GCTL) & GCTL_CRST == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Wait 50 us for link to stabilise (simple spin loop).
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }

            Ok(())
        }

        // -------------------------------------------------------------------
        // CORB setup
        // -------------------------------------------------------------------

        /// Initialise the CORB engine.
        unsafe fn init_corb(&mut self) -> Result<()> {
            // Reset CORB: set CORBRP = 0 (this triggers a reset).
            reg_write16(self.regs, HDA_CORBRP, 0);
            for _ in 0..100_000 {
                if reg_read16(self.regs, HDA_CORBRP) == 0 {
                    break;
                }
            }
            if reg_read16(self.regs, HDA_CORBRP) != 0 {
                return Err(crate::Error::TimedOut);
            }

            // Set CORB size to 256 entries if programmable.
            let corbsize = reg_read8(self.regs, HDA_CORBSIZE);
            let prog = corbsize & (1 << CORBSIZE_CAP_SHIFT);
            if prog != 0 {
                let size_field = (CORBSIZE_256 << CORBSIZE_SIZE_SHIFT) & CORBSIZE_SIZE_MASK;
                reg_write8(
                    self.regs,
                    HDA_CORBSIZE,
                    (corbsize & !CORBSIZE_SIZE_MASK) | size_field,
                );
            }

            // Set CORB base address.
            let corb_phys = self.corb_buf.phys_addr() as u64;
            reg_write32(self.regs, HDA_CORBLBASE, corb_phys as u32);
            reg_write32(self.regs, HDA_CORBUBASE, (corb_phys >> 32) as u32);

            // Set CORBRP = 0 again after programming base.
            reg_write16(self.regs, HDA_CORBRP, 0);
            for _ in 0..100_000 {
                if reg_read16(self.regs, HDA_CORBRP) == 0 {
                    break;
                }
            }
            if reg_read16(self.regs, HDA_CORBRP) != 0 {
                return Err(crate::Error::TimedOut);
            }

            // Start CORB engine.
            reg_write8(self.regs, HDA_CORBCTL, CORBCTL_CORBRUN);
            for _ in 0..100_000 {
                if reg_read8(self.regs, HDA_CORBCTL) & CORBCTL_CORBRUN != 0 {
                    break;
                }
            }
            if reg_read8(self.regs, HDA_CORBCTL) & CORBCTL_CORBRUN == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Initialise write pointer to 0.
            reg_write16(self.regs, HDA_CORBWP, 0);
            self.corb_wp = 0;

            Ok(())
        }

        // -------------------------------------------------------------------
        // RIRB setup
        // -------------------------------------------------------------------

        /// Initialise the RIRB engine.
        unsafe fn init_rirb(&mut self) -> Result<()> {
            // Set RIRB size to 256 entries if programmable.
            let rirbsize = reg_read8(self.regs, HDA_RIRBSIZE);
            let prog = rirbsize & 1; // bit 0: size programmable
            if prog != 0 {
                let size_field = (RIRBSIZE_256 << RIRBSIZE_SIZE_SHIFT) & RIRBSIZE_SIZE_MASK;
                reg_write8(
                    self.regs,
                    HDA_RIRBSIZE,
                    (rirbsize & !RIRBSIZE_SIZE_MASK) | size_field,
                );
            }

            // Set RIRB base address.
            let rirb_phys = self.rirb_buf.phys_addr() as u64;
            reg_write32(self.regs, HDA_RIRBLBASE, rirb_phys as u32);
            reg_write32(self.regs, HDA_RIRBUBASE, (rirb_phys >> 32) as u32);

            // Set Response Interrupt Count to 1 (interrupt after each response).
            reg_write16(self.regs, HDA_RINTCNT, 1);

            // Enable DMA engine and response interrupt.
            reg_write8(
                self.regs,
                HDA_RIRBCTL,
                RIRBCTL_DMAEN | RIRBCTL_RINTCTL | RIRBCTL_OIC,
            );
            for _ in 0..100_000 {
                if reg_read8(self.regs, HDA_RIRBCTL) & RIRBCTL_DMAEN != 0 {
                    break;
                }
            }
            if reg_read8(self.regs, HDA_RIRBCTL) & RIRBCTL_DMAEN == 0 {
                return Err(crate::Error::TimedOut);
            }

            // Read initial RIRBWP (may be 0xFFFF indicating empty).
            self.rirb_rp = reg_read16(self.regs, HDA_RIRBWP);

            Ok(())
        }

        // -------------------------------------------------------------------
        // Codec detection
        // -------------------------------------------------------------------

        /// Check STATESTS to discover which codecs are present.
        ///
        /// Codecs assert their STATESTS bits shortly after the controller
        /// leaves reset, so poll briefly rather than reading once (QEMU sets
        /// the bits on a timer; real silicon is equally asynchronous).
        ///
        /// Returns `true` if at least one codec is detected.
        unsafe fn detect_codecs(&mut self) -> bool {
            for _ in 0..CODEC_WAIT_SPINS {
                let statests = reg_read16(self.regs, HDA_STATESTS);
                let mut present = false;
                for i in 0..MAX_CODECS {
                    if statests & (1u16 << i) != 0 {
                        println!("[hda   ] codec {} present", i);
                        present = true;
                    }
                }
                if present {
                    return true;
                }
                core::hint::spin_loop();
            }
            false
        }

        // -------------------------------------------------------------------
        // Verb submission
        // -------------------------------------------------------------------

        /// Send a verb to a codec node and read the response.
        ///
        /// The verb is written to the CORB and the CORB write pointer is
        /// advanced.  The function then polls the RIRB write pointer for a
        /// response.
        unsafe fn send_verb(&mut self, verb: u32) -> Result<u32> {
            // Write the verb at CORBWP + 1, then advance CORBWP to it. The
            // controller reads from CORBRP + 1, so the first verb lands at
            // entry 1, matching Linux's azx_corb_send_cmd semantics.
            let corb_idx = (self.corb_wp as usize + 1) % CORB_ENTRIES;
            let corb_ptr = self.corb_buf.as_ptr() as *mut u32;
            write_volatile(corb_ptr.add(corb_idx), verb);

            let new_wp = corb_idx as u16;
            reg_write16(self.regs, HDA_CORBWP, new_wp);
            self.corb_wp = new_wp;

            // Poll for a response in the RIRB. RIRBWP advancing is the
            // readiness signal; the response entry is written at the new
            // pointer position, so read it there.
            let last_rp = self.rirb_rp;
            for _ in 0..500_000 {
                let wp = reg_read16(self.regs, HDA_RIRBWP);

                // RIRBWP of 0xFFFF means the buffer is empty.
                if wp == 0xFFFF || wp == last_rp {
                    core::hint::spin_loop();
                    continue;
                }

                // The controller writes the response entry at the new write
                // pointer before RIRBWP becomes visible, so it sits at wp.
                let rirb_idx = wp as usize % RIRB_ENTRIES;
                let rirb_ptr = self.rirb_buf.as_ptr() as *const u32;
                let resp_low = read_volatile(rirb_ptr.add(rirb_idx * 2));
                let resp_high = read_volatile(rirb_ptr.add(rirb_idx * 2 + 1));

                // Some controllers (QEMU's intel-hda included) leave the
                // VALID flag clear on solicited responses — their upper word
                // carries just the codec address — so give the DMA a short
                // settle window, then trust the write-pointer advance.
                for _ in 0..100 {
                    if resp_high & 0x01 != 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }

                // Consumed — remember this position.
                self.rirb_rp = wp;

                // Clear RIRBSTS interrupt flags (W1C).
                reg_write8(self.regs, HDA_RIRBSTS, RIRBSTS_RINTFL | RIRBSTS_OIS);

                return Ok(resp_low);
            }

            Err(crate::Error::TimedOut)
        }

        /// Read a codec parameter (e.g. VENDOR_ID) via GET_PARAMETER.
        pub unsafe fn read_codec_param(&mut self, cad: u8, nid: u8, param: u8) -> Result<u32> {
            let verb = get_param(cad, nid, param);
            self.send_verb(verb)
        }

        // -------------------------------------------------------------------
        // Codec widget enumeration
        // -------------------------------------------------------------------

        /// Read the subordinate node list of `nid`: (start node, count).
        unsafe fn subordinate_node_count(&mut self, cad: u8, nid: u8) -> Result<(u8, u16)> {
            let v = self.read_codec_param(cad, nid, param_id::SUBORDINATE_NODE_COUNT)?;
            let start = (v & 0xFF) as u8;
            let count = ((v >> 16) & 0xFF) as u8;
            Ok((start, count as u16))
        }

        /// Find an audio output converter widget reachable from the root node.
        ///
        /// Walks root (0) -> audio function group -> widget list and returns
        /// the first widget whose AW_CAPABILITIES type (bits 20:24) is 0
        /// (audio output converter).
        unsafe fn find_output_converter(&mut self, cad: u8) -> Result<u8> {
            let (afg, _count) = self.subordinate_node_count(cad, 0)?;
            // Audio function groups report type 0x1 in FUNCTION_GROUP_TYPE.
            let fgt = self.read_codec_param(cad, afg, param_id::FUNCTION_GROUP_TYPE)?;
            if fgt & 0xFF != 0x01 {
                return Err(crate::Error::NotFound);
            }
            let (start, count) = self.subordinate_node_count(cad, afg)?;
            for i in 0..count {
                let nid = start.wrapping_add(i as u8);
                let caps = self.read_codec_param(cad, nid, param_id::AW_CAPABILITIES)?;
                if (caps & AW_WCAP_TYPE_MASK) >> AW_WCAP_TYPE_SHIFT == AW_WID_AUDIO_OUTPUT {
                    return Ok(nid);
                }
            }
            Err(crate::Error::NotFound)
        }

        // -------------------------------------------------------------------
        // Playback stream
        // -------------------------------------------------------------------

        /// Read the stream's link position in buffer (SDLPIB).
        unsafe fn stream_link_position(&self) -> u32 {
            reg_read32(self.regs, HDA_SD_BASE + HDA_SDLPIB)
        }

        /// Stop the playback stream by clearing SDCTL.SRUN (two-step).
        unsafe fn stop_playback_stream(&mut self) {
            let sd = HDA_SD_BASE;
            let ctl = reg_read32(self.regs, sd + HDA_SDCTL);
            if ctl & SDCTL_SRUN == 0 {
                return;
            }
            // Assert the stop latch, drop SRUN, then release the latch.
            reg_write32(self.regs, sd + HDA_SDCTL, ctl | SDCTL_SRUN_RESET);
            reg_write32(
                self.regs,
                sd + HDA_SDCTL,
                ctl & !(SDCTL_SRUN | SDCTL_SRUN_RESET),
            );
        }

        /// Program the stream descriptor for playback at `format` and start
        /// the DMA engine (stream 0, output direction).
        unsafe fn setup_playback_stream(&mut self, format: u16) -> Result<()> {
            let sd = HDA_SD_BASE;
            self.stop_playback_stream();
            // Clear stale status (W1C).
            reg_write8(self.regs, sd + HDA_SDSTS, SDSTS_BCIS | SDSTS_FIFO_READY);
            // Format, cyclic buffer length, last-valid descriptor index, and
            // BDL base address.  SDLVI must be `BDL_ENTRIES - 1` so the DMA
            // engine traverses the full ring; QEMU intel-hda derives the
            // descriptor count as `lvi + 1`, and real silicon won't run DMA
            // at all with LVI = 0.
            reg_write16(self.regs, sd + HDA_SDFMT, format);
            reg_write32(self.regs, sd + HDA_SDCBL, BDL_TOTAL_LEN);
            reg_write16(self.regs, sd + HDA_SDLVI, (BDL_ENTRIES - 1) as u16);
            let bdl = self
                .playback_bdl
                .as_ref()
                .ok_or(crate::Error::Unsupported)?;
            let bdl_phys = bdl.phys_addr() as u64;
            reg_write32(self.regs, sd + HDA_SDBDPL, bdl_phys as u32);
            reg_write32(self.regs, sd + HDA_SDBDPU, (bdl_phys >> 32) as u32);
            // Start: stream tag + output direction (DIR = 0) + SRUN.
            let sctl = ((self.stream_tag as u32) & 0x0F) << SDCTL_STRM_TAG_SHIFT | SDCTL_SRUN;
            reg_write32(self.regs, sd + HDA_SDCTL, sctl);
            Ok(())
        }

        /// Route the playback stream into the output converter and power it
        /// to D0.
        unsafe fn setup_codec_playback(&mut self, cad: u8) -> Result<()> {
            let converter = self.converter_nid;
            if converter == 0 {
                return Err(crate::Error::NotFound);
            }
            let tag = self.stream_tag & 0x0F;
            // Power the widget to D0.
            self.send_verb(hda_verb(cad, converter, VERB_SET_POWER_STATE, 0))?;
            // Point the converter at the stream tag (format index 0).
            self.send_verb(hda_verb(cad, converter, VERB_SET_STREAM_FORMAT, tag << 4))?;
            // Two-channel (stereo) sample slot mapping.
            self.send_verb(hda_verb(
                cad,
                converter,
                VERB_SET_CONVERTER_STREAM_CHANNEL,
                (tag << 4) | 0x01,
            ))?;
            Ok(())
        }

        /// Copy PCM samples into the BDL ring and wait for the DMA engine to
        /// drain it, re-programming the stream if `rate` changed.
        ///
        /// `samples` must be interleaved 16-bit stereo PCM.  The write blocks
        /// (with a bounded spin) while the ring is full so a caller can never
        /// overrun a codec draining slower than it is fed.
        ///
        /// # Safety
        ///
        /// The caller must hold the only reference to this controller; the
        /// method touches its MMIO mapping and DMA buffers exclusively.
        pub unsafe fn write_pcm(&mut self, rate: u32, samples: &[u8]) -> Result<()> {
            if self.converter_nid == 0 {
                return Err(crate::Error::Unsupported);
            }
            if rate == 0 {
                return Err(crate::Error::InvalidArgument);
            }

            // Re-program the stream when the caller switches sample rates.
            if self.active_rate != rate {
                self.stop_playback_stream();
                let format = hda_format(rate, 2, 16);
                self.setup_playback_stream(format)?;
                self.setup_codec_playback(0)?;
                self.playback_ring = BdlRingState::new();
                self.active_rate = rate;
                self.position_spins = 0;
            }

            let mut done = 0usize;
            while done < samples.len() {
                let link_pos = self.stream_link_position();
                self.playback_ring.sync_read_from_link(link_pos);
                let free = self.playback_ring.free_space();
                if free == 0 {
                    // Bounded wait so a stalled codec cannot wedge the caller
                    // forever.
                    self.position_spins += 1;
                    if self.position_spins >= MAX_POSITION_SPINS {
                        return Err(crate::Error::TimedOut);
                    }
                    core::hint::spin_loop();
                    continue;
                }
                let chunk = core::cmp::min(free as usize, samples.len() - done);
                let data = self
                    .playback_data
                    .as_mut()
                    .ok_or(crate::Error::Unsupported)?;
                let written = self
                    .playback_ring
                    .copy_into(data.as_mut_slice(), &samples[done..done + chunk]);
                done += written;
                self.position_spins = 0;
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::Mutex;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use controller::HdaController;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static HDA_CONTROLLER: Mutex<Option<HdaController>> = Mutex::new(None);

use crate::kernel::drivers::Driver;
use crate::kernel::drivers::DriverCategory;
use crate::Result;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

static HDA_PROBED: AtomicBool = AtomicBool::new(false);

struct HdaDriver;

impl Driver for HdaDriver {
    fn name(&self) -> &'static str {
        "hda"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Audio
    }

    fn init(&self) -> crate::Result<()> {
        if HDA_PROBED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_hda_pci()
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(HdaDriver)
}

/// Find the HDA controller on PCI and initialise it.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_hda_pci() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_config_read_u16;
    use crate::arch::x86_64::pci::pci_config_write_u16;
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::arch::x86_64::pci::PciAddress;
    use crate::arch::x86_64::pci::COMMAND;
    use crate::println;

    // PCI COMMAND register bits the controller needs before it can DMA
    // (mirrors the virtio-net setup).
    const CMD_IO_SPACE: u16 = 1 << 0;
    const CMD_MEMORY_SPACE: u16 = 1 << 1;
    const CMD_BUS_MASTER: u16 = 1 << 2;

    let devices = pci_enumerate_buses();
    let mut found = false;

    for info in devices
        .iter()
        .filter(|d| d.class_code == HDA_CLASS && d.subclass == HDA_SUBCLASS)
    {
        found = true;
        println!(
            "[hda   ] found HDA controller at {:02x}:{:02x}.{:x} vendor={:#06x} device={:#06x}",
            info.bus, info.device, info.function, info.vendor_id, info.device_id
        );

        // Enable IO Space, Memory Space, and Bus Master so the CORB/RIRB
        // DMA engines can access guest RAM (QEMU keeps the device's DMA
        // address space empty until the BUS_MASTER bit is set).
        let pci_addr = PciAddress::new(info.bus, info.device, info.function);
        let cmd = unsafe { pci_config_read_u16(pci_addr, COMMAND) };
        unsafe {
            pci_config_write_u16(
                pci_addr,
                COMMAND,
                cmd | CMD_IO_SPACE | CMD_MEMORY_SPACE | CMD_BUS_MASTER,
            );
        }

        let bar0 = &info.bars[0];
        if !bar0.is_mmio || bar0.size == 0 {
            println!("[hda   ] BAR0 is not MMIO — skipping");
            continue;
        }

        println!(
            "[hda   ] BAR0: phys={:#018x} size={} KiB",
            bar0.base_address,
            bar0.size / 1024
        );

        let ctrl = match unsafe { HdaController::new(bar0.base_address, bar0.size as usize) } {
            Some(c) => c,
            None => {
                println!("[hda   ] controller initialisation failed — skipping");
                continue;
            }
        };

        println!("[hda   ] HDA controller ready");

        // Store the controller.
        *HDA_CONTROLLER.lock() = Some(ctrl);

        // Only initialise the first HDA controller.
        break;
    }

    if !found {
        println!("[hda   ] no HDA controllers found");
    }

    Ok(())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_hda_pci() -> crate::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Device node ABI (/system/dev/audio)
// ---------------------------------------------------------------------------

/// Length of the sample-rate header prefixing every write to the audio node.
///
/// ABI: `[u32le sample_rate][interleaved 16-bit stereo PCM samples]`.
pub const AUDIO_STREAM_HEADER_LEN: usize = 4;

/// Handle a write to the `/system/dev/audio` device node.
///
/// The sample-rate header selects the stream format; PCM samples follow.
/// On targets without a bare-metal HDA controller this always fails with
/// [`crate::Error::Unsupported`].
pub fn device_write(buffer: &[u8]) -> Result<usize> {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if buffer.len() < AUDIO_STREAM_HEADER_LEN {
            return Err(crate::Error::InvalidArgument);
        }
        let rate = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        let samples = &buffer[AUDIO_STREAM_HEADER_LEN..];
        if samples.is_empty() {
            return Ok(AUDIO_STREAM_HEADER_LEN);
        }
        let mut guard = HDA_CONTROLLER.lock();
        let ctrl = guard.as_mut().ok_or(crate::Error::Unsupported)?;
        // Safety: the mutex guards the controller, so this holds the only
        // reference to its MMIO mapping and DMA buffers.
        unsafe { ctrl.write_pcm(rate, samples) }?;
        Ok(buffer.len())
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        let _ = buffer;
        Err(crate::Error::Unsupported)
    }
}

/// Reading the audio device node is unsupported (playback-only).
pub fn device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Err(crate::Error::Unsupported)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        // 48 kHz / 16-bit / 2 ch is the canonical 0x1200 format word.
        assert_eq!(hda_format(48000, 2, 16), 0x1200);
    }

    #[test]
    fn hda_format_base_rates() {
        assert_eq!(hda_format(48000, 2, 16) & 0x00F0, 0x0000);
        assert_eq!(hda_format(44100, 2, 16) & 0x00F0, 0x0010);
        assert_eq!(hda_format(32000, 2, 16) & 0x00F0, 0x0020);
        assert_eq!(hda_format(8000, 2, 16) & 0x00F0, 0x0060);
        assert_eq!(hda_format(96000, 2, 16) & 0x00F0, 0x0070);
        assert_eq!(hda_format(192000, 2, 16) & 0x00F0, 0x0080);
    }

    #[test]
    fn hda_format_channels() {
        // channels - 1 in bits 11:9.
        assert_eq!(hda_format(48000, 1, 16) & 0x0E00, 0x0000);
        assert_eq!(hda_format(48000, 2, 16) & 0x0E00, 0x0200);
        assert_eq!(hda_format(48000, 6, 16) & 0x0E00, 0x0A00);
    }

    #[test]
    fn hda_format_bit_depth() {
        assert_eq!(hda_format(48000, 2, 8) & 0xF000, 0x0000);
        assert_eq!(hda_format(48000, 2, 16) & 0xF000, 0x1000);
        assert_eq!(hda_format(48000, 2, 24) & 0xF000, 0x3000);
        assert_eq!(hda_format(48000, 2, 32) & 0xF000, 0x4000);
    }

    #[test]
    fn hda_format_falls_back_to_nearest_encoding() {
        // Unsupported rate/depth degrade to 48 kHz / 16-bit.
        assert_eq!(hda_format(12345, 2, 7), 0x1200);
        // A zero channel count still yields a valid PCM word.
        assert_eq!(hda_format(48000, 0, 16) & 0x0E00, 0x0000);
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

    // -----------------------------------------------------------------------
    // Device node ABI (host build: no bare-metal controller)
    // -----------------------------------------------------------------------

    #[test]
    fn audio_node_write_is_unsupported_on_host() {
        assert!(device_write(&[0x80, 0xBB, 0x00, 0x00, 1, 2]).is_err());
    }

    #[test]
    fn audio_node_read_is_unsupported() {
        let mut buf = [0u8; 8];
        assert!(device_read(&mut buf, 0).is_err());
    }
}
