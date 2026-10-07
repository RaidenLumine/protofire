//! src/drivers/hda.rs
//!
//! Intel HDA audio driver, on the machines that have one.
//!
//! The controller is discovered on the PCI/PCIe bus (class 0x04, subclass
//! 0x03) through [`crate::arch::platform::pci_register_window`], brought up
//! through its CORB/RIRB engines, and driven from the bare-metal device node.
//! The register map and the codec protocol are in
//! [`crate::drivers::hda_protocol`]; this file is the register-level half, and
//! because the platform hands back the controller's BAR already mapped, it is
//! the same file on every bus — x86_64's configuration ports, AArch64's ECAM
//! alias, riscv64's identity-mapped window.  The controller polls its
//! completion ring and claims no interrupt, so it needs nothing of a machine's
//! interrupt controller.  A machine without a controller answers under the
//! same module name from `hda_absent.rs`.

use crate::drivers::hda_protocol::*;
use crate::memory::DmaBuffer;
use crate::println;
use crate::Result;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

/// Bounded spin budget for waiting on the DMA engine to drain the ring.
const MAX_POSITION_SPINS: u32 = 50_000_000;

/// Bounded poll for codec-present bits after controller reset.
const CODEC_WAIT_SPINS: u32 = 10_000_000;

/// Bounded poll for a stream descriptor to latch its reset.
const STREAM_RESET_SPINS: u32 = 100_000;

/// The base of the playback stream descriptor: the first of the four the
/// controller reserves for output.
const fn playback_stream_base() -> usize {
    HDA_SD_BASE + HDA_PLAYBACK_STREAM * HDA_SD_STRIDE
}

/// MMIO helpers for 32-bit, 16-bit, and 8-bit register access.
unsafe fn reg_read32(base: *mut u8, offset: usize) -> u32 {
    // SAFETY: the caller passes this controller's mapped register block and an
    // offset the HDA specification defines; the read is volatile.
    unsafe { read_volatile(base.add(offset) as *const u32) }
}
unsafe fn reg_write32(base: *mut u8, offset: usize, val: u32) {
    // SAFETY: as `reg_read32` — the same block, on the write side.
    unsafe {
        write_volatile(base.add(offset) as *mut u32, val);
    }
}
unsafe fn reg_read16(base: *mut u8, offset: usize) -> u16 {
    // SAFETY: as `reg_read32`, for a 16-bit register.
    unsafe { read_volatile(base.add(offset) as *const u16) }
}
unsafe fn reg_write16(base: *mut u8, offset: usize, val: u16) {
    // SAFETY: as `reg_write32`, for a 16-bit register.
    unsafe {
        write_volatile(base.add(offset) as *mut u16, val);
    }
}
unsafe fn reg_read8(base: *mut u8, offset: usize) -> u8 {
    // SAFETY: as `reg_read32`, for a byte-wide register.
    unsafe { read_volatile(base.add(offset) as *const u8) }
}
unsafe fn reg_write8(base: *mut u8, offset: usize, val: u8) {
    // SAFETY: as `reg_write32`, for a byte-wide register.
    unsafe {
        write_volatile(base.add(offset), val);
    }
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
    /// Create and initialise a new HDA controller over its mapped BAR0.
    ///
    /// `bar_address` is the platform's mapping of the controller's BAR0 — the
    /// `bar_address` of the window
    /// [`crate::arch::platform::pci_register_window`] hands back.  On a machine
    /// that identity-maps its device window the number is the BAR's own
    /// address; on a machine whose window sits above the range its page
    /// tables map, it is the low alias the platform reserved for this
    /// device.  The driver reads registers through whatever the platform
    /// returned and maps nothing itself, which is what lets one file drive
    /// the controller on every bus.
    ///
    /// # Safety
    ///
    /// `bar_address` must be a live mapping of the controller's BAR0, as the
    /// platform's PCI enumeration produced it; every later register access is
    /// sound only while that mapping exists.
    pub unsafe fn new(bar_address: usize) -> Option<Self> {
        // SAFETY: the caller passes the platform's mapping of BAR0, which is the
        // register block every later method reads and writes.
        unsafe {
            let regs = bar_address as *mut u8;

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
                return Some(ctrl); // Still return the controller for later
                                   // use.
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
    }

    // -------------------------------------------------------------------
    // Reset
    // -------------------------------------------------------------------

    /// Reset the controller (GCTL.CRST toggle).
    unsafe fn reset(&mut self) -> Result<()> {
        // SAFETY: the controller is constructed and its registers mapped; the reset
        // touches only its own block.
        unsafe {
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
    }

    // -------------------------------------------------------------------
    // CORB setup
    // -------------------------------------------------------------------

    /// Initialise the CORB engine.
    unsafe fn init_corb(&mut self) -> Result<()> {
        // SAFETY: as `reset` — the CORB is allocated here and registered in the
        // controller's own registers.
        unsafe {
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
    }

    // -------------------------------------------------------------------
    // RIRB setup
    // -------------------------------------------------------------------

    /// Initialise the RIRB engine.
    unsafe fn init_rirb(&mut self) -> Result<()> {
        // SAFETY: as above — the RIRB, likewise.
        unsafe {
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
        // SAFETY: codec detection reads the controller's own state-change register and
        // talks to codecs on its own link.
        unsafe {
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
        // SAFETY: a verb goes out through this controller's CORB and its answer comes
        // back through the RIRB, both owned by `self`.
        unsafe {
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
    }

    /// Read a codec parameter (e.g. VENDOR_ID) via GET_PARAMETER.
    ///
    /// # Safety
    ///
    /// As [`Self::send_verb`]: the controller must be initialised, because the
    /// verb leaves through its own CORB/RIRB pair.
    pub unsafe fn read_codec_param(&mut self, cad: u8, nid: u8, param: u8) -> Result<u32> {
        // SAFETY: as `send_verb` — the parameter read is a verb on the same link.
        unsafe {
            let verb = get_param(cad, nid, param);
            self.send_verb(verb)
        }
    }

    // -------------------------------------------------------------------
    // Codec widget enumeration
    // -------------------------------------------------------------------

    /// Read the subordinate node list of `nid`: (start node, count).
    unsafe fn subordinate_node_count(&mut self, cad: u8, nid: u8) -> Result<(u8, u16)> {
        // SAFETY: as above — one more verb to the same codec.
        unsafe {
            let v = self.read_codec_param(cad, nid, param_id::SUBORDINATE_NODE_COUNT)?;
            let start = (v & 0xFF) as u8;
            let count = ((v >> 16) & 0xFF) as u8;
            Ok((start, count as u16))
        }
    }

    /// Find an audio output converter widget reachable from the root node.
    ///
    /// Walks root (0) -> audio function group -> widget list and returns
    /// the first widget whose AW_CAPABILITIES type (bits 20:24) is 0
    /// (audio output converter).
    unsafe fn find_output_converter(&mut self, cad: u8) -> Result<u8> {
        // SAFETY: as above — the converter search issues verbs on this controller's
        // link.
        unsafe {
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
    }

    // -------------------------------------------------------------------
    // Playback stream
    // -------------------------------------------------------------------

    /// Read the stream's link position in buffer (SDLPIB).
    unsafe fn stream_link_position(&self) -> u32 {
        // SAFETY: reading this controller's own stream-link position register.
        unsafe { reg_read32(self.regs, playback_stream_base() + HDA_SDLPIB) }
    }

    /// Stop the playback stream and put its descriptor back in reset.
    ///
    /// SDCTL has a two-step reset — set `SRST`, wait until it reads back set,
    /// then clear it — and `RUN` must be clear first.  Doing it in that order
    /// is what leaves the descriptor programmable; the previous version of
    /// this wrote the two bits as if they were swapped and never stopped the
    /// stream at all.
    unsafe fn stop_playback_stream(&mut self) {
        // SAFETY: stopping a stream means touching the controller's stream registers,
        // which it owns.
        unsafe {
            let sd = playback_stream_base();
            let ctl = reg_read32(self.regs, sd + HDA_SDCTL);
            if ctl & SDCTL_RUN != 0 {
                reg_write32(self.regs, sd + HDA_SDCTL, ctl & !SDCTL_RUN);
            }
            let ctl = reg_read32(self.regs, sd + HDA_SDCTL);
            reg_write32(self.regs, sd + HDA_SDCTL, ctl | SDCTL_SRST);
            for _ in 0..STREAM_RESET_SPINS {
                if reg_read32(self.regs, sd + HDA_SDCTL) & SDCTL_SRST != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            let ctl = reg_read32(self.regs, sd + HDA_SDCTL);
            reg_write32(self.regs, sd + HDA_SDCTL, ctl & !SDCTL_SRST);
        }
    }

    /// Program the stream descriptor for playback at `format` and start
    /// the DMA engine (stream 0, output direction).
    unsafe fn setup_playback_stream(&mut self, format: u16) -> Result<()> {
        // SAFETY: as above — the stream descriptor belongs to this controller.
        unsafe {
            let sd = playback_stream_base();
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
            // Start: stream tag (the direction is the descriptor's, which is
            // why playback uses one of the last four) and RUN with SRST clear.
            let sctl = ((self.stream_tag as u32) & 0x0F) << SDCTL_STRM_TAG_SHIFT | SDCTL_RUN;
            reg_write32(self.regs, sd + HDA_SDCTL, sctl);
            Ok(())
        }
    }

    /// Route the playback stream into the output converter and power it
    /// to D0.
    ///
    /// `format` is the same [`hda_format`] word the stream descriptor's
    /// SDFMT carries.  The converter is told the stream's *shape* through it
    /// — how many channels, how deep, at what rate — and told only which
    /// stream tag to listen for through the channel verb.  Sending the tag
    /// as if it were the format is what made every tone an octave low: the
    /// codec decoded the truncated word as one channel, so it played the two
    /// interleaved samples of each stereo frame in sequence.
    unsafe fn setup_codec_playback(&mut self, cad: u8, format: u16) -> Result<()> {
        // SAFETY: the codec verbs for playback go out through the same CORB/RIRB pair.
        unsafe {
            let converter = self.converter_nid;
            if converter == 0 {
                return Err(crate::Error::NotFound);
            }
            let tag = self.stream_tag & 0x0F;
            // Power the widget to D0.
            self.send_verb(hda_verb(cad, converter, VERB_SET_POWER_STATE, 0))?;
            // The stream's format word, in the verb's sixteen-bit form.
            self.send_verb(hda_verb16(cad, converter, VERB_SET_STREAM_FORMAT, format))?;
            // The stream tag in bits 7:4, and the first channel this
            // converter handles (0) in bits 3:0 — the channel *count* is in
            // the format word above, not here.
            self.send_verb(hda_verb(
                cad,
                converter,
                VERB_SET_CONVERTER_STREAM_CHANNEL,
                tag << 4,
            ))?;
            Ok(())
        }
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
        // SAFETY: the caller's contract says the controller is up; the write goes into
        // this controller's stream DMA buffer and ring.
        unsafe {
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
                self.setup_codec_playback(0, format)?;
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

use crate::drivers::Driver;
use crate::drivers::DriverCategory;
use crate::kernel::sync::Mutex;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

static HDA_CONTROLLER: Mutex<Option<HdaController>> = Mutex::new(None);

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
///
/// The discovery is the platform's: `pci_register_window` walks whatever bus
/// this machine reaches its devices through — x86_64's configuration ports, or
/// the ECAM window the two device-tree machines map — and hands back a
/// controller's register block already mapped.  Vendor `0` is "any vendor": the
/// class is what names an HDA controller, and it says nothing about who built
/// it, the same way NVMe's does.
fn probe_hda_pci() -> crate::Result<()> {
    use crate::println;

    // The platform's window is the BAR the controller's registers live in —
    // BAR0, the one memory BAR an HDA controller has — and it arrives already
    // mapped, with memory space and bus mastering enabled so the CORB/RIRB
    // engines can reach guest RAM (QEMU keeps a function's DMA address space
    // empty until the bus-master bit is set, and the platform sets it).
    let Some(window) = crate::arch::platform::pci_register_window(0, HDA_CLASS, HDA_SUBCLASS)
    else {
        println!("[hda   ] no HDA controllers found");
        return Ok(());
    };

    println!(
        "[hda   ] found HDA controller vendor={:#06x} device={:#06x} BAR0={:#018x} size={} KiB",
        window.vendor_id,
        window.device_id,
        window.bar_address,
        window.bar_size / 1024
    );

    // SAFETY: `window.bar_address` is the platform's live mapping of the
    // controller's BAR0, which is what `HdaController::new` asks for.
    let ctrl = match unsafe { HdaController::new(window.bar_address) } {
        Some(c) => c,
        None => {
            println!("[hda   ] controller initialisation failed — skipping");
            return Ok(());
        }
    };

    println!("[hda   ] HDA controller ready");

    // Store the controller.
    *HDA_CONTROLLER.lock() = Some(ctrl);
    crate::drivers::record_bound_device(
        "hda",
        "hda",
        crate::drivers::DriverCategory::Audio,
        Some(window.bar_address),
    );

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
    // SAFETY: the mutex guards the controller, so this holds the only
    // reference to its MMIO mapping and DMA buffers.
    unsafe { ctrl.write_pcm(rate, samples) }?;
    Ok(buffer.len())
}

/// Reading the audio device node is unsupported (playback-only).
pub fn device_read(_buffer: &mut [u8], _timeout_ticks: u64) -> Result<usize> {
    Err(crate::Error::Unsupported)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
