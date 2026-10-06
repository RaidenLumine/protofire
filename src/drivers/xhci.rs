//! src/drivers/xhci.rs
//!
//! xHCI (USB 3.x) host controller driver, on the machines that have one.
//!
//! The controller is discovered via PCI (class 0x0C, subclass 0x03, prog-if
//! 0x30) and exposes MMIO registers via BAR0.
//!
//! ## Implementation status
//!
//! - PCI discovery and BAR0 MMIO mapping: done
//! - Controller initialisation (reset, start): done
//! - Command ring: done (polled completion)
//! - Event ring: done (polled)
//! - Device enumeration (Enable Slot, Address Device): done
//! - Control transfers (GET_DESCRIPTOR): done
//! - Interrupt endpoint for HID keyboard reports: done
//! - MSI-X interrupt wiring: done (the event ring's vector drains the ring when
//!   the rings are free, and the timer tick still drains it as the fallback)
//!
//! The register map and the USB structures live in
//! [`crate::drivers::xhci_protocol`]; this file is the machine's half, which is
//! why it is compiled where PCI and BAR0 mapping exist.  A machine without them
//! answers under the same module name from `xhci_absent.rs`.

use crate::arch::mmu::map_device_mmio;
use crate::drivers::xhci_protocol::*;
use crate::memory::DmaBuffer;
use crate::println;
use crate::Result;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

/// Maximum number of device slots we support.
const MAX_SLOTS: usize = 64;

/// How many PORTSC reads to wait for a port's connection to stabilise.
const PORT_CONNECT_SETTLE_SPINS: usize = 100_000;

/// How many times to ask a hub whether a port's reset has finished.
const HUB_PORT_RESET_SPINS: usize = 100_000;

/// A hub whose status-change endpoint is watched.
///
/// The endpoint's reports are a bitmap: bit *n* names downstream port *n*, and
/// the hub keeps asserting a bit until the change behind it has been cleared.
/// Watching it is what turns "a hub is scanned at boot" into "a hub is a hub".
struct HubState {
    /// The hub's slot, for the requests that read and clear its ports.
    slot_id: u8,
    /// The root port the hub itself hangs off.
    root_port: u8,
    /// The route string the hub itself was found at.
    route: u32,
    /// How many downstream ports it reports.
    ports: u8,
    /// The status-change interrupt IN endpoint, as the HID devices configure
    /// theirs — the reports differ, the ring does not.
    ep: HidEndpointInfo,
    /// The DMA buffer its reports land in.
    report_buf: DmaBuffer,
    /// A completed report that has not been run yet.
    ///
    /// A report leads to *requests* — a port status read, a reset, an
    /// enumeration — and those use the same rings the transfer that completed
    /// was in flight on, so running one where its event is found would push a
    /// second TD onto a ring whose first is still outstanding.  The residual
    /// is recorded here and the work is done by
    /// [`XhciController::service_pending`], from the outermost drain.
    pending: Option<u32>,
}

/// The xHCI host controller.
pub struct XhciController {
    /// Operational register base (mmio_base + caplength).
    op_base: *mut u32,
    /// Runtime register base (mmio_base + rtsoff).
    runtime_base: *mut u32,
    /// Doorbell array base (mmio_base + dboff).
    doorbell_base: *mut u32,
    /// Maximum device slots (from HCSPARAMS1).
    max_slots: u8,
    /// Maximum root hub ports (from HCSPARAMS1).
    pub(crate) max_ports: u8,
    /// Device context size in bytes (32 or 64).
    context_size: u8,
    /// Page size mask (from PAGESIZE register).
    #[allow(dead_code)]
    page_size: u32,
    /// Command ring and its producer position.
    cmd_ring: TransferRing,
    /// Event ring DMA buffer.
    event_ring: DmaBuffer,
    /// ERST DMA buffer (one segment table entry).
    erst_buf: DmaBuffer,
    /// Event ring dequeue index.
    evt_dequeue: u32,
    /// Event ring consumer cycle state.
    evt_ccs: bool,
    /// DCBAAP DMA buffer.
    dcbaa: DmaBuffer,
    /// Per-slot device context DMA buffers.
    device_contexts: [Option<DmaBuffer>; MAX_SLOTS],
    /// Per-slot transfer ring for EP0.
    ep0_transfer_rings: [Option<TransferRing>; MAX_SLOTS],
    /// Per-slot interrupt transfer ring.
    int_transfer_rings: [Option<TransferRing>; MAX_SLOTS],
    /// Enumerated slot for HID keyboard (0 = none).
    pub keyboard_slot: u8,
    /// HID keyboard endpoint info.
    pub keyboard_ep: Option<HidEndpointInfo>,
    /// Pre-allocated DMA buffer for HID keyboard report reception (reused
    /// across re-armed reads).
    keyboard_report_buf: Option<DmaBuffer>,
    /// Enumerated slot for HID mouse (0 = none).
    pub mouse_slot: u8,
    /// HID mouse endpoint info.
    pub mouse_ep: Option<HidEndpointInfo>,
    /// Pre-allocated DMA buffer for HID mouse report reception (reused
    /// across re-armed reads).
    mouse_report_buf: Option<DmaBuffer>,
    /// Per-slot bulk OUT transfer rings.
    bulk_out_rings: [Option<TransferRing>; MAX_SLOTS],
    /// Per-slot bulk IN transfer rings.
    bulk_in_rings: [Option<TransferRing>; MAX_SLOTS],
    /// USB mass storage slot (0 = none).
    pub msd_slot: u8,
    /// Mass storage bulk endpoint info.
    pub msd_endpoints: Option<crate::drivers::usb_msd::MsdBulkEndpoints>,
    /// The hubs whose status-change endpoints are watched: one watch each, one
    /// entry per hub found, and no count the machine can outrun.
    ///
    /// A hub is watched through its own interrupt endpoint, and every hub has
    /// one, so the number of watches is the number of hubs — which is why this
    /// is a list rather than a fixed table.  It is also the one part of the
    /// controller's state that grows with the machine rather than with the
    /// slot count, and the controller is built as a value on the boot's stack:
    /// the per-slot tables are the next thing to move to the heap if this one
    /// ever grows again.
    hubs: alloc::vec::Vec<HubState>,
    /// Whether a root port changed since the last drain.  The port is not
    /// kept: the ports are re-read, which is what makes one missed event
    /// harmless.
    port_change_pending: bool,
    /// Where each addressed slot's device hangs: its root port and its route
    /// string.  A device behind a hub is found again by its route when the hub
    /// reports the port it was on as gone, which is how its slot is released.
    slot_routes: [(u8, u32); MAX_SLOTS],
}

// SAFETY: XhciController owns its MMIO mapping and DMA buffers exclusively.
unsafe impl Send for XhciController {}

// -----------------------------------------------------------------------
// MMIO helpers
// -----------------------------------------------------------------------

unsafe fn reg_read32(base: *const u32, offset: usize) -> u32 {
    // SAFETY: the caller passes the controller's own register base and an offset
    // the controller defines; the read is volatile so it is not reordered or
    // elided.
    unsafe { read_volatile(base.add(offset / 4)) }
}

unsafe fn reg_write32(base: *mut u32, offset: usize, value: u32) {
    // SAFETY: as `reg_read32` — the register block belongs to this controller and
    // the offset is one it defines.
    unsafe {
        write_volatile(base.add(offset / 4), value);
    }
}

unsafe fn reg_write64_lo_hi(base: *mut u32, lo_off: usize, hi_off: usize, value: u64) {
    // SAFETY: as `reg_read32` — two writes into the same register block, the low
    // and high halves of one 64-bit register.
    unsafe {
        write_volatile(base.add(lo_off / 4), value as u32);
        write_volatile(base.add(hi_off / 4), (value >> 32) as u32);
    }
}

// -----------------------------------------------------------------------
// TRB ring helpers
// -----------------------------------------------------------------------

/// Get a pointer to the n-th TRB in a ring buffer.
unsafe fn ring_trb_ptr(ring: &DmaBuffer, index: u32) -> *mut Trb {
    // SAFETY: the ring is this controller's DMA buffer and `index` is bounded by
    // its entry count before every call site.
    unsafe {
        let base = ring.as_ptr() as *mut Trb;
        base.add(index as usize)
    }
}

/// The usable TRBs of one ring segment: the last entry holds the Link TRB.
const RING_USABLE_TRBS: u32 = (RING_SEGMENT_TRBS - 1) as u32;

/// Where a producer ring writes next, and the cycle state its lap carries.
///
/// The cycle bit is the whole handshake.  A slot written *this* lap carries
/// `pcs`; a slot still holding the previous lap's TRB carries the opposite,
/// so a consumer walking the segment stops at the first slot the producer
/// has not rewritten this lap.  With a cycle bit that never changes, every
/// slot ever written looks like work, and the ring is usable exactly once —
/// which is the defect the event ring's dropped completions and the mass
/// storage mount's timeout were both made of.
///
/// The Link TRB is the other half of the handshake, and it goes where the lap
/// *ends* rather than at a fixed slot: it points back at the segment's base
/// and carries the lap's own cycle state, so a consumer that has consumed
/// everything the producer wrote follows it, flips, and reads the next lap
/// from the base.  A link pinned at the segment's last slot, with the lap
/// wrapping past the slots the last TD did not fill, leaves those slots
/// carrying the *previous* lap's state — and a consumer stops at the first
/// TRB it does not own, so it would stop before the link, never learn to
/// wrap, and never see another TRB.
#[derive(Clone, Copy)]
struct RingPos {
    /// Slot the next TRB goes into, in `0..=RING_USABLE_TRBS`; a position at
    /// the end is the next TD's cue that the lap ends here.
    index: u32,
    /// True while the lap being written carries cycle 1.
    pcs: bool,
}

impl RingPos {
    const NEW: Self = Self {
        index: 0,
        pcs: true,
    };

    /// The cycle bit a TRB written at the current position carries.
    fn cycle(&self) -> u32 {
        if self.pcs {
            TRB_CYCLE_BIT
        } else {
            0
        }
    }

    /// Write a Link TRB at `index`: it points back at the segment's base,
    /// carries `cycle` so the consumer follows it, and sets Toggle Cycle so
    /// the consumer's own cycle state flips with the lap.
    ///
    /// # Safety
    ///
    /// `ring` must be a ring segment of `RING_SEGMENT_TRBS` TRBs owned by the
    /// caller, and it must outlive every access the controller makes to it.
    unsafe fn write_link_at(&self, ring: &DmaBuffer, index: u32, cycle: u32) {
        // SAFETY: the caller owns the segment, and `index` is inside it.
        unsafe {
            let link = ring_trb_ptr(ring, index);
            write_volatile(link, Trb::link(ring.phys_addr() as u64, cycle));
        }
    }

    /// Write the segment's Link TRB for an untouched lap.
    ///
    /// A ring that has never wrapped ends its first lap at the segment's last
    /// slot, because that is the only slot a lap can reach without being told
    /// where to end; the link carries the lap's cycle state so the consumer
    /// may follow it there.
    ///
    /// # Safety
    ///
    /// As [`Self::write_link_at`].
    unsafe fn write_link(&self, ring: &DmaBuffer) {
        // SAFETY: the caller owns the ring segment.
        unsafe {
            self.write_link_at(ring, RING_USABLE_TRBS, self.cycle());
        }
    }

    /// Reserve room for `trbs` TRBs in the lap being written, ending the lap
    /// with a Link TRB first when they would not fit before the segment's
    /// end.
    ///
    /// The lap ends where the work ends, so there is never a slot between the
    /// last TRB written and the Link TRB: a TD must not straddle the link
    /// (its TRBs would carry two different cycle states and the controller
    /// would stop between them), and the slots it would have straddled are
    /// exactly the ones a consumer must not be stopped by.
    ///
    /// # Safety
    ///
    /// As [`Self::write_link`].
    unsafe fn reserve(&mut self, ring: &DmaBuffer, trbs: u32) {
        debug_assert!(trbs <= RING_USABLE_TRBS);
        if self.index + trbs > RING_USABLE_TRBS {
            // SAFETY: the caller owns the ring, which `end_lap` requires.
            unsafe { self.end_lap(ring) };
        }
    }

    /// Hand the consumer a Link TRB at the current position and start the
    /// next lap at the segment's base with the opposite cycle state.
    ///
    /// # Safety
    ///
    /// As [`Self::write_link_at`].
    unsafe fn end_lap(&mut self, ring: &DmaBuffer) {
        // SAFETY: the position is inside the segment the caller owns.
        unsafe {
            self.write_link_at(ring, self.index, self.cycle());
        }
        self.pcs = !self.pcs;
        self.index = 0;
    }

    /// Place one TRB at the current position and advance.
    ///
    /// # Safety
    ///
    /// As [`Self::write_link`], and the caller must have reserved room for
    /// this TRB with [`Self::reserve`].
    unsafe fn place(&mut self, ring: &DmaBuffer, mut trb: Trb) {
        // SAFETY: the position is inside the segment the caller owns; the
        // controller reads the TRB this writes.
        unsafe {
            trb.control |= self.cycle();
            write_volatile(ring_trb_ptr(ring, self.index), trb);
        }
        self.index += 1;
    }
}

/// A transfer ring segment and where its producer will write next.
///
/// The controller consumes these rings (they are the *producer* side of the
/// command ring and of each endpoint's transfer ring), so the position and
/// the segment travel together: a ring without a position, or a position
/// without its ring, is a state that cannot be expressed.
struct TransferRing {
    buf: DmaBuffer,
    pos: RingPos,
    /// How much of the ring is submitted and not yet completed.
    ///
    /// The ring cannot be asked how full it is — the controller writes its
    /// dequeue pointer back into an endpoint's context only when the endpoint
    /// stops or faults — so what the producer has not seen complete is the
    /// measure, and it is what bounds a caller that submits without waiting.
    room: RingRoom,
}

impl TransferRing {
    /// Allocate a ring segment and program its Link TRB for a first lap.
    fn allocate() -> Option<Self> {
        let ring = Self {
            buf: DmaBuffer::allocate(1)?,
            pos: RingPos::NEW,
            room: RingRoom::new(),
        };
        // SAFETY: the ring owns its segment, which stays alive with it.
        unsafe { ring.pos.write_link(&ring.buf) };
        Some(ring)
    }

    /// Physical address of the segment, for a register or a context.
    fn phys_addr(&self) -> u64 {
        self.buf.phys_addr() as u64
    }

    /// Take room for a TD of `trbs` TRBs, and end the lap first if they do not
    /// fit in it.
    ///
    /// Every submission goes through here, which is what keeps the ring's
    /// occupancy honest: a caller that waits for each completion is never
    /// refused, and one that pipelines is told when it has to stop instead of
    /// writing over a TRB the controller has not read.
    ///
    /// # Safety
    ///
    /// As [`RingPos::write_link`].
    unsafe fn reserve(&mut self, trbs: u32) -> Result<()> {
        self.room.reserve(trbs).ok_or(crate::Error::Busy)?;
        // SAFETY: the ring owns its segment and stays alive with it.
        unsafe {
            self.pos.reserve(&self.buf, trbs);
        }
        Ok(())
    }

    /// Place one TRB at the position the last [`Self::reserve`] took room for.
    ///
    /// # Safety
    ///
    /// As [`RingPos::place`], and the caller must have reserved room with
    /// [`Self::reserve`].
    unsafe fn place(&mut self, trb: Trb) {
        // SAFETY: the position is inside the segment this ring owns.
        unsafe {
            self.pos.place(&self.buf, trb);
        }
    }

    /// Give back the room a TD used, once its completion has been seen.
    fn release(&mut self, trbs: u32) {
        self.room.release(trbs);
    }

    /// Reserve room and place one TRB.
    ///
    /// # Safety
    ///
    /// As [`Self::reserve`].
    unsafe fn push(&mut self, trb: Trb) -> Result<()> {
        // SAFETY: the ring owns its segment and stays alive with it.
        unsafe {
            self.reserve(1)?;
            self.place(trb);
        }
        Ok(())
    }
}

/// Walk a configuration descriptor and return the first interface
/// descriptor's (class, subclass, protocol).
///
/// Devices that report bDeviceClass == 0 declare their class per
/// interface, so the effective class has to come from the interface
/// descriptor (e.g. HID keyboards and bulk-only mass storage).
fn config_interface_class(config: &[u8]) -> Option<(u8, u8, u8)> {
    let mut i = 0usize;
    while i + 1 < config.len() {
        let dlen = config[i] as usize;
        if dlen < 2 {
            break;
        }
        // INTERFACE descriptor: bInterfaceClass at +5, subclass +6,
        // protocol +7.
        if config[i + 1] == 4 && i + 7 < config.len() {
            return Some((config[i + 5], config[i + 6], config[i + 7]));
        }
        i += dlen;
    }
    None
}

/// The bulk ring a submit used, for handing its TRB back after the wait.
fn using_in_ring(
    ctrl: &mut XhciController,
    idx: usize,
    direction_in: bool,
) -> Option<&mut TransferRing> {
    if direction_in {
        ctrl.bulk_in_rings[idx].as_mut()
    } else {
        ctrl.bulk_out_rings[idx].as_mut()
    }
}

/// Place a command TRB at the command ring's position (wrapping first if it
/// would cross the Link TRB) and ring the doorbell.
unsafe fn post_cmd_trb(ctrl: &mut XhciController, trb: Trb) -> Result<()> {
    // SAFETY: `ctrl` owns the command ring and its doorbell; the enqueue index is
    // kept inside the ring by the ring's own position.
    unsafe {
        ctrl.cmd_ring.push(trb)?;
        // Ring doorbell for the command ring (doorbell 0).
        write_volatile(ctrl.doorbell_base, 0u32);
    }
    Ok(())
}

/// Wait for a command completion event on the event ring.
/// Returns the Command Completion Event TRB.
unsafe fn await_cmd_completion(ctrl: &mut XhciController) -> Result<Trb> {
    // SAFETY: as `post_cmd_trb` — the event ring and its consumer position are
    // the controller's own.
    unsafe {
        for _ in 0..10_000_000 {
            let Some(evt) = ctrl.peek_event() else {
                continue;
            };
            ctrl.advance_event_ring();
            if evt.trb_type() == trb_type::COMMAND_COMPLETION_EVENT {
                // The command is done with its slot on the ring, whether it
                // completed or failed; a failure is the caller's to report.
                ctrl.cmd_ring.release(1);
                return Ok(evt);
            }
        }
        Err(crate::Error::TimedOut)
    }
}

// -----------------------------------------------------------------------
// Controller lifecycle
// -----------------------------------------------------------------------

impl XhciController {
    /// Initialise a new xHCI controller given BAR0 physical address and
    /// size. Returns `None` if MMIO mapping fails or the controller
    /// is not usable.
    ///
    /// # Safety
    ///
    /// `bar0_phys` and `bar0_size` must describe the controller's BAR0 as PCI
    /// enumeration reported it, so that the range is live MMIO; the mapping
    /// this builds is what makes every later register access sound.
    pub unsafe fn new(bar0_phys: u64, bar0_size: usize) -> Option<alloc::boxed::Box<Self>> {
        // SAFETY: the caller passes a BAR address PCI enumeration produced; the mapping
        // this block performs is what makes every later register access sound.
        unsafe {
            let mmio = map_device_mmio(bar0_phys, bar0_size)?;
            let mmio_base = mmio;

            // Read CAPLENGTH (byte 0 of BAR0).
            let caplen = read_volatile(mmio_base as *const u8) as usize;
            let op_base = mmio_base.add(caplen) as *mut u32;

            // Read capability registers.
            let cap = mmio_base as *const u32;
            let hcsparams1 = read_volatile(cap.add(XHCI_CAP_HCSPARAMS1 / 4));
            let hccparams1 = read_volatile(cap.add(XHCI_CAP_HCCPARAMS1 / 4));
            let dboff = read_volatile(cap.add(XHCI_CAP_DBOFF / 4)) as usize;
            let rtsoff = read_volatile(cap.add(XHCI_CAP_RTSOFF / 4)) as usize;

            let max_slots = (hcsparams1 & HCSPARAMS1_MAX_SLOTS_MASK) as u8;
            let max_ports =
                ((hcsparams1 & HCSPARAMS1_MAX_PORTS_MASK) >> HCSPARAMS1_MAX_PORTS_SHIFT) as u8;
            let context_size: u8 = if hccparams1 & HCCPARAMS1_CSZ != 0 {
                64
            } else {
                32
            };

            let doorbell_base = mmio_base.add(dboff) as *mut u32;
            let runtime_base = mmio_base.add(rtsoff) as *mut u32;

            // Read page size.
            let page_size = read_volatile(op_base.add(XHCI_OP_PAGESIZE / 4));

            println!(
            "[xhci  ] hcsparams1={:#010x} max_slots={} max_ports={} ctx_size={} page_size={:#x}",
            hcsparams1, max_slots, max_ports, context_size, page_size
        );

            // The controller is tens of kilobytes — a context and three rings
            // per slot — and the boot runs on a 64 KiB stack.  Returning it by
            // value costs that stack the value *twice* (the constructor's
            // literal and the caller's return slot), which a field as large as
            // a per-slot table pushes over the edge; a box costs one copy, in
            // the constructor, and the rest of it is heap.
            let mut ctrl = alloc::boxed::Box::new(Self {
                op_base,
                runtime_base,
                doorbell_base,
                max_slots,
                max_ports,
                context_size,
                page_size,
                // The command ring is a producer ring like any endpoint's:
                // its Link TRB is written when it is allocated, so the
                // controller has somewhere to stop before the first wrap.
                cmd_ring: TransferRing::allocate()?,
                event_ring: DmaBuffer::allocate(1)?, // 4 KiB for event ring
                erst_buf: DmaBuffer::allocate(1)?,   // 4 KiB for ERST (we only need 16 bytes)
                evt_dequeue: 0,
                evt_ccs: true,
                dcbaa: DmaBuffer::allocate(1)?, // 4 KiB for DCBAAP
                device_contexts: [const { None }; MAX_SLOTS],
                ep0_transfer_rings: [const { None }; MAX_SLOTS],
                int_transfer_rings: [const { None }; MAX_SLOTS],
                keyboard_slot: 0,
                keyboard_ep: None,
                keyboard_report_buf: None,
                mouse_slot: 0,
                mouse_ep: None,
                mouse_report_buf: None,
                bulk_out_rings: [const { None }; MAX_SLOTS],
                bulk_in_rings: [const { None }; MAX_SLOTS],
                msd_slot: 0,
                msd_endpoints: None,
                hubs: alloc::vec::Vec::new(),
                port_change_pending: false,
                slot_routes: [(0, 0); MAX_SLOTS],
            });

            ctrl.reset().ok()?;
            ctrl.init_rings().ok()?;
            ctrl.start().ok()?;

            println!("[xhci  ] controller initialised and running");
            Some(ctrl)
        }
    }

    /// Reset the host controller.
    unsafe fn reset(&mut self) -> Result<()> {
        // SAFETY: the controller is constructed and its register base mapped; reset
        // touches only its own registers.
        unsafe {
            // Wait for CNR (Controller Not Ready) to clear.
            for _ in 0..100_000 {
                let usbsts = reg_read32(self.op_base, XHCI_OP_USBSTS);
                if usbsts & USBSTS_CNR == 0 {
                    break;
                }
            }
            if reg_read32(self.op_base, XHCI_OP_USBSTS) & USBSTS_CNR != 0 {
                return Err(crate::Error::TimedOut);
            }

            // Assert HCRST.
            let mut usbcmd = reg_read32(self.op_base, XHCI_OP_USBCMD);
            usbcmd |= USBCMD_HCRST;
            reg_write32(self.op_base, XHCI_OP_USBCMD, usbcmd);

            // Wait for HCRST to clear and HCH (Halted) to set.
            for _ in 0..100_000 {
                let usbcmd2 = reg_read32(self.op_base, XHCI_OP_USBCMD);
                let usbsts2 = reg_read32(self.op_base, XHCI_OP_USBSTS);
                if usbcmd2 & USBCMD_HCRST == 0 && usbsts2 & USBSTS_HCH != 0 {
                    return Ok(());
                }
            }
            Err(crate::Error::TimedOut)
        }
    }

    /// Allocate and program command ring, event ring, DCBAAP.
    unsafe fn init_rings(&mut self) -> Result<()> {
        // SAFETY: as `reset` — the rings are allocated here and registered with the
        // controller's own registers.
        unsafe {
            // --- Command ring ---
            // The ring was allocated with its Link TRB already in place; all
            // that is left is to point the controller at it.  RCS = 1 starts
            // the controller's cycle state on the lap the ring opened.
            let cmd_ring_phys = self.cmd_ring.phys_addr();

            // Program CRCR (Command Ring Control Register).
            // Bits 63:4 = physical address of cmd ring (64-byte aligned, always true for
            // page-aligned) Bit 0 = RCS (Ring Cycle State), start with 1.
            let crcr = cmd_ring_phys | CRCR_RCS;
            reg_write64_lo_hi(self.op_base, XHCI_OP_CRCR_LOW, XHCI_OP_CRCR_HIGH, crcr);

            // --- Event ring ---
            // The event ring is the controller's to produce and ours to
            // consume, so it has no Link TRB: the ERST segment size below is
            // where *both* wraps happen, and the controller flips its
            // producer cycle state there.  The whole segment is usable; a
            // Link TRB in the last entry would be a slot the controller
            // would write an event into.
            let evt_ring_phys = self.event_ring.phys_addr() as u64;

            // Build ERST entry.
            let erst_entry = ErstEntry::new(evt_ring_phys, RING_SEGMENT_TRBS as u16);
            let erst_ptr = self.erst_buf.as_ptr() as *mut ErstEntry;
            write_volatile(erst_ptr, erst_entry);

            // Program Interrupter 0 ERST.
            let ir_base = XHCI_RT_IR_BASE;
            let erst_phys = self.erst_buf.phys_addr() as u64;
            reg_write32(self.runtime_base, ir_base + XHCI_RT_ERSTSZ, 1); // one segment
            reg_write64_lo_hi(
                self.runtime_base,
                ir_base + XHCI_RT_ERSTBA_LOW,
                ir_base + XHCI_RT_ERSTBA_HIGH,
                erst_phys,
            );
            // Set ERDP to start of event ring with EHB clear.
            reg_write64_lo_hi(
                self.runtime_base,
                ir_base + XHCI_RT_ERDP_LOW,
                ir_base + XHCI_RT_ERDP_HIGH,
                evt_ring_phys | (1u64 << 3), // DCS=1
            );

            // --- DCBAAP ---
            let dcbaa_phys = self.dcbaa.phys_addr() as u64;
            // Zero all entries.
            let dcbaa_slice = self.dcbaa.as_mut_slice();
            dcbaa_slice.fill(0);

            reg_write64_lo_hi(
                self.op_base,
                XHCI_OP_DCBAAP_LOW,
                XHCI_OP_DCBAAP_HIGH,
                dcbaa_phys,
            );

            // --- CONFIG register ---
            let max_slots_val = self.max_slots.min(MAX_SLOTS as u8) as u32;
            reg_write32(self.op_base, XHCI_OP_CONFIG, max_slots_val);

            // Let the interrupter raise a message when it posts an event, and
            // clear whatever pending bit bring-up left behind so the *next*
            // event is a 0→1 transition the controller will speak about.  The
            // message itself needs the function's MSI-X table programmed and
            // unmasked, which the platform does once the local APIC is up;
            // until then the pending bit stays set and the timer tick drains
            // the ring, which is what this driver did before.
            let iman = reg_read32(self.runtime_base, ir_base + XHCI_RT_IMAN);
            reg_write32(
                self.runtime_base,
                ir_base + XHCI_RT_IMAN,
                iman | IMAN_IE | IMAN_IP,
            );
            let usbcmd = reg_read32(self.op_base, XHCI_OP_USBCMD);
            reg_write32(self.op_base, XHCI_OP_USBCMD, usbcmd | USBCMD_INTE);

            Ok(())
        }
    }

    /// Start the host controller (set Run/Stop = 1).
    unsafe fn start(&mut self) -> Result<()> {
        // SAFETY: as `reset` — starting the controller writes its own operational
        // registers.
        unsafe {
            let mut usbcmd = reg_read32(self.op_base, XHCI_OP_USBCMD);
            usbcmd |= USBCMD_RS;
            reg_write32(self.op_base, XHCI_OP_USBCMD, usbcmd);

            // Wait for HCH (Halted) to clear.
            for _ in 0..100_000 {
                let usbsts = reg_read32(self.op_base, XHCI_OP_USBSTS);
                if usbsts & USBSTS_HCH == 0 {
                    return Ok(());
                }
            }
            Err(crate::Error::TimedOut)
        }
    }

    // -------------------------------------------------------------------
    // Command helpers
    // -------------------------------------------------------------------

    /// Send a command TRB and wait for its completion event.
    unsafe fn send_command(&mut self, trb: Trb) -> Result<Trb> {
        // SAFETY: `send_command` operates on this controller's command and event rings,
        // both owned by `self`.
        unsafe {
            post_cmd_trb(self, trb)?;
            await_cmd_completion(self)
        }
    }

    /// The cycle bit the controller's event-ring producer is using at the
    /// consumer's current position.
    fn event_cycle(&self) -> u32 {
        if self.evt_ccs {
            TRB_CYCLE_BIT
        } else {
            0
        }
    }

    /// The event the controller has posted at the consumer's position, or
    /// `None` while that slot still belongs to the previous lap.
    ///
    /// The cycle bit is taken from the control word **first**, on its own.
    /// An event TRB is published in address order — parameter, status, then
    /// the control word the cycle bit lives in — so a control word that
    /// already reads as the expected cycle is a promise that the rest of the
    /// entry is in place; and the rest is read only after that promise, with
    /// the control word checked again so a slot rewritten underneath the read
    /// is refused rather than half-accepted.  A single read of the whole
    /// `Trb` is not one access — the compiler emits two, and the controller
    /// can publish its event between them — which is how this used to return
    /// an entry with a matching cycle bit and a zeroed parameter, and how a
    /// transfer that had completed came back as a timeout.
    ///
    /// # Safety
    ///
    /// The controller is the one this object was built for and its event
    /// ring is still mapped.
    unsafe fn peek_event(&self) -> Option<Trb> {
        // SAFETY: the dequeue index stays inside the segment, which the
        // controller owns through this object; the four word reads are the
        // four words of the entry at that index.
        unsafe {
            let base = ring_trb_ptr(&self.event_ring, self.evt_dequeue) as *const u32;
            let control = read_volatile(base.add(3));
            if control & TRB_CYCLE_BIT != self.event_cycle() {
                return None;
            }
            let parameter =
                read_volatile(base) as u64 | (u64::from(read_volatile(base.add(1))) << 32);
            let status = read_volatile(base.add(2));
            if read_volatile(base.add(3)) != control {
                return None;
            }
            Some(Trb {
                parameter,
                status,
                control,
            })
        }
    }

    /// Consume the event at the consumer's position and move on.
    ///
    /// The wrap is the *segment size* the ERST states, because that is where
    /// the controller's producer wraps and flips its cycle state; the event
    /// ring carries no Link TRB.  ERDP is written with EHB set, which
    /// acknowledges the event and is the value the controller tests its
    /// event-ring-full condition against, so a consumer that stays in step is
    /// also what keeps the controller willing to post the next event.
    ///
    /// # Safety
    ///
    /// As [`Self::peek_event`].
    unsafe fn advance_event_ring(&mut self) {
        self.evt_dequeue += 1;
        if self.evt_dequeue >= RING_SEGMENT_TRBS as u32 {
            self.evt_dequeue = 0;
            self.evt_ccs = !self.evt_ccs;
        }
        let erdp = self.event_ring.phys_addr() as u64 + self.evt_dequeue as u64 * TRB_SIZE as u64;
        // SAFETY: the runtime window belongs to this controller, and ERDP is
        // one of the interrupter's own registers.
        unsafe {
            reg_write64_lo_hi(
                self.runtime_base,
                XHCI_RT_IR_BASE + XHCI_RT_ERDP_LOW,
                XHCI_RT_IR_BASE + XHCI_RT_ERDP_HIGH,
                erdp | (1u64 << 3), // EHB: write 1 to clear
            );
        }
    }

    // -------------------------------------------------------------------
    // Device enumeration
    // -------------------------------------------------------------------

    /// Enable a device slot on a root hub port. Returns the slot ID
    /// (1-based).
    ///
    /// # Safety
    ///
    /// The controller must be one [`Self::new`] returned and still have its BAR
    /// mapped: the command is posted to that controller's own rings.
    pub unsafe fn enable_slot(&mut self, root_port: u8) -> Result<u8> {
        // SAFETY: as `send_command` — the enable-slot command is posted to the same
        // rings.
        unsafe {
            // The cycle bit is applied when the ring places the TRB.
            let trb = Trb::enable_slot(0, root_port);
            let evt = self.send_command(trb)?;
            let cc = evt.completion_code();
            if cc != cc::SUCCESS {
                println!("[xhci  ] enable_slot failed: cc={}", cc);
                return Err(crate::Error::InvalidArgument);
            }
            let slot_id = evt.slot_id();
            if slot_id == 0 || slot_id as usize > MAX_SLOTS {
                return Err(crate::Error::InvalidArgument);
            }
            Ok(slot_id)
        }
    }

    /// Allocate device context and EP0 transfer ring for a slot.
    ///
    /// # Safety
    ///
    /// `slot_id` must name a slot this controller enabled, and the controller
    /// must still own its rings and doorbells.
    pub unsafe fn alloc_slot_resources(&mut self, slot_id: u8) -> Result<()> {
        // SAFETY: as above — the slot's contexts are written through this controller's
        // rings and doorbells.
        unsafe {
            let idx = slot_id as usize - 1;

            // Device context: (1 + 2) * context_size = 3 contexts (Slot + EP0 + EP1).
            // Actually: Slot Context + EP0 Control Context + EP1 IN Context.
            let num_contexts = 3usize;
            let total_size = num_contexts * self.context_size as usize;
            let nframes = total_size.div_ceil(4096);
            let mut dev_ctx = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            dev_ctx.as_mut_slice().fill(0);

            // Store device context pointer in DCBAAP.
            let dcbaa_slice: &mut [u64] = core::slice::from_raw_parts_mut(
                self.dcbaa.as_ptr() as *mut u64,
                self.max_slots as usize + 1,
            );
            dcbaa_slice[slot_id as usize] = dev_ctx.phys_addr() as u64;

            // EP0 transfer ring (Default Control Endpoint).
            let ep0_ring = TransferRing::allocate().ok_or(crate::Error::OutOfMemory)?;

            self.device_contexts[idx] = Some(dev_ctx);
            self.ep0_transfer_rings[idx] = Some(ep0_ring);
            Ok(())
        }
    }

    /// Build an input context for Address Device command.
    ///
    /// The layout follows QEMU 8.2.2's `xhci_address_slot` (which reads the
    /// Slot Context at `ictx + 32` and the EP0 Context at `ictx + 64`, i.e.
    /// a 32-byte Input Control Context):
    /// - ICC DWORD 0 = Drop Context flags, must be 0.
    /// - ICC DWORD 1 = Add Context flags, must be 0x3 (add Slot + EP0); any
    ///   other combination is rejected with CC_TRB_ERROR.
    /// - Slot Context: Context Entries at bits 31:27
    ///   (`SLOT_CONTEXT_ENTRIES_SHIFT`), Root Hub Port Number at DWORD 1 bits
    ///   23:16 (`(slot_ctx[1] >> 16) & 0xFF`).  Bits 19:0 of DWORD 0 must stay
    ///   0 so `xhci_lookup_uport` sees no hub route path.
    /// - EP0 Control Context: EP type at bits 5:3 (`EP_TYPE_SHIFT`), Max Packet
    ///   Size at bits 23:16 (`ctx[1] >> 16`), TR Dequeue Pointer in DWORDs 2-3.
    unsafe fn build_address_device_input(
        &self,
        _slot_id: u8,
        ep0_ring: &TransferRing,
        root_port: u8,
        route: u32,
    ) -> DmaBuffer {
        let ctx_size = self.context_size as usize;
        // Input context: ICC + Slot + EP0 + EP1 IN = 4 * ctx_size.
        let total = 4 * ctx_size;
        let nframes = total.div_ceil(4096);
        let mut buf = DmaBuffer::allocate(nframes).unwrap();
        buf.as_mut_slice().fill(0);

        let base = buf.as_ptr();

        // Input Control Context (ICC) at offset 0.
        // SAFETY: the input context sits inside this controller's context DMA buffer,
        // at the offset the buffer layout fixes.
        unsafe {
            let icc = base as *mut u32;
            write_volatile(icc, 0x0); // drop flags: nothing dropped
            write_volatile(icc.add(1), 0x3); // add flags: slot + EP0
        }

        // Slot Context at offset ctx_size.
        // SAFETY: the slot context is in the same buffer, one context size on.
        unsafe {
            let sc_base = base.add(ctx_size) as *mut u32;
            // Context Entries = 1, and the route string in bits 19:0: the path
            // of hub ports from the root to this device, one nibble per tier.
            // A device on a root port has an empty route, which is why this
            // field used to be written as zero outright.
            write_volatile(sc_base, (1 << 27) | (route & 0x000F_FFFF));
            write_volatile(sc_base.add(1), (root_port as u32) << 16);
            // DWORD 2 (interrupter target) and DWORD 3 left 0.
        }

        // Endpoint 0 Control Context at offset 2*ctx_size.
        // SAFETY: the endpoint-0 context is in the same buffer, two context sizes on.
        unsafe {
            let ep0_ctrl = base.add(2 * ctx_size) as *mut u32;
            // TR Dequeue Pointer: physical address of EP0 ring | DCS=1
            let tr_dq = ep0_ring.phys_addr() | 1; // DCS=1
            write_volatile(ep0_ctrl.add(2), tr_dq as u32);
            write_volatile(ep0_ctrl.add(3), (tr_dq >> 32) as u32);
            // EP type: Control (4), Max Packet Size: 8 (initial MPS).
            let ep_type_val: u32 = 4; // Control
            let mps_val: u32 = 8;
            write_volatile(ep0_ctrl.add(1), (ep_type_val << 3) | (mps_val << 16));
            write_volatile(ep0_ctrl.add(4), 8); // Average TRB Length
        }

        buf
    }

    /// Send Address Device command (BSR=0, issues SET_ADDRESS).
    /// After this, the device is at the assigned address and EP0 is ready.
    /// Uses the EP0 ring stored in self.ep0_transfer_rings.
    ///
    /// # Safety
    ///
    /// As [`Self::alloc_slot_resources`]: the slot must be one this controller
    /// enabled, and its resources allocated.
    pub unsafe fn address_device(&mut self, slot_id: u8, root_port: u8, route: u32) -> Result<()> {
        // SAFETY: the address-device command goes through this controller's command
        // ring, with the input context above as its payload.
        unsafe {
            let idx = slot_id as usize - 1;
            if self.ep0_transfer_rings[idx].is_none() {
                return Err(crate::Error::InvalidArgument);
            }
            // SAFETY: we just checked it's Some.
            let ep0_ring = self.ep0_transfer_rings[idx].as_ref().unwrap();
            let ict = self.build_address_device_input(slot_id, ep0_ring, root_port, route);
            let ict_phys = ict.phys_addr() as u64;
            let trb = Trb::address_device(ict_phys, slot_id, false, 0);
            let evt = self.send_command(trb)?;
            let cc = evt.completion_code();
            if cc != cc::SUCCESS {
                println!(
                    "[xhci  ] address_device failed for slot {}: cc={}",
                    slot_id, cc
                );
                return Err(crate::Error::InvalidArgument);
            }
            Ok(())
        }
    }

    /// Submit a control transfer on EP0 of the given slot.
    /// Returns the number of bytes transferred (data stage length).
    ///
    /// # Safety
    ///
    /// The slot must be addressed and its EP0 ring live; `buffer` must be the
    /// transfer's own staging buffer, since the device writes into it.
    pub unsafe fn control_transfer(
        &mut self,
        slot_id: u8,
        setup: &SetupPacket,
        data_buf: &mut [u8],
        direction_in: bool,
    ) -> Result<usize> {
        // SAFETY: as the commands above — the transfer goes through this controller's
        // rings, and the slot's endpoint is one it configured.
        unsafe {
            let idx = slot_id as usize - 1;
            let ep0_ring = self.ep0_transfer_rings[idx]
                .as_mut()
                .ok_or(crate::Error::InvalidArgument)?;

            // Build the setup packet as bytes.
            let setup_bytes: &[u8; 8] = { core::mem::transmute(setup) };

            // We need a DMA buffer for data if direction is IN.
            let data_dma: Option<DmaBuffer> = if direction_in && !data_buf.is_empty() {
                let nframes = data_buf.len().div_ceil(4096);
                let buf = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
                Some(buf)
            } else {
                None
            };

            let data_phys = data_dma.as_ref().map(|b| b.phys_addr() as u64).unwrap_or(0);
            let data_len = data_buf.len() as u32;

            // Setup Stage TRB.  The 8-byte setup packet is carried in the
            // parameter field, so the IDT (Immediate Data) bit must be set —
            // QEMU 8.2.2's xhci_fire_ctl_transfer rejects the TD without it.
            // TRT (bits 17:16) tells the controller the data-stage direction;
            // QEMU instead derives it from bmRequestType.
            let trt: u32 = if data_len > 0 {
                if direction_in {
                    3
                } else {
                    2
                } // IN / OUT
            } else {
                0 // no data stage
            };

            // Append the TD to the persistent EP0 transfer ring.  The
            // controller tracks this endpoint's dequeue in its own state, so
            // clearing the ring between transfers strands a fresh TD behind a
            // dequeue pointer that has already moved on; the ring is
            // therefore written at its position, and the position carries the
            // cycle state that makes a wrapped lap readable.  The whole TD is
            // reserved in one lap first: a TD that crossed the Link TRB would
            // carry two cycle states and stop the controller between stages.
            let ring_phys = ep0_ring.phys_addr();
            let stages: u32 = 1 + u32::from(data_len > 0) + 1;
            let setup_trb = Trb {
                parameter: u64::from_le_bytes(*setup_bytes),
                status: 8, // 8 bytes to transfer
                control: trb_control(trb_type::SETUP_STAGE, 0) | TRB_IDT | (trt << 16),
            };

            // Data Stage TRB (only when there is a data stage).
            let data_trb = if data_len > 0 {
                let data_dir_flag: u32 = if direction_in { TRB_DIR_IN } else { 0 };
                Some(Trb {
                    parameter: data_phys,
                    status: data_len & TRB_TL_MASK,
                    control: trb_control(trb_type::DATA_STAGE, 0) | data_dir_flag,
                })
            } else {
                None
            };

            // Status Stage TRB (opposite direction from data).
            let status_dir: u32 = if direction_in { 0 } else { TRB_DIR_IN };
            let status_trb = Trb {
                parameter: 0,
                status: 0,
                control: trb_control(trb_type::STATUS_STAGE, 0) | status_dir | TRB_IOC,
            };

            // The transfer event names the TRB that carries Interrupt On
            // Completion, and that address is the completion's identity: the
            // status stage is the last TRB of the TD, so its slot is where
            // the position lands minus one.
            // The ring takes room for the whole TD and places its TRBs, so the
            // TD never straddles the Link TRB and never writes over a TRB the
            // controller has not read.
            ep0_ring.reserve(stages)?;
            ep0_ring.place(setup_trb);
            if let Some(data_trb) = data_trb {
                ep0_ring.place(data_trb);
            }
            ep0_ring.place(status_trb);
            // The event names the TRB carrying Interrupt On Completion, which
            // is the last of the TD — the position the pushes left behind.
            let status_trb_phys = ring_phys + (ep0_ring.pos.index - 1) as u64 * TRB_SIZE as u64;

            // Ring doorbell for EP0 of this slot: doorbell array slot
            // `slot_id` (byte offset slot_id * 4), value = target endpoint
            // DCI (1 = EP0).  QEMU decodes reg >>= 2 as the slot and
            // `val & 0xff` as the endpoint.
            {
                write_volatile(
                    self.doorbell_base.add(slot_id as usize),
                    DOORBELL_TARGET_EP0,
                );
            }

            // Poll for Transfer Event on the event ring.  The event's length
            // field is the residual (bytes not transferred) of the reporting
            // TRB, so transferred = requested - residual.
            // Wait for this TD's completion, then hand its TRBs back to the
            // ring — on either outcome, because a TD that timed out has no
            // completion left to key the release on.
            let outcome = self
                .poll_transfer_event(slot_id, DOORBELL_TARGET_EP0, status_trb_phys)
                .map_err(|_| crate::Error::TimedOut);
            if let Some(ring) = self.ep0_transfer_rings[idx].as_mut() {
                ring.release(stages);
            }
            let residual = outcome?;
            let transferred = data_len.saturating_sub(residual);

            // Copy data out if direction was IN.
            if let Some(ref dma) = data_dma {
                let src = dma.as_ptr();
                let len = data_buf.len().min(transferred as usize);
                {
                    core::ptr::copy_nonoverlapping(src, data_buf.as_mut_ptr(), len);
                }
            }

            Ok(transferred as usize)
        }
    }

    /// Poll the event ring for the Transfer Event that names `trb_phys`.
    ///
    /// A Transfer Event's parameter field is the address of the TRB that
    /// produced it, and that is the completion's identity: the slot and the
    /// endpoint say whose ring, and the address says *which* transfer.  A
    /// ring that is out of step therefore surfaces as a timeout rather than
    /// as a plausible-looking completion for a transfer that never finished.
    ///
    /// Transfer events belonging to a HID interrupt endpoint are delivered
    /// and re-armed rather than dropped, so a bulk or data transfer never
    /// steals a report from the shared event ring.
    unsafe fn poll_transfer_event(
        &mut self,
        expected_slot: u8,
        expected_dci: u32,
        trb_phys: u64,
    ) -> Result<u32> {
        // SAFETY: the event ring is this controller's, and the dequeue index is
        // advanced in step with what the device wrote.
        unsafe {
            for _ in 0..10_000_000 {
                let Some(evt) = self.peek_event() else {
                    continue;
                };
                // Advance and acknowledge — shared by all event types.
                self.advance_event_ring();

                if evt.trb_type() != trb_type::TRANSFER_EVENT {
                    continue;
                }
                if evt.slot_id() == expected_slot
                    && u32::from(evt.endpoint_id()) == expected_dci
                    && evt.parameter == trb_phys
                {
                    let cc = evt.completion_code();
                    if cc != cc::SUCCESS {
                        return Err(crate::Error::InvalidArgument);
                    }
                    // Transferred = requested - residual.
                    return Ok(evt.status & TRB_TL_MASK);
                }
                // Not ours: a HID endpoint's completed report is delivered
                // and re-armed here rather than dropped.
                self.dispatch_event(&evt);
            }
            Err(crate::Error::TimedOut)
        }
    }

    /// Read the device descriptor via control transfer on EP0.
    /// Uses the 8-byte setup packet + 18-byte data transfer.
    /// Note: For USB 3.0 ports, the device descriptor request is
    /// usually dispatched by the controller itself during Address Device
    /// when BSR=0.  This function is provided for explicit re-read.
    ///
    /// # Safety
    ///
    /// As [`Self::control_transfer`] — the request goes through this
    /// controller's rings for a slot it enabled.
    pub unsafe fn get_device_descriptor(&mut self, slot_id: u8) -> Result<UsbDeviceDescriptor> {
        // SAFETY: the descriptor request goes through this controller's rings for a
        // slot it enabled.
        unsafe {
            let setup = SetupPacket::get_descriptor_device(18);
            let mut buf = [0u8; 18];
            self.control_transfer(slot_id, &setup, &mut buf, true)?;

            // Parse the descriptor.
            let desc: UsbDeviceDescriptor = { core::ptr::read_unaligned(buf.as_ptr() as *const _) };
            Ok(desc)
        }
    }

    /// Configure a HID interrupt IN endpoint for a slot.
    /// We need the device to be addressed first.
    /// `ep_info` describes the HID interrupt IN endpoint.
    ///
    /// # Safety
    ///
    /// As [`Self::address_device`] — the slot must be addressed, and `ep_info`
    /// must describe an endpoint of that device.
    pub unsafe fn configure_hid_endpoint(
        &mut self,
        slot_id: u8,
        ep_info: HidEndpointInfo,
    ) -> Result<()> {
        // SAFETY: as above — the control transfer uses the same rings and slots.
        unsafe {
            let idx = slot_id as usize - 1;
            let dev_ctx = self.device_contexts[idx]
                .as_ref()
                .ok_or(crate::Error::InvalidArgument)?;
            let ctx_size = self.context_size as usize;
            let ep_num = (ep_info.endpoint_address & 0x0F) as usize;

            // The doorbell Device Context Index for an IN endpoint N is 2*N+1.
            let dci = 2u32 * ep_num as u32 + 1;
            let ctx_index = dci as usize;

            // Allocate interrupt transfer ring.
            let int_ring = TransferRing::allocate().ok_or(crate::Error::OutOfMemory)?;
            let int_ring_phys = int_ring.phys_addr();

            // Build an Input Context whose endpoint contexts cover the DCI of
            // the interrupt IN endpoint, mirroring configure_bulk_endpoint:
            // copy the slot + EP0 contexts out of the output context, flag
            // every context index 0..=ctx_index as "add", and program the
            // interrupt endpoint context at its DCI offset.
            let n_contexts = (ctx_index + 1).max(2);
            let total_input = (n_contexts + 1) * ctx_size;
            let nframes = total_input.div_ceil(4096);
            let mut ict = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            ict.as_mut_slice().fill(0);
            let ict_base = ict.as_ptr();

            // ICC: Drop flags = 0 (nothing dropped), Add flags = the slot
            // context (bit 0) plus this endpoint (bit ctx_index).  QEMU's
            // xhci_configure_slot validates `ictl_ctx[0] & 0x3 == 0` and
            // `ictl_ctx[1] & 0x3 == 0x1`, so the add word must set bit 0 and
            // must NOT set bit 1 (EP0).
            {
                let icc = ict_base as *mut u32;
                write_volatile(icc, 0);
                write_volatile(icc.add(1), 0x1 | (1 << ctx_index));
            }

            // Copy slot + EP0 contexts from the output device context.
            let out_ctx_base = dev_ctx.as_ptr();
            {
                core::ptr::copy_nonoverlapping(out_ctx_base, ict_base.add(ctx_size), ctx_size * 2);
            }

            // Interrupt IN endpoint context at the DCI offset.
            let ep_offset = (ctx_index + 1) * ctx_size;
            {
                let ep_ctx = ict_base.add(ep_offset) as *mut u32;
                // Interval at bits 23:16 (QEMU: interval = 1 << (ctx[0]>>16 &
                // 0xff)), encoded from the descriptor's own period rather
                // than copied from it; EP state stays 0 (disabled) until the
                // command runs.
                write_volatile(ep_ctx, endpoint_interval_field(ep_info.interval) << 16);
                // EP type at bits 5:3 (7 = interrupt IN), Max Packet Size at
                // bits 23:16 of DWORD 1.
                let ep_ctrl: u32 = (7 << 3) | ((ep_info.max_packet_size as u32 & 0xFFFF) << 16);
                write_volatile(ep_ctx.add(1), ep_ctrl);

                // TR Dequeue Pointer.
                let tr_dq = int_ring_phys | 1; // DCS=1
                write_volatile(ep_ctx.add(2), tr_dq as u32);
                write_volatile(ep_ctx.add(3), (tr_dq >> 32) as u32);

                // Average TRB Length = the boot-protocol report size.
                write_volatile(ep_ctx.add(4), ep_info.report_len as u32);
            }

            let ict_phys = ict.phys_addr() as u64;
            let trb = Trb::configure_endpoint(ict_phys, slot_id, 0);
            let evt = self.send_command(trb)?;
            let cc = evt.completion_code();
            if cc != cc::SUCCESS {
                println!(
                    "[xhci  ] configure_endpoint failed for slot {}: cc={}",
                    slot_id, cc
                );
                return Err(crate::Error::InvalidArgument);
            }

            self.int_transfer_rings[idx] = Some(int_ring);
            println!(
                "[xhci  ] HID interrupt endpoint configured: slot={} ep_addr={:#04x} mps={} dci={}",
                slot_id, ep_info.endpoint_address, ep_info.max_packet_size, dci
            );
            Ok(())
        }
    }

    /// Read the full configuration descriptor for a slot: the 9-byte
    /// header for `wTotalLength`, then the whole blob.
    unsafe fn read_config_descriptor(&mut self, slot_id: u8) -> crate::Result<alloc::vec::Vec<u8>> {
        // SAFETY: as above — reading the configuration descriptor reuses the control
        // transfer path.
        unsafe {
            let mut header_buf = [0u8; 9];
            let setup9 = SetupPacket::get_descriptor_configuration(9);
            self.control_transfer(slot_id, &setup9, &mut header_buf, true)?;
            let total_len = u16::from_le_bytes([header_buf[2], header_buf[3]]) as usize;
            if !(9..=4096).contains(&total_len) {
                println!("[xhci  ] invalid config descriptor length {}", total_len);
                return Err(crate::Error::InvalidArgument);
            }

            let mut config_buf = alloc::vec![0u8; total_len];
            let setup_full = SetupPacket::get_descriptor_configuration(total_len as u16);
            let n = self.control_transfer(slot_id, &setup_full, &mut config_buf, true)?;
            println!(
                "[xhci  ] slot {} config len={} got={} bytes={:02x?}",
                slot_id,
                total_len,
                n,
                &config_buf[..]
            );
            Ok(config_buf)
        }
    }

    /// Probe a mass storage device at the given slot: read config
    /// descriptor, find bulk endpoints, configure them, and
    /// initialise the MSC driver.
    ///
    /// # Safety
    ///
    /// As above — the controller is the one whose slot was just addressed, and
    /// it registers the endpoints it finds with the global MSD registry.
    pub unsafe fn init_msd(&mut self, slot_id: u8) -> crate::Result<()> {
        // SAFETY: the MSD initialisation talks to the same controller whose slot was
        // just addressed.
        unsafe {
            use crate::drivers::usb_msd::MsdBulkEndpoints;
            use crate::drivers::usb_msd::USB_CLASS_MSC;
            use crate::drivers::usb_msd::USB_PROTOCOL_BOT;
            use crate::drivers::usb_msd::USB_SUBCLASS_SCSI;
            use crate::drivers::usb_msd::{self};

            let config_buf = self.read_config_descriptor(slot_id)?;

            // Parse configuration descriptor to find MSD interface bulk endpoints.
            // USB descriptor types: 2=CONFIGURATION, 4=INTERFACE, 5=ENDPOINT
            let mut ep_in_addr = 0u8;
            let mut ep_out_addr = 0u8;
            let mut mps = 512u16;
            let mut config_val = 0u8;
            let mut found = false;

            let mut i = 0usize;
            while i + 1 < config_buf.len() {
                let dlen = config_buf[i] as usize;
                if dlen < 2 {
                    break;
                }
                let dtype = config_buf[i + 1];
                if dtype == 2 && i + 3 < config_buf.len() {
                    // CONFIGURATION descriptor: bConfigurationValue at offset 3
                    config_val = config_buf[i + 3];
                } else if dtype == 4 && i + 7 < config_buf.len() {
                    // INTERFACE descriptor
                    let if_class = config_buf[i + 5];
                    let if_sub = config_buf[i + 6];
                    let if_proto = config_buf[i + 7];
                    let num_eps = config_buf[i + 4];
                    if (if_class == USB_CLASS_MSC
                        && if_sub == USB_SUBCLASS_SCSI
                        && if_proto == USB_PROTOCOL_BOT)
                        || (if_class == USB_CLASS_MSC && num_eps >= 2)
                    {
                        // Scan this interface's endpoints.  Walk forward past
                        // interleaved non-endpoint descriptors (QEMU's
                        // usb-storage places a vendor 0x30 descriptor between
                        // the bulk IN and OUT endpoints), stopping after
                        // `num_eps` endpoints or at the next interface/config
                        // boundary.
                        let mut pos = i + dlen;
                        let mut eps_seen = 0usize;
                        while eps_seen < num_eps as usize && pos + 6 < config_buf.len() {
                            let dtype = config_buf[pos + 1];
                            if dtype == 5 {
                                // ENDPOINT descriptor
                                let ea = config_buf[pos + 2];
                                let attr = config_buf[pos + 3];
                                let psz =
                                    u16::from_le_bytes([config_buf[pos + 4], config_buf[pos + 5]]);
                                if attr & 3 == 2 {
                                    // bulk transfer
                                    if (ea & 0x80) != 0 {
                                        ep_in_addr = ea;
                                    } else {
                                        ep_out_addr = ea;
                                    }
                                    mps = psz;
                                }
                                eps_seen += 1;
                            } else if dtype == 4 || dtype == 2 {
                                // Next interface/configuration descriptor.
                                break;
                            }
                            pos += config_buf[pos] as usize;
                        }
                        if ep_in_addr != 0 && ep_out_addr != 0 {
                            found = true;
                        }
                        break;
                    }
                }
                i += dlen;
            }

            if !found {
                println!("[xhci  ] msd: no bulk endpoints at slot {}", slot_id);
                return Err(crate::Error::NotFound);
            }

            // Configure bulk endpoints.
            self.configure_bulk_endpoint(slot_id, ep_out_addr, mps, false)?;
            self.configure_bulk_endpoint(slot_id, ep_in_addr, mps, true)?;

            // Set configuration.
            let setup_cfg = SetupPacket::set_configuration(config_val);
            let mut dummy = [];
            self.control_transfer(slot_id, &setup_cfg, &mut dummy, false)?;

            // Register with the MSD driver.
            self.msd_slot = slot_id;
            let endpoints = MsdBulkEndpoints {
                slot_id,
                ep_out_addr,
                ep_in_addr,
                max_packet_size: mps,
            };
            self.msd_endpoints = Some(endpoints);
            // Registration only: the SCSI geometry probe is deferred until
            // the controller is published to the global registry, because
            // bot_transfer reaches it through `with_controller`.
            usb_msd::register_msd(endpoints);
            Ok(())
        }
    }

    /// Configure a bulk endpoint for a USB device (second part).
    /// `direction_in`: true for IN, false for OUT.
    ///
    /// # Safety
    ///
    /// As above — the endpoint belongs to a slot this controller configured.
    pub unsafe fn configure_bulk_endpoint(
        &mut self,
        slot_id: u8,
        ep_addr: u8,
        max_packet_size: u16,
        direction_in: bool,
    ) -> Result<()> {
        // SAFETY: as above — the transfer targets an endpoint of a slot this controller
        // configured.
        unsafe {
            let idx = slot_id as usize - 1;
            let dev_ctx = self.device_contexts[idx]
                .as_ref()
                .ok_or(crate::Error::InvalidArgument)?;
            let ctx_size = self.context_size as usize;
            let ep_num = (ep_addr & 0x0F) as usize;

            let bulk_ring = TransferRing::allocate().ok_or(crate::Error::OutOfMemory)?;
            let bulk_ring_phys = bulk_ring.phys_addr();

            let dci = if direction_in {
                2u32 * ep_num as u32 + 1
            } else {
                2u32 * ep_num as u32
            };
            let ctx_index = dci as usize;
            let n_contexts = (ctx_index + 1).max(2);
            let total_input = (n_contexts + 1) * ctx_size;
            let nframes = total_input.div_ceil(4096);
            let mut ict = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            ict.as_mut_slice().fill(0);
            let ict_base = ict.as_ptr();

            // ICC: Drop flags = 0 (nothing dropped), Add flags = the slot
            // context (bit 0) plus this endpoint (bit ctx_index).  Same
            // QEMU validation as configure_hid_endpoint.
            {
                let icc = ict_base as *mut u32;
                write_volatile(icc, 0);
                write_volatile(icc.add(1), 0x1 | (1 << ctx_index));
            }

            // Copy slot + EP0 contexts from output.
            let out_ctx_base = dev_ctx.as_ptr();
            {
                core::ptr::copy_nonoverlapping(out_ctx_base, ict_base.add(ctx_size), ctx_size * 2);
            }

            // Set up the bulk endpoint context at the correct DCI offset.
            let ep_offset = (ctx_index + 1) * ctx_size;
            {
                let ep_ctx = ict_base.add(ep_offset) as *mut u32;
                write_volatile(ep_ctx, 0);
                // EP type at bits 5:3 (6 = bulk IN, 2 = bulk OUT), Max Packet
                // Size at bits 23:16 of DWORD 1.
                let ep_type: u32 = if direction_in { 6 } else { 2 };
                let ep_ctrl: u32 = (ep_type << 3) | ((max_packet_size as u32 & 0xFFFF) << 16);
                write_volatile(ep_ctx.add(1), ep_ctrl);
                let tr_dq = bulk_ring_phys | 1; // DCS=1
                write_volatile(ep_ctx.add(2), tr_dq as u32);
                write_volatile(ep_ctx.add(3), (tr_dq >> 32) as u32);
                write_volatile(ep_ctx.add(4), max_packet_size as u32);
            }

            let ict_phys = ict.phys_addr() as u64;
            let trb = Trb::configure_endpoint(ict_phys, slot_id, 0);
            let evt = self.send_command(trb)?;
            let cc = evt.completion_code();
            if cc != cc::SUCCESS {
                println!(
                    "[xhci  ] configure_bulk_endpoint failed slot={} ep={:#04x} cc={}",
                    slot_id, ep_addr, cc
                );
                return Err(crate::Error::InvalidArgument);
            }

            if direction_in {
                self.bulk_in_rings[idx] = Some(bulk_ring);
            } else {
                self.bulk_out_rings[idx] = Some(bulk_ring);
            }
            println!(
                "[xhci  ] bulk {} endpoint configured: slot={} ep={:#04x} mps={}",
                if direction_in { "IN" } else { "OUT" },
                slot_id,
                ep_addr,
                max_packet_size
            );
            Ok(())
        }
    }

    /// Submit a Normal TRB on a bulk ring and wait for completion.
    unsafe fn submit_bulk_trb(
        &mut self,
        slot_id: u8,
        ep_addr: u8,
        data_phys: u64,
        length: u32,
        direction_in: bool,
    ) -> Result<()> {
        // SAFETY: as above.
        unsafe {
            let idx = slot_id as usize - 1;
            let ep_num = (ep_addr & 0x0F) as usize;
            let dci = if direction_in {
                2u32 * ep_num as u32 + 1
            } else {
                2u32 * ep_num as u32
            };

            // Pick the ring and its producer index for this direction.  Like
            // EP0, each bulk ring is persistent: QEMU's dequeue advances past
            // every consumed NORMAL TRB (a one-TRB TD, terminated at the IOC
            // TRB), so we append at the next position rather than rebuilding
            // at slot 0 — otherwise the second transfer on the same ring is
            // stranded behind a dequeue pointer that has already moved on.
            let ring = if direction_in {
                self.bulk_in_rings[idx]
                    .as_mut()
                    .ok_or(crate::Error::InvalidArgument)?
            } else {
                self.bulk_out_rings[idx]
                    .as_mut()
                    .ok_or(crate::Error::InvalidArgument)?
            };

            let trb_flags = if direction_in { TRB_DIR_IN } else { 0 };
            let normal_trb = Trb {
                parameter: data_phys,
                status: length & TRB_TL_MASK,
                control: trb_control(trb_type::NORMAL, 0) | TRB_IOC | trb_flags,
            };
            // The ring owns its segment, and the position keeps the write
            // inside it.
            ring.push(normal_trb)?;
            // The event names the TRB that carries Interrupt On Completion,
            // which is the one just placed — *after* any wrap, so its address
            // is read from the position the push left behind.
            let trb_phys = ring.phys_addr() + (ring.pos.index - 1) as u64 * TRB_SIZE as u64;

            // Ring doorbell: doorbell array slot `slot_id`, value = target
            // endpoint DCI.
            write_volatile(self.doorbell_base.add(slot_id as usize), dci);

            // Poll for transfer event, and hand the TRB back either way: a TD
            // that timed out has no completion left to key the release on.
            let outcome = self.poll_transfer_event(slot_id, dci, trb_phys);
            if let Some(ring) = using_in_ring(self, idx, direction_in) {
                ring.release(1);
            }
            outcome?;
            Ok(())
        }
    }

    /// Send data on a bulk OUT endpoint.
    ///
    /// # Safety
    ///
    /// The controller must have a mass-storage slot configured, and `ep_addr`
    /// must name one of its bulk OUT endpoints; `data` is copied into the
    /// controller's own transfer buffer and not retained.
    pub unsafe fn bulk_send(&mut self, ep_addr: u8, data: &[u8]) -> Result<()> {
        // SAFETY: the bulk endpoint belongs to a slot this controller configured, and
        // the data is a caller slice it does not retain.
        unsafe {
            let slot_id = if self.msd_slot != 0 {
                self.msd_slot
            } else {
                return Err(crate::Error::InvalidArgument);
            };
            let nframes = data.len().div_ceil(4096);
            let buf = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            let phys = buf.phys_addr() as u64;
            {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buf.as_ptr(), data.len());
            }
            self.submit_bulk_trb(slot_id, ep_addr, phys, data.len() as u32, false)?;
            Ok(())
        }
    }

    /// Receive data on a bulk IN endpoint.
    ///
    /// # Safety
    ///
    /// As [`Self::bulk_send`] — the endpoint belongs to a slot this controller
    /// configured, and `buffer` is the caller's own staging space, which the
    /// device writes into.
    pub unsafe fn bulk_recv(&mut self, ep_addr: u8, buffer: &mut [u8]) -> Result<()> {
        // SAFETY: as `bulk_send` — the receive buffer is the caller's and outlives the
        // transfer.
        unsafe {
            let slot_id = if self.msd_slot != 0 {
                self.msd_slot
            } else {
                return Err(crate::Error::InvalidArgument);
            };
            let nframes = buffer.len().div_ceil(4096);
            let buf = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            let phys = buf.phys_addr() as u64;
            self.submit_bulk_trb(slot_id, ep_addr, phys, buffer.len() as u32, true)?;
            {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), buffer.as_mut_ptr(), buffer.len());
            }
            Ok(())
        }
    }

    /// Arm a non-blocking interrupt-IN read on a HID endpoint.
    ///
    /// Posts a Normal TRB on the slot's interrupt transfer ring and rings
    /// the doorbell, then returns immediately.  The completed report is
    /// drained from the per-device DMA buffer by
    /// [`dispatch_interrupt_transfer_event`] when its Transfer Event
    /// shows up on the event ring.
    unsafe fn arm_hid_read(
        &mut self,
        slot_id: u8,
        dci: u32,
        report_len: usize,
        data_phys: u64,
    ) -> Result<()> {
        // SAFETY: as above.
        unsafe {
            let idx = slot_id as usize - 1;
            let int_ring = self.int_transfer_rings[idx]
                .as_mut()
                .ok_or(crate::Error::InvalidArgument)?;

            // Append the Normal TRB at the ring's next position.  The interrupt
            // ring is persistent and re-armed after every completed report, so
            // rebuilding at slot 0 would strand each re-arm behind the
            // controller's dequeue pointer (which advances past the consumed
            // one-TRB TD).  The position carries the cycle state across a wrap.
            let normal_trb = Trb {
                parameter: data_phys,
                status: (report_len as u32) & TRB_TL_MASK,
                control: trb_control(trb_type::NORMAL, 0) | TRB_IOC,
            };
            // The ring owns its segment, and the position keeps the write
            // inside it.  A ring with no room is a ring whose earlier reads
            // have not completed, which the caller hears as `Busy`.
            int_ring.push(normal_trb)?;

            // Ring the doorbell for the endpoint's DCI.
            // Ring doorbell: doorbell array slot `slot_id`, value = target
            // endpoint DCI.
            write_volatile(self.doorbell_base.add(slot_id as usize), dci);
            Ok(())
        }
    }

    /// Re-arm an interrupt endpoint after a report, giving the report's TRB
    /// back to its ring's room first.
    ///
    /// # Safety
    ///
    /// As [`Self::arm_hid_read`] — the endpoint is one this controller
    /// configured, and a read of its just completed.
    unsafe fn rearm_hid_read(
        &mut self,
        slot_id: u8,
        dci: u32,
        report_len: usize,
        data_phys: u64,
    ) -> Result<()> {
        // SAFETY: the ring belongs to the slot this controller addressed.
        unsafe {
            let idx = slot_id as usize - 1;
            if let Some(ring) = self.int_transfer_rings[idx].as_mut() {
                ring.release(1);
            }
            self.arm_hid_read(slot_id, dci, report_len, data_phys)
        }
    }

    /// Deliver a completed keyboard report and re-arm the next read.
    unsafe fn deliver_keyboard_report(&mut self, residual: u32) {
        // SAFETY: the report came from this controller's event ring and is delivered to
        // the arch-neutral keyboard layer.
        unsafe {
            if let Some(ep) = self.keyboard_ep {
                if let Some(buf) = self.keyboard_report_buf.as_ref() {
                    let transferred = ep.report_len.saturating_sub(residual as usize);
                    let mut report = [0u8; 8];
                    let len = core::cmp::min(transferred, 8);
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), report.as_mut_ptr(), len);
                    crate::drivers::usb_hid::handle_keyboard_report(&report);
                }
                if let Some(buf) = self.keyboard_report_buf.as_ref() {
                    let _ = self.rearm_hid_read(
                        self.keyboard_slot,
                        ep.dci(),
                        ep.report_len,
                        buf.phys_addr() as u64,
                    );
                }
            }
        }
    }

    /// Deliver a completed mouse report and re-arm the next read.
    unsafe fn deliver_mouse_report(&mut self, residual: u32) {
        // SAFETY: as above, for the mouse.
        unsafe {
            if let Some(ep) = self.mouse_ep {
                if let Some(buf) = self.mouse_report_buf.as_ref() {
                    let transferred = ep.report_len.saturating_sub(residual as usize);
                    let mut report = [0u8; crate::drivers::mouse::MOUSE_REPORT_LEN];
                    let len = core::cmp::min(transferred, report.len());
                    core::ptr::copy_nonoverlapping(buf.as_ptr(), report.as_mut_ptr(), len);
                    crate::drivers::usb_hid::handle_mouse_report(&report[..len]);
                }
                if let Some(buf) = self.mouse_report_buf.as_ref() {
                    let _ = self.rearm_hid_read(
                        self.mouse_slot,
                        ep.dci(),
                        ep.report_len,
                        buf.phys_addr() as u64,
                    );
                }
            }
        }
    }

    /// Act on a root port whose status changed.
    ///
    /// The event names only the port; the port's own register says what
    /// happened to it, and the two cases are a device that arrived and a
    /// device that left.  An arriving device is enumerated where it stands; a
    /// departing one takes its whole subtree with it, because everything
    /// behind a hub is behind the hub's port.
    ///
    /// The change bits are cleared last, and that is not tidiness: the
    /// controller raises this event on the 0→1 transition of a change bit, so
    /// a port whose bits are left set says nothing the next time a device is
    /// plugged into or pulled from it.
    ///
    /// # Safety
    ///
    /// As [`Self::peek_event`] — the port is one of this controller's root
    /// ports, and every request made for it goes through this controller's own
    /// rings.
    unsafe fn handle_port_status_change(&mut self, port: u8) {
        // SAFETY: the port register belongs to this controller and `port` is
        // bounded against its own port count.
        unsafe {
            if port == 0 || port > self.max_ports {
                return;
            }
            let offset = XHCI_OP_PORTSC + (port as usize - 1) * 0x10;
            let portsc = reg_read32(self.op_base, offset);

            if portsc & PORTSC_CSC != 0 {
                if portsc & PORTSC_CCS != 0 {
                    // Nothing may already answer for this port: a second
                    // enumeration of the same device would take a second slot
                    // for it.
                    if self.slot_for_route(port, 0).is_none() && self.enumerate_port(port) {
                        println!("[xhci  ] enumerated port {}", port);
                    }
                } else if let Some(slot) = self.slot_for_route(port, 0) {
                    println!("[xhci  ] port {}: device removed (slot {})", port, slot);
                    let released = self.release_subtree(port, 0);
                    println!("[xhci  ] port {}: {} slot(s) released", port, released);
                }
            }

            // W1C.  Writing the register's own value back with the change bits
            // set clears exactly those bits and leaves every other field as it
            // was read.
            reg_write32(self.op_base, offset, portsc | PORTSC_CHANGE_BITS);
        }
    }

    /// Clear every root port's change bits once the boot's scan has handled
    /// them.
    ///
    /// A device that was already plugged in when the controller started has
    /// its connect change bit set and no event posted for it (the controller
    /// does not post events before it is running), so those bits have to be
    /// cleared here or the *first* hotplug after the boot on that port would
    /// be a transition the controller never sees.
    ///
    /// # Safety
    ///
    /// As [`Self::handle_port_status_change`].
    unsafe fn sync_root_port_changes(&mut self) {
        for port in 1..=self.max_ports {
            let offset = XHCI_OP_PORTSC + (port as usize - 1) * 0x10;
            // SAFETY: each of these registers belongs to this controller.
            unsafe {
                let portsc = reg_read32(self.op_base, offset);
                if portsc & PORTSC_CHANGE_BITS != 0 {
                    reg_write32(self.op_base, offset, portsc | PORTSC_CHANGE_BITS);
                }
            }
        }
    }

    /// Dispatch one event from the event ring to what it belongs to.
    ///
    /// Called from the drain ([`poll_events`]) and from
    /// [`poll_transfer_event`] for events that are not the one being awaited,
    /// so an event arriving under a transfer's own wait is not lost.
    ///
    /// What it does *not* do is the work: a hub's report and a root port's
    /// change both lead to further requests, and those go out on the same
    /// rings as the transfer that just completed — one ring, one TD in
    /// flight, which a nested submission would break.  So both are recorded,
    /// and [`Self::service_pending`] runs them once the drain has the
    /// controller to itself.  Delivering a HID report *is* done here, because
    /// it only reads its own buffer and re-arms its own endpoint's ring.
    ///
    /// # Safety
    ///
    /// As [`Self::peek_event`] — the event is one this controller's event ring
    /// produced.
    unsafe fn dispatch_event(&mut self, evt: &Trb) {
        // SAFETY: the event is one this controller's event ring produced, and
        // what it is dispatched to belongs to this controller.
        unsafe {
            match evt.trb_type() {
                trb_type::TRANSFER_EVENT => self.dispatch_interrupt_transfer_event(evt),
                trb_type::PORT_STATUS_CHANGE_EVENT => self.port_change_pending = true,
                _ => {}
            }
        }
    }

    /// Do the work the drained events asked for, with the controller to
    /// itself.
    ///
    /// Called from [`poll_events`] once the event ring is empty.  Nothing is
    /// in flight here — every transfer path waits for its completion, and the
    /// drain holds the controller's lock — so this is the only place a report
    /// may be answered with requests of its own.
    ///
    /// # Safety
    ///
    /// The controller must own its rings, and this must not be called from
    /// under a transfer's wait.
    unsafe fn service_pending(&mut self) {
        // SAFETY: this runs from the drain, which holds the controller's lock
        // and has no transfer outstanding.
        unsafe {
            for index in 0..self.hubs.len() {
                if let Some(residual) = self.hubs[index].pending.take() {
                    let slot_id = self.hubs[index].slot_id;
                    self.handle_hub_status_change(slot_id, residual);
                }
            }
            if self.port_change_pending {
                self.port_change_pending = false;
                self.service_root_port_changes();
            }
        }
    }

    /// Read every root port's status and act on the ones that changed.
    ///
    /// The event names one port, but the ports are re-read as a set: a port
    /// whose change bit is set is a port whose device arrived or left, and
    /// looking at all of them is what makes an event that was missed or
    /// coalesced harmless.
    ///
    /// # Safety
    ///
    /// As [`Self::handle_port_status_change`].
    unsafe fn service_root_port_changes(&mut self) {
        for port in 1..=self.max_ports {
            // SAFETY: each port register belongs to this controller.
            unsafe {
                let offset = XHCI_OP_PORTSC + (port as usize - 1) * 0x10;
                let portsc = reg_read32(self.op_base, offset);
                if portsc & PORTSC_CSC == 0 && portsc & PORTSC_CHANGE_BITS == 0 {
                    continue;
                }
                self.handle_port_status_change(port);
            }
        }
    }

    /// Dispatch an interrupt Transfer Event to the device it belongs to: a HID
    /// keyboard or mouse, or a hub reporting a port change.
    ///
    /// The event is identified by (slot ID, DCI); unknown slots are
    /// ignored.
    unsafe fn dispatch_interrupt_transfer_event(&mut self, evt: &Trb) {
        // SAFETY: the event is one this controller's event ring produced; the dispatch
        // only reads it.
        unsafe {
            let slot = evt.slot_id();
            let dci = evt.endpoint_id();
            let residual = evt.status & TRB_TL_MASK;
            if slot != 0 {
                if let Some(index) = self.hub_index(slot) {
                    if u32::from(dci) == self.hubs[index].ep.dci() {
                        // Recorded, not run: a report is answered with requests.
                        self.hubs[index].pending = Some(residual);
                        return;
                    }
                }
            }
            if slot == self.keyboard_slot {
                if let Some(ep) = self.keyboard_ep {
                    if u32::from(dci) == ep.dci() {
                        self.deliver_keyboard_report(residual);
                        return;
                    }
                }
            }
            if slot == self.mouse_slot {
                if let Some(ep) = self.mouse_ep {
                    if u32::from(dci) == ep.dci() {
                        self.deliver_mouse_report(residual);
                    }
                }
            }
        }
    }

    /// Poll the event ring for any pending events.
    /// Called from the timer tick to check for HID reports and hub port
    /// changes.
    /// Returns true if a transfer event was processed.
    ///
    /// # Safety
    ///
    /// The controller must be the one `new` returned with its BAR still mapped;
    /// the poll touches that controller's own event ring and doorbells.
    pub unsafe fn poll_events(&mut self) -> bool {
        // SAFETY: polling touches this controller's own event ring and doorbells.
        unsafe {
            // Drain what the controller has posted.  `peek_event` reads the
            // consumer's own slot, and every consumed event moves the consumer
            // on, so the loop ends when that slot belongs to the previous lap
            // again.  The drain is unconditional: a root port's status change
            // is an event a machine with no device at all still has to see.
            let mut processed = false;
            while let Some(evt) = self.peek_event() {
                self.advance_event_ring();
                if evt.trb_type() == trb_type::TRANSFER_EVENT
                    || evt.trb_type() == trb_type::PORT_STATUS_CHANGE_EVENT
                {
                    processed = true;
                    self.dispatch_event(&evt);
                }
            }

            // Now that nothing is in flight, do what the events asked for.
            self.service_pending();

            // Acknowledge the interrupter once the ring is drained, so the next
            // event is again a 0→1 transition the controller will raise a
            // message for.  The handler does this too, for the case where it
            // could not take the rings; doing it here as well is what keeps the
            // messages coming when the drain happens on the tick.
            self.acknowledge_interrupt();

            processed
        }
    }

    /// Clear the interrupter's pending bit, leaving it enabled.
    fn acknowledge_interrupt(&self) {
        // SAFETY: the runtime window belongs to this controller, and the
        // interrupter's management register is one of its own.
        unsafe {
            let iman = reg_read32(self.runtime_base, XHCI_RT_IR_BASE + XHCI_RT_IMAN);
            reg_write32(
                self.runtime_base,
                XHCI_RT_IR_BASE + XHCI_RT_IMAN,
                iman | IMAN_IE | IMAN_IP,
            );
        }
    }

    /// Enumerate a device on a root hub port: wait for connection, enable
    /// a slot, address the device, and classify it (HID vs MSC).
    /// Returns true if a device was configured.
    pub(crate) unsafe fn enumerate_port(&mut self, port: u8) -> bool {
        // SAFETY: the port belongs to this controller's root hub (the loop that calls
        // this stays inside `max_ports`).
        unsafe {
            let portsc_offset = XHCI_OP_PORTSC + (port as usize - 1) * 0x10;

            // Wait briefly for the connection to stabilise (CCS set).
            let mut connected = false;
            for _ in 0..PORT_CONNECT_SETTLE_SPINS {
                if reg_read32(self.op_base, portsc_offset) & PORTSC_CCS != 0 {
                    connected = true;
                    break;
                }
            }
            if !connected {
                return false;
            }
            // A device at the root sits at route string 0: no hub is in the
            // path, which is what the descriptor's own route nibbles say.
            self.enumerate_device(port, 0)
        }
    }

    /// Enable, address and classify the device that `route` names under
    /// `root_port`.
    ///
    /// The route string is the xHCI way of saying "behind which hub ports": one
    /// nibble per tier, the first tier in the low nibble.  A device plugged
    /// straight into a root port has an empty route; one behind a hub's port 1
    /// has `0x1`, and one behind a second hub at that hub's port 2 has `0x21`.
    /// The controller reads it out of the Slot Context to find which USB port
    /// the device is on, so a device whose route is wrong is never found — the
    /// failure is `CC_TRB_ERROR` from Address Device, not a wrong device.
    pub(crate) unsafe fn enumerate_device(&mut self, root_port: u8, route: u32) -> bool {
        // SAFETY: as `enumerate_port` — the slot this enables and addresses is
        // this controller's, and the route only says where in its own tree the
        // device hangs.
        unsafe {
            let slot_id = match self.enable_slot(root_port) {
                Ok(s) => s,
                Err(_) => {
                    println!("[xhci  ] enable_slot failed for route {:#x}", route);
                    return false;
                }
            };
            println!(
                "[xhci  ] enabled slot {} (root port {}, route {:#x})",
                slot_id, root_port, route
            );

            if self.alloc_slot_resources(slot_id).is_err() {
                println!("[xhci  ] failed to allocate slot resources");
                return false;
            }
            if self.address_device(slot_id, root_port, route).is_err() {
                println!(
                    "[xhci  ] address_device failed for slot {} (route {:#x})",
                    slot_id, route
                );
                return false;
            }
            // Remember where this slot's device hangs: a hub reports its
            // ports, not its children's slot numbers, so the route is how a
            // device that left is found again to have its slot released.
            self.slot_routes[slot_id as usize - 1] = (root_port, route);
            println!("[xhci  ] device addressed at slot {}", slot_id);

            match self.get_device_descriptor(slot_id) {
                Ok(desc) => self.configure_slot_device(slot_id, desc, root_port, route),
                Err(e) => {
                    println!("[xhci  ] get_device_descriptor failed: {}", e.as_str());
                    false
                }
            }
        }
    }

    /// Read a hub's port count, watch its status-change endpoint, and bring up
    /// whatever its ports already hold.
    ///
    /// A hub needs one class request — how many ports it has — and then one
    /// pass per port: power it, see whether anything is connected, reset it,
    /// and address what appears behind it.  The addressing is the interesting
    /// part: that device is a *tier* deeper, so its route string gains this
    /// port's nibble, and the controller walks exactly those nibbles to find
    /// which USB port the device hangs off.  Nothing else about the child
    /// differs, so the work is the same [`Self::enumerate_device`] a root port
    /// runs, one tier down.
    ///
    /// The pass is only half of a hub.  The other half is its interrupt IN
    /// endpoint, which the hub asserts whenever one of its ports changes: a
    /// hub that is scanned once is a hub only for devices that were already
    /// plugged in.  That endpoint is configured here — the same way a HID
    /// device's is, because it is the same kind of endpoint — armed with the
    /// first read, and its reports are run by
    /// [`Self::handle_hub_status_change`], so a device plugged in later is
    /// enumerated then rather than at the next boot.
    ///
    /// # Safety
    ///
    /// `slot_id` must be an addressed hub on this controller, and `root_port`
    /// and `route` must be where that hub itself was found.
    unsafe fn configure_hub(&mut self, slot_id: u8, root_port: u8, route: u32) {
        // SAFETY: the hub is a device on a slot this controller addressed, and
        // every request goes out through this controller's own EP0 ring.
        unsafe {
            let mut descriptor = [0u8; 8];
            if self
                .control_transfer(
                    slot_id,
                    &SetupPacket::hub_descriptor(descriptor.len() as u16),
                    &mut descriptor,
                    true,
                )
                .is_err()
            {
                println!("[xhci  ] hub at slot {}: no hub descriptor", slot_id);
                return;
            }
            // bNbrPorts is the third byte of the hub descriptor.
            let ports = descriptor[2];
            println!(
                "[xhci  ] hub at slot {}: {} downstream port(s), route {:#x}",
                slot_id, ports, route
            );

            // The status-change endpoint comes first, so the changes this pass
            // produces already have somewhere to be reported.
            if let Some(state) = self.configure_hub_endpoint(slot_id, root_port, route, ports) {
                self.hubs.push(state);
            }

            self.scan_hub_ports(slot_id, root_port, route, ports);
        }
    }

    /// Configure and arm a hub's status-change endpoint.
    ///
    /// Returns the hub's watch state, or `None` when the hub has no interrupt
    /// IN endpoint to watch — in which case the port pass below still runs and
    /// the hub is simply a hub that has to be rescanned at boot, as it was
    /// before this existed.
    ///
    /// # Safety
    ///
    /// As [`Self::configure_hub`].
    unsafe fn configure_hub_endpoint(
        &mut self,
        slot_id: u8,
        root_port: u8,
        route: u32,
        ports: u8,
    ) -> Option<HubState> {
        use crate::drivers::usb_hid;

        // SAFETY: the hub is on a slot this controller addressed; the
        // configuration read and the endpoint configure both go out through
        // this controller's own rings.
        unsafe {
            let config = match self.read_config_descriptor(slot_id) {
                Ok(config) => config,
                Err(_) => {
                    println!(
                        "[xhci  ] hub at slot {}: no configuration descriptor",
                        slot_id
                    );
                    return None;
                }
            };
            let endpoint = usb_hid::interface_interrupt_in(&config, USB_CLASS_HUB)?;
            // The report is a bitmap, one bit per port plus the hub's own bit,
            // so its length is what the endpoint's max packet size covers.
            let report_len = core::cmp::max(1, endpoint.max_packet_size) as usize;
            let ep = HidEndpointInfo {
                endpoint_address: endpoint.endpoint_address,
                max_packet_size: endpoint.max_packet_size,
                interval: endpoint.interval,
                interface_number: endpoint.interface_number,
                report_len,
            };
            if self.configure_hid_endpoint(slot_id, ep).is_err() {
                println!(
                    "[xhci  ] hub at slot {}: status-change endpoint refused",
                    slot_id
                );
                return None;
            }
            // An endpoint only answers once its device is in the configured
            // state.
            let mut dummy = [];
            let _ = self.control_transfer(
                slot_id,
                &SetupPacket::set_configuration(config[5]),
                &mut dummy,
                false,
            );

            let report_buf = DmaBuffer::allocate(1)?;
            let state = HubState {
                slot_id,
                root_port,
                route,
                ports,
                ep,
                report_buf,
                pending: None,
            };
            self.arm_hid_read(
                slot_id,
                ep.dci(),
                ep.report_len,
                state.report_buf.phys_addr() as u64,
            )
            .ok()?;
            println!(
                "[xhci  ] hub at slot {}: status-change endpoint watching {} port(s)",
                slot_id, ports
            );
            Some(state)
        }
    }

    /// Power and enumerate every port of a hub, at boot or on a rescan.
    ///
    /// # Safety
    ///
    /// As [`Self::configure_hub`].
    unsafe fn scan_hub_ports(&mut self, slot_id: u8, root_port: u8, route: u32, ports: u8) {
        for port in 1..=ports {
            // SAFETY: the hub is on a slot this controller addressed, and
            // every request for its port goes out through this controller's
            // own EP0 ring.
            unsafe {
                self.bring_up_hub_port(slot_id, root_port, route, port);
            }
        }
    }

    /// Bring one hub port up: power it, and if a device is on it that is not
    /// already running, reset the port and address the device behind it.
    ///
    /// The "not already running" half is what makes this usable for a rescan
    /// as well as for the boot pass.  A port that carries a device the driver
    /// has already addressed is *enabled* by the hub, and resetting it again
    /// would address the same device a second time under a second slot.
    ///
    /// # Safety
    ///
    /// As [`Self::configure_hub`].
    unsafe fn bring_up_hub_port(&mut self, slot_id: u8, root_port: u8, route: u32, port: u8) {
        // SAFETY: as `configure_hub` — the hub's own port requests, through
        // this controller's own EP0 ring.
        unsafe {
            // Power first: a port that is off reports nothing else.
            let _ = self.control_transfer(
                slot_id,
                &SetupPacket::hub_set_port_feature(port, HUB_PORT_POWER),
                &mut [],
                false,
            );
            let Some(status) = self.hub_port_status(slot_id, port) else {
                return;
            };
            if status & u32::from(HUB_PORT_STATUS_CONNECTION) == 0 {
                return;
            }
            if status & u32::from(HUB_PORT_STATUS_ENABLE) != 0 {
                // Already addressed; a second reset would enumerate it twice.
                return;
            }
            // Reset the port, then wait for the hub to *say* the reset
            // finished — addressing a device whose port is still resetting is
            // answered with a TRB error.
            if self
                .control_transfer(
                    slot_id,
                    &SetupPacket::hub_set_port_feature(port, HUB_PORT_RESET),
                    &mut [],
                    false,
                )
                .is_err()
            {
                println!("[xhci  ] hub port {}: the reset was refused", port);
                return;
            }
            let mut reset_done = false;
            for _ in 0..HUB_PORT_RESET_SPINS {
                match self.hub_port_status(slot_id, port) {
                    Some(status) => {
                        if status & HUB_PORT_CHANGE_RESET != 0 {
                            reset_done = true;
                            break;
                        }
                    }
                    None => break,
                }
            }
            if !reset_done {
                println!("[xhci  ] hub port {} did not finish resetting", port);
                return;
            }
            if self
                .control_transfer(
                    slot_id,
                    &SetupPacket::hub_clear_port_feature(port, HUB_C_PORT_RESET),
                    &mut [],
                    false,
                )
                .is_err()
            {
                println!(
                    "[xhci  ] hub port {}: the reset change would not clear",
                    port
                );
                return;
            }

            // One tier deeper: this port's nibble is appended to the route the
            // hub itself was found at.
            let child_route = ((route << 4) | u32::from(port)) & 0x000F_FFFF;
            if self.enumerate_device(root_port, child_route) {
                println!(
                    "[xhci  ] hub port {} enumerated (route {:#x})",
                    port, child_route
                );
            }
            // The connection this device arrived on has now been handled, and
            // a change bit that is not cleared is a status-change report the
            // hub will keep making.
            if self
                .control_transfer(
                    slot_id,
                    &SetupPacket::hub_clear_port_feature(port, HUB_C_PORT_CONNECTION),
                    &mut [],
                    false,
                )
                .is_err()
            {
                println!(
                    "[xhci  ] hub port {}: the connection change would not clear",
                    port
                );
            }
        }
    }

    /// Run a hub's status-change report: one bit per port whose state changed.
    ///
    /// The report is a *level*, not an event queue — the hub keeps asserting a
    /// bit until the change behind it is cleared — so this reads each named
    /// port, does what its change asks, clears the port's change bits, and
    /// only then arms the next read.  A report left half-handled re-arms onto
    /// itself; a change bit that cannot be cleared would re-arm onto itself
    /// forever, and that is why it ends the watch rather than the boot.
    ///
    /// # Safety
    ///
    /// The report must be the residual of the hub's own completed read, and
    /// the controller must still own that hub's rings.
    unsafe fn handle_hub_status_change(&mut self, slot_id: u8, residual: u32) {
        // SAFETY: the report landed in the hub's own DMA buffer, written by a
        // transfer on this controller's interrupt ring.
        unsafe {
            let mut report = [0u8; 8];
            let Some(index) = self.hub_index(slot_id) else {
                return;
            };
            let (root_port, route, ports, transferred) = {
                let hub = &self.hubs[index];
                let transferred = hub.ep.report_len.saturating_sub(residual as usize);
                let len = core::cmp::min(transferred, report.len());
                core::ptr::copy_nonoverlapping(hub.report_buf.as_ptr(), report.as_mut_ptr(), len);
                (hub.root_port, hub.route, hub.ports, len)
            };

            for (byte, bits) in report.iter().enumerate().take(transferred) {
                for bit in 0..8u8 {
                    // Bit 0 is the hub's own status; the ports start at 1.
                    let port = (byte as u8).wrapping_mul(8).wrapping_add(bit);
                    if port == 0 || port > ports {
                        continue;
                    }
                    if *bits & (1 << bit) == 0 {
                        continue;
                    }
                    if !self.service_hub_port(slot_id, root_port, route, port) {
                        // A port whose change cannot be read or cleared would
                        // keep this report coming back for as long as the
                        // endpoint is armed, so stop watching rather than
                        // spin.
                        self.hubs.remove(index);
                        println!(
                            "[xhci  ] hub at slot {}: port {} will not finish changing — \
                             no longer watching its ports",
                            slot_id, port
                        );
                        return;
                    }
                }
            }

            // Arm the next read only once this report is fully handled.
            let (slot, dci, len, phys) = match self.hubs.get(index) {
                Some(hub) => (
                    hub.slot_id,
                    hub.ep.dci(),
                    hub.ep.report_len,
                    hub.report_buf.phys_addr() as u64,
                ),
                None => return,
            };
            let _ = self.rearm_hid_read(slot, dci, len, phys);
        }
    }

    /// Do what one port's change asks for, and clear the change bits that
    /// produced the report.
    ///
    /// Returns false when a change bit could not be cleared.
    ///
    /// A change says only *that* the port's state changed; the port's own
    /// status word says which way.  A port with a connection that is not
    /// enabled has a device that just arrived — power it, reset it, address
    /// the device behind it — and a port with no connection has one that just
    /// left, whose slot has to be released or the next device on the same
    /// route meets a slot that is still in use.
    ///
    /// # Safety
    ///
    /// As [`Self::configure_hub`].
    unsafe fn service_hub_port(
        &mut self,
        slot_id: u8,
        root_port: u8,
        route: u32,
        port: u8,
    ) -> bool {
        // SAFETY: as `configure_hub` — the hub's own port requests.
        unsafe {
            let Some(status) = self.hub_port_status(slot_id, port) else {
                return false;
            };
            let change = (status >> 16) as u16;
            let state = (status & 0xFFFF) as u16;

            if change & (1 << (HUB_C_PORT_CONNECTION - 16)) != 0 {
                if state & HUB_PORT_STATUS_CONNECTION != 0 {
                    self.bring_up_hub_port(slot_id, root_port, route, port);
                } else {
                    let child_route = ((route << 4) | u32::from(port)) & 0x000F_FFFF;
                    if let Some(slot) = self.slot_for_route(root_port, child_route) {
                        println!("[xhci  ] hub port {}: device removed (slot {})", port, slot);
                        let _ = self.release_slot(slot);
                    }
                }
            }

            // Every change bit the hub raised has to go, including the ones
            // this driver does not act on (a port that suspended, one that
            // reported overcurrent): they are the report's own content, and
            // one left set keeps the report coming forever.
            for feature in [
                HUB_C_PORT_CONNECTION,
                HUB_C_PORT_RESET,
                HUB_C_PORT_ENABLE,
                HUB_C_PORT_SUSPEND,
                HUB_C_PORT_OVERCURRENT,
            ] {
                if change & (1 << (feature - 16)) == 0 {
                    continue;
                }
                if self
                    .control_transfer(
                        slot_id,
                        &SetupPacket::hub_clear_port_feature(port, feature),
                        &mut [],
                        false,
                    )
                    .is_err()
                {
                    return false;
                }
            }
            true
        }
    }

    /// Where a hub's watch sits in the list, by the slot the hub is on.
    ///
    /// A hub is a device on a slot and a slot holds one device, so a slot
    /// names at most one watch.
    fn hub_index(&self, slot_id: u8) -> Option<usize> {
        self.hubs.iter().position(|hub| hub.slot_id == slot_id)
    }

    /// The slot a device hangs from, named the way a hub names it: the root
    /// port its tree starts at, and the route string down to it.
    fn slot_for_route(&self, root_port: u8, route: u32) -> Option<u8> {
        self.slot_routes
            .iter()
            .position(|&(slot_root, slot_route)| slot_root == root_port && slot_route == route)
            .map(|idx| idx as u8 + 1)
    }

    /// Release the slot a route names and every slot behind it.
    ///
    /// A device's route string is the path of hub ports from the root to it,
    /// one nibble per tier with the first tier in the lowest nibble, so the
    /// devices *behind* one are exactly those whose route keeps its low
    /// nibbles — a hub that leaves the bus takes its children with it, and a
    /// device that leaves a root port takes the hub behind that port and its
    /// children too (a route of zero is a prefix of every route on the port).
    ///
    /// Returns how many slots were released.
    ///
    /// # Safety
    ///
    /// As [`Self::release_slot`] — the slots released belong to this
    /// controller, and nothing on them may be in flight.
    unsafe fn release_subtree(&mut self, root_port: u8, route: u32) -> usize {
        let mask = route_prefix_mask(route_tiers(route));
        let mut released = 0;
        for idx in 0..MAX_SLOTS {
            let (slot_root, slot_route) = self.slot_routes[idx];
            if slot_root != root_port || (slot_route & mask) != route {
                continue;
            }
            // SAFETY: the slot is one this controller addressed, and releasing
            // it disables it before anything else can use it.
            unsafe {
                if self.release_slot(idx as u8 + 1).is_ok() {
                    released += 1;
                }
            }
        }
        released
    }

    /// Disable a slot and forget everything this driver holds for it.
    ///
    /// A device that leaves the bus does not take its slot with it: the
    /// controller keeps the slot's contexts until the host disables it, and
    /// the driver keeps the rings built on them.  Both halves are what the
    /// next device on that port needs to be able to take the slot.
    ///
    /// # Safety
    ///
    /// `slot_id` must name a slot this controller enabled, and nothing on
    /// that slot may be in flight.
    unsafe fn release_slot(&mut self, slot_id: u8) -> Result<()> {
        // SAFETY: the disable-slot command goes out through this controller's
        // own command ring.
        unsafe {
            let evt = self.send_command(Trb::disable_slot(slot_id, 0))?;
            let cc = evt.completion_code();
            if cc != cc::SUCCESS {
                println!(
                    "[xhci  ] disable_slot failed for slot {}: cc={}",
                    slot_id, cc
                );
                return Err(crate::Error::InvalidArgument);
            }

            let idx = slot_id as usize - 1;
            self.device_contexts[idx] = None;
            self.ep0_transfer_rings[idx] = None;
            self.int_transfer_rings[idx] = None;
            self.bulk_in_rings[idx] = None;
            self.bulk_out_rings[idx] = None;
            self.slot_routes[idx] = (0, 0);
            // The device context address goes with them: the controller reads
            // it out of the DCBAAP for the next command that names this slot.
            let dcbaa_slice: &mut [u64] = core::slice::from_raw_parts_mut(
                self.dcbaa.as_ptr() as *mut u64,
                self.max_slots as usize + 1,
            );
            dcbaa_slice[slot_id as usize] = 0;

            if self.keyboard_slot == slot_id {
                self.keyboard_slot = 0;
                self.keyboard_ep = None;
                self.keyboard_report_buf = None;
            }
            if self.mouse_slot == slot_id {
                self.mouse_slot = 0;
                self.mouse_ep = None;
                self.mouse_report_buf = None;
            }
            if self.msd_slot == slot_id {
                self.msd_slot = 0;
                self.msd_endpoints = None;
            }
            // The watch belongs to the slot: releasing the slot releases it.
            if let Some(index) = self.hub_index(slot_id) {
                self.hubs.remove(index);
            }
            Ok(())
        }
    }
    /// One port's status word: `wPortStatus` in the low half, `wPortChange` in
    /// the high half, as the hub reports them.
    ///
    /// # Safety
    ///
    /// As [`Self::configure_hub`].
    unsafe fn hub_port_status(&mut self, slot_id: u8, port: u8) -> Option<u32> {
        let mut buffer = [0u8; 4];
        // SAFETY: the hub is on a slot this controller addressed, and the
        // request goes out through this controller's own EP0 ring.
        unsafe {
            self.control_transfer(
                slot_id,
                &SetupPacket::hub_port_status(port),
                &mut buffer,
                true,
            )
            .ok()?;
        }
        Some(u32::from_le_bytes(buffer))
    }

    /// Classify an addressed device by its device descriptor and wire it
    /// up: a hub's downstream ports, HID keyboard/mouse (real endpoint
    /// discovery + armed first read) or USB mass storage (bulk endpoints +
    /// MSC init).
    unsafe fn configure_slot_device(
        &mut self,
        slot_id: u8,
        desc: UsbDeviceDescriptor,
        root_port: u8,
        route: u32,
    ) -> bool {
        // SAFETY: the slot was enabled by this controller and its contexts are its own
        // DMA memory.
        unsafe {
            use crate::drivers::usb_hid::HidDeviceKind;
            use crate::drivers::usb_hid::{self};
            use crate::drivers::usb_msd;

            let dev_class = desc.device_class;
            let dev_subclass = desc.device_subclass;
            let dev_proto = desc.device_protocol;
            // Copy the 16-bit fields out of the packed descriptor before
            // formatting (taking a reference to a packed field is unaligned).
            let vendor_id = desc.vendor_id;
            let product_id = desc.product_id;
            println!(
            "[xhci  ] device descriptor: class={:#04x} sub={:#04x} proto={:#04x} vid={:04x} pid={:04x}",
            dev_class, dev_subclass, dev_proto, vendor_id, product_id
        );

            // Devices with bDeviceClass == 0 declare their class per
            // interface (typical of HID keyboards and bulk-only mass
            // storage), so read the configuration descriptor and dispatch on
            // the first interface's class.  The config is reused by the HID
            // endpoint walk below.
            let mut config: Option<alloc::vec::Vec<u8>> = None;
            let if_class = if dev_class == 0 {
                match self.read_config_descriptor(slot_id) {
                    Ok(c) => {
                        let cls = config_interface_class(&c).map(|x| x.0);
                        config = Some(c);
                        cls
                    }
                    Err(e) => {
                        println!("[xhci  ] read config descriptor failed: {}", e.as_str());
                        return false;
                    }
                }
            } else {
                None
            };
            let is_hid = if_class == Some(usb_hid::USB_CLASS_HID)
                || (dev_class == usb_hid::USB_CLASS_HID && if_class.is_none());
            let is_msc = if_class == Some(usb_msd::USB_CLASS_MSC)
                || (dev_class == usb_msd::USB_CLASS_MSC && if_class.is_none());
            // A hub declares 0x09 either on the device or, like the others, on
            // its interface.  QEMU's `usb-hub` declares it as the device class
            // and has no interface class to read, so both are checked.
            let is_hub = if_class == Some(USB_CLASS_HUB)
                || (dev_class == USB_CLASS_HUB && if_class.is_none());

            if is_hub {
                self.configure_hub(slot_id, root_port, route);
                return true;
            }

            if is_hid {
                // HID device: walk the configuration descriptor for its real
                // interrupt IN endpoint and classify it as keyboard or mouse.
                let config = match config {
                    Some(c) => c,
                    None => match self.read_config_descriptor(slot_id) {
                        Ok(c) => c,
                        Err(e) => {
                            println!("[xhci  ] read config descriptor failed: {}", e.as_str());
                            return false;
                        }
                    },
                };
                let info = match usb_hid::classify_hid_device(&config, dev_proto) {
                    Some(i) => i,
                    None => {
                        println!("[xhci  ] no HID interrupt IN endpoint at slot {}", slot_id);
                        return false;
                    }
                };
                let ep_info = HidEndpointInfo {
                    endpoint_address: info.endpoint_address,
                    max_packet_size: info.max_packet_size,
                    interval: info.interval,
                    interface_number: info.interface_number,
                    report_len: info.report_len,
                };
                if self.configure_hid_endpoint(slot_id, ep_info).is_err() {
                    return false;
                }
                // Activate the configuration so the interrupt endpoint responds.
                let setup_cfg = SetupPacket::set_configuration(config[5]); // bConfigurationValue
                let mut dummy = [];
                let _ = self.control_transfer(slot_id, &setup_cfg, &mut dummy, false);

                let dci = ep_info.dci();
                match info.kind {
                    HidDeviceKind::Keyboard => {
                        let buf = match DmaBuffer::allocate(1) {
                            Some(b) => b,
                            None => return false,
                        };
                        self.keyboard_report_buf = Some(buf);
                        self.keyboard_slot = slot_id;
                        self.keyboard_ep = Some(ep_info);
                        if let Some(b) = self.keyboard_report_buf.as_ref() {
                            let _ = self.arm_hid_read(
                                slot_id,
                                dci,
                                ep_info.report_len,
                                b.phys_addr() as u64,
                            );
                        }
                        println!("[xhci  ] HID keyboard ready at slot {}", slot_id);
                    }
                    HidDeviceKind::Mouse => {
                        let buf = match DmaBuffer::allocate(1) {
                            Some(b) => b,
                            None => return false,
                        };
                        self.mouse_report_buf = Some(buf);
                        self.mouse_slot = slot_id;
                        self.mouse_ep = Some(ep_info);
                        if let Some(b) = self.mouse_report_buf.as_ref() {
                            let _ = self.arm_hid_read(
                                slot_id,
                                dci,
                                ep_info.report_len,
                                b.phys_addr() as u64,
                            );
                        }
                        println!("[xhci  ] HID mouse ready at slot {}", slot_id);
                    }
                }
                true
            } else if is_msc {
                // USB Mass Storage device — read config descriptor and init.
                println!("[xhci  ] mass storage device detected at slot {}", slot_id);
                if self.init_msd(slot_id).is_ok() {
                    println!("[xhci  ] mass storage initialised at slot {}", slot_id);
                    true
                } else {
                    false
                }
            } else {
                println!("[xhci  ] unsupported device class at slot {}", slot_id);
                false
            }
        }
    }
}

use crate::kernel::sync::Mutex;

// ---------------------------------------------------------------------------
// Global xHCI controller instance (bare-metal only)
// ---------------------------------------------------------------------------

static XHCI_CONTROLLER: Mutex<Option<alloc::boxed::Box<XhciController>>> = Mutex::new(None);

/// The interrupter's runtime window, for the interrupt handler.
///
/// The handler must not wait on the controller's lock — a transfer in flight
/// holds it, and the interrupt that ends the wait is exactly what would be
/// blocked — so the one address it needs out of the controller is captured
/// here, once, at probe time.  Zero means no controller.
static XHCI_RUNTIME_BASE: AtomicUsize = AtomicUsize::new(0);

/// Interrupts taken since the controller claimed its vector.
static XHCI_IRQ_COUNT: AtomicUsize = AtomicUsize::new(0);

/// What the controller's MSI-X vector runs.
///
/// Two jobs, in this order.  **Acknowledge**: the controller raises a message
/// per 0→1 transition of its pending bit, so a message that is never cleared
/// silences every one after it.  **Drain**, when nobody else holds the rings:
/// that is the latency this interrupt exists for — before it, the timer tick
/// was the only drainer and a report could wait a whole tick.  The drain is
/// taken with `try_lock` rather than the blocking lock because an interrupt
/// must not wait on the ring's owner, and the owner drains on its way out.
fn xhci_msi_handler(irq: u32) {
    let base = XHCI_RUNTIME_BASE.load(Ordering::Acquire) as *mut u32;
    if !base.is_null() {
        // SAFETY: the address is the runtime window of the controller this
        // driver probed, captured before any of its interrupts could arrive.
        // Writing the read value back with the pending bit set clears it
        // (write-1-to-clear) and re-states the enable bit.
        unsafe {
            let iman = reg_read32(base, XHCI_RT_IR_BASE + XHCI_RT_IMAN);
            reg_write32(
                base,
                XHCI_RT_IR_BASE + XHCI_RT_IMAN,
                iman | IMAN_IE | IMAN_IP,
            );
        }
    }

    let seen = XHCI_IRQ_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if seen <= 2 {
        crate::println!("[xhci  ] event ring MSI (irq {})", irq);
    }

    if let Some(mut guard) = XHCI_CONTROLLER.try_lock() {
        if let Some(controller) = guard.as_mut() {
            // SAFETY: the controller is the one this driver probed, and the
            // lock is held for the duration of the drain.
            unsafe {
                controller.poll_events();
            }
        }
    }
}

/// Try to take a lock on the global XHCI controller and run a closure.
pub fn with_controller<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut XhciController) -> R,
{
    let mut guard = XHCI_CONTROLLER.lock();
    guard.as_deref_mut().map(f)
}

/// Poll the xHCI event ring (called from timer tick).
/// Returns true if keyboard input was processed.
pub fn xhci_poll() -> bool {
    {
        if let Some(guard) = XHCI_CONTROLLER.lock().as_deref_mut() {
            // SAFETY: the global controller is published only after a successful probe, and
            // the polling path is the only reader of its rings.
            unsafe {
                return guard.poll_events();
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

use crate::drivers::Driver;
use crate::drivers::DriverCategory;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

static XHCI_PROBED: AtomicBool = AtomicBool::new(false);

struct XhciDriver;

impl Driver for XhciDriver {
    fn name(&self) -> &'static str {
        "xhci"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Bus
    }

    fn init(&self) -> crate::Result<()> {
        if XHCI_PROBED.swap(true, Ordering::Acquire) {
            return Ok(());
        }
        probe_xhci()
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(XhciDriver)
}

/// Find xHCI USB controllers and enumerate every connected root hub port
/// (multiple HID + storage devices may share the bus).
fn probe_xhci() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::println;

    let devices = pci_enumerate_buses();
    let mut found = false;
    for info in devices.iter().filter(|d| {
        d.class_code == XHCI_CLASS && d.subclass == XHCI_SUBCLASS && d.prog_if == XHCI_PROGIF
    }) {
        found = true;
        println!(
            "[xhci  ] found xHCI controller at {:02x}:{:02x}.{:x} vendor={:04x} device={:04x}",
            info.bus, info.device, info.function, info.vendor_id, info.device_id
        );

        let bar0 = &info.bars[0];
        if !bar0.is_mmio || bar0.size == 0 {
            println!("[xhci  ] BAR0 is not MMIO — skipping");
            continue;
        }

        // Initialise the controller.
        // SAFETY: `XhciController::new` takes the BAR address and size PCI enumeration
        // produced; mapping them is what makes the controller usable.
        let mut ctrl = match unsafe { XhciController::new(bar0.base_address, bar0.size as usize) } {
            Some(c) => c,
            None => {
                println!("[xhci  ] controller initialisation failed — skipping");
                continue;
            }
        };

        // Scan every root hub port for a connected device.
        for port in 1..=ctrl.max_ports {
            // SAFETY: `enumerate_port` operates on the controller just constructed above,
            // for a port inside its own count.
            if unsafe { ctrl.enumerate_port(port) } {
                println!("[xhci  ] enumerated port {}", port);
            }
        }
        // SAFETY: the controller was just constructed, and the sync only
        // clears its own ports' change bits.
        unsafe { ctrl.sync_root_port_changes() };

        // Store the controller.
        *XHCI_CONTROLLER.lock() = Some(ctrl);
        crate::drivers::record_bound_device(
            "xhci",
            "xhci",
            crate::drivers::DriverCategory::Bus,
            Some(bar0.base_address as usize),
        );

        // Claim the controller's interrupt, now that its rings exist and
        // before anything waits on one.  One identity, for the table's entry 0:
        // this driver uses a single interrupter, and the event ring is what it
        // posts to, so the other fifteen entries of the controller's table take
        // no vector and stay masked rather than each holding one of the
        // window's.  The platform programs the table once the local APIC is
        // up; a machine or a function where that fails leaves the tick draining
        // the ring, which is what this driver did before the wiring existed.
        if let Some(controller) = XHCI_CONTROLLER.lock().as_deref() {
            XHCI_RUNTIME_BASE.store(controller.runtime_base as usize, Ordering::Release);
        }
        let handler: crate::arch::irq_handlers::IrqHandler = Arc::new(xhci_msi_handler);
        let named = [(0u16, handler.clone())];
        if crate::arch::platform::claim_function_interrupts(
            crate::arch::x86_64::pci::PciAddress::new(info.bus, info.device, info.function),
            &named,
        )
        .is_some()
        {
            println!(
                "[xhci  ] device interrupts claimed: the event ring signals on its own vector \
                 once the controller programs the table"
            );
        }

        // The MSD SCSI geometry probe was deferred out of device
        // enumeration (bot_transfer reaches the controller through
        // `with_controller`, which needs the global to be populated).
        // Run it now that the controller is published.
        crate::drivers::usb_msd::probe_geometry();

        // Only initialise the first xHCI controller.
        break;
    }
    if !found {
        println!("[xhci  ] no xHCI controllers found");
    }
    Ok(())
}
