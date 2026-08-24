//! src/kernel/drivers/xhci.rs
//!
//! xHCI (USB 3.x) host controller driver.
//! xHCI (USB 3.0) host controller driver.
//!
//! The xHCI controller is discovered via PCI (class 0x0C, subclass 0x03,
//! prog-if 0x30).  It exposes MMIO registers via BAR0.
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
//! - MSI-X interrupt wiring: deferred (polled event ring via timer tick)
//!
//! ## Testing
//!
//! QEMU q35 + qemu-xhci + usb-kbd:
//!   qemu-system-x86_64 -M q35 -device qemu-xhci -device usb-kbd ...

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// xHCI class code (USB 3.0 host controller).
pub const XHCI_CLASS: u8 = 0x0C;
/// xHCI subclass.
pub const XHCI_SUBCLASS: u8 = 0x03;
/// xHCI programming interface (0x30 = xHCI, 0x20 = EHCI, 0x10 = OHCI, 0x00 = UHCI).
pub const XHCI_PROGIF: u8 = 0x30;

// ---------------------------------------------------------------------------
// xHCI capability registers (offset from BAR0, via CAPLENGTH)
// ---------------------------------------------------------------------------

pub const XHCI_CAP_CAPLENGTH: usize = 0x00;
pub const XHCI_CAP_HCSPARAMS1: usize = 0x04;
pub const XHCI_CAP_HCSPARAMS2: usize = 0x08;
pub const XHCI_CAP_HCSPARAMS3: usize = 0x0C;
pub const XHCI_CAP_HCCPARAMS1: usize = 0x10;
pub const XHCI_CAP_DBOFF: usize = 0x14;
pub const XHCI_CAP_RTSOFF: usize = 0x18;

// HCSPARAMS1 fields.
pub const HCSPARAMS1_MAX_SLOTS_MASK: u32 = 0x0000_00FF;
pub const HCSPARAMS1_MAX_PORTS_MASK: u32 = 0x00FF_0000;
pub const HCSPARAMS1_MAX_PORTS_SHIFT: u32 = 8;

// HCCPARAMS1 field.
pub const HCCPARAMS1_CSZ: u32 = 1 << 2; // Context Size (0 = 32 bytes, 1 = 64 bytes)

// ---------------------------------------------------------------------------
// xHCI operational registers (offset from BAR0 + CAPLENGTH)
// ---------------------------------------------------------------------------

pub const XHCI_OP_USBCMD: usize = 0x00;
pub const XHCI_OP_USBSTS: usize = 0x04;
pub const XHCI_OP_PAGESIZE: usize = 0x08;
pub const XHCI_OP_DNCTRL: usize = 0x14;
pub const XHCI_OP_CRCR_LOW: usize = 0x18;
pub const XHCI_OP_CRCR_HIGH: usize = 0x1C;
pub const XHCI_OP_DCBAAP_LOW: usize = 0x30;
pub const XHCI_OP_DCBAAP_HIGH: usize = 0x34;
pub const XHCI_OP_CONFIG: usize = 0x38;

// USBCMD bits.
pub const USBCMD_RS: u32 = 1 << 0; // Run/Stop
pub const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
pub const USBCMD_INTE: u32 = 1 << 2; // Interrupter Enable
pub const USBCMD_HSEE: u32 = 1 << 3; // Host System Error Enable

// USBSTS bits.
pub const USBSTS_HCH: u32 = 1 << 0; // HC Halted
pub const USBSTS_HSE: u32 = 1 << 2; // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// CRCR bits.
pub const CRCR_RCS: u64 = 1; // Ring Cycle State

// ---------------------------------------------------------------------------
// xHCI runtime registers (offset from BAR0 + RTSOFF)
// ---------------------------------------------------------------------------

pub const XHCI_RT_MFINDEX: usize = 0x00; // Microframe Index

// Interrupter registers (stride 0x20 from RTSOFF + 0x20).
pub const XHCI_RT_IR_BASE: usize = 0x20;
pub const XHCI_RT_IR_STRIDE: usize = 0x20;
pub const XHCI_RT_IMAN: usize = 0x00; // Interrupt Management
pub const XHCI_RT_IMOD: usize = 0x04; // Interrupt Moderation
pub const XHCI_RT_ERSTSZ: usize = 0x08; // Event Ring Segment Table Size
pub const XHCI_RT_ERSTBA_LOW: usize = 0x10; // ERST Base Address Low
pub const XHCI_RT_ERSTBA_HIGH: usize = 0x14; // ERST Base Address High
pub const XHCI_RT_ERDP_LOW: usize = 0x18; // Event Ring Dequeue Pointer Low
pub const XHCI_RT_ERDP_HIGH: usize = 0x1C; // Event Ring Dequeue Pointer High

// IMAN bits.
pub const IMAN_IP: u32 = 1 << 0; // Interrupt Pending
pub const IMAN_IE: u32 = 1 << 1; // Interrupt Enable

// ---------------------------------------------------------------------------
// Doorbell array (offset from BAR0 + DBOFF)
// ---------------------------------------------------------------------------

pub const DOORBELL_ARRAY_OFFSET: usize = 0x00; // relative to DBOFF
pub const DOORBELL_STRIDE: usize = 4;
pub const DOORBELL_TARGET_EP0: u32 = 1; // Doorbell target for Default Control EP

// ---------------------------------------------------------------------------
// TRB (Transfer Request Block) types and sizes
// ---------------------------------------------------------------------------

pub const TRB_SIZE: usize = 16; // 16 bytes per TRB

/// Ring segment size (number of TRBs). Must be a multiple of 16.
pub const RING_SEGMENT_TRBS: usize = 64;

/// TRB type codes.
pub mod trb_type {
    pub const NORMAL: u32 = 1;
    pub const SETUP_STAGE: u32 = 2;
    pub const DATA_STAGE: u32 = 3;
    pub const STATUS_STAGE: u32 = 4;
    pub const LINK: u32 = 6;
    pub const NO_OP: u32 = 8;
    pub const ENABLE_SLOT: u32 = 9;
    pub const DISABLE_SLOT: u32 = 10;
    pub const ADDRESS_DEVICE: u32 = 11;
    pub const CONFIGURE_ENDPOINT: u32 = 12;
    pub const EVALUATE_CONTEXT: u32 = 13;
    pub const RESET_ENDPOINT: u32 = 14;
    pub const STOP_ENDPOINT: u32 = 15;
    pub const TRANSFER_EVENT: u32 = 32;
    pub const COMMAND_COMPLETION_EVENT: u32 = 33;
    pub const PORT_STATUS_CHANGE_EVENT: u32 = 34;
    pub const HOST_CONTROLLER_EVENT: u32 = 37;
}

/// TRB control field: Cycle bit (bit 0).
pub const TRB_CYCLE_BIT: u32 = 1;
/// TRB control field: TRB type shift (bits 10:16).
pub const TRB_TYPE_SHIFT: u32 = 10;
/// TRB control field: Chain bit (bit 4) — link TRBs in a transfer.
pub const TRB_CHAIN_BIT: u32 = 1 << 4;
/// TRB control field: Interrupt On Completion (bit 5).
pub const TRB_IOC: u32 = 1 << 5;
/// TRB control field: Interrupt On Short Packet (bit 1).
pub const TRB_ISP: u32 = 1 << 1;
/// TRB status field: Direction bit for Data Stage TRB (bit 16 = IN).
pub const TRB_DIR_IN: u32 = 1 << 16;
/// TRB control field: TRB Transfer Length (bits 0:16 of status).
pub const TRB_TL_MASK: u32 = 0x0001_FFFF;

/// Build a TRB control word from type, cycle bit, and optional flags.
pub const fn trb_control(trb_type: u32, cycle: u32) -> u32 {
    (trb_type << TRB_TYPE_SHIFT) | (cycle & TRB_CYCLE_BIT)
}

// ---------------------------------------------------------------------------
// Command completion codes (extracted from event TRB status, bits 24:31)
// ---------------------------------------------------------------------------

pub mod cc {
    pub const SUCCESS: u32 = 1;
    pub const TRB_ERROR: u32 = 5;
    pub const SLOT_NOT_ENABLED: u32 = 7;
    pub const USB_TRANSACTION_ERROR: u32 = 4;
    pub const PARAMETER_ERROR: u32 = 2;
}

// ---------------------------------------------------------------------------
// USB standard request constants
// ---------------------------------------------------------------------------

/// bmRequestType: Device-to-Host, Standard, Device recipient.
pub const REQ_DEVICE_TO_HOST_STANDARD: u8 = 0x80;
/// bmRequestType: Host-to-Device, Standard, Device recipient.
pub const REQ_HOST_TO_DEVICE_STANDARD: u8 = 0x00;
/// GET_DESCRIPTOR request.
pub const REQ_GET_DESCRIPTOR: u8 = 6;
/// SET_ADDRESS request.
pub const REQ_SET_ADDRESS: u8 = 5;
/// SET_CONFIGURATION request.
pub const REQ_SET_CONFIGURATION: u8 = 9;
/// Descriptor type: Device = 1, Configuration = 2.
pub const DESC_DEVICE: u8 = 1;
pub const DESC_CONFIGURATION: u8 = 2;

/// A standard USB setup packet (8 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl SetupPacket {
    pub const fn get_descriptor_device(length: u16) -> Self {
        Self {
            bm_request_type: REQ_DEVICE_TO_HOST_STANDARD,
            b_request: REQ_GET_DESCRIPTOR,
            w_value: ((DESC_DEVICE as u16) << 8), // descriptor type << 8 | index
            w_index: 0, // 0 for device descriptor (language for string desc)
            w_length: length,
        }
    }

    pub const fn set_address(address: u8) -> Self {
        Self {
            bm_request_type: REQ_HOST_TO_DEVICE_STANDARD,
            b_request: REQ_SET_ADDRESS,
            w_value: address as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    pub const fn get_descriptor_configuration(length: u16) -> Self {
        Self {
            bm_request_type: REQ_DEVICE_TO_HOST_STANDARD,
            b_request: REQ_GET_DESCRIPTOR,
            w_value: ((DESC_CONFIGURATION as u16) << 8),
            w_index: 0,
            w_length: length,
        }
    }

    pub const fn set_configuration(config_val: u8) -> Self {
        Self {
            bm_request_type: REQ_HOST_TO_DEVICE_STANDARD,
            b_request: REQ_SET_CONFIGURATION,
            w_value: config_val as u16,
            w_index: 0,
            w_length: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TRB and data structures
// ---------------------------------------------------------------------------

/// A Transfer Request Block (16 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub const fn zeroed() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    /// Create a Link TRB pointing to `ring_addr` (physical).
    pub fn link(ring_addr: u64, cycle: u32) -> Self {
        Self {
            parameter: ring_addr,
            status: 0,
            control: trb_control(trb_type::LINK, cycle),
        }
    }

    /// Create a No-Op command TRB.
    pub fn no_op(cycle: u32) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: trb_control(trb_type::NO_OP, cycle),
        }
    }

    /// Create an Enable Slot command TRB.
    pub fn enable_slot(cycle: u32) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: trb_control(trb_type::ENABLE_SLOT, cycle),
        }
    }

    /// Create an Address Device command TRB.
    /// `ict_phys`: physical address of the Input Context.
    /// `bsr`: Block Set Address Request (0 = send SET_ADDRESS, 1 = block).
    pub fn address_device(ict_phys: u64, bsr: bool, cycle: u32) -> Self {
        let bsr_bit: u64 = if bsr { 1 << 9 } else { 0 };
        Self {
            parameter: ict_phys | bsr_bit,
            status: 0,
            control: trb_control(trb_type::ADDRESS_DEVICE, cycle),
        }
    }

    /// Create a Configure Endpoint command TRB.
    pub fn configure_endpoint(ict_phys: u64, cycle: u32) -> Self {
        Self {
            parameter: ict_phys,
            status: 0,
            control: trb_control(trb_type::CONFIGURE_ENDPOINT, cycle),
        }
    }

    pub fn cycle_bit(&self) -> u32 {
        self.control & TRB_CYCLE_BIT
    }

    /// Completion code from a Command Completion Event TRB (bits 24:31 of status).
    pub fn completion_code(&self) -> u32 {
        (self.status >> 24) & 0xFF
    }

    /// Slot ID from a Command Completion Event TRB (bits 24:31 of control).
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// TRB type from control word (bits 10:16).
    pub fn trb_type(&self) -> u32 {
        (self.control >> TRB_TYPE_SHIFT) & 0x3F
    }
}

// ---------------------------------------------------------------------------
// Event Ring Segment Table entry (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
struct ErstEntry {
    segment_base_low: u32,
    segment_base_high: u32,
    segment_size: u32,
    _reserved: u32,
}

impl ErstEntry {
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    fn new(base_phys: u64, segment_trb_count: u16) -> Self {
        Self {
            segment_base_low: base_phys as u32,
            segment_base_high: (base_phys >> 32) as u32,
            segment_size: segment_trb_count as u32,
            _reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Standard USB device descriptor
// ---------------------------------------------------------------------------

/// Standard USB Device Descriptor (18 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub usb_version: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_index: u8,
    pub num_configurations: u8,
}

/// Standard USB Configuration Descriptor (9 bytes header).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbConfigDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub config_index: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// USB Interface Descriptor (9 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbInterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_index: u8,
}

/// USB Endpoint Descriptor (7 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

/// Parsed information about a HID keyboard endpoint.
#[derive(Debug, Clone, Copy)]
pub struct HidEndpointInfo {
    pub endpoint_address: u8,
    pub max_packet_size: u16,
    pub interval: u8,
    pub interface_number: u8,
}

// ---------------------------------------------------------------------------
// XHCI controller state (bare-metal only)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod controller {
    use super::*;
    use crate::arch::mmu::map_device_mmio;
    use crate::kernel::memory::DmaBuffer;
    use crate::println;
    use crate::Result;
    use core::ptr::{read_volatile, write_volatile};

    /// Maximum number of device slots we support.
    const MAX_SLOTS: usize = 64;

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
        /// Device context size in bytes (32 or 64).
        context_size: u8,
        /// Page size mask (from PAGESIZE register).
        #[allow(dead_code)]
        page_size: u32,
        /// Command ring DMA buffer.
        cmd_ring: DmaBuffer,
        /// Command ring enqueue index.
        cmd_enqueue: u32,
        /// Command ring producer cycle state.
        cmd_pcs: bool,
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
        ep0_transfer_rings: [Option<DmaBuffer>; MAX_SLOTS],
        /// Per-slot interrupt transfer ring.
        int_transfer_rings: [Option<DmaBuffer>; MAX_SLOTS],
        /// Enumerated slot for HID keyboard (0 = none).
        pub keyboard_slot: u8,
        /// HID keyboard endpoint info.
        pub keyboard_ep: Option<HidEndpointInfo>,
        /// Pre-allocated DMA buffer for HID report reception (reused across polls).
        hid_report_buf: Option<DmaBuffer>,
        /// Per-slot bulk OUT transfer rings.
        bulk_out_rings: [Option<DmaBuffer>; MAX_SLOTS],
        /// Per-slot bulk IN transfer rings.
        bulk_in_rings: [Option<DmaBuffer>; MAX_SLOTS],
        /// USB mass storage slot (0 = none).
        pub msd_slot: u8,
        /// Mass storage bulk endpoint info.
        pub msd_endpoints: Option<crate::kernel::drivers::usb_msd::MsdBulkEndpoints>,
    }

    // SAFETY: XhciController owns its MMIO mapping and DMA buffers exclusively.
    unsafe impl Send for XhciController {}

    // -----------------------------------------------------------------------
    // MMIO helpers
    // -----------------------------------------------------------------------

    unsafe fn reg_read32(base: *const u32, offset: usize) -> u32 {
        read_volatile(base.add(offset / 4))
    }

    unsafe fn reg_write32(base: *mut u32, offset: usize, value: u32) {
        write_volatile(base.add(offset / 4), value);
    }

    unsafe fn reg_write64_lo_hi(base: *mut u32, lo_off: usize, hi_off: usize, value: u64) {
        write_volatile(base.add(lo_off / 4), value as u32);
        write_volatile(base.add(hi_off / 4), (value >> 32) as u32);
    }

    // -----------------------------------------------------------------------
    // TRB ring helpers
    // -----------------------------------------------------------------------

    /// Get a pointer to the n-th TRB in a ring buffer.
    unsafe fn ring_trb_ptr(ring: &DmaBuffer, index: u32) -> *mut Trb {
        let base = ring.as_ptr() as *mut Trb;
        base.add(index as usize)
    }

    /// Write a command TRB to the command ring at the enqueue position,
    /// advance the enqueue index, and ring the doorbell.
    unsafe fn post_cmd_trb(ctrl: &mut XhciController, mut trb: Trb) {
        let cycle = if ctrl.cmd_pcs { TRB_CYCLE_BIT } else { 0 };
        trb.control |= cycle;

        let ptr = ring_trb_ptr(&ctrl.cmd_ring, ctrl.cmd_enqueue);
        write_volatile(ptr, trb);

        // Place a Link TRB before the end so we wrap cleanly.
        // The last usable TRB index is RING_SEGMENT_TRBS - 2, the
        // second-to-last is the Link TRB we always keep there.
        ctrl.cmd_enqueue += 1;
        if ctrl.cmd_enqueue >= (RING_SEGMENT_TRBS as u32) - 1 {
            // We hit the Link TRB we placed at [n-1]; it should advance to [0].
            ctrl.cmd_pcs = !ctrl.cmd_pcs;
            ctrl.cmd_enqueue = 0;
        }

        // Ring doorbell for the command ring (doorbell 0).
        write_volatile(ctrl.doorbell_base, 0u32);
    }

    /// Wait for a command completion event on the event ring.
    /// Returns the Command Completion Event TRB.
    unsafe fn await_cmd_completion(ctrl: &mut XhciController) -> Result<Trb> {
        // Poll the event ring for a Command Completion Event.
        for _ in 0..10_000_000 {
            let evt_ptr = ring_trb_ptr(&ctrl.event_ring, ctrl.evt_dequeue);
            let evt = read_volatile(evt_ptr);
            let evt_cycle = evt.cycle_bit();
            let expected_cycle = if ctrl.evt_ccs { TRB_CYCLE_BIT } else { 0 };

            if evt_cycle == expected_cycle {
                // Event available.
                let trb_type = evt.trb_type();
                if trb_type == trb_type::COMMAND_COMPLETION_EVENT {
                    // Advance dequeue.
                    ctrl.evt_dequeue += 1;
                    if ctrl.evt_dequeue >= (RING_SEGMENT_TRBS as u32) - 1 {
                        ctrl.evt_ccs = !ctrl.evt_ccs;
                        ctrl.evt_dequeue = 0;
                    }
                    // Write ERDP to acknowledge.
                    let erdp = ctrl.event_ring.phys_addr() as u64
                        + (ctrl.evt_dequeue as u64 * TRB_SIZE as u64);
                    reg_write64_lo_hi(
                        ctrl.runtime_base,
                        XHCI_RT_IR_BASE + XHCI_RT_ERDP_LOW,
                        XHCI_RT_IR_BASE + XHCI_RT_ERDP_HIGH,
                        erdp | (if ctrl.evt_ccs { 1u64 << 3 } else { 0 }),
                    );
                    return Ok(evt);
                }
                // Other event types: skip and advance.
                ctrl.evt_dequeue += 1;
                if ctrl.evt_dequeue >= (RING_SEGMENT_TRBS as u32) - 1 {
                    ctrl.evt_ccs = !ctrl.evt_ccs;
                    ctrl.evt_dequeue = 0;
                }
            }
        }
        Err(crate::Error::TimedOut)
    }

    // -----------------------------------------------------------------------
    // Controller lifecycle
    // -----------------------------------------------------------------------

    impl XhciController {
        /// Initialise a new xHCI controller given BAR0 physical address and size.
        /// Returns `None` if MMIO mapping fails or the controller is not usable.
        pub unsafe fn new(bar0_phys: u64, bar0_size: usize) -> Option<Self> {
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
                "[xhci  ] max_slots={} max_ports={} ctx_size={} page_size={:#x}",
                max_slots, max_ports, context_size, page_size
            );

            let mut ctrl = Self {
                op_base,
                runtime_base,
                doorbell_base,
                max_slots,
                context_size,
                page_size,
                cmd_ring: DmaBuffer::allocate(1)?, // 4 KiB for command ring
                cmd_enqueue: 0,
                cmd_pcs: true,
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
                hid_report_buf: None,
                bulk_out_rings: [const { None }; MAX_SLOTS],
                bulk_in_rings: [const { None }; MAX_SLOTS],
                msd_slot: 0,
                msd_endpoints: None,
            };

            ctrl.reset().ok()?;
            ctrl.init_rings().ok()?;
            ctrl.start().ok()?;

            println!("[xhci  ] controller initialised and running");
            Some(ctrl)
        }

        /// Reset the host controller.
        unsafe fn reset(&mut self) -> Result<()> {
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

        /// Allocate and program command ring, event ring, DCBAAP.
        unsafe fn init_rings(&mut self) -> Result<()> {
            // --- Command ring ---
            // Set up the ring with a Link TRB at the end to loop back.
            let cmd_ring_phys = self.cmd_ring.phys_addr() as u64;
            let link_index = (RING_SEGMENT_TRBS - 1) as u32;
            let link_ptr = ring_trb_ptr(&self.cmd_ring, link_index);
            write_volatile(link_ptr, Trb::link(cmd_ring_phys, TRB_CYCLE_BIT));

            // Program CRCR (Command Ring Control Register).
            // Bits 63:4 = physical address of cmd ring (64-byte aligned, always true for page-aligned)
            // Bit 0 = RCS (Ring Cycle State), start with 1.
            let crcr = cmd_ring_phys | CRCR_RCS;
            reg_write64_lo_hi(self.op_base, XHCI_OP_CRCR_LOW, XHCI_OP_CRCR_HIGH, crcr);

            // --- Event ring ---
            let evt_ring_phys = self.event_ring.phys_addr() as u64;
            // Write Link TRB at end of event ring.
            let evt_link_index = (RING_SEGMENT_TRBS - 1) as u32;
            let evt_link_ptr = ring_trb_ptr(&self.event_ring, evt_link_index);
            write_volatile(evt_link_ptr, Trb::link(evt_ring_phys, TRB_CYCLE_BIT));

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

            Ok(())
        }

        /// Start the host controller (set Run/Stop = 1).
        unsafe fn start(&mut self) -> Result<()> {
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

        // -------------------------------------------------------------------
        // Command helpers
        // -------------------------------------------------------------------

        /// Send a command TRB and wait for its completion event.
        unsafe fn send_command(&mut self, trb: Trb) -> Result<Trb> {
            post_cmd_trb(self, trb);
            await_cmd_completion(self)
        }

        // -------------------------------------------------------------------
        // Device enumeration
        // -------------------------------------------------------------------

        /// Enable a device slot. Returns the slot ID (1-based).
        pub unsafe fn enable_slot(&mut self) -> Result<u8> {
            let trb = Trb::enable_slot(if self.cmd_pcs { TRB_CYCLE_BIT } else { 0 });
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

        /// Allocate device context and EP0 transfer ring for a slot.
        pub unsafe fn alloc_slot_resources(&mut self, slot_id: u8) -> Result<()> {
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
            let ep0_ring = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;
            let ep0_phys = ep0_ring.phys_addr() as u64;
            // Add Link TRB at end.
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;
            unsafe {
                let link_ptr = ring_trb_ptr(&ep0_ring, link_idx);
                write_volatile(link_ptr, Trb::link(ep0_phys, TRB_CYCLE_BIT));
            }

            self.device_contexts[idx] = Some(dev_ctx);
            self.ep0_transfer_rings[idx] = Some(ep0_ring);
            Ok(())
        }

        /// Build an input context for Address Device command.
        unsafe fn build_address_device_input(
            &self,
            _slot_id: u8,
            ep0_ring: &DmaBuffer,
        ) -> DmaBuffer {
            let ctx_size = self.context_size as usize;
            // Input context: ICC + Slot + EP0 Control + EP1 IN = 4 * ctx_size
            let total = 4 * ctx_size;
            let nframes = total.div_ceil(4096);
            let mut buf = DmaBuffer::allocate(nframes).unwrap();
            buf.as_mut_slice().fill(0);

            let base = buf.as_ptr();

            // Input Control Context (ICC): A0 (add slot) + A1 (add EP0 control).
            unsafe {
                let icc = base as *mut u32;
                write_volatile(icc, 0x03); // A0=1, A1=1
            }

            // Slot Context at offset ctx_size:
            // - Root Hub Port = 1 (speed handled by controller)
            // - Context Entries = 1 (one endpoint context, the control EP)
            unsafe {
                let sc_base = base.add(ctx_size) as *mut u32;
                // context_entries (bits 26:0) = 1
                write_volatile(sc_base, 1);
                // route_string_and_speed = 0 (root port)
                write_volatile(sc_base.add(2), 0);
            }

            // Endpoint 0 Control Context at offset 2*ctx_size (EP0 in input = offset 1)
            unsafe {
                let ep0_ctrl = base.add(2 * ctx_size) as *mut u32;
                // TR Dequeue Pointer: physical address of EP0 ring | DCS=1
                let tr_dq = ep0_ring.phys_addr() as u64 | 1; // DCS=1
                write_volatile(ep0_ctrl.add(2), tr_dq as u32);
                write_volatile(ep0_ctrl.add(3), (tr_dq >> 32) as u32);
                // EP type: Control (4), Max Packet Size=8, Average TRB Length=8.
                // Bits 3:0 = endpoint type (4 = Control).
                // Bits 15:8 = Max Packet Size.
                // Bits 31:16 = Max Burst Size (set 0).
                let ep_type_val: u32 = 4; // Control
                let mps_val: u32 = 8; // initial MPS for control EP
                write_volatile(ep0_ctrl.add(1), (mps_val << 8) | ep_type_val);
                write_volatile(ep0_ctrl.add(4), 8); // Average TRB Length
            }

            buf
        }

        /// Send Address Device command (BSR=0, issues SET_ADDRESS).
        /// After this, the device is at the assigned address and EP0 is ready.
        /// Uses the EP0 ring stored in self.ep0_transfer_rings.
        pub unsafe fn address_device(&mut self, slot_id: u8) -> Result<()> {
            let idx = slot_id as usize - 1;
            if self.ep0_transfer_rings[idx].is_none() {
                return Err(crate::Error::InvalidArgument);
            }
            // SAFETY: we just checked it's Some.
            let ep0_ring = self.ep0_transfer_rings[idx].as_ref().unwrap();
            let ict = self.build_address_device_input(slot_id, ep0_ring);
            let ict_phys = ict.phys_addr() as u64;
            let trb = Trb::address_device(
                ict_phys,
                false,
                if self.cmd_pcs { TRB_CYCLE_BIT } else { 0 },
            );
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

        /// Submit a control transfer on EP0 of the given slot.
        /// Returns the number of bytes transferred (data stage length).
        pub unsafe fn control_transfer(
            &mut self,
            slot_id: u8,
            setup: &SetupPacket,
            data_buf: &mut [u8],
            direction_in: bool,
        ) -> Result<usize> {
            let idx = slot_id as usize - 1;
            let ep0_ring = self.ep0_transfer_rings[idx]
                .as_mut()
                .ok_or(crate::Error::InvalidArgument)?;

            // Allocate temporary buffer for Setup TRB + Data TRB + Status TRB.
            // We put these on a temporary DMA buffer to avoid corrupting the ring.
            // Actually, we should enqueue them directly on the EP0 transfer ring.
            // But for simplicity, we reset and rebuild the ring for each transfer.

            let _ring_phys = ep0_ring.phys_addr() as u64;
            let ring_base = ep0_ring.as_ptr() as *mut Trb;
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;

            // Clear all TRBs in the ring (except the Link TRB).
            for i in 0u32..link_idx {
                unsafe {
                    write_volatile(ring_base.add(i as usize), Trb::zeroed());
                }
            }

            // Build the setup packet as bytes.
            let setup_bytes: &[u8; 8] = unsafe { core::mem::transmute(setup) };

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

            // Enqueue TRBs: Setup → Data → Status → Link (link already at [n-1]).
            let mut enq: u32 = 0;
            // Cycle bit is 1 for the first pass through the ring.
            // The Link TRB at ring[n-1] toggles the cycle on wraparound.

            // Setup Stage TRB.
            let setup_trb = Trb {
                parameter: u64::from_le_bytes(*setup_bytes),
                status: 8, // 8 bytes to transfer
                control: trb_control(trb_type::SETUP_STAGE, TRB_CYCLE_BIT)
                    | TRB_IOC // interrupt on completion
                    | (if direction_in { TRB_DIR_IN } else { 0 }),
            };
            unsafe {
                write_volatile(ring_base.add(enq as usize), setup_trb);
            }
            enq += 1;

            // Data Stage TRB.
            let data_dir_flag: u32 = if direction_in { TRB_DIR_IN } else { 0 };
            let data_trb = Trb {
                parameter: data_phys,
                status: data_len & TRB_TL_MASK,
                control: trb_control(trb_type::DATA_STAGE, TRB_CYCLE_BIT) | data_dir_flag,
            };
            unsafe {
                write_volatile(ring_base.add(enq as usize), data_trb);
            }
            enq += 1;

            // Status Stage TRB (opposite direction from data).
            let status_dir: u32 = if direction_in { 0 } else { TRB_DIR_IN };
            let status_trb = Trb {
                parameter: 0,
                status: 0,
                control: trb_control(trb_type::STATUS_STAGE, TRB_CYCLE_BIT) | status_dir | TRB_IOC,
            };
            unsafe {
                write_volatile(ring_base.add(enq as usize), status_trb);
            }

            // Ring doorbell for EP0 of this slot.
            let db_val = slot_id as u32 * DOORBELL_STRIDE as u32 + DOORBELL_TARGET_EP0;
            unsafe {
                write_volatile(self.doorbell_base.add(db_val as usize / 4), db_val);
            }

            // Poll for Transfer Event on the event ring.
            let transferred = self
                .poll_transfer_event()
                .map_err(|_| crate::Error::TimedOut)?;

            // Copy data out if direction was IN.
            if let Some(ref dma) = data_dma {
                let src = dma.as_ptr();
                let len = data_buf.len().min(transferred as usize);
                unsafe {
                    core::ptr::copy_nonoverlapping(src, data_buf.as_mut_ptr(), len);
                }
            }

            Ok(transferred as usize)
        }

        /// Poll the event ring for a Transfer Event.
        unsafe fn poll_transfer_event(&mut self) -> Result<u32> {
            for _ in 0..10_000_000 {
                let evt_ptr = ring_trb_ptr(&self.event_ring, self.evt_dequeue);
                let evt = read_volatile(evt_ptr);
                let evt_cycle = evt.cycle_bit();
                let expected_cycle = if self.evt_ccs { TRB_CYCLE_BIT } else { 0 };

                if evt_cycle == expected_cycle {
                    let trb_type = evt.trb_type();
                    if trb_type == trb_type::TRANSFER_EVENT {
                        let residual = evt.status & TRB_TL_MASK;
                        let cc = evt.completion_code();
                        // Advance dequeue.
                        self.evt_dequeue += 1;
                        if self.evt_dequeue >= (RING_SEGMENT_TRBS as u32) - 1 {
                            self.evt_ccs = !self.evt_ccs;
                            self.evt_dequeue = 0;
                        }
                        // Write ERDP.
                        let erdp = self.event_ring.phys_addr() as u64
                            + (self.evt_dequeue as u64 * TRB_SIZE as u64);
                        reg_write64_lo_hi(
                            self.runtime_base,
                            XHCI_RT_IR_BASE + XHCI_RT_ERDP_LOW,
                            XHCI_RT_IR_BASE + XHCI_RT_ERDP_HIGH,
                            erdp | (if self.evt_ccs { 1u64 << 3 } else { 0 }),
                        );
                        if cc != cc::SUCCESS {
                            return Err(crate::Error::InvalidArgument);
                        }
                        // Transferred = requested - residual.
                        // Requested was in the Data Stage TRB status field…
                        // We don't track it here, but residual is what's left.
                        // For GET_DESCRIPTOR, the actual transferred is 18 - residual.
                        return Ok(residual);
                    } else if trb_type == trb_type::COMMAND_COMPLETION_EVENT {
                        // Handle stray command completion.
                        self.evt_dequeue += 1;
                        if self.evt_dequeue >= (RING_SEGMENT_TRBS as u32) - 1 {
                            self.evt_ccs = !self.evt_ccs;
                            self.evt_dequeue = 0;
                        }
                    }
                }
            }
            Err(crate::Error::TimedOut)
        }

        /// Read the device descriptor via control transfer on EP0.
        /// Uses the 8-byte setup packet + 18-byte data transfer.
        /// Note: For USB 3.0 ports, the device descriptor request is
        /// usually dispatched by the controller itself during Address Device
        /// when BSR=0.  This function is provided for explicit re-read.
        pub unsafe fn get_device_descriptor(&mut self, slot_id: u8) -> Result<UsbDeviceDescriptor> {
            let setup = SetupPacket::get_descriptor_device(18);
            let mut buf = [0u8; 18];
            self.control_transfer(slot_id, &setup, &mut buf, true)?;

            // Parse the descriptor.
            let desc: UsbDeviceDescriptor =
                unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };
            Ok(desc)
        }

        /// Configure the HID keyboard interrupt endpoint for a slot.
        /// We need the device to be addressed first.
        /// `ep_info` describes the HID interrupt IN endpoint.
        pub unsafe fn configure_hid_endpoint(
            &mut self,
            slot_id: u8,
            ep_info: HidEndpointInfo,
        ) -> Result<()> {
            let idx = slot_id as usize - 1;
            let dev_ctx = self.device_contexts[idx]
                .as_ref()
                .ok_or(crate::Error::InvalidArgument)?;
            let ctx_size = self.context_size as usize;

            // Allocate interrupt transfer ring.
            let int_ring = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;
            let int_ring_phys = int_ring.phys_addr() as u64;
            // Add Link TRB.
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;
            unsafe {
                let link_ptr = ring_trb_ptr(&int_ring, link_idx);
                write_volatile(link_ptr, Trb::link(int_ring_phys, TRB_CYCLE_BIT));
            }

            // Read existing output device context to preserve slot + EP0 state.
            // The output context has: Slot Context at offset 0, EP0 at ctx_size.
            // The input context needs: ICC + Slot + EP0 (preserved) + EP1 (new).
            // Actually we use Evaluate Context or Configure Endpoint.
            // For Configure Endpoint: ICC sets A0=1, A1=1 (add EP1).
            // The slot context and EP0 context must be copied from output context.

            let total_input = 4 * ctx_size; // ICC + Slot + EP0 + EP1
            let nframes = total_input.div_ceil(4096);
            let mut ict = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            ict.as_mut_slice().fill(0);

            let ict_base = ict.as_ptr();

            // ICC: A0=1 (add slot), A1=1 (add EP0), A2=1 (drop EP0), A1+A2 cancel
            // Actually: Set A0=1 (slot context), A1=1 (EP0 unchanged), A2=1 (add EP1).
            // Wait — the context indices in Add Context flags: bit 0 = slot, bit 1 = EP1 (control EP), bit 2 = EP2.
            // For Configure Endpoint, we need to set the ADD flags for contexts we want to modify.
            // All contexts not flagged are preserved.
            // Flag A0=1 (modify slot), A1=1 (modify EP0 control — set to max packet size from descriptor),
            // A2=1 (add EP1 = interrupt IN EP).
            unsafe {
                let icc = ict_base as *mut u32;
                write_volatile(icc, 0x07); // A0=1, A1=1, A2=1
            }

            // Copy slot context from output device context (DCBAAP entry points to output ctx).
            let out_ctx_base = dev_ctx.as_ptr();
            unsafe {
                let src_slot = out_ctx_base;
                let dst_slot = ict_base.add(ctx_size);
                core::ptr::copy_nonoverlapping(src_slot, dst_slot, ctx_size);

                // Update slot context: Context Entries = 2 (EP0 + EP1 interrupt IN).
                let sc = dst_slot as *mut u32;
                let current_entries = read_volatile(sc) & 0x7FFF_FFFF;
                write_volatile(sc, current_entries | 2); // now with 2 endpoint contexts

                // Copy EP0 context from output (offset ctx_size in output = EP0).
                let src_ep0 = out_ctx_base.add(ctx_size);
                let dst_ep0 = ict_base.add(2 * ctx_size);
                core::ptr::copy_nonoverlapping(src_ep0, dst_ep0, ctx_size);
            }

            // Set up EP1 input context (interrupt IN endpoint).
            // In the input context array, endpoint contexts are at:
            //   ctx_size * (ep_num + 1). EP1 = ctx_size * 2.
            // But we already placed slot at ctx_size and EP0 at 2*ctx_size.
            // So EP1 goes at 3*ctx_size.
            let _ep_num = (ep_info.endpoint_address & 0x0F) as usize;
            let _ep_is_in = (ep_info.endpoint_address & 0x80) != 0;
            let ep_offset = 3 * ctx_size;
            unsafe {
                let ep_ctx = ict_base.add(ep_offset) as *mut u32;

                // EP type: bits 3:0 (3 = Interrupt).
                // Max Packet Size: bits 15:8.
                // Max Burst: bits 31:16.
                let _ep_type: u32 = 3; // Interrupt
                                       // Actually bit 5 = direction (1 = IN). So for IN: 3 | (1<<5) = 0x23.
                                       // Wait, the xHCI spec says for EP Context:
                                       // Bits 3:0 = EP Type (3 = Interrupt)
                                       // Bit 5 = Direction (0 = OUT, 1 = IN). Wait no, direction is separate.
                                       // Actually: EP Type 3 = Interrupt. Direction = bit 5? No.
                                       // Looking more carefully: The EP context has "EP Type" in bits 3:0,
                                       // and the endpoint direction is NOT part of EP type. The direction
                                       // is implied by the DCI (Device Context Index). Odd DCI = IN, Even = OUT.
                                       // For EP1 (DCI=2), EP1 IN would be DCI=3.
                                       // Actually no — in xHCI:
                                       // EP0 is bidirectional (DCI=1)
                                       // EP1 OUT = DCI 2, EP1 IN = DCI 3
                                       // EP2 OUT = DCI 4, EP2 IN = DCI 5
                                       // So the EP number in the endpoint_address doesn't directly map to DCI.
                                       // For a HID keyboard with EP 1 IN (addr=0x81),
                                       // EP number = 1, IN → DCI = 2*1 + 1 = 3.
                                       // But our input context layout needs to place this at the right position.
                                       // Actually the input context indices for endpoints:
                                       // Context 0 = Slot
                                       // Context 1 = EP0 (DCI 1)
                                       // Context 2 = EP1 OUT (DCI 2)
                                       // Context 3 = EP1 IN (DCI 3)
                                       // etc.
                                       // For EP 1 IN (addr=0x81), DCI=3, so Context index = 3.
                                       // Total input context = 4 * ctx_size entries.
                                       // ICC + Slot(C0) + EP0(C1) + EP1-OUT-if-needed(C2) + EP1-IN(C3).
                                       // Since we only need EP1 IN, we put it at offset 3*ctx_size (Context 3).

                write_volatile(ep_ctx, 0); // state = 0 (disabled)
                let ep_ctrl: u32 = 3 // Interrupt
                    | ((ep_info.max_packet_size as u32 & 0xFFFF) << 8)
                    | ((ep_info.interval as u32 & 0xFF) << 16);
                write_volatile(ep_ctx.add(1), ep_ctrl);

                // TR Dequeue Pointer.
                let tr_dq = int_ring_phys | 1; // DCS=1
                write_volatile(ep_ctx.add(2), tr_dq as u32);
                write_volatile(ep_ctx.add(3), (tr_dq >> 32) as u32);

                // Average TRB Length = 8 (for HID boot protocol report).
                write_volatile(ep_ctx.add(4), 8);
            }

            let ict_phys = ict.phys_addr() as u64;
            let trb =
                Trb::configure_endpoint(ict_phys, if self.cmd_pcs { TRB_CYCLE_BIT } else { 0 });
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
            self.keyboard_ep = Some(ep_info);
            println!(
                "[xhci  ] HID interrupt endpoint configured: slot={} ep_addr={:#04x} mps={}",
                slot_id, ep_info.endpoint_address, ep_info.max_packet_size
            );
            Ok(())
        }

        /// Probe a mass storage device at the given slot: read config descriptor,
        /// find bulk endpoints, configure them, and initialise the MSC driver.
        pub unsafe fn init_msd(&mut self, slot_id: u8) -> crate::Result<()> {
            use crate::kernel::drivers::usb_msd::{
                self, MsdBulkEndpoints, USB_CLASS_MSC, USB_PROTOCOL_BOT, USB_SUBCLASS_SCSI,
            };

            // Read the full configuration descriptor (first 9 bytes for header).
            let mut header_buf = [0u8; 9];
            let setup9 = super::SetupPacket::get_descriptor_configuration(9);
            self.control_transfer(slot_id, &setup9, &mut header_buf, true)?;
            let total_len = u16::from_le_bytes([header_buf[2], header_buf[3]]) as usize;
            if !(9..=4096).contains(&total_len) {
                println!(
                    "[xhci  ] msd: invalid config descriptor length {}",
                    total_len
                );
                return Err(crate::Error::InvalidArgument);
            }

            // Read the full config descriptor.
            let mut config_buf = alloc::vec![0u8; total_len];
            let setup_full = super::SetupPacket::get_descriptor_configuration(total_len as u16);
            self.control_transfer(slot_id, &setup_full, &mut config_buf, true)?;

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
                        // Scan this interface's endpoints.
                        let mut pos = i + dlen;
                        for _ in 0..num_eps {
                            if pos + 6 >= config_buf.len() {
                                break;
                            }
                            if config_buf[pos + 1] == 5 && pos + 5 < config_buf.len() {
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
            let setup_cfg = super::SetupPacket::set_configuration(config_val);
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
            usb_msd::init_msd(endpoints)
        }

        /// Configure a bulk endpoint for a USB device (second part).
        /// `direction_in`: true for IN, false for OUT.
        pub unsafe fn configure_bulk_endpoint(
            &mut self,
            slot_id: u8,
            ep_addr: u8,
            max_packet_size: u16,
            direction_in: bool,
        ) -> Result<()> {
            let idx = slot_id as usize - 1;
            let dev_ctx = self.device_contexts[idx]
                .as_ref()
                .ok_or(crate::Error::InvalidArgument)?;
            let ctx_size = self.context_size as usize;
            let ep_num = (ep_addr & 0x0F) as usize;

            let bulk_ring = DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?;
            let bulk_ring_phys = bulk_ring.phys_addr() as u64;
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;
            unsafe {
                let link_ptr = ring_trb_ptr(&bulk_ring, link_idx);
                write_volatile(link_ptr, Trb::link(bulk_ring_phys, TRB_CYCLE_BIT));
            }

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

            // ICC: add bit for all contexts up to ctx_index.
            unsafe {
                let icc = ict_base as *mut u32;
                let mut add_flags: u32 = 0;
                for i in 0..=ctx_index {
                    add_flags |= 1 << i;
                }
                write_volatile(icc, add_flags);
            }

            // Copy slot + EP0 contexts from output.
            let out_ctx_base = dev_ctx.as_ptr();
            unsafe {
                core::ptr::copy_nonoverlapping(out_ctx_base, ict_base.add(ctx_size), ctx_size * 2);
            }

            // Set up the bulk endpoint context at the correct DCI offset.
            let ep_offset = (ctx_index + 1) * ctx_size;
            unsafe {
                let ep_ctx = ict_base.add(ep_offset) as *mut u32;
                write_volatile(ep_ctx, 0);
                let ep_ctrl: u32 = 2 | ((max_packet_size as u32 & 0xFFFF) << 8);
                write_volatile(ep_ctx.add(1), ep_ctrl);
                let tr_dq = bulk_ring_phys | TRB_CYCLE_BIT as u64;
                write_volatile(ep_ctx.add(2), tr_dq as u32);
                write_volatile(ep_ctx.add(3), (tr_dq >> 32) as u32);
                write_volatile(ep_ctx.add(4), max_packet_size as u32);
            }

            let ict_phys = ict.phys_addr() as u64;
            let trb =
                Trb::configure_endpoint(ict_phys, if self.cmd_pcs { TRB_CYCLE_BIT } else { 0 });
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

        /// Submit a Normal TRB on a bulk ring and wait for completion.
        unsafe fn submit_bulk_trb(
            &mut self,
            slot_id: u8,
            ep_addr: u8,
            data_phys: u64,
            length: u32,
            direction_in: bool,
        ) -> Result<()> {
            let idx = slot_id as usize - 1;
            let ep_num = (ep_addr & 0x0F) as usize;
            let dci = if direction_in {
                2u32 * ep_num as u32 + 1
            } else {
                2u32 * ep_num as u32
            };

            let ring = if direction_in {
                self.bulk_in_rings[idx]
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgument)?
            } else {
                self.bulk_out_rings[idx]
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgument)?
            };
            let ring_base = ring.as_ptr() as *mut Trb;
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;

            // Clear ring (except link).
            for i in 0u32..link_idx {
                write_volatile(ring_base.add(i as usize), Trb::zeroed());
            }

            let trb_flags = if direction_in { TRB_DIR_IN } else { 0 };
            let normal_trb = Trb {
                parameter: data_phys,
                status: length & TRB_TL_MASK,
                control: trb_control(trb_type::NORMAL, TRB_CYCLE_BIT) | TRB_IOC | trb_flags,
            };
            write_volatile(ring_base, normal_trb);

            // Ring doorbell.
            let db_val = slot_id as u32 * DOORBELL_STRIDE as u32 + dci;
            write_volatile(self.doorbell_base.add(db_val as usize / 4), db_val);

            // Poll for transfer event.
            self.poll_transfer_event()?;
            Ok(())
        }

        /// Send data on a bulk OUT endpoint.
        pub unsafe fn bulk_send(&mut self, ep_addr: u8, data: &[u8]) -> Result<()> {
            let slot_id = if self.msd_slot != 0 {
                self.msd_slot
            } else {
                return Err(crate::Error::InvalidArgument);
            };
            let nframes = data.len().div_ceil(4096);
            let buf = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            let phys = buf.phys_addr() as u64;
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buf.as_ptr(), data.len());
            }
            self.submit_bulk_trb(slot_id, ep_addr, phys, data.len() as u32, false)?;
            Ok(())
        }

        /// Receive data on a bulk IN endpoint.
        pub unsafe fn bulk_recv(&mut self, ep_addr: u8, buffer: &mut [u8]) -> Result<()> {
            let slot_id = if self.msd_slot != 0 {
                self.msd_slot
            } else {
                return Err(crate::Error::InvalidArgument);
            };
            let nframes = buffer.len().div_ceil(4096);
            let buf = DmaBuffer::allocate(nframes).ok_or(crate::Error::OutOfMemory)?;
            let phys = buf.phys_addr() as u64;
            self.submit_bulk_trb(slot_id, ep_addr, phys, buffer.len() as u32, true)?;
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), buffer.as_mut_ptr(), buffer.len());
            }
            Ok(())
        }

        /// Submit a Normal TRB on the interrupt transfer ring to receive a HID report.
        /// Returns the number of bytes received.
        pub unsafe fn poll_hid_report(&mut self, slot_id: u8, buf: &mut [u8; 8]) -> Result<usize> {
            let idx = slot_id as usize - 1;
            let int_ring = self.int_transfer_rings[idx]
                .as_ref()
                .ok_or(crate::Error::InvalidArgument)?;

            let _ring_phys = int_ring.phys_addr() as u64;
            let ring_base = int_ring.as_ptr() as *mut Trb;
            let link_idx = (RING_SEGMENT_TRBS - 1) as u32;

            // Reuse or lazily allocate the pre-allocated HID report DMA buffer.
            if self.hid_report_buf.is_none() {
                self.hid_report_buf =
                    Some(DmaBuffer::allocate(1).ok_or(crate::Error::OutOfMemory)?);
            }
            // Snapshot the physical address before the mutable borrow on
            // poll_transfer_event below — the immutable borrow on
            // hid_report_buf must not overlap with the &mut self call.
            let data_phys = self.hid_report_buf.as_ref().unwrap().phys_addr() as u64;

            // Clear the ring and set up one Normal TRB + Link.
            for i in 0u32..link_idx {
                unsafe {
                    write_volatile(ring_base.add(i as usize), Trb::zeroed());
                }
            }

            // Normal TRB for interrupt IN transfer.
            let normal_trb = Trb {
                parameter: data_phys,
                status: 8, // 8 bytes for boot protocol keyboard report
                control: trb_control(trb_type::NORMAL, TRB_CYCLE_BIT) | TRB_IOC,
            };
            unsafe {
                write_volatile(ring_base, normal_trb);
            }

            // Ring doorbell for the interrupt endpoint.
            // DCI = 3 for EP1 IN (context index 3).
            let dci: u32 = 3; // EP1 IN
            let db_val = slot_id as u32 * DOORBELL_STRIDE as u32 + dci;
            unsafe {
                write_volatile(self.doorbell_base.add(db_val as usize / 4), db_val);
            }

            // Poll for transfer event.
            let _residual = self.poll_transfer_event()?;

            // Copy data from the reusable DMA buffer (fresh immutable borrow
            // after poll_transfer_event's mutable borrow has ended).
            let src = self.hid_report_buf.as_ref().unwrap().as_ptr();
            let len = 8usize;
            unsafe {
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
            }

            // The DMA buffer is retained in self.hid_report_buf — no allocation
            // or free on each poll. poll_transfer_event ensures the transfer is
            // complete before we reuse the buffer.
            Ok(8)
        }

        /// Poll the event ring for any pending events.
        /// Called from the timer tick to check for HID reports.
        /// Returns true if a keyboard report was processed.
        pub unsafe fn poll_events(&mut self) -> bool {
            if self.keyboard_slot == 0 {
                return false;
            }
            // Quick check: is there a new event?
            let evt_ptr = ring_trb_ptr(&self.event_ring, self.evt_dequeue);
            let evt = read_volatile(evt_ptr);
            let evt_cycle = evt.cycle_bit();
            let expected_cycle = if self.evt_ccs { TRB_CYCLE_BIT } else { 0 };

            if evt_cycle != expected_cycle {
                return false;
            }

            // Process event(s).
            let mut processed = false;
            loop {
                let evt_ptr2 = ring_trb_ptr(&self.event_ring, self.evt_dequeue);
                let evt2 = read_volatile(evt_ptr2);
                let evt2_cycle = evt2.cycle_bit();
                let expected2 = if self.evt_ccs { TRB_CYCLE_BIT } else { 0 };
                if evt2_cycle != expected2 {
                    break;
                }

                let trb_type = evt2.trb_type();
                self.evt_dequeue += 1;
                if self.evt_dequeue >= (RING_SEGMENT_TRBS as u32) - 1 {
                    self.evt_ccs = !self.evt_ccs;
                    self.evt_dequeue = 0;
                }

                if trb_type == trb_type::TRANSFER_EVENT {
                    processed = true;
                }

                // Update ERDP.
                let erdp = self.event_ring.phys_addr() as u64
                    + (self.evt_dequeue as u64 * TRB_SIZE as u64);
                reg_write64_lo_hi(
                    self.runtime_base,
                    XHCI_RT_IR_BASE + XHCI_RT_ERDP_LOW,
                    XHCI_RT_IR_BASE + XHCI_RT_ERDP_HIGH,
                    erdp | (if self.evt_ccs { 1u64 << 3 } else { 0 }),
                );
            }

            if processed {
                // Re-submit the Normal TRB for the next report.
                if let Some(ref _ep_info) = self.keyboard_ep {
                    let mut report_buf = [0u8; 8];
                    if self
                        .poll_hid_report(self.keyboard_slot, &mut report_buf)
                        .is_ok()
                    {
                        // Process the report via the USB HID scancode mapper.
                        crate::kernel::drivers::usb_hid::handle_keyboard_report(&report_buf);
                    }
                }
            }

            processed
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::Mutex;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use controller::XhciController;

// ---------------------------------------------------------------------------
// Global xHCI controller instance (bare-metal only)
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static XHCI_CONTROLLER: Mutex<Option<XhciController>> = Mutex::new(None);

/// Try to take a lock on the global XHCI controller and run a closure.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn with_controller<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut XhciController) -> R,
{
    let mut guard = XHCI_CONTROLLER.lock();
    guard.as_mut().map(f)
}

/// Poll the xHCI event ring (called from timer tick).
/// Returns true if keyboard input was processed.
pub fn xhci_poll() -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if let Some(guard) = XHCI_CONTROLLER.lock().as_mut() {
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

use crate::kernel::drivers::{Driver, DriverCategory};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// Find xHCI USB controllers, initialise the first one found.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_xhci() -> crate::Result<()> {
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::kernel::drivers::usb_hid;
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

        println!(
            "[xhci  ] BAR0: phys={:#018x} size={} KiB",
            bar0.base_address,
            bar0.size / 1024
        );

        // Initialise the controller.
        let mut ctrl = match unsafe { XhciController::new(bar0.base_address, bar0.size as usize) } {
            Some(c) => c,
            None => {
                println!("[xhci  ] controller initialisation failed — skipping");
                continue;
            }
        };

        // Enable a slot and address the device.
        match unsafe { ctrl.enable_slot() } {
            Ok(slot_id) => {
                println!("[xhci  ] enabled slot {}", slot_id);

                // Allocate resources for this slot.
                if unsafe { ctrl.alloc_slot_resources(slot_id) }.is_err() {
                    println!("[xhci  ] failed to allocate slot resources");
                    continue;
                }

                // Address the device.
                if unsafe { ctrl.address_device(slot_id) }.is_err() {
                    println!("[xhci  ] address_device failed for slot {}", slot_id);
                    continue;
                }
                println!("[xhci  ] device addressed at slot {}", slot_id);

                // Read the device descriptor.
                match unsafe { ctrl.get_device_descriptor(slot_id) } {
                    Ok(desc) => {
                        // Copy packed fields to locals to avoid unaligned references.
                        let dev_class = desc.device_class;
                        let dev_subclass = desc.device_subclass;
                        let dev_proto = desc.device_protocol;
                        let vid = { desc.vendor_id };
                        let pid = { desc.product_id };
                        println!(
                            "[xhci  ] device descriptor: class={:#04x} sub={:#04x} proto={:#04x} vid={:04x} pid={:04x}",
                            dev_class, dev_subclass, dev_proto, vid, pid
                        );

                        // Check if this is a HID keyboard.
                        if dev_class == usb_hid::USB_CLASS_HID
                            || (dev_class == 0
                                && dev_subclass == usb_hid::USB_SUBCLASS_BOOT
                                && dev_proto == usb_hid::USB_PROTOCOL_KEYBOARD)
                        {
                            println!("[xhci  ] HID keyboard detected at slot {}", slot_id);

                            // For a boot-protocol HID keyboard on QEMU:
                            // The standard configuration has one interface (HID, boot,
                            // keyboard) with one interrupt IN endpoint (EP 1 IN, 8 bytes,
                            // interval typically 10–12). We use known working defaults.
                            let ep_info = HidEndpointInfo {
                                endpoint_address: 0x81, // EP 1 IN
                                max_packet_size: 8,
                                interval: 10,
                                interface_number: 0,
                            };

                            if unsafe { ctrl.configure_hid_endpoint(slot_id, ep_info) }.is_ok() {
                                ctrl.keyboard_slot = slot_id;
                                println!("[xhci  ] HID keyboard ready at slot {}", slot_id);
                            }
                        } else if dev_class == crate::kernel::drivers::usb_msd::USB_CLASS_MSC
                            || (dev_class == 0
                                && dev_subclass
                                    == crate::kernel::drivers::usb_msd::USB_SUBCLASS_SCSI)
                        {
                            // USB Mass Storage device — read config descriptor.
                            println!("[xhci  ] mass storage device detected at slot {}", slot_id);
                            if let Ok(()) = unsafe { ctrl.init_msd(slot_id) } {
                                println!("[xhci  ] mass storage initialised at slot {}", slot_id);
                            }
                        }
                    }
                    Err(e) => {
                        println!("[xhci  ] get_device_descriptor failed: {}", e.as_str());
                    }
                }
            }
            Err(e) => {
                println!("[xhci  ] enable_slot failed: {}", e.as_str());
            }
        }

        // Store the controller.
        *XHCI_CONTROLLER.lock() = Some(ctrl);

        // Only initialise the first xHCI controller.
        break;
    }
    if !found {
        println!("[xhci  ] no xHCI controllers found");
    }
    Ok(())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn probe_xhci() -> crate::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trb_size_is_16() {
        assert_eq!(core::mem::size_of::<Trb>(), 16);
    }

    #[test]
    fn usb_device_descriptor_size_is_18() {
        assert_eq!(core::mem::size_of::<UsbDeviceDescriptor>(), 18);
    }

    #[test]
    fn xhci_register_offsets_are_valid() {
        const {
            assert!(XHCI_CAP_CAPLENGTH < 0x100);
            assert!(XHCI_CAP_HCSPARAMS1 < 0x100);
            assert!(XHCI_OP_USBCMD < 0x100);
        }
    }

    #[test]
    fn usb_command_bits() {
        assert_ne!(USBCMD_RS, 0);
        assert_ne!(USBCMD_HCRST, 0);
        assert_ne!(USBSTS_HCH, 0);
        assert_ne!(USBSTS_CNR, 0);
    }

    #[test]
    fn trb_type_constants() {
        assert_eq!(trb_type::NORMAL, 1);
        assert_eq!(trb_type::ENABLE_SLOT, 9);
        assert_eq!(trb_type::ADDRESS_DEVICE, 11);
        assert_eq!(trb_type::CONFIGURE_ENDPOINT, 12);
        assert_eq!(trb_type::TRANSFER_EVENT, 32);
        assert_eq!(trb_type::COMMAND_COMPLETION_EVENT, 33);
    }

    #[test]
    fn trb_control_build() {
        let ctrl = trb_control(trb_type::NO_OP, TRB_CYCLE_BIT);
        assert_eq!(ctrl & TRB_CYCLE_BIT, TRB_CYCLE_BIT);
        assert_eq!((ctrl >> TRB_TYPE_SHIFT) & 0x3F, trb_type::NO_OP);
    }

    #[test]
    fn setup_packet_get_descriptor() {
        let sp = SetupPacket::get_descriptor_device(18);
        // Copy packed fields to locals to avoid unaligned references.
        let bmrt = { sp.bm_request_type };
        let br = { sp.b_request };
        let wv = { sp.w_value };
        let wl = { sp.w_length };
        assert_eq!(bmrt, 0x80);
        assert_eq!(br, 6);
        assert_eq!(wv, 0x0100); // descriptor type 1, index 0
        assert_eq!(wl, 18);
    }

    #[test]
    fn trb_zeroed() {
        let t = Trb::zeroed();
        assert_eq!(t.parameter, 0);
        assert_eq!(t.status, 0);
        assert_eq!(t.control, 0);
        assert_eq!(t.cycle_bit(), 0);
    }

    #[test]
    fn trb_link() {
        let link = Trb::link(0xDEAD_BEEF, TRB_CYCLE_BIT);
        assert_eq!(link.parameter, 0xDEAD_BEEF);
        assert_eq!(link.trb_type(), trb_type::LINK);
        assert_eq!(link.cycle_bit(), TRB_CYCLE_BIT);
    }

    #[test]
    fn completion_code_extraction() {
        let mut trb = Trb::zeroed();
        trb.status = cc::SUCCESS << 24;
        assert_eq!(trb.completion_code(), cc::SUCCESS);

        trb.status = cc::TRB_ERROR << 24;
        assert_eq!(trb.completion_code(), cc::TRB_ERROR);
    }

    #[test]
    fn erst_entry_layout() {
        let entry = ErstEntry::new(0x1234_5678_9ABC, 256);
        assert_eq!(entry.segment_base_low, 0x5678_9ABC);
        assert_eq!(entry.segment_base_high, 0x1234);
        assert_eq!(entry.segment_size, 256);
    }
}
