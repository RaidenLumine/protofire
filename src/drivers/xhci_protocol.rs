//! src/drivers/xhci_protocol.rs
//!
//! The xHCI register map and the USB structures the driver speaks in.
//!
//! Command/event/transfer rings, port registers, descriptors, setup packets:
//! these are the specification's layouts, not hardware.  They compile — and
//! their size and offset checks run — everywhere, while the controller that
//! drives them is compiled where the machine has one.

// ---------------------------------------------------------------------------
// PCI identifiers
// ---------------------------------------------------------------------------

/// xHCI class code (USB 3.0 host controller).
pub const XHCI_CLASS: u8 = 0x0C;
/// xHCI subclass.
pub const XHCI_SUBCLASS: u8 = 0x03;
/// xHCI programming interface (0x30 = xHCI, 0x20 = EHCI, 0x10 = OHCI, 0x00 =
/// UHCI).
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
pub const HCSPARAMS1_MAX_PORTS_MASK: u32 = 0xFF00_0000;
// MaxPorts lives in bits 31:24 of HCSPARAMS1 (Linux `HCS_MAX_PORTS` and the
// xHCI spec; QEMU's hcd-xhci also uses `numports << 24`).
pub const HCSPARAMS1_MAX_PORTS_SHIFT: u32 = 24;

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
// Port Status and Control registers (PORTSC), offset from the operational
// base.  Port n's PORTSC lives at XHCI_OP_PORTSC + (n-1) * 0x10.
// ---------------------------------------------------------------------------

pub const XHCI_OP_PORTSC: usize = 0x400;
/// PORTSC: Current Connect Status (a device is attached to this port).
pub const PORTSC_CCS: u32 = 1 << 0;
/// PORTSC: Port Enabled/Disabled.
pub const PORTSC_PED: u32 = 1 << 1;
/// PORTSC: Port Reset.  Set by software to reset (and, for a USB2 port, to
/// enable) the device on the port; the controller clears it when the reset
/// finishes and raises the port reset *change* bit.
pub const PORTSC_PR: u32 = 1 << 4;
/// PORTSC: Port Power.
pub const PORTSC_PP: u32 = 1 << 9;
/// PORTSC: Port Speed, bits 13:10 (0 = full, 1 = low, 2 = high, 3 = super).
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_SPEED_MASK: u32 = 0x0F << PORTSC_SPEED_SHIFT;

/// PORTSC: the change bits in the upper half of the register.
///
/// These are write-1-to-clear, and they are also how the controller decides
/// whether a *new* change is worth an event: it raises an event when a change
/// bit goes from clear to set, so a bit this driver never clears is a port
/// whose next attach or detach says nothing.
pub const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change
pub const PORTSC_PEC: u32 = 1 << 18; // Port Enabled/Disabled Change
pub const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change
pub const PORTSC_OCC: u32 = 1 << 20; // Over-Current Change
pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change
pub const PORTSC_PLC: u32 = 1 << 22; // Port Link State Change
pub const PORTSC_CEC: u32 = 1 << 23; // Port Config Error Change
/// Every change bit above, for the one write that clears them.
pub const PORTSC_CHANGE_BITS: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

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
/// TRB control field: Link TRB Toggle Cycle (bit 1).  A consumer that
/// follows a Link TRB with this bit set inverts its cycle state, which is
/// what lets a ring be reused for a second lap.
pub const TRB_LINK_TC: u32 = 1 << 1;
/// TRB control field: TRB type shift (bits 10:16).
pub const TRB_TYPE_SHIFT: u32 = 10;
/// TRB control field: Chain bit (bit 4) — link TRBs in a transfer.
pub const TRB_CHAIN_BIT: u32 = 1 << 4;
/// TRB control field: Interrupt On Completion (bit 5).
pub const TRB_IOC: u32 = 1 << 5;
/// TRB control field: Immediate Data (bit 6) — Setup Stage TRBs carry the
/// 8-byte setup packet in their parameter field and must set this.
pub const TRB_IDT: u32 = 1 << 6;
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
/// Descriptor type: Hub = 0x29.  A hub reports its port count here rather than
/// through an endpoint, which is why a hub is brought up by control transfers
/// alone.
pub const DESC_HUB: u8 = 0x29;

// ---------------------------------------------------------------------------
// USB hub class (a hub's own requests, USB 2.0 §11.24)
// ---------------------------------------------------------------------------

/// bDeviceClass / bInterfaceClass of a hub.
pub const USB_CLASS_HUB: u8 = 0x09;

/// bmRequestType for a class request about the device itself, device-to-host.
pub const REQ_CLASS_DEVICE_TO_HOST: u8 = 0xA0;
/// bmRequestType for a class request about another recipient, host-to-device —
/// what a port feature is set and cleared through.
pub const REQ_CLASS_HOST_TO_DEVICE_OTHER: u8 = 0x23;
/// bmRequestType for a class request about another recipient, device-to-host.
pub const REQ_CLASS_DEVICE_TO_HOST_OTHER: u8 = 0xA3;

pub const REQ_CLEAR_FEATURE: u8 = 1;
pub const REQ_SET_FEATURE: u8 = 3;

/// Hub class features a port is asked about, from USB 2.0 §11.24.2.
pub const HUB_PORT_CONNECTION: u16 = 0;
pub const HUB_PORT_ENABLE: u16 = 1;
pub const HUB_PORT_RESET: u16 = 4;
pub const HUB_PORT_POWER: u16 = 8;
/// The change bits, cleared once the change has been handled.
///
/// These are feature *selectors*, and the last of them is not where the
/// pattern of the others suggests: the port reset's own selector is 4, its
/// change bit is 20, and 21 is the test feature a hub is never asked for.
/// Clearing 21 on a hub that follows the class specification is answered
/// with a stall — which halts the endpoint the request went out on, so every
/// later request on it is queued and never seen.  (`wPortChange` bit 20, the
/// one [`HUB_PORT_CHANGE_RESET`] names, is a different thing: a bit position
/// in the status pair the hub *reports*, not a selector the host sends.)
pub const HUB_C_PORT_CONNECTION: u16 = 16;
pub const HUB_C_PORT_ENABLE: u16 = 17;
pub const HUB_C_PORT_SUSPEND: u16 = 18;
pub const HUB_C_PORT_OVERCURRENT: u16 = 19;
pub const HUB_C_PORT_RESET: u16 = 20;

/// `wPortStatus` bits (USB 2.0 §11.24.2.7).
pub const HUB_PORT_STATUS_CONNECTION: u16 = 1 << 0;
pub const HUB_PORT_STATUS_ENABLE: u16 = 1 << 1;
pub const HUB_PORT_STATUS_POWER: u16 = 1 << 9;
pub const HUB_PORT_STATUS_LOW_SPEED: u16 = 1 << 10;
/// `wPortChange` bit 4: the reset finished.  It sits in the second word, so it
/// is read as bit 20 of the 32-bit status pair.
pub const HUB_PORT_CHANGE_RESET: u32 = 1 << 20;

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
            w_index: 0,                           /* 0 for device descriptor (language for string
                                                   * desc) */
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

    /// The hub descriptor: how many downstream ports the hub has.
    pub const fn hub_descriptor(length: u16) -> Self {
        Self {
            bm_request_type: REQ_CLASS_DEVICE_TO_HOST,
            b_request: REQ_GET_DESCRIPTOR,
            w_value: (DESC_HUB as u16) << 8,
            w_index: 0,
            w_length: length,
        }
    }

    /// One port's status and change bits: four bytes, `wPortStatus` then
    /// `wPortChange`.
    pub const fn hub_port_status(port: u8) -> Self {
        Self {
            bm_request_type: REQ_CLASS_DEVICE_TO_HOST_OTHER,
            b_request: 0, // GET_STATUS
            w_value: 0,
            w_index: port as u16,
            w_length: 4,
        }
    }

    /// Ask a hub to set one of its port features — power, or a reset.
    pub const fn hub_set_port_feature(port: u8, feature: u16) -> Self {
        Self {
            bm_request_type: REQ_CLASS_HOST_TO_DEVICE_OTHER,
            b_request: REQ_SET_FEATURE,
            w_value: feature,
            w_index: port as u16,
            w_length: 0,
        }
    }

    /// Clear a port's change bit, which is how the hub is told the change was
    /// handled.
    pub const fn hub_clear_port_feature(port: u8, feature: u16) -> Self {
        Self {
            bm_request_type: REQ_CLASS_HOST_TO_DEVICE_OTHER,
            b_request: REQ_CLEAR_FEATURE,
            w_value: feature,
            w_index: port as u16,
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

    /// Create a Link TRB pointing to `ring_addr` (physical), with Toggle
    /// Cycle set: the consumer inverts its cycle state when it follows it.
    /// The caller decides which state the link carries — for a producer ring,
    /// the lap that is ending — and that choice is `RingPos` in `xhci.rs`.
    pub fn link(ring_addr: u64, cycle: u32) -> Self {
        Self {
            parameter: ring_addr,
            status: 0,
            control: trb_control(trb_type::LINK, cycle) | TRB_LINK_TC,
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

    /// Create an Enable Slot command TRB for a root hub port.
    /// The Root Hub Port Number lives in bits 15:0 of the parameter field.
    pub fn enable_slot(cycle: u32, root_port: u8) -> Self {
        Self {
            parameter: root_port as u64,
            status: 0,
            control: trb_control(trb_type::ENABLE_SLOT, cycle),
        }
    }

    /// Create an Address Device command TRB.
    /// `ict_phys`: physical address of the Input Context.
    /// `slot_id`: the slot being addressed, encoded in control bits 24:31.
    /// `bsr`: Block Set Address Request (0 = send SET_ADDRESS, 1 = block),
    /// held in status bit 0.
    pub fn address_device(ict_phys: u64, slot_id: u8, bsr: bool, cycle: u32) -> Self {
        Self {
            parameter: ict_phys,
            status: if bsr { 1 } else { 0 },
            control: trb_control(trb_type::ADDRESS_DEVICE, cycle) | ((slot_id as u32) << 24),
        }
    }

    /// Create a Disable Slot command TRB.
    ///
    /// A device that leaves the bus does not take its slot with it: the
    /// controller keeps the slot's contexts and its endpoint state until the
    /// host says so, and the slot number it holds cannot address a different
    /// device until then.
    pub fn disable_slot(slot_id: u8, cycle: u32) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: trb_control(trb_type::DISABLE_SLOT, cycle) | ((slot_id as u32) << 24),
        }
    }

    /// Create a Configure Endpoint command TRB.
    /// `slot_id` is encoded in control bits 24:31.
    pub fn configure_endpoint(ict_phys: u64, slot_id: u8, cycle: u32) -> Self {
        Self {
            parameter: ict_phys,
            status: 0,
            control: trb_control(trb_type::CONFIGURE_ENDPOINT, cycle) | ((slot_id as u32) << 24),
        }
    }

    pub fn cycle_bit(&self) -> u32 {
        self.control & TRB_CYCLE_BIT
    }

    /// Completion code from a Command Completion Event TRB (bits 24:31 of
    /// status).
    pub fn completion_code(&self) -> u32 {
        (self.status >> 24) & 0xFF
    }

    /// Slot ID from a Command Completion Event TRB (bits 24:31 of control).
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// Port ID from a Port Status Change Event TRB.
    ///
    /// It sits in bits 24:31 of the *parameter* field, which is the field a
    /// transfer event spends on the TRB it completed — the two event kinds
    /// share the layout but not what its halves mean, and the status word's
    /// top byte is this event's completion code rather than its port.
    pub fn port_id(&self) -> u8 {
        ((self.parameter >> 24) & 0xFF) as u8
    }

    /// Endpoint ID (DCI) from a Transfer Event TRB (bits 16:20 of control).
    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
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
pub struct ErstEntry {
    segment_base_low: u32,
    segment_base_high: u32,
    segment_size: u32,
    _reserved: u32,
}

impl ErstEntry {
    pub fn new(base_phys: u64, segment_trb_count: u16) -> Self {
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

/// Parsed information about a HID interrupt IN endpoint.
#[derive(Debug, Clone, Copy)]
pub struct HidEndpointInfo {
    pub endpoint_address: u8,
    pub max_packet_size: u16,
    pub interval: u8,
    pub interface_number: u8,
    /// Bytes per boot-protocol input report.
    pub report_len: usize,
}

impl HidEndpointInfo {
    /// The doorbell Device Context Index for this interrupt IN endpoint.
    /// xHCI maps an IN endpoint N to DCI 2*N+1.
    pub const fn dci(&self) -> u32 {
        2u32 * (self.endpoint_address & 0x0F) as u32 + 1
    }
}

/// The endpoint context's `Interval` field for an interrupt endpoint, from
/// the descriptor's `bInterval`.
///
/// The field holds the *exponent* of the endpoint's poll period, not the
/// period: `2^interval` microframes for a high-speed endpoint, and `2^interval`
/// milliseconds for a low- or full-speed one.  So `bInterval` and the field
/// are not the same number, and the conversion rounds the descriptor's value
/// *down to a power of two* — the hub's 255 ms becomes 2^7 = 128 ms, a
/// keyboard's 10 ms becomes 2^3 = 8 ms — which is the same rounding the
/// controller's own scheduler applies and the same one Linux applies to
/// interrupt endpoints at both speeds (`fls(bInterval) - 1`).
///
/// Copying the byte across instead, which is what this driver used to do, is
/// not a rounding error but a different number: a hub's 255 becomes a shift
/// of 255, which schedules the next check of a status-change endpoint days
/// away, and a keyboard's ten becomes a poll twenty times faster than it
/// asked for.
pub const fn endpoint_interval_field(b_interval: u8) -> u32 {
    if b_interval == 0 {
        // The field's own "as soon as possible" value; only a SuperSpeed
        // endpoint may ask for it, and the exponent of 0 is 1 microframe.
        return 0;
    }
    (u8::BITS - b_interval.leading_zeros()) - 1
}

/// How many tiers a route string names: one nibble per hub port the device is
/// behind, and zero for a device on a root port.
pub const fn route_tiers(route: u32) -> u32 {
    let mut tiers = 0;
    let mut rest = route;
    while rest != 0 {
        tiers += 1;
        rest >>= 4;
    }
    tiers
}

/// The mask over the first `tiers` nibbles of a route string.
///
/// A device's route is the path of hub ports from the root to it, one nibble
/// per tier with the first tier in the lowest nibble, so one route is *behind*
/// another exactly when the other's nibbles are its low ones: masking a route
/// to that many nibbles leaves the route above it.  A hub that leaves the bus
/// takes everything behind it, which is what that question is asked for.
pub const fn route_prefix_mask(tiers: u32) -> u32 {
    if tiers == 0 {
        0
    } else {
        (1u32 << (4 * tiers)) - 1
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_strings_name_their_tiers() {
        assert_eq!(route_tiers(0), 0); // a root port
        assert_eq!(route_tiers(0x1), 1); // a hub's first port
        assert_eq!(route_tiers(0x21), 2); // port 1 of a hub on a hub's port 2
        assert_eq!(route_prefix_mask(0), 0);
        assert_eq!(route_prefix_mask(1), 0xF);
        assert_eq!(route_prefix_mask(2), 0xFF);
        // "behind" is the prefix relation the whole subtree is found by.
        let behind =
            |route: u32, above: u32| (route & route_prefix_mask(route_tiers(above))) == above;
        assert!(behind(0x11, 0x1)); // two tiers under port 1
        assert!(behind(0x21, 0x1)); // and so is a second tier on port 1
        assert!(!behind(0x12, 0x1)); // first tier is port 2, not port 1
        assert!(behind(0x1, 0x1));
        assert!(behind(0x11, 0)); // everything on a root port is behind it
    }

    #[test]
    fn endpoint_interval_is_the_exponent_of_the_period() {
        // A high-speed endpoint's bInterval is already an exponent (2^n
        // microframes); a low/full-speed one is a period in milliseconds and
        // rounds down to the power of two below it.
        assert_eq!(endpoint_interval_field(1), 0); // 1 ms / 1 uframe
        assert_eq!(endpoint_interval_field(2), 1);
        assert_eq!(endpoint_interval_field(8), 3); // 8 ms
        assert_eq!(endpoint_interval_field(10), 3); // 10 ms rounds to 8
        assert_eq!(endpoint_interval_field(16), 4);
        assert_eq!(endpoint_interval_field(255), 7); // a hub: 128 ms
                                                     // Zero is the "no delay" encoding, not an underflow.
        assert_eq!(endpoint_interval_field(0), 0);
        // And the byte the driver used to write across is not this number.
        assert_ne!(endpoint_interval_field(255), 255u32);
    }

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
        let link = Trb::link(0xDEAD_BEEF, 0);
        assert_eq!(link.parameter, 0xDEAD_BEEF);
        assert_eq!(link.trb_type(), trb_type::LINK);
        // The link carries no cycle of its own until the producer writes one:
        // a fresh ring's link is written with the state *opposite* the lap in
        // progress, and Toggle Cycle is always set so the consumer's state
        // flips in step with the producer's.
        assert_eq!(link.cycle_bit(), 0);
        assert_eq!(link.control & TRB_LINK_TC, TRB_LINK_TC);

        let toggling = Trb::link(0xDEAD_BEEF, TRB_CYCLE_BIT);
        assert_eq!(toggling.cycle_bit(), TRB_CYCLE_BIT);
        assert_eq!(toggling.control & TRB_LINK_TC, TRB_LINK_TC);
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
