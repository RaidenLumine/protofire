//! src/kernel/drivers/usb_hid.rs
//!
//! USB Human Interface Device (keyboard/mouse) driver.
//! USB HID (Human Interface Device) driver — boot protocol keyboard/mouse.
//!
//! Parses USB HID boot protocol keyboard reports (mapping HID keycodes to
//! PS/2 Set 1 scancodes for the keyboard core) and mouse reports (injecting
//! relative motion into the mouse core).  Also owns the real HID device
//! discovery: walking a configuration descriptor for the HID interface's
//! interrupt IN endpoint and classifying the device as keyboard or mouse —
//! the xHCI probe calls [`classify_hid_device`] instead of hard-coding an
//! endpoint.
//!
//! ## Activation
//!
//! Depends on the xHCI controller driver for USB transport.  Both require
//! high-MMIO page mapping for PCI BAR access.

// ---------------------------------------------------------------------------
// USB HID class codes
// ---------------------------------------------------------------------------

pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_PROTOCOL_MOUSE: u8 = 0x02;

// ---------------------------------------------------------------------------
// Boot protocol keyboard report (8 bytes)
// ---------------------------------------------------------------------------

/// USB HID Boot Protocol Keyboard Input Report.
///
/// Byte 0: Modifier keys (bitfield).
/// Byte 1: Reserved (0).
/// Bytes 2–7: Key codes (up to 6 simultaneous keys, 0 = no event).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UsbKeyboardReport {
    pub modifiers: u8,
    _reserved: u8,
    pub keycodes: [u8; 6],
}

// Modifier bits.
pub const MOD_LEFT_CTRL: u8 = 1 << 0;
pub const MOD_LEFT_SHIFT: u8 = 1 << 1;
pub const MOD_LEFT_ALT: u8 = 1 << 2;
pub const MOD_LEFT_GUI: u8 = 1 << 3;
pub const MOD_RIGHT_CTRL: u8 = 1 << 4;
pub const MOD_RIGHT_SHIFT: u8 = 1 << 5;
pub const MOD_RIGHT_ALT: u8 = 1 << 6;
pub const MOD_RIGHT_GUI: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// USB HID to PS/2 scancode mapping (subset — common keys)
// ---------------------------------------------------------------------------

/// Map a USB HID keycode to a PS/2 Set 1 scancode (for integration with
/// the existing keyboard driver).
///
/// Returns 0 if the keycode is not in the mapping table.
pub fn usb_hid_to_scancode_set1(hid_code: u8) -> u8 {
    match hid_code {
        0x04 => 0x1E, // A
        0x05 => 0x30, // B
        0x06 => 0x2E, // C
        0x07 => 0x20, // D
        0x08 => 0x12, // E
        0x09 => 0x21, // F
        0x0A => 0x22, // G
        0x0B => 0x23, // H
        0x0C => 0x17, // I
        0x0D => 0x24, // J
        0x0E => 0x25, // K
        0x0F => 0x26, // L
        0x10 => 0x32, // M
        0x11 => 0x31, // N
        0x12 => 0x18, // O
        0x13 => 0x19, // P
        0x14 => 0x10, // Q
        0x15 => 0x13, // R
        0x16 => 0x1F, // S
        0x17 => 0x14, // T
        0x18 => 0x16, // U
        0x19 => 0x2F, // V
        0x1A => 0x11, // W
        0x1B => 0x2D, // X
        0x1C => 0x15, // Y
        0x1D => 0x2C, // Z
        0x1E => 0x02, // 1
        0x1F => 0x03, // 2
        0x20 => 0x04, // 3
        0x21 => 0x05, // 4
        0x22 => 0x06, // 5
        0x23 => 0x07, // 6
        0x24 => 0x08, // 7
        0x25 => 0x09, // 8
        0x26 => 0x0A, // 9
        0x27 => 0x0B, // 0
        0x28 => 0x1C, // Enter
        0x29 => 0x01, // Escape
        0x2A => 0x0E, // Backspace
        0x2B => 0x0F, // Tab
        0x2C => 0x39, // Space
        0x2D => 0x0C, // Minus
        0x2E => 0x0D, // Equals
        0x2F => 0x1A, // Left Bracket
        0x30 => 0x1B, // Right Bracket
        0x31 => 0x2B, // Backslash
        0x33 => 0x27, // Semicolon
        0x34 => 0x28, // Apostrophe
        0x35 => 0x29, // Grave
        0x36 => 0x33, // Comma
        0x37 => 0x34, // Period
        0x38 => 0x35, // Slash
        0x39 => 0x3A, // Caps Lock
        0x3A => 0x3B, // F1
        0x3B => 0x3C, // F2
        0x3C => 0x3D, // F3
        0x3D => 0x3E, // F4
        0x3E => 0x3F, // F5
        0x3F => 0x40, // F6
        0x40 => 0x41, // F7
        0x41 => 0x42, // F8
        0x42 => 0x43, // F9
        0x43 => 0x44, // F10
        0x44 => 0x57, // F11
        0x45 => 0x58, // F12
        0x4F => 0x4B, // Right Arrow → PS/2 Left Arrow equivalent area
        0x50 => 0x4D, // Left Arrow  → PS/2 Right Arrow equivalent area
        0x51 => 0x50, // Down Arrow
        0x52 => 0x48, // Up Arrow
        0xE0 => 0x1D, // Left Control
        0xE1 => 0x2A, // Left Shift
        0xE2 => 0x38, // Left Alt
        0xE3 => 0x5B, // Left GUI
        0xE4 => 0x1D, // Right Control
        0xE5 => 0x36, // Right Shift
        0xE6 => 0x38, // Right Alt
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Keyboard report processing
// ---------------------------------------------------------------------------

use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

/// Previous keyboard report state for detecting key releases.
static PREV_MODIFIERS: AtomicU8 = AtomicU8::new(0);
static PREV_KEYCODES: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

/// Process a USB HID Boot Protocol keyboard input report (8 bytes).
///
/// Extracts pressed keycodes, maps them to PS/2 Set 1 scancodes, and
/// injects them into the keyboard subsystem via `inject_scancode`.
/// Tracks previous report state to generate break codes for released keys.
pub fn handle_keyboard_report(report: &[u8; 8]) {
    use super::keyboard;

    let modifiers = report[0];
    let prev_mods = PREV_MODIFIERS.swap(modifiers, Ordering::Relaxed);
    let keycodes = &report[2..8]; // bytes 2–7 are up to 6 simultaneous keycodes

    // Release modifier keys that were pressed but are no longer held.
    let released_mods = prev_mods & !modifiers;
    inject_modifier_break(released_mods);

    // Press modifier keys that are now held but weren't before.
    let pressed_mods = modifiers & !prev_mods;
    inject_modifier_make(pressed_mods);

    // Process regular keycodes.
    for i in 0..6 {
        let hid_code = keycodes[i];
        let prev_code = PREV_KEYCODES[i].swap(hid_code, Ordering::Relaxed);

        if prev_code != 0 && prev_code != hid_code {
            // Previous key at this slot was released.
            let sc = usb_hid_to_scancode_set1(prev_code);
            if sc != 0 {
                keyboard::inject_scancode(sc | 0x80); // break code
            }
        }
        if hid_code != 0 {
            let scancode = usb_hid_to_scancode_set1(hid_code);
            if scancode != 0 {
                keyboard::inject_scancode(scancode); // make code
            }
        }
    }
}

fn inject_modifier_make(modifiers: u8) {
    use super::keyboard;
    // Left modifiers: single-byte PS/2 make codes.
    if modifiers & MOD_LEFT_CTRL != 0 {
        keyboard::inject_scancode(0x1D);
    }
    if modifiers & MOD_LEFT_SHIFT != 0 {
        keyboard::inject_scancode(0x2A);
    }
    if modifiers & MOD_LEFT_ALT != 0 {
        keyboard::inject_scancode(0x38);
    }
    // Right modifiers: Right Ctrl/Alt/GUI use E0-prefixed make codes.
    if modifiers & MOD_RIGHT_CTRL != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0x1D);
    }
    if modifiers & MOD_RIGHT_SHIFT != 0 {
        keyboard::inject_scancode(0x36);
    }
    if modifiers & MOD_RIGHT_ALT != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0x38);
    }
    if modifiers & MOD_LEFT_GUI != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0x5B);
    }
    if modifiers & MOD_RIGHT_GUI != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0x5C);
    }
}

fn inject_modifier_break(modifiers: u8) {
    use super::keyboard;
    // Left modifiers: single-byte PS/2 break codes.
    if modifiers & MOD_LEFT_CTRL != 0 {
        keyboard::inject_scancode(0x9D);
    }
    if modifiers & MOD_LEFT_SHIFT != 0 {
        keyboard::inject_scancode(0xAA);
    }
    if modifiers & MOD_LEFT_ALT != 0 {
        keyboard::inject_scancode(0xB8);
    }
    // Right modifiers: break codes with or without E0 prefix.
    if modifiers & MOD_RIGHT_CTRL != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0x9D);
    }
    if modifiers & MOD_RIGHT_SHIFT != 0 {
        keyboard::inject_scancode(0xB6);
    }
    if modifiers & MOD_RIGHT_ALT != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0xB8);
    }
    if modifiers & MOD_LEFT_GUI != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0xDB);
    }
    if modifiers & MOD_RIGHT_GUI != 0 {
        keyboard::inject_scancode(0xE0);
        keyboard::inject_scancode(0xDC);
    }
}

// ---------------------------------------------------------------------------
// Boot protocol mouse report processing
// ---------------------------------------------------------------------------

/// Process a USB HID Boot Protocol mouse input report (up to 4 bytes).
///
/// Byte 0: buttons (bitfield).  Bytes 1–2: signed X/Y deltas.  Byte 3 (when
/// present): wheel.  Relative motion is injected into the mouse core, which
/// the `/system/dev/mouse` device node drains.
pub fn handle_mouse_report(report: &[u8]) {
    if report.len() < 3 {
        return;
    }
    let buttons = report[0];
    let dx = report[1] as i8;
    let dy = report[2] as i8;
    let wheel = if report.len() > 3 { report[3] as i8 } else { 0 };
    super::mouse::inject_motion(buttons, dx, dy, wheel);
}

// ---------------------------------------------------------------------------
// Real HID device discovery (configuration descriptor walking)
// ---------------------------------------------------------------------------

/// Classification of a discovered HID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDeviceKind {
    Keyboard,
    Mouse,
}

/// HID device discovered from a configuration descriptor: the boot-protocol
/// kind plus its interrupt IN endpoint, so the xHCI driver can configure the
/// endpoint and arm the right report length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidDeviceInfo {
    pub kind: HidDeviceKind,
    pub endpoint_address: u8,
    pub max_packet_size: u16,
    pub interval: u8,
    pub interface_number: u8,
    /// Bytes per input report (endpoint max-packet-size, floored to the
    /// boot-protocol minimum for the device kind).
    pub report_len: usize,
}

impl HidDeviceInfo {
    /// Minimum report size for a boot-protocol device kind.
    const fn min_report_len(kind: HidDeviceKind) -> usize {
        match kind {
            HidDeviceKind::Keyboard => 8,
            HidDeviceKind::Mouse => 4,
        }
    }

    /// The doorbell Device Context Index for this interrupt IN endpoint.
    /// xHCI maps an IN endpoint N to DCI 2*N+1.
    pub const fn dci(&self) -> u32 {
        2u32 * (self.endpoint_address & 0x0F) as u32 + 1
    }
}

/// Walk a USB configuration descriptor and classify the HID interface,
/// returning its interrupt IN endpoint.
///
/// `fallback_proto` is the device-descriptor `bDeviceProtocol`, used only when
/// the interface reports protocol 0 (boot-class devices on some emulators
/// leave the interface protocol unset).
///
/// Returns `None` when the configuration has no HID interface with an
/// interrupt IN endpoint.
pub fn classify_hid_device(config: &[u8], fallback_proto: u8) -> Option<HidDeviceInfo> {
    let mut i = 0usize;
    while i + 1 < config.len() {
        let dlen = config[i] as usize;
        if dlen < 2 {
            break;
        }
        let dtype = config[i + 1];
        if dtype == 4 && i + 7 < config.len() {
            // INTERFACE descriptor: bInterfaceNumber=2, bNumEndpoints=4,
            // bInterfaceClass=5, bInterfaceSubClass=6, bInterfaceProtocol=7.
            let if_class = config[i + 5];
            if if_class != USB_CLASS_HID {
                i += dlen;
                continue;
            }

            let if_number = config[i + 2];
            let num_eps = config[i + 4];
            let if_proto = config[i + 7];

            // Walk the interface's subordinate descriptors (bLength-sized),
            // skipping HID and other non-endpoint descriptors between them,
            // until all `num_eps` endpoint descriptors have been examined.
            // The endpoint may follow one or more HID descriptors, so the
            // iteration count is endpoints found, not descriptors stepped.
            let mut pos = i + dlen;
            let mut endpoint = None;
            let mut eps_found = 0;
            while eps_found < num_eps as usize && pos + 5 < config.len() {
                let sub_dlen = config[pos] as usize;
                if sub_dlen < 2 {
                    break;
                }
                if config[pos + 1] == 5 {
                    // ENDPOINT descriptor: bEndpointAddress=2, bmAttributes=3,
                    // wMaxPacketSize=4-5, bInterval=6.
                    let ea = config[pos + 2];
                    let attr = config[pos + 3];
                    let mps = u16::from_le_bytes([config[pos + 4], config[pos + 5]]);
                    let interval = if pos + 6 < config.len() {
                        config[pos + 6]
                    } else {
                        0
                    };
                    if (attr & 3) == 3 && (ea & 0x80) != 0 {
                        endpoint = Some((ea, mps, interval));
                    }
                    eps_found += 1;
                }
                pos += sub_dlen;
            }
            let (endpoint_address, max_packet_size, interval) = endpoint?;

            let kind = match if_proto {
                USB_PROTOCOL_MOUSE => HidDeviceKind::Mouse,
                USB_PROTOCOL_KEYBOARD => HidDeviceKind::Keyboard,
                // Protocol 0: fall back to the device-level boot protocol.
                _ => match fallback_proto {
                    USB_PROTOCOL_MOUSE => HidDeviceKind::Mouse,
                    _ => HidDeviceKind::Keyboard,
                },
            };
            let report_len =
                max_packet_size.max(HidDeviceInfo::min_report_len(kind) as u16) as usize;

            return Some(HidDeviceInfo {
                kind,
                endpoint_address,
                max_packet_size,
                interval,
                interface_number: if_number,
                report_len,
            });
        }
        i += dlen;
    }
    None
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

use alloc::sync::Arc;

use super::Driver;
use super::DriverCategory;

struct UsbHidDriver;

impl Driver for UsbHidDriver {
    fn name(&self) -> &'static str {
        "usb-hid"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Input
    }

    fn init(&self) -> crate::Result<()> {
        // The xHCI probe discovers HID devices on the bus and routes each one
        // through this module's real discovery logic ([`classify_hid_device`])
        // before configuring the endpoint and arming the first report read.
        Ok(())
    }
}

pub fn driver() -> Arc<dyn Driver> {
    Arc::new(UsbHidDriver)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::drivers::mouse::clear_global;
    use crate::kernel::drivers::mouse::try_read_motion;
    use alloc::vec::Vec;

    /// Build a configuration descriptor for a single-interface HID device.
    ///
    /// `proto` is the interface boot protocol (1 = keyboard, 2 = mouse);
    /// `mps` is the interrupt IN endpoint's max packet size; `interval` the
    /// poll interval.
    fn build_hid_config(proto: u8, mps: u16, interval: u8) -> Vec<u8> {
        let mut config = Vec::new();
        // Configuration descriptor (type 2): bLength=9, bNumInterfaces=1,
        // bConfigurationValue=1, total length patched below.
        config.extend_from_slice(&[9, 2, 0, 0, 1, 1, 0, 0xC0, 50]);
        // Interface descriptor (type 4): bInterfaceNumber=0, alt=0, 1 EP,
        // class=HID(0x03), sub=1 boot, proto=`proto`.
        config.extend_from_slice(&[9, 4, 0, 0, 1, USB_CLASS_HID, 1, proto, 0]);
        // HID descriptor (type 0x21) between interface and endpoint.
        config.extend_from_slice(&[9, 0x21, 0x10, 0x01, 0, 1, 0x22, 0, 0]);
        // Endpoint descriptor (type 5): EP 1 IN, interrupt, mps, interval.
        config.extend_from_slice(&[7, 5, 0x81, 3, mps as u8, (mps >> 8) as u8, interval]);
        // Patch wTotalLength (offset 2-3).
        let total = config.len() as u16;
        config[2] = total as u8;
        config[3] = (total >> 8) as u8;
        config
    }

    #[test]
    fn hid_report_size() {
        assert_eq!(core::mem::size_of::<UsbKeyboardReport>(), 8);
    }

    #[test]
    fn classify_hid_config_keyboard() {
        let config = build_hid_config(USB_PROTOCOL_KEYBOARD, 8, 10);
        let info = classify_hid_device(&config, 0).expect("keyboard classified");
        assert_eq!(info.kind, HidDeviceKind::Keyboard);
        assert_eq!(info.endpoint_address, 0x81);
        assert_eq!(info.max_packet_size, 8);
        assert_eq!(info.interval, 10);
        assert_eq!(info.report_len, 8);
        assert_eq!(info.dci(), 3); // EP 1 IN → DCI 3
    }

    #[test]
    fn classify_hid_config_mouse() {
        let config = build_hid_config(USB_PROTOCOL_MOUSE, 4, 10);
        let info = classify_hid_device(&config, 0).expect("mouse classified");
        assert_eq!(info.kind, HidDeviceKind::Mouse);
        assert_eq!(info.report_len, 4);
    }

    #[test]
    fn classify_hid_uses_device_protocol_fallback() {
        // Interface protocol 0 → classify from the device-level protocol.
        let config = build_hid_config(0, 4, 8);
        let info = classify_hid_device(&config, USB_PROTOCOL_MOUSE).expect("mouse classified");
        assert_eq!(info.kind, HidDeviceKind::Mouse);
    }

    #[test]
    fn classify_hid_report_len_floors_to_kind_minimum() {
        // Endpoint advertises 1-byte packets; the boot-protocol keyboard
        // report is still 8 bytes.
        let config = build_hid_config(USB_PROTOCOL_KEYBOARD, 1, 10);
        let info = classify_hid_device(&config, 0).expect("keyboard classified");
        assert_eq!(info.report_len, 8);
    }

    #[test]
    fn classify_hid_rejects_missing_hid_interface() {
        // A config with no HID interface (class 0x08 MSC) returns None.
        let mut config = build_hid_config(USB_PROTOCOL_KEYBOARD, 8, 10);
        config[14] = 0x08; // bInterfaceClass at interface descriptor offset 5
        assert!(classify_hid_device(&config, 0).is_none());
    }

    #[test]
    fn mouse_report_injects_motion() {
        clear_global();
        // 4-byte boot-protocol mouse report: left button + (dx, dy, wheel).
        handle_mouse_report(&[0x01, 0x03, 0xFC, 0xFF]);
        let motion = try_read_motion().expect("motion injected");
        assert_eq!(motion.buttons, 0x01);
        assert_eq!(motion.dx, 3);
        assert_eq!(motion.dy, -4);
        assert_eq!(motion.wheel, -1);
    }

    #[test]
    fn mouse_report_tolerates_short_reports() {
        clear_global();
        // 3-byte report (no wheel byte) still injects motion with wheel = 0.
        handle_mouse_report(&[0x00, 0x02, 0x01]);
        let motion = try_read_motion().expect("motion injected");
        assert_eq!(motion.dx, 2);
        assert_eq!(motion.dy, 1);
        assert_eq!(motion.wheel, 0);

        // A 2-byte fragment is ignored entirely.
        handle_mouse_report(&[0x00, 0x00]);
        assert!(try_read_motion().is_none());
    }

    #[test]
    fn scancode_mapping_known_keys() {
        assert_eq!(usb_hid_to_scancode_set1(0x04), 0x1E); // A
        assert_eq!(usb_hid_to_scancode_set1(0x1D), 0x2C); // Z
        assert_eq!(usb_hid_to_scancode_set1(0x28), 0x1C); // Enter
        assert_eq!(usb_hid_to_scancode_set1(0x2C), 0x39); // Space
        assert_eq!(usb_hid_to_scancode_set1(0x52), 0x48); // Up Arrow
    }

    #[test]
    fn scancode_mapping_unknown_key() {
        assert_eq!(usb_hid_to_scancode_set1(0xFF), 0);
        assert_eq!(usb_hid_to_scancode_set1(0x00), 0);
    }

    #[test]
    fn modifier_bits() {
        assert_eq!(MOD_LEFT_CTRL, 0x01);
        assert_eq!(MOD_LEFT_SHIFT, 0x02);
        assert_eq!(MOD_RIGHT_GUI, 0x80);
    }
}
