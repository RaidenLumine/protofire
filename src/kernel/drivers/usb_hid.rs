//! src/kernel/drivers/usb_hid.rs
//!
//! USB Human Interface Device (keyboard/mouse) driver.
//! USB HID (Human Interface Device) driver — boot protocol keyboard.
//!
//! Parses USB HID boot protocol keyboard reports and maps USB HID keycodes
//! to the kernel's internal key event representation.
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
        // The xHCI driver handles USB HID device discovery and initialisation
        // during its probe phase.  This driver only provides the scancode
        // mapping and report-processing logic.
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

    #[test]
    fn hid_report_size() {
        assert_eq!(core::mem::size_of::<UsbKeyboardReport>(), 8);
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
