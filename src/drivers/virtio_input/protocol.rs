//! src/drivers/virtio_input/protocol.rs
//!
//! The virtio-input protocol: the event layout on the wire, and the
//! translation back to the PS/2 Set-1 scancodes the keyboard layer speaks.
//!
//! Nothing here touches a device, which is why it compiles wherever it is
//! useful: under the host tests, which check the translation, and on the
//! machines that have the device to feed it.  Which machines those are is the
//! architecture's answer, and so is where this module is declared — see
//! `src/arch/<arch>/devices.rs`.  The items are `pub(crate)` because the two
//! consumers are the device half beside them and the driver's tests.

/// Each event is `type: le16` + `code: le16` + `value: le32` = 8 bytes
/// (virtio spec §5.8.3).  Reading it as three `le32` mis-parses every event —
/// the key code (e.g. `0x1E` for KEY_A) leaks into the high bytes of `type`.
pub(crate) const EVENT_BYTES: usize = 8;

/// EV_KEY event type.
pub(crate) const EV_KEY: u16 = 1;

/// PS/2 Set-1 break-code bit and the E0 extended prefix, mirrored from the
/// keyboard driver (which keeps these private).
pub(crate) const SET1_BREAK_BIT: u8 = 0x80;
pub(crate) const SET1_EXTENDED_PREFIX: u8 = 0xE0;

/// A raw VirtIO input event: `type`/`code` are `le16`, `value` is `le32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VirtioInputEvent {
    pub(crate) event_type: u16,
    pub(crate) code: u16,
    pub(crate) value: u32,
}

/// Read one event from a device-written event buffer.
pub(crate) fn read_event(buf: &[u8; EVENT_BYTES]) -> VirtioInputEvent {
    VirtioInputEvent {
        event_type: u16::from_le_bytes([buf[0], buf[1]]),
        code: u16::from_le_bytes([buf[2], buf[3]]),
        value: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    }
}

/// Translate a Linux input (evdev) key code to a PS/2 Set-1 scancode.
///
/// Returns `(make_or_break_scancode, extended)`.  The AT/PS-2 Set-1 make
/// codes for the primary keyboard block equal the Linux input-event key codes
/// (both descend from the same original 83-key layout), so codes 1..=88 map
/// to themselves.  Keys above that range need the E0 prefix and are listed
/// explicitly.  This table is for *evdev* codes — do not reuse the HID-usage
/// numbering in `usb_hid.rs`.
pub(crate) fn evdev_to_set1(code: u32) -> Option<(u8, bool)> {
    match code {
        1..=88 => Some((code as u8, false)),
        // E0-extended keys.
        96 => Some((0x1C, true)),  // KEY_KPENTER
        97 => Some((0x1D, true)),  // KEY_RIGHTCTRL
        98 => Some((0x35, true)),  // KEY_KPSLASH
        100 => Some((0x38, true)), // KEY_RIGHTALT
        102 => Some((0x47, true)), // KEY_HOME
        103 => Some((0x48, true)), // KEY_UP
        104 => Some((0x49, true)), // KEY_PAGEUP
        105 => Some((0x4B, true)), // KEY_LEFT
        106 => Some((0x4D, true)), // KEY_RIGHT
        107 => Some((0x4F, true)), // KEY_END
        108 => Some((0x50, true)), // KEY_DOWN
        109 => Some((0x51, true)), // KEY_PAGEDOWN
        110 => Some((0x52, true)), // KEY_INSERT
        111 => Some((0x53, true)), // KEY_DELETE
        // KEY_SYSRQ (99, Print Screen) is a chained E0-2A-E0-37 sequence the
        // console shell does not need; drop it along with media/consumer keys.
        _ => None,
    }
}

/// Convert an EV_KEY event into the 1-2 PS/2 Set-1 scancode bytes to inject.
///
/// The first byte is either the make/break scancode (single-byte key) or the
/// E0 prefix (extended key); when extended the second byte holds the actual
/// make/break scancode, otherwise the array is sentinel-terminated with 0.
pub(crate) fn event_scancodes(event: &VirtioInputEvent) -> Option<[u8; 2]> {
    if event.event_type != EV_KEY {
        return None;
    }
    let (code, extended) = evdev_to_set1(event.code as u32)?;
    // value 0 = release, 1 = press, 2 = autorepeat (treated as another press).
    let make = if event.value == 0 {
        code | SET1_BREAK_BIT
    } else {
        code
    };
    Some(if extended {
        [SET1_EXTENDED_PREFIX, make]
    } else {
        [make, 0]
    })
}
