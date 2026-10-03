//! src/drivers/virtio_input.rs
//!
//! VirtIO input device driver (VirtIO 1.0 spec §5.8).
//!
//! QEMU's `virt` machines expose keyboards as MMIO virtio-input devices
//! (`-device virtio-keyboard-device`, device id 18) on the same MMIO bus as
//! virtio-net and virtio-gpu.  The device reports Linux input (evdev) key
//! events on its event virtqueue, each `struct virtio_input_event` being
//! `type: le16`, `code: le16`, `value: le32` (8 bytes, spec §5.8.3): `EV_KEY`
//! (1) carries the Linux key code in `code`, and `value` is 0 (release) /
//! 1 (press) / 2 (autorepeat).
//!
//! aarch64/riscv64 have no PS/2 keyboard, so this driver is the window-input
//! path for those platforms: it translates EV_KEY events back to PS/2 Set-1
//! scancodes and feeds them through the arch-neutral [`keyboard`] layer, which
//! already bridges printable characters into the console cooked queue — the
//! same route PS/2 IRQs use on x86.
//!
//! Like virtio-net/block on these platforms there is no device IRQ dispatch
//! yet, so events are drained from a timer-tick poll ([`poll_hardware`]).
//!
//! The driver is two halves, and which of them this machine gets is the
//! machine's answer rather than this file's: the wire format and the device
//! machinery are declared in `src/arch/<arch>/devices.rs`, and the re-exports
//! below are all this file needs to know about it.

use alloc::sync::Arc;

use crate::drivers::Driver;
use crate::drivers::DriverCategory;
use crate::Result;

// The machine picks the device half — the MMIO machinery where there is a
// VirtIO MMIO bus, the stub that answers under the same name where there is
// not — and the wire format that goes with it (see the arch `devices.rs`).
pub(crate) use crate::arch::machine_devices::virtio_input_mmio as mmio;
pub use crate::arch::machine_devices::virtio_input_mmio::poll_hardware;

// ─── Driver registration ─────────────────────────────────────────────────

struct VirtioInputDriver;

impl Driver for VirtioInputDriver {
    fn name(&self) -> &'static str {
        "virtio-input"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Input
    }

    fn init(&self) -> Result<()> {
        mmio::probe_input();
        Ok(())
    }
}

/// Return the VirtIO input driver for registration with the [`DriverManager`].
pub fn driver() -> Arc<dyn Driver> {
    Arc::new(VirtioInputDriver)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::arch::machine_devices::protocol::*;

    #[test]
    fn identity_region_covers_letters_digits_and_symbols() {
        // KEY_A = 30 → Set-1 0x1E (make), KEY_2 = 3 → 0x03, KEY_SLASH = 53 →
        // 0x35.  All live in the identity region 1..=88.
        for code in [30u32, 2, 53, 41, 14, 57] {
            let (make, extended) = evdev_to_set1(code).unwrap();
            assert_eq!(make as u32, code);
            assert!(!extended);
        }
    }

    #[test]
    fn extended_keys_get_e0_prefix() {
        let (make, extended) = evdev_to_set1(103).unwrap(); // KEY_UP
        assert!(extended);
        assert_eq!(make, 0x48);
        assert!(evdev_to_set1(99).is_none()); // KEY_SYSRQ unsupported
    }

    #[test]
    fn make_and_break_produce_expected_bytes() {
        // KEY_A press → 0x1E; release → 0x9E.
        let make = event_scancodes(&VirtioInputEvent {
            event_type: EV_KEY,
            code: 30,
            value: 1,
        })
        .unwrap();
        assert_eq!(make, [0x1E, 0]);
        let break_ = event_scancodes(&VirtioInputEvent {
            event_type: EV_KEY,
            code: 30,
            value: 0,
        })
        .unwrap();
        assert_eq!(break_, [0x9E, 0]);

        // KEY_UP press → E0 0x48; release → E0 0xC8.
        let up = event_scancodes(&VirtioInputEvent {
            event_type: EV_KEY,
            code: 103,
            value: 1,
        })
        .unwrap();
        assert_eq!(up, [0xE0, 0x48]);
        let up_break = event_scancodes(&VirtioInputEvent {
            event_type: EV_KEY,
            code: 103,
            value: 0,
        })
        .unwrap();
        assert_eq!(up_break, [0xE0, 0xC8]);

        // Non-key events (e.g. EV_SYN = 0) and unknown keys yield nothing.
        assert!(event_scancodes(&VirtioInputEvent {
            event_type: 0,
            code: 0,
            value: 0,
        })
        .is_none());
        assert!(event_scancodes(&VirtioInputEvent {
            event_type: EV_KEY,
            code: 113,
            value: 1,
        })
        .is_none());
    }

    #[test]
    fn le16_le16_le32_event_bytes_decode() {
        // Wire layout: type(le16)=1, code(le16)=30, value(le32)=1 → 8 bytes.
        let buf = [
            1u8, 0, // type = 1 (EV_KEY)
            0x1E, 0, // code = 30 (KEY_A)
            1, 0, 0, 0, // value = 1 (press)
        ];
        assert_eq!(buf.len(), EVENT_BYTES);
        let event = read_event(&buf);
        assert_eq!(
            event,
            VirtioInputEvent {
                event_type: EV_KEY,
                code: 30,
                value: 1,
            }
        );
        assert_eq!(event_scancodes(&event), Some([0x1E, 0]));
    }
}
