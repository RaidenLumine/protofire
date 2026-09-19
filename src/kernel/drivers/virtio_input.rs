//! src/kernel/drivers/virtio_input.rs
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

// The device machinery only exists on the MMIO platforms that host a
// virtio-input device (aarch64/riscv64 QEMU `virt`); x86 keeps PS/2.
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use alloc::boxed::Box;
use alloc::sync::Arc;
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use alloc::vec::Vec;

#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use crate::kernel::drivers::virtio::VirtIoMmio;
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use crate::kernel::drivers::virtio::VirtQueue;
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use crate::kernel::drivers::virtio::VIRTQ_DESC_F_WRITE;
use crate::kernel::drivers::Driver;
use crate::kernel::drivers::DriverCategory;
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use crate::kernel::sync::Mutex;
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
use crate::Error;
use crate::Result;

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
        #[cfg(all(
            target_os = "none",
            any(target_arch = "aarch64", target_arch = "riscv64")
        ))]
        probe_input();
        Ok(())
    }
}

/// Return the VirtIO input driver for registration with the [`DriverManager`].
pub fn driver() -> Arc<dyn Driver> {
    Arc::new(VirtioInputDriver)
}

// ─── Protocol constants and translation (shared with host tests) ─────────

/// The event queue is virtqueue 0 (device machinery only).
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
const EVENT_QUEUE: u16 = 0;
/// Number of event buffers posted to the device (device machinery only).
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
const EVENT_QUEUE_SIZE: u16 = 64;

/// Each event is `type: le16` + `code: le16` + `value: le32` = 8 bytes
/// (virtio spec §5.8.3).  Reading it as three `le32` mis-parses every event —
/// the key code (e.g. `0x1E` for KEY_A) leaks into the high bytes of `type`.
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
const EVENT_BYTES: usize = 8;

/// EV_KEY event type.
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
const EV_KEY: u16 = 1;

/// PS/2 Set-1 break-code bit and the E0 extended prefix, mirrored from the
/// keyboard driver (which keeps these private).
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
const SET1_BREAK_BIT: u8 = 0x80;
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
const SET1_EXTENDED_PREFIX: u8 = 0xE0;

/// A raw VirtIO input event: `type`/`code` are `le16`, `value` is `le32`.
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtioInputEvent {
    event_type: u16,
    code: u16,
    value: u32,
}

/// Read one event from a device-written event buffer.
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
fn read_event(buf: &[u8; EVENT_BYTES]) -> VirtioInputEvent {
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
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
fn evdev_to_set1(code: u32) -> Option<(u8, bool)> {
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
#[cfg(any(
    test,
    all(
        target_os = "none",
        any(target_arch = "aarch64", target_arch = "riscv64")
    )
))]
fn event_scancodes(event: &VirtioInputEvent) -> Option<[u8; 2]> {
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

// ─── Device implementation (bare metal, MMIO platforms only) ─────────────

/// The single probed input device, if any.
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
static INPUT_DEVICE: Mutex<Option<Arc<VirtioInputDevice>>> = Mutex::new(None);

/// A split virtqueue plus its device-writable event buffers.
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
struct EventQueue {
    /// Split virtqueue with the PCI ring layout, wired to the MMIO transport
    /// exactly as virtio-net does on these platforms.
    vq: VirtQueue,
    /// Device-writable event buffers.  Descriptor `i` is permanently bound to
    /// `bufs[i]`, so a completion for head `h` carries the bytes in `bufs[h]`.
    bufs: Box<[[u8; EVENT_BYTES]; EVENT_QUEUE_SIZE as usize]>,
}

#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
impl EventQueue {
    fn new() -> Self {
        Self {
            vq: VirtQueue::new_pci(EVENT_QUEUE_SIZE),
            bufs: Box::new([[0u8; EVENT_BYTES]; EVENT_QUEUE_SIZE as usize]),
        }
    }
}

#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
pub struct VirtioInputDevice {
    transport: VirtIoMmio,
    eventq: Mutex<EventQueue>,
}

#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
impl VirtioInputDevice {
    fn new(transport: VirtIoMmio) -> Self {
        Self {
            transport,
            eventq: Mutex::new(EventQueue::new()),
        }
    }

    /// Configure the event virtqueue and post all event buffers, then set
    /// DRIVER_OK and kick so the device can start delivering key events.
    fn configure_event_queue(&self) -> Result<()> {
        {
            let mut queue = self.eventq.lock();
            let (desc, avail, used) = queue.vq.ring_addrs();
            self.transport.select_queue(EVENT_QUEUE);
            self.transport.configure_queue(
                queue.vq.queue_size() as u32,
                desc as u64,
                avail as u64,
                used as u64,
            )?;

            // Post every buffer as a single WRITE descriptor so the device
            // always has somewhere to write an incoming event.  Descriptor i
            // is bound to bufs[i] (see the struct comment).
            for i in 0..EVENT_QUEUE_SIZE as usize {
                let head = queue.vq.alloc_chain(1).ok_or(Error::DeviceError)?;
                // Snapshot the buffer address before the mutable `queue.vq`
                // borrow: both fields are reached through the same mutex guard
                // deref, so a two-field borrow in one call would alias.
                let buf_ptr = queue.bufs[i].as_ptr() as u64;
                queue
                    .vq
                    .set_desc(head, buf_ptr, EVENT_BYTES as u32, VIRTQ_DESC_F_WRITE);
                queue.vq.submit(head);
            }
        }

        // Set DRIVER_OK after queue setup (VirtIO §3.1 step 8).
        self.transport.set_driver_ok()?;
        self.kick();
        Ok(())
    }

    /// Notify the device that fresh event buffers are available.
    fn kick(&self) {
        self.transport.regs().write32(
            crate::kernel::drivers::virtio::REG_QUEUE_NOTIFY,
            EVENT_QUEUE as u32,
        );
    }
}

/// Validate a slot and construct the input device from a matching transport.
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
fn open_input(transport: VirtIoMmio) -> Option<VirtioInputDevice> {
    let mut transport = transport;
    if transport.discover().is_err() {
        return None;
    }
    if transport.device_id() != crate::kernel::drivers::virtio::DEVICE_ID_INPUT {
        return None;
    }
    // The keyboard needs no feature bits; pass 0 so only the device status
    // handshake runs.
    if transport.init_device_with_features(0).is_err() {
        return None;
    }
    Some(VirtioInputDevice::new(transport))
}

/// Scan the VirtIO MMIO bus for an input device and, on success, install it as
/// the global [`INPUT_DEVICE`].  No-op when the platform has no virtio-input
/// device (which is normal on x86, where PS/2 handles the keyboard).
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
fn probe_input() {
    use crate::kernel::drivers::virtio::BareMmioRegion;

    for addr in crate::kernel::drivers::virtio::mmio_slot_addresses() {
        // SAFETY: `addr` is a VirtIO MMIO register block discovered from the
        // FDT or the fixed MMIO window; it stays mapped for the kernel's
        // lifetime and access is serialised by the transport.
        let region = unsafe { BareMmioRegion::new(addr) };
        let transport = VirtIoMmio::new(Box::new(region));

        let device = match open_input(transport) {
            Some(device) => device,
            None => continue,
        };
        match device.configure_event_queue() {
            Ok(()) => {}
            Err(error) => {
                crate::println!(
                    "[virtio-input] probe at 0x{:x} failed: error={}",
                    addr,
                    error.as_str()
                );
                continue;
            }
        }

        crate::println!("[virtio-input] found virtio-keyboard at 0x{:x}", addr);
        *INPUT_DEVICE.lock() = Some(Arc::new(device));
        return;
    }
}

/// Drain completed key events from the event queue and inject them into the
/// arch-neutral PS/2 keyboard layer.  Called from the scheduler timer tick on
/// platforms without input IRQ dispatch.
#[cfg(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
pub fn poll_hardware() {
    let device = match INPUT_DEVICE.lock().as_ref().cloned() {
        Some(device) => device,
        None => return,
    };

    let mut scancodes = Vec::new();
    {
        let mut queue = device.eventq.lock();
        queue.vq.sync_device_used_idx();
        while queue.vq.completed_count() > 0 {
            // Consume frees the chain and returns the head descriptor.  Because
            // descriptor i is bound to bufs[i], the completion's buffer index
            // is the head modulo the queue size.
            let head = match queue.vq.consume_completion() {
                Some(head) => head,
                None => break,
            };
            let buf_index = (head as usize) % EVENT_QUEUE_SIZE as usize;
            let event = read_event(&queue.bufs[buf_index]);

            // Recycle the buffer before decoding so a slow inject never lets
            // the device run out of writable slots.  The freed head is the only
            // descriptor on the free list, so alloc_chain(1) returns it and the
            // bufs[i] binding is preserved.
            if let Some(reposted) = queue.vq.alloc_chain(1) {
                // Snapshot the buffer address first (see configure_event_queue
                // for why the two-field call would not borrow-check).
                let buf_ptr = queue.bufs[buf_index].as_ptr() as u64;
                queue
                    .vq
                    .set_desc(reposted, buf_ptr, EVENT_BYTES as u32, VIRTQ_DESC_F_WRITE);
                queue.vq.submit(reposted);
            }

            if let Some(bytes) = event_scancodes(&event) {
                scancodes.push(bytes);
            }
        }
    }

    // Inject outside the queue lock: the keyboard layer may wake a reader that
    // contends on the scheduler, and we must not hold the eventq lock across a
    // potential context switch.
    for bytes in &scancodes {
        let count = if bytes[1] == 0 { 1 } else { 2 };
        for byte in &bytes[..count] {
            crate::kernel::drivers::keyboard::inject_scancode(*byte);
        }
    }

    device.kick();
}

/// Host / x86 stub: nothing to poll.
#[cfg(not(all(
    target_os = "none",
    any(target_arch = "aarch64", target_arch = "riscv64")
)))]
pub fn poll_hardware() {}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
