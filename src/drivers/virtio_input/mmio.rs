//! src/drivers/virtio_input/mmio.rs
//!
//! The device half of virtio-input: a MMIO transport found on the VirtIO
//! MMIO bus, the event virtqueue it drives, and the timer-tick poll that
//! drains completed key events into the keyboard layer.
//!
//! It is compiled only on the platforms that have such a device — aarch64 and
//! riscv64 QEMU `virt` — and the gate for that is on this module's
//! declaration in `mod.rs`, not on the items here.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::drivers::virtio::VirtIoMmio;
use crate::drivers::virtio::VirtQueue;
use crate::drivers::virtio::VIRTQ_DESC_F_WRITE;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

use super::protocol::event_scancodes;
use super::protocol::read_event;
use super::protocol::EVENT_BYTES;

/// The event queue is virtqueue 0 (device machinery only).
const EVENT_QUEUE: u16 = 0;
/// Number of event buffers posted to the device (device machinery only).
const EVENT_QUEUE_SIZE: u16 = 64;

/// The single probed input device, if any.
static INPUT_DEVICE: Mutex<Option<Arc<VirtioInputDevice>>> = Mutex::new(None);

/// A split virtqueue plus its device-writable event buffers.
struct EventQueue {
    /// Split virtqueue with the PCI ring layout, wired to the MMIO transport
    /// exactly as virtio-net does on these platforms.
    vq: VirtQueue,
    /// Device-writable event buffers.  Descriptor `i` is permanently bound to
    /// `bufs[i]`, so a completion for head `h` carries the bytes in `bufs[h]`.
    bufs: Box<[[u8; EVENT_BYTES]; EVENT_QUEUE_SIZE as usize]>,
}

impl EventQueue {
    fn new() -> Self {
        Self {
            vq: VirtQueue::new_pci(EVENT_QUEUE_SIZE),
            bufs: Box::new([[0u8; EVENT_BYTES]; EVENT_QUEUE_SIZE as usize]),
        }
    }
}

pub struct VirtioInputDevice {
    transport: VirtIoMmio,
    eventq: Mutex<EventQueue>,
}

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
        self.transport
            .regs()
            .write32(crate::drivers::virtio::REG_QUEUE_NOTIFY, EVENT_QUEUE as u32);
    }
}

/// Validate a slot and construct the input device from a matching transport.
fn open_input(transport: VirtIoMmio) -> Option<VirtioInputDevice> {
    let mut transport = transport;
    if transport.discover().is_err() {
        return None;
    }
    if transport.device_id() != crate::drivers::virtio::DEVICE_ID_INPUT {
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
pub(super) fn probe_input() {
    use crate::drivers::virtio::BareMmioRegion;

    for addr in crate::drivers::virtio::mmio_slot_addresses() {
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
            crate::drivers::keyboard::inject_scancode(*byte);
        }
    }

    device.kick();
}
