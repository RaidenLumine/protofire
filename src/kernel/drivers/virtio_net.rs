//! src/kernel/drivers/virtio_net.rs
//!
//! VirtIO network device driver.
//! VirtIO network device driver using the existing MMIO transport and split
//! virtqueue infrastructure.
//!
//! Follows the same pattern as the block driver (`virtio.rs` / `VirtIoBlock`)
//! and implements the `NetworkDevice` trait.
//!
//! References: VirtIO v1.2 specification, section 5.1 (Network Device).

#[cfg(target_os = "none")]
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::drivers::virtio::VirtIoMmio;
use crate::kernel::drivers::virtio::VirtQueue;
use crate::kernel::drivers::virtio::REG_QUEUE_NOTIFY;
use crate::kernel::drivers::virtio::VIRTQ_DESC_F_NEXT;
use crate::kernel::drivers::virtio::VIRTQ_DESC_F_WRITE;
use crate::kernel::drivers::virtio::{self};
use crate::kernel::drivers::Driver;
use crate::kernel::drivers::DriverCategory;
use crate::kernel::fs::block::DeviceHealth;
use crate::kernel::network::link::device::NetworkDevice;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

// ─── VirtIO net feature bits (spec section 5.1.3) ───

/// Device provides a MAC address in config space.
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
/// Link status field in config space is valid.
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;

/// Feature bits this driver understands.
#[cfg_attr(not(any(target_os = "none", test)), allow(dead_code))]
const SUPPORTED_FEATURES: u32 = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;

// ─── VirtIO net header flags (spec section 5.1.6) ───

/// No checksum / offload needed; packet data is bare.
const VIRTIO_NET_HDR_F_NONE: u8 = 0;

// ─── VirtIO net header (spec section 5.1.6) ───

/// The 10-byte header prepended to every packet on both TX and RX queues.
/// We use it in "none" mode (no checksum / GSO offload).
#[repr(C)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

const VIRTIO_NET_HDR_SIZE: usize = core::mem::size_of::<VirtioNetHdr>();

// ─── Default VirtIO queue assignments ───

const RECEIVE_QUEUE: u16 = 0;
const TRANSMIT_QUEUE: u16 = 1;
#[allow(dead_code)]
const DEFAULT_QUEUE_SIZE: u16 = 128;

// ─── Descriptor chain slot counts ───

/// TX descriptor count: [header (device-readable), data (device-readable)]
const TX_DESC_COUNT: u16 = 2;
/// RX descriptor count: [header (device-writable), data (device-writable)]
const RX_DESC_COUNT: u16 = 2;

// ─── RX buffer pool ───

/// Number of pre-allocated receive buffers kept in the available ring so the
/// device always has somewhere to deliver incoming packets.
const RX_BUFFER_COUNT: usize = 16;
/// Per-packet data-buffer size (MTU 1500 + Ethernet header 14 + slack).
const RX_DATA_SIZE: usize = 1536;

/// Pre-allocated buffer for one RX descriptor chain.
///
/// The header is written by the device (VirtIO spec §5.1.6); the data region
/// receives the raw Ethernet frame.
struct RxPacketBuffer {
    header: VirtioNetHdr,
    data: [u8; RX_DATA_SIZE],
}

// ─── Device-specific config space offsets ───

/// MAC address lives at offset 0x100 in device-specific config (section 5.1.4).
const NET_CONFIG_MAC_LO: u64 = 0x100;
const NET_CONFIG_MAC_HI: u64 = 0x104;

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const DEFAULT_MTU: usize = 1500;

/// Spin-loop iteration limit for bare-metal completion polling.
#[cfg(target_os = "none")]
const NET_POLL_LIMIT: u32 = 1_000_000;
// ─── VirtIO net driver ───

/// A VirtIO network device driver.
///
/// On bare-metal the driver communicates through an MMIO transport and two
/// virtqueues (receive + transmit).  On host (test) builds the mock device
/// processes virtqueues synchronously against in-memory packet buffers.
pub struct VirtIoNet {
    pub(crate) transport: VirtIoMmio,
    rx_queue: Mutex<VirtQueue>,
    tx_queue: Mutex<VirtQueue>,
    mac: [u8; 6],
    mtu: usize,
    /// Features negotiated with the device (device_features &
    /// SUPPORTED_FEATURES).
    features: u32,
    /// Pre-allocated RX buffers that are submitted to the available ring so
    /// the device can deliver incoming packets.  Used on both host (for
    /// virtqueue-level tests) and bare-metal.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    rx_buffers: Vec<RxPacketBuffer>,
    /// Round-robin index into `rx_buffers` for the next buffer to submit.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    rx_next_buffer: Mutex<usize>,
    /// Number of RX buffers currently in the available ring (submitted but
    /// not yet consumed).
    #[cfg_attr(target_os = "none", allow(dead_code))]
    rx_in_flight: Mutex<usize>,
    /// In mock mode (host) this holds received-but-not-yet-claimed packets
    /// and transmitted packets for test inspection.  On bare-metal the
    /// physical device owns the actual packet data and this field is unused.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    mock_rx: Mutex<VecDeque<Vec<u8>>>,
    #[cfg_attr(target_os = "none", allow(dead_code))]
    mock_tx: Mutex<VecDeque<Vec<u8>>>,
}

impl VirtIoNet {
    /// Create a new VirtIO net driver.
    ///
    /// The transport must have already completed `discover()` and
    /// `init_device_with_features()`.  `features` is the negotiated
    /// feature set (device_features & SUPPORTED_FEATURES).
    /// `queue_size` must match the device's fixed queue size (relevant
    /// for PCI legacy transports where the QueueSize register is
    /// read-only).
    pub fn new(transport: VirtIoMmio, mtu: usize, features: u32, queue_size: u16) -> Result<Self> {
        // Read MAC address from config space when VIRTIO_NET_F_MAC is
        // negotiated.  Fall back to QEMU's default vendor MAC if the
        // feature was not offered (unlikely on QEMU virt, but required
        // for spec compliance).
        let mac = if features & VIRTIO_NET_F_MAC != 0 {
            let mac_0 = transport.regs().read32(NET_CONFIG_MAC_LO);
            let mac_1 = transport.regs().read32(NET_CONFIG_MAC_HI);
            [
                mac_0 as u8,
                (mac_0 >> 8) as u8,
                (mac_0 >> 16) as u8,
                (mac_0 >> 24) as u8,
                mac_1 as u8,
                (mac_1 >> 8) as u8,
            ]
        } else {
            // QEMU virt default MAC: 52:54:00:12:34:56
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        };

        let rx_queue = Mutex::new(VirtQueue::new_pci(queue_size));
        let tx_queue = Mutex::new(VirtQueue::new_pci(queue_size));

        // Pre-allocate receive buffers.  Each one provides a header + data
        // region that the device will DMA into.
        let rx_buffers: Vec<RxPacketBuffer> = (0..RX_BUFFER_COUNT)
            .map(|_| RxPacketBuffer {
                header: VirtioNetHdr {
                    flags: 0,
                    gso_type: 0,
                    hdr_len: 0,
                    gso_size: 0,
                    csum_start: 0,
                    csum_offset: 0,
                },
                data: [0u8; RX_DATA_SIZE],
            })
            .collect();

        Ok(Self {
            transport,
            rx_queue,
            tx_queue,
            mac,
            mtu,
            features,
            rx_buffers,
            rx_next_buffer: Mutex::new(0),
            rx_in_flight: Mutex::new(0),
            mock_rx: Mutex::new(VecDeque::new()),
            mock_tx: Mutex::new(VecDeque::new()),
        })
    }

    /// Configure both virtqueues on the device.  Must be called after
    /// construction and before the first I/O request.
    pub fn configure_queues(&self) -> Result<()> {
        // Configure receive queue (index 0)
        {
            let rx = self.rx_queue.lock();
            let (desc, avail, used) = rx.ring_addrs();
            self.transport.select_queue(RECEIVE_QUEUE);
            self.transport.configure_queue(
                rx.queue_size() as u32,
                desc as u64,
                avail as u64,
                used as u64,
            )?;
        }

        // Configure transmit queue (index 1)
        {
            let tx = self.tx_queue.lock();
            let (desc, avail, used) = tx.ring_addrs();
            self.transport.select_queue(TRANSMIT_QUEUE);
            self.transport.configure_queue(
                tx.queue_size() as u32,
                desc as u64,
                avail as u64,
                used as u64,
            )?;
        }

        // Pre-fill the RX available ring with empty buffers so the device
        // can deliver incoming packets immediately.
        self.prime_rx_ring()?;

        Ok(())
    }

    /// Kick the device to notify it that new descriptors are available on
    /// the given queue.
    fn kick(&self, queue_index: u16) {
        self.transport
            .regs()
            .write32(REG_QUEUE_NOTIFY, queue_index as u32);
    }

    // ─── RX buffer priming ───

    /// Ensure the RX available ring holds at least one empty buffer so the
    /// device can deliver an incoming packet.
    ///
    /// Idempotent: once `RX_BUFFER_COUNT` buffers are in flight the method
    /// returns immediately.  After each successful receive the caller
    /// decrements the in-flight counter and calls this again to replenish
    /// the ring by one.
    fn prime_rx_ring(&self) -> Result<()> {
        // Lock ordering: rx_in_flight → rx_next_buffer → rx_queue.
        // All call sites must follow this order to avoid deadlocks.
        let mut in_flight = self.rx_in_flight.lock();
        if *in_flight >= self.rx_buffers.len() {
            return Ok(());
        }
        let mut next = self.rx_next_buffer.lock();

        let mut rx = self.rx_queue.lock();
        let mut kicked = false;

        while *in_flight < self.rx_buffers.len() {
            let buf = &self.rx_buffers[*next % self.rx_buffers.len()];
            let head = match rx.alloc_chain(RX_DESC_COUNT) {
                Some(h) => h,
                None => break, // queue is full
            };
            let header_desc = head;
            let data_desc = rx.descriptors[header_desc as usize].next;

            // Both descriptors are device-writable: the device writes the
            // header and the packet data.
            rx.set_desc(
                header_desc,
                &buf.header as *const VirtioNetHdr as u64,
                VIRTIO_NET_HDR_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
            );
            rx.set_desc(
                data_desc,
                buf.data.as_ptr() as u64,
                RX_DATA_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
            );
            rx.submit(head);

            *next += 1;
            *in_flight += 1;
            kicked = true;
        }

        drop(rx);
        if kicked {
            self.kick(RECEIVE_QUEUE);
        }
        Ok(())
    }

    // ─── TX path ───

    /// Internal: transmit a packet through the TX virtqueue.
    fn do_send(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(Error::InvalidArgument);
        }

        let mut tx = self.tx_queue.lock();

        // Allocate 2 descriptors: header + data
        let head = tx.alloc_chain(TX_DESC_COUNT).ok_or(Error::DeviceError)?;
        let header_desc = head;
        let data_desc = tx.descriptors[header_desc as usize].next;

        // Build the net header on the stack.
        let header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NONE,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        };

        // Configure header descriptor (device-readable).
        tx.set_desc(
            header_desc,
            &header as *const VirtioNetHdr as u64,
            VIRTIO_NET_HDR_SIZE as u32,
            0, // device-readable
        );

        // Configure data descriptor (device-readable).
        tx.set_desc(
            data_desc,
            packet.as_ptr() as u64,
            packet.len() as u32,
            0, // device-readable
        );

        // Submit and process
        tx.submit(head);
        self.kick(TRANSMIT_QUEUE);

        #[cfg(not(target_os = "none"))]
        {
            // Host: mock device processes the queue synchronously.
            let mut mock_buf = self.mock_tx.lock();
            process_net_tx_virtqueue(&mut tx, &mut mock_buf)?;
        }
        #[cfg(target_os = "none")]
        {
            // Bare-metal: drop the lock and poll for hardware completion.
            drop(tx);
            self.poll_completion(TRANSMIT_QUEUE)?;
            tx = self.tx_queue.lock();
        }

        // Consume completion
        let _completed = tx.consume_completion().ok_or(Error::DeviceError)?;
        Ok(())
    }

    // ─── RX path ───

    /// Internal: try to receive one packet through the RX virtqueue.
    /// Returns `Ok(0)` when no packet is available (non-blocking poll).
    fn do_receive(&self, buffer: &mut [u8]) -> Result<usize> {
        // On the host the mock RX queue is checked first so existing tests
        // that inject packets through `mock_rx` continue to work unchanged.
        #[cfg(not(target_os = "none"))]
        {
            let mut mock_buf = self.mock_rx.lock();
            if let Some(packet) = mock_buf.pop_front() {
                let len = packet.len().min(buffer.len());
                buffer[..len].copy_from_slice(&packet[..len]);
                return Ok(len);
            }
        }

        // ── virtqueue path (host and bare-metal) ──────────────────────
        // Prime the available ring so the device has somewhere to write.
        self.prime_rx_ring()?;

        let mut rx = self.rx_queue.lock();
        // On bare-metal the hardware writes the used-ring idx; we must
        // sync it before checking for completions.
        #[cfg(target_os = "none")]
        rx.sync_device_used_idx();
        if rx.completed_count() == 0 {
            return Ok(0);
        }

        // Snapshot descriptor pointers and the used-ring element BEFORE
        // calling consume_completion(), which frees the descriptors.
        let slot = (rx.driver_used_idx % rx.queue_size()) as usize;
        let used_elem = rx.used_ring[slot];
        let head = used_elem.id as u16;

        let desc0 = rx.descriptors[head as usize];
        if desc0.flags & VIRTQ_DESC_F_NEXT == 0 {
            // Malformed chain – consume and skip.  Re-prime the ring with a
            // fresh buffer and restore the in-flight accounting so the device
            // never runs out of receive slots.
            rx.consume_completion();
            drop(rx);
            {
                let mut in_flight = self.rx_in_flight.lock();
                *in_flight = in_flight.saturating_sub(1);
            }
            self.prime_rx_ring()?;
            return Ok(0);
        }
        let data_idx = desc0.next;
        let data_desc = rx.descriptors[data_idx as usize];

        let header_addr = desc0.addr;
        let data_addr = data_desc.addr;
        // The used-ring `len` is the total bytes the device wrote (header +
        // packet).  Subtract the header size to get the actual packet length.
        let total_len = used_elem.len as usize;
        let data_len = total_len.saturating_sub(VIRTIO_NET_HDR_SIZE);
        let copy_len = data_len.min(buffer.len());

        // Copy data out of the device-writable buffer while the descriptor
        // is still valid.
        unsafe {
            core::ptr::copy_nonoverlapping(data_addr as *const u8, buffer.as_mut_ptr(), copy_len);
        }

        // Free the descriptors and immediately recycle the buffer addresses
        // into a new chain so the device never runs out of RX slots.
        rx.consume_completion();

        if let Some(new_head) = rx.alloc_chain(RX_DESC_COUNT) {
            let new_header_desc = new_head;
            let new_data_desc = rx.descriptors[new_header_desc as usize].next;
            rx.set_desc(
                new_header_desc,
                header_addr,
                VIRTIO_NET_HDR_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
            );
            rx.set_desc(
                new_data_desc,
                data_addr,
                RX_DATA_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
            );
            rx.submit(new_head);
        }
        drop(rx);

        // On bare-metal the device needs a kick to see the re-submitted
        // buffer; on the host the mock doesn't process RX completions
        // asynchronously, so the kick is harmless.
        self.kick(RECEIVE_QUEUE);

        Ok(copy_len)
    }

    // ─── Polling (bare-metal only) ───

    #[cfg(target_os = "none")]
    fn poll_completion(&self, _queue_index: u16) -> Result<()> {
        // Poll the TX used ring until a completion appears or the limit
        // is exhausted.  The device writes the used-ring idx field in
        // guest RAM; we must sync it before checking.
        let mut last_idx: u16 = 0;
        for _ in 0..NET_POLL_LIMIT {
            {
                let mut tx = self.tx_queue.lock();
                tx.sync_device_used_idx();
                let count = tx.completed_count();
                if count > 0 {
                    return Ok(());
                }
                // Track raw used-ring idx for diagnostics (quiet).
                if let Some(base) = tx.pci_used_base_addr() {
                    let raw_idx = unsafe { core::ptr::read_volatile((base as *const u16).add(1)) };
                    if raw_idx != last_idx && raw_idx != 0 {
                        last_idx = raw_idx;
                    }
                }
            }
            core::hint::spin_loop();
        }
        // Log the final used idx value before timing out.
        {
            let tx = self.tx_queue.lock();
            if let Some(base) = tx.pci_used_base_addr() {
                let raw_idx = unsafe { core::ptr::read_volatile((base as *const u16).add(1)) };
                crate::println!(
                    "[virtio-net] TX poll timed out after {} spins, used_idx={} (driver_used={})",
                    NET_POLL_LIMIT,
                    raw_idx,
                    tx.driver_used_idx
                );
            } else {
                crate::println!("[virtio-net] TX poll timed out (no pci_used_base)");
            }
        }
        Err(Error::TimedOut)
    }
}

// ─── NetworkDevice impl ───

impl NetworkDevice for VirtIoNet {
    fn name(&self) -> &str {
        "virtio-net"
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn send(&self, packet: &[u8]) -> Result<()> {
        self.do_send(packet)
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
        self.do_receive(buffer)
    }

    fn device_health(&self) -> DeviceHealth {
        // When VIRTIO_NET_F_STATUS was negotiated the config space contains
        // a le16 status field at offset 6 from the start of device-specific
        // config (immediately after the 6-byte MAC).  The MAC_HI register
        // (offset 0x104) holds mac[4..6] in bits 0-15 and status in bits
        // 16-31.  Bit 16 of that word = LINK_UP.
        if self.features & VIRTIO_NET_F_STATUS != 0 {
            let mac_hi = self.transport.regs().read32(NET_CONFIG_MAC_HI);
            if mac_hi & (1 << 16) == 0 {
                return DeviceHealth::Degraded;
            }
        }
        DeviceHealth::Healthy
    }
}

// ─── Mock virtqueue processing for host-side testing ───

#[cfg(not(target_os = "none"))]
fn process_net_tx_virtqueue(
    queue: &mut VirtQueue,
    tx_buffer: &mut VecDeque<Vec<u8>>,
) -> Result<()> {
    let pending_start = queue.device_used_idx;
    let pending_end = queue.driver_avail_idx;
    let pending = pending_end.wrapping_sub(pending_start);

    for offset in 0..pending {
        let avail_slot = ((pending_start.wrapping_add(offset)) % queue.queue_size()) as usize;
        let head = queue.avail_ring[avail_slot];

        // Walk the descriptor chain: header (device-readable) → data
        let mut cur = head;
        let mut data_buf: Option<(*const u8, usize)> = None;

        loop {
            let desc = &queue.descriptors[cur as usize];
            let has_next = desc.flags & VIRTQ_DESC_F_NEXT != 0; // VIRTQ_DESC_F_NEXT
            let next = desc.next;

            if data_buf.is_none() && cur != head {
                // First descriptor after header = data
                data_buf = Some((desc.addr as *const u8, desc.len as usize));
            }

            if !has_next {
                break;
            }
            cur = next;
        }

        // Copy the data into the mock TX buffer
        if let Some((ptr, len)) = data_buf {
            let mut packet = alloc::vec![0u8; len];
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, packet.as_mut_ptr(), len);
            }
            tx_buffer.push_back(packet);
        }

        // Write completion to used ring
        let used_slot = (queue.device_used_idx % queue.queue_size()) as usize;
        queue.used_ring[used_slot] = virtio::VirtqUsedElem {
            id: head as u32,
            len: 0,
        };
        queue.device_used_idx = queue.device_used_idx.wrapping_add(1);
    }

    Ok(())
}

/// Mock the device receiving a packet: consume one pending RX buffer from the
/// available ring, write a [`VirtioNetHdr`] + payload into the device-writable
/// descriptors, and post a completion to the used ring.
///
/// `packet` is the raw Ethernet frame (without the VirtIO net header).
#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
fn process_net_rx_virtqueue(queue: &mut VirtQueue, packet: &[u8]) -> Result<()> {
    let pending_start = queue.device_used_idx;
    let pending_end = queue.driver_avail_idx;
    let pending = pending_end.wrapping_sub(pending_start);

    if pending == 0 {
        return Err(Error::Busy);
    }

    // Take the oldest pending buffer.
    let avail_slot = (pending_start % queue.queue_size()) as usize;
    let head = queue.avail_ring[avail_slot];

    // Walk the chain: [header (device-writable), data (device-writable)]
    let desc0 = queue.descriptors[head as usize];
    if desc0.flags & VIRTQ_DESC_F_NEXT == 0 {
        return Err(Error::DeviceError);
    }
    let data_idx = desc0.next;
    let data_desc = queue.descriptors[data_idx as usize];

    let header_addr = desc0.addr as *mut VirtioNetHdr;
    let data_addr = data_desc.addr as *mut u8;
    let max_data = data_desc.len as usize;

    let copy_len = packet.len().min(max_data);

    // Write the header (flags=0 → no checksum offload information).
    unsafe {
        core::ptr::write_volatile(
            header_addr,
            VirtioNetHdr {
                flags: VIRTIO_NET_HDR_F_NONE,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            },
        );
        core::ptr::copy_nonoverlapping(packet.as_ptr(), data_addr, copy_len);
    }

    // Complete: total bytes written = header + packet data.
    let used_slot = (queue.device_used_idx % queue.queue_size()) as usize;
    queue.used_ring[used_slot] = virtio::VirtqUsedElem {
        id: head as u32,
        len: (VIRTIO_NET_HDR_SIZE + copy_len) as u32,
    };
    queue.device_used_idx = queue.device_used_idx.wrapping_add(1);

    Ok(())
}

// ─── Device discovery ───

// ── Driver registration ──

struct VirtIoNetDriver;

impl Driver for VirtIoNetDriver {
    fn name(&self) -> &'static str {
        "virtio-net"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Network
    }

    fn init(&self) -> Result<()> {
        // Device discovery is deferred to probe_boot_net(); the driver
        // itself requires no early initialisation.
        Ok(())
    }
}

/// Return a `Driver` handle for the VirtIO network driver so the
/// `DriverManager` can register and report it.
pub fn driver() -> Arc<dyn Driver> {
    Arc::new(VirtIoNetDriver)
}

/// Probe VirtIO MMIO devices (discovered via FDT) for a network device.
///
/// On platforms where the FDT provides VirtIO MMIO addresses (aarch64 and
/// riscv64 QEMU virt), we iterate the actual device list.  Falls back to a
/// blind scan of a fixed range when FDT info is unavailable.
#[cfg(target_os = "none")]
pub fn probe_boot_net() -> Option<Arc<dyn NetworkDevice>> {
    use crate::kernel::drivers::virtio::BareMmioRegion;

    #[cfg(target_arch = "aarch64")]
    const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;
    #[cfg(target_arch = "aarch64")]
    const VIRTIO_MMIO_STRIDE: usize = 0x200;
    #[cfg(target_arch = "riscv64")]
    const VIRTIO_MMIO_BASE: usize = 0x1000_8000;
    #[cfg(target_arch = "riscv64")]
    const VIRTIO_MMIO_STRIDE: usize = 0x1000;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    const VIRTIO_MMIO_STRIDE: usize = 0x200;
    const VIRTIO_MMIO_MAX_SLOTS: usize = 8;

    // Try FDT-discovered devices first.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        let info = crate::arch::fdt::platform_info();
        if let (Some(base), Some(count), Some(stride)) = (
            info.virtio_mmio_base,
            info.virtio_mmio_count,
            info.virtio_mmio_stride,
        ) {
            crate::println!(
                "[drivers] probing {} virtio-mmio slot(s) at 0x{:x} stride 0x{:x} (FDT)",
                count,
                base,
                stride
            );
            for slot in 0..count {
                let addr = base + slot * stride;
                let region = unsafe { BareMmioRegion::new(addr) };
                let transport = VirtIoMmio::new(Box::new(region));
                if let Some(net) = try_virtio_net_device(transport) {
                    crate::println!("[drivers] virtio-net device found at 0x{:x}", addr);
                    return Some(net);
                }
            }
            crate::println!(
                "[drivers] no virtio-net device found (FDT scan, {} slot(s))",
                count
            );
            // Fall through to blind scan and PCI probe.
        }
    }

    // Fallback: blind scan.
    crate::println!(
        "[drivers] blind-scanning virtio-mmio at 0x{:x} stride 0x{:x} ({} slot(s))",
        VIRTIO_MMIO_BASE,
        VIRTIO_MMIO_STRIDE,
        VIRTIO_MMIO_MAX_SLOTS
    );
    for slot in 0..VIRTIO_MMIO_MAX_SLOTS {
        let addr = VIRTIO_MMIO_BASE + slot * VIRTIO_MMIO_STRIDE;
        let region = unsafe { BareMmioRegion::new(addr) };
        let transport = VirtIoMmio::new(Box::new(region));
        if let Some(net) = try_virtio_net_device(transport) {
            crate::println!(
                "[drivers] virtio-net device found at 0x{:x} (blind scan)",
                addr
            );
            return Some(net);
        }
    }
    crate::println!(
        "[drivers] no virtio-net device found (blind scan, {} slot(s))",
        VIRTIO_MMIO_MAX_SLOTS
    );

    // On aarch64, QEMU 8.x `virt` machine places virtio-net devices on the
    // PCIe bus (virtio-net-pci) rather than the MMIO transport.  Probe PCIe
    // after MMIO scans have been exhausted.
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(net) = probe_pci_net() {
            return Some(net);
        }
    }

    // On x86_64, virtio-net may also be a PCI device (virtio-net-pci).
    // Probe the already-enumerated PCI bus for a matching device.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if let Some(net) = probe_pci_net_x86_64() {
            return Some(net);
        }
    }

    None
}

/// Probe PCI bus for a VirtIO network device on x86_64.
///
/// Uses PCI enumeration to find a device with VirtIO vendor (0x1af4)
/// and network controller device ID (0x1000).  Tries the **modern**
/// (1.0) PCI transport via the MMIO BAR (BAR4) first, falling back
/// to the legacy IO-port BAR (BAR0) if no MMIO BAR is available.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn probe_pci_net_x86_64() -> Option<Arc<dyn NetworkDevice>> {
    use crate::arch::x86_64::pci::pci_config_read_u16;
    use crate::arch::x86_64::pci::pci_config_write_u16;
    use crate::arch::x86_64::pci::pci_enumerate_buses;
    use crate::arch::x86_64::pci::PciAddress;
    use crate::arch::x86_64::pci::COMMAND;
    use crate::kernel::drivers::virtio_pci::PciLegacyMmioRegion;
    use crate::kernel::drivers::virtio_pci_modern::PciModernRegion;
    use alloc::boxed::Box;

    const VIRTIO_VENDOR: u16 = 0x1af4;
    const VIRTIO_NET_DEVICE: u16 = 0x1000;
    const CMD_IO_SPACE: u16 = 1 << 0;
    const CMD_MEMORY_SPACE: u16 = 1 << 1;
    const CMD_BUS_MASTER: u16 = 1 << 2;

    let devices = pci_enumerate_buses();
    for device in &devices {
        if device.vendor_id != VIRTIO_VENDOR || device.device_id != VIRTIO_NET_DEVICE {
            continue;
        }

        let pci_addr = PciAddress::new(device.bus, device.device, device.function);

        // Enable IO Space, Memory Space, and Bus Master.
        let cmd = unsafe { pci_config_read_u16(pci_addr, COMMAND) };
        unsafe {
            pci_config_write_u16(
                pci_addr,
                COMMAND,
                cmd | CMD_IO_SPACE | CMD_MEMORY_SPACE | CMD_BUS_MASTER,
            );
        }

        // ── Try modern PCI transport via MMIO BAR first ──────────
        if let Some(mmio_bar) = device
            .bars
            .iter()
            .find(|bar| bar.is_mmio && bar.base_address != 0)
        {
            crate::println!(
                "[drivers] virtio-net PCI: trying modern transport BAR base=0x{:x} size=0x{:x}",
                mmio_bar.base_address,
                mmio_bar.size
            );

            // Map the MMIO BAR into kernel page tables.
            let _mapping = unsafe {
                crate::arch::mmu::map_device_mmio(mmio_bar.base_address, mmio_bar.size as usize)
            };
            if _mapping.is_none() {
                crate::println!(
                    "[drivers] virtio-net PCI: failed to map MMIO BAR at 0x{:x}",
                    mmio_bar.base_address
                );
            } else {
                let region = Box::new(PciModernRegion::new(
                    mmio_bar.base_address as usize,
                    device.device_id,
                    device.vendor_id,
                ));
                let transport = VirtIoMmio::new(region);
                if let Some(net) = try_virtio_net_device(transport) {
                    crate::println!("[drivers] virtio-net device found (PCI modern)");
                    return Some(net);
                }
                crate::println!("[drivers] virtio-net PCI: modern transport failed, trying legacy");
            }
        }

        // ── Fallback: legacy IO-port BAR ─────────────────────────
        if let Some(io_bar) = device
            .bars
            .first()
            .filter(|bar| !bar.is_mmio && bar.base_address != 0)
        {
            let io_base = io_bar.base_address as u16;
            crate::println!(
                "[drivers] virtio-net PCI: trying legacy IO BAR base=0x{:x}",
                io_base
            );

            let region = Box::new(PciLegacyMmioRegion::new(
                io_base,
                device.device_id,
                device.vendor_id,
            ));
            let transport = VirtIoMmio::new(region);
            if let Some(net) = try_virtio_net_device(transport) {
                crate::println!("[drivers] virtio-net device found (PCI legacy IO)");
                return Some(net);
            }
        }
    }

    None
}

/// Probe PCIe for a VirtIO network device on AArch64.
///
/// On QEMU `virt` machines, virtio-net devices may be placed on the PCIe bus
/// as `virtio-net-pci` transitional devices.  This function uses the generic
/// ECAM probe ([`crate::arch::aarch64::pci::probe_and_enumerate`]) to
/// discover and map the PCIe bus, then locates a VirtIO network controller,
/// maps its MMIO BAR through a low VA alias, and initialises the device
/// through its legacy MMIO interface.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn probe_pci_net() -> Option<Arc<dyn NetworkDevice>> {
    use crate::arch::aarch64::mmu::map_device_mmio_at;
    use crate::arch::aarch64::pci;
    use crate::kernel::drivers::virtio::BareMmioRegion;

    // Discover, map, and enumerate the PCIe bus.  Returns `None` when no
    // ECAM region is described or the low-VA alias mapping fails.
    let probe = pci::probe_and_enumerate()?;

    // VirtIO devices use vendor ID 0x1AF4.  Network controllers are
    // class 0x02, subclass 0x00 (Ethernet).
    let net_devices = probe
        .devices
        .iter()
        .filter(|dev| dev.vendor_id == 0x1AF4 && dev.class_code == 0x02 && dev.subclass == 0x00);

    for dev in net_devices {
        for bar in &dev.bars {
            if !bar.is_mmio || bar.base_address == 0 {
                continue;
            }

            crate::println!(
                "[drivers] trying virtio-net at PCI BAR base={:#018x}",
                bar.base_address
            );

            // Map the MMIO BAR through a second VA alias.  The legacy
            // VirtIO MMIO interface occupies at most 0x200 bytes.
            const BAR_VA: usize = 0x2_0040_0000; // 8 GiB + 4 MiB
            let _bar_mapped = unsafe { map_device_mmio_at(BAR_VA, bar.base_address, 0x200)? };

            // Enable bus-mastering and memory-space access on the PCI
            // device so it responds to MMIO reads/writes.
            pci::pci_enable_memory_and_bus_master(&probe.region, dev.bus, dev.device, dev.function);

            let region = unsafe { BareMmioRegion::new(BAR_VA) };
            let transport = VirtIoMmio::new(Box::new(region));
            if let Some(net) = try_virtio_net_device(transport) {
                crate::println!(
                    "[drivers] virtio-net PCI device found at BAR base={:#018x}",
                    bar.base_address
                );
                return Some(net);
            }
        }
    }

    crate::println!("[drivers] no virtio-net PCI device found");
    None
}

#[cfg(target_os = "none")]
fn try_virtio_net_device(mut transport: VirtIoMmio) -> Option<Arc<dyn NetworkDevice>> {
    if transport.discover().is_err() {
        return None;
    }
    if transport.device_id() != virtio::DEVICE_ID_NET {
        return None;
    }

    // Negotiate features page 0 (bits 0-31).
    let mut features = match transport.init_device_with_features(SUPPORTED_FEATURES) {
        Ok(f) => f as u64,
        Err(_) => return None,
    };

    // Negotiate features page 1 (bits 32-63).  VirtIO 1.0 devices
    // offer VIRTIO_F_VERSION_1 (bit 32 = bit 0 of page 1), which is
    // required for the modern PCI transport.
    const VIRTIO_F_VERSION_1_PAGE1: u32 = 1u32; // bit 0 of page 1
    transport.regs().write32(virtio::REG_DEVICE_FEATURES_SEL, 1);
    let dev_features_p1 = transport.regs().read32(virtio::REG_DEVICE_FEATURES);
    if dev_features_p1 & VIRTIO_F_VERSION_1_PAGE1 != 0 {
        transport.regs().write32(virtio::REG_DRIVER_FEATURES_SEL, 1);
        transport
            .regs()
            .write32(virtio::REG_DRIVER_FEATURES, VIRTIO_F_VERSION_1_PAGE1);
        features |= (VIRTIO_F_VERSION_1_PAGE1 as u64) << 32;
        // Re-assert FEATURES_OK after writing page 1 driver features.
        let status = transport.regs().read32(virtio::REG_STATUS);
        transport
            .regs()
            .write32(virtio::REG_STATUS, status | virtio::STATUS_FEATURES_OK);
        let status = transport.regs().read32(virtio::REG_STATUS);
        crate::println!(
            "[virtio-net] negotiated VIRTIO_F_VERSION_1, status=0x{:02x}",
            status
        );
    }

    // Read the device's default queue sizes before creating virtqueues.
    transport.select_queue(RECEIVE_QUEUE);
    let rx_max = transport.regs().read32(virtio::REG_QUEUE_NUM_MAX);
    transport.select_queue(TRANSMIT_QUEUE);
    let tx_max = transport.regs().read32(virtio::REG_QUEUE_NUM_MAX);
    let qsize = if rx_max > 0 && rx_max <= 256 {
        rx_max as u16
    } else {
        DEFAULT_QUEUE_SIZE
    };
    crate::println!(
        "[virtio-net] device queue sizes: rx_max={} tx_max={} using={}",
        rx_max,
        tx_max,
        qsize
    );

    let driver = match VirtIoNet::new(transport, DEFAULT_MTU, features as u32, qsize) {
        Ok(d) => d,
        Err(_) => return None,
    };
    if driver.configure_queues().is_err() {
        return None;
    }
    // Set DRIVER_OK after queue configuration (VirtIO §3.1 step 8).
    {
        let current = driver.transport.regs().read32(virtio::REG_STATUS);
        crate::println!("[virtio-net] pre-set_driver_ok: status=0x{:02x}", current);
        if current & virtio::STATUS_DRIVER_OK == 0 {
            crate::println!("[virtio-net] calling set_driver_ok()");
            if driver.transport.set_driver_ok().is_err() {
                crate::println!("[virtio-net] set_driver_ok FAILED");
                return None;
            }
            crate::println!("[virtio-net] set_driver_ok SUCCESS");
        }
    }
    Some(Arc::new(driver))
}

/// Host-side stub: no MMIO to scan.
#[cfg(not(target_os = "none"))]
pub fn probe_boot_net() -> Option<Arc<dyn NetworkDevice>> {
    None
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::drivers::virtio::mock::MockMmioRegion;
    use crate::kernel::drivers::virtio::DEVICE_ID_NET;
    use crate::kernel::drivers::virtio::MAGIC_VALUE;
    use crate::kernel::drivers::virtio::REG_DEVICE_FEATURES;
    use crate::kernel::drivers::virtio::REG_DEVICE_ID;
    use crate::kernel::drivers::virtio::REG_MAGIC_VALUE;
    use crate::kernel::drivers::virtio::REG_QUEUE_NUM_MAX;
    use crate::kernel::drivers::virtio::REG_STATUS;
    use crate::kernel::drivers::virtio::REG_VERSION;
    use crate::kernel::drivers::virtio::STATUS_DRIVER_OK;
    use crate::kernel::drivers::virtio::VIRTIO_VERSION;
    use alloc::boxed::Box;

    /// Pre-populate a MockMmioRegion for a VirtIO net device.
    fn make_net_device_region() -> MockMmioRegion {
        let region = MockMmioRegion::new();
        region.set32(REG_MAGIC_VALUE, MAGIC_VALUE);
        region.set32(REG_VERSION, VIRTIO_VERSION);
        region.set32(REG_DEVICE_ID, DEVICE_ID_NET);
        // Advertise MAC and status features.
        region.set32(REG_DEVICE_FEATURES, VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        region.set32(REG_QUEUE_NUM_MAX, DEFAULT_QUEUE_SIZE as u32);
        // Pre-populate a MAC address in config space.
        // MAC = 52:54:00:12:34:56 (QEMU default)
        // Lower 32 bits at 0x100: 0x54, 0x52, 0x00, 0x12 → 0x12005452 as le bytes
        region.set32(NET_CONFIG_MAC_LO, 0x1200_5452);
        // Bytes 4-5 at NET_CONFIG_MAC_HI: 0x34, 0x56 → 0x0000_5634 as le bytes.
        // Bits 16-31 hold the status field; set bit 16 (LINK_UP).
        region.set32(NET_CONFIG_MAC_HI, 0x0001_5634);
        region
    }

    fn make_net_driver() -> VirtIoNet {
        let region = make_net_device_region();
        let mut transport = VirtIoMmio::new(Box::new(region));
        transport.discover().expect("discover net device");
        assert_eq!(transport.device_id(), DEVICE_ID_NET);
        let features = transport
            .init_device_with_features(SUPPORTED_FEATURES)
            .expect("init net device");
        let driver = VirtIoNet::new(transport, DEFAULT_MTU, features, DEFAULT_QUEUE_SIZE)
            .expect("create VirtIoNet");
        driver.configure_queues().expect("configure queues");
        driver
    }

    #[test]
    fn discover_accepts_valid_net_device() {
        let region = make_net_device_region();
        let mut transport = VirtIoMmio::new(Box::new(region));
        transport.discover().expect("discover net device");
        assert_eq!(transport.device_id(), DEVICE_ID_NET);
    }

    #[test]
    fn mac_address_read_from_config_space() {
        let driver = make_net_driver();
        // MAC bytes from set32 above: 0x52, 0x54, 0x00, 0x12, 0x34, 0x56
        assert_eq!(driver.mac_address(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn driver_reports_identity() {
        let driver = make_net_driver();
        assert_eq!(driver.name(), "virtio-net");
        assert_eq!(driver.mtu(), DEFAULT_MTU);
        assert_eq!(driver.device_health(), DeviceHealth::Healthy);
    }

    #[test]
    fn send_and_receive_round_trip() {
        let driver = make_net_driver();
        let packet = b"Hello, VirtIO net!";

        // Send
        driver.send(packet).expect("send should succeed");

        // The mock puts the TX packet into mock_tx; verify it's there.
        {
            let mut mock_tx = driver.mock_tx.lock();
            let sent = mock_tx.pop_front().expect("should have TX packet");
            assert_eq!(&sent, b"Hello, VirtIO net!");
        }

        // Inject a packet into the mock RX queue
        {
            let mut mock_rx = driver.mock_rx.lock();
            mock_rx.push_back(b"incoming data".to_vec());
        }

        let mut buf = [0u8; 2048];
        let n = driver.receive(&mut buf).expect("receive should succeed");
        assert_eq!(n, 13);
        assert_eq!(&buf[..n], b"incoming data");
    }

    #[test]
    fn receive_returns_zero_when_no_packet() {
        let driver = make_net_driver();
        let mut buf = [0u8; 2048];
        assert_eq!(driver.receive(&mut buf), Ok(0));
    }

    #[test]
    fn send_rejects_empty_packet() {
        let driver = make_net_driver();
        assert_eq!(driver.send(b""), Err(Error::InvalidArgument));
    }

    #[test]
    fn send_rejects_oversized_packet() {
        let driver = make_net_driver();
        let big = alloc::vec![0xAB; 1600]; // > MTU 1500
        assert_eq!(driver.send(&big), Err(Error::InvalidArgument));
    }

    #[test]
    fn init_device_sets_driver_ok_status() {
        let region = make_net_device_region();
        let mut transport = VirtIoMmio::new(Box::new(region));
        transport.discover().expect("discover");
        transport
            .init_device_with_features(!0)
            .expect("init features");
        transport.set_driver_ok().expect("set_driver_ok");
        let status = transport.regs().read32(REG_STATUS);
        assert!(status & STATUS_DRIVER_OK != 0, "DRIVER_OK should be set");
    }

    #[test]
    fn rx_buffers_are_preallocated_on_construction() {
        let driver = make_net_driver();

        // After configure_queues → prime_rx_ring, all RX buffers should
        // be in flight.
        assert_eq!(driver.rx_buffers.len(), RX_BUFFER_COUNT);
        let in_flight = *driver.rx_in_flight.lock();
        assert_eq!(in_flight, RX_BUFFER_COUNT);

        // The queue should have used the right number of descriptors.
        let rx = driver.rx_queue.lock();
        assert_eq!(rx.used_count(), RX_BUFFER_COUNT as u16 * RX_DESC_COUNT);
    }

    #[test]
    fn prime_rx_ring_is_idempotent() {
        let driver = make_net_driver();

        // Calling prime_rx_ring again should not submit more buffers.
        driver.prime_rx_ring().expect("second prime_rx_ring");
        let in_flight = *driver.rx_in_flight.lock();
        assert_eq!(in_flight, RX_BUFFER_COUNT);
    }

    #[test]
    fn receive_through_virtqueue_reads_packet_data() {
        let driver = make_net_driver();

        // The RX ring is already primed by configure_queues.  Simulate
        // the device delivering one packet by writing into the oldest
        // pending buffer and posting a completion.
        let test_packet: &[u8] = b"virtio-rx-test-payload";
        {
            let mut rx = driver.rx_queue.lock();
            process_net_rx_virtqueue(&mut rx, test_packet).expect("mock RX deliver");
        }

        // Now receive should pick up the packet from the virtqueue path.
        let mut buf = [0u8; 2048];
        let n = driver.receive(&mut buf).expect("receive should succeed");
        assert_eq!(n, test_packet.len());
        assert_eq!(&buf[..n], test_packet);

        // The in-flight count should still be RX_BUFFER_COUNT (one buffer
        // was consumed and immediately re-submitted).
        let in_flight = *driver.rx_in_flight.lock();
        assert_eq!(in_flight, RX_BUFFER_COUNT);
    }

    #[test]
    fn send_and_receive_round_trip_through_virtqueue() {
        let driver = make_net_driver();

        // Send a packet through the TX virtqueue — mock processes it
        // synchronously into mock_tx.
        let sent = b"round-trip-packet";
        driver.send(sent).expect("send");

        // Grab the TX'd data from mock_tx and feed it into the RX
        // virtqueue as if the device looped it back.
        {
            let mut mock_tx = driver.mock_tx.lock();
            let tx_data = mock_tx.pop_front().expect("TX packet in mock_tx");
            assert_eq!(&tx_data, sent);

            let mut rx = driver.rx_queue.lock();
            process_net_rx_virtqueue(&mut rx, &tx_data).expect("mock RX deliver");
        }

        // Read the looped-back packet through the normal receive path.
        let mut buf = [0u8; 2048];
        let n = driver.receive(&mut buf).expect("receive should succeed");
        assert_eq!(n, sent.len());
        assert_eq!(&buf[..n], sent);
    }

    #[test]
    fn receive_returns_zero_when_virtqueue_empty() {
        let driver = make_net_driver();

        // Even with primed buffers, an empty used ring means no packet.
        // (The mock device never asynchronously completes anything.)
        let mut buf = [0u8; 2048];
        assert_eq!(driver.receive(&mut buf), Ok(0));
    }
}
