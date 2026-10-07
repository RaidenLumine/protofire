//! src/network/link/device.rs
//!
//! `NetworkDevice` trait — hardware abstraction for network interface cards.
//!
//! Follows the same pattern as `BlockDevice` from `src/fs/block.rs`.

use crate::fs::block::DeviceHealth;
use crate::Result;

/// A network interface card abstraction.
///
/// Implementations must be `Send + Sync` so that the driver can be shared
/// across threads (e.g. behind `Arc<dyn NetworkDevice>`).
pub trait NetworkDevice: Send + Sync {
    /// Human-readable device name (e.g. `"virtio-net"`).
    fn name(&self) -> &str;

    /// The device's 6-byte MAC address.
    fn mac_address(&self) -> [u8; 6];

    /// Maximum transmission unit in bytes.
    fn mtu(&self) -> usize;

    /// Transmit a single frame.  Returns `Err(Error::InvalidArgument)`
    /// when `packet` exceeds the MTU.
    fn send(&self, packet: &[u8]) -> Result<()>;

    /// Receive a single frame into `buffer`.  Returns the number of bytes
    /// copied, or `0` when no frame is pending.
    fn receive(&self, buffer: &mut [u8]) -> Result<usize>;

    /// Report the current device health.
    fn device_health(&self) -> DeviceHealth;
}

/// In-memory mock device for host-side protocol tests.
pub mod mock {
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    use crate::fs::block::DeviceHealth;
    use crate::kernel::sync::Mutex;
    use crate::network::link::device::NetworkDevice;
    use crate::Error;
    use crate::Result;

    /// A mock network device backed by in-memory TX / RX queues.
    ///
    /// Tests can push packets into the RX queue (simulating inbound data)
    /// and drain the TX queue to inspect outbound frames.
    pub struct MockNetworkDevice {
        name: &'static str,
        mac: [u8; 6],
        mtu: usize,
        rx_queue: Mutex<VecDeque<Vec<u8>>>,
        tx_queue: Mutex<VecDeque<Vec<u8>>>,
        health: Mutex<DeviceHealth>,
    }

    impl MockNetworkDevice {
        pub fn new(name: &'static str, mac: [u8; 6]) -> Self {
            Self {
                name,
                mac,
                mtu: 1500,
                rx_queue: Mutex::new(VecDeque::new()),
                tx_queue: Mutex::new(VecDeque::new()),
                health: Mutex::new(DeviceHealth::Healthy),
            }
        }

        pub fn new_with_mtu(name: &'static str, mac: [u8; 6], mtu: usize) -> Self {
            Self {
                name,
                mac,
                mtu,
                rx_queue: Mutex::new(VecDeque::new()),
                tx_queue: Mutex::new(VecDeque::new()),
                health: Mutex::new(DeviceHealth::Healthy),
            }
        }

        /// Push a packet into the RX queue for the driver to consume via
        /// `receive()`.
        pub fn inject_rx(&self, packet: Vec<u8>) {
            self.rx_queue.lock().push_back(packet);
        }

        /// Drain all transmitted packets from the TX queue.
        pub fn drain_tx(&self) -> Vec<Vec<u8>> {
            let mut queue = self.tx_queue.lock();
            let drained: Vec<Vec<u8>> = queue.drain(..).collect();
            drained
        }

        /// Set the device health for testing degraded / failed states.
        pub fn set_health(&self, health: DeviceHealth) {
            *self.health.lock() = health;
        }
    }

    impl NetworkDevice for MockNetworkDevice {
        fn name(&self) -> &str {
            self.name
        }

        fn mac_address(&self) -> [u8; 6] {
            self.mac
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn send(&self, packet: &[u8]) -> Result<()> {
            if packet.len() > self.mtu {
                return Err(Error::InvalidArgument);
            }
            self.tx_queue.lock().push_back(packet.to_vec());
            Ok(())
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
            let mut rx = self.rx_queue.lock();
            match rx.pop_front() {
                Some(packet) => {
                    let len = packet.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                None => Ok(0),
            }
        }

        fn device_health(&self) -> DeviceHealth {
            *self.health.lock()
        }
    }
}

// ─── tests ───

/// The loopback device: what a frame sent to it is received from.
///
/// The stack drives one device, so an interface that answers its own
/// transmissions is what lets a boot exercise the protocol paths — the frame
/// builder, the checksums, the receive path, the protocols' own state
/// machines — with no peer, no network and no host behind them.  It is a
/// device rather than a shortcut: a frame handed to `send` is queued for
/// `receive` the way a driver's transmit descriptor would be, and comes back
/// through the stack's own receive path.
///
/// The queue is bounded.  A device whose queue grows without limit is a memory
/// leak with a packet-shaped trigger, so a send into a full queue fails the
/// way a driver's would.
pub mod loopback {
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    use crate::fs::block::DeviceHealth;
    use crate::kernel::sync::Mutex;
    use crate::network::link::device::NetworkDevice;
    use crate::Error;
    use crate::Result;

    /// What the loopback answers to.  `02:00:00:00:00:00` is the locally
    /// administered form (bit 1 of the first octet) and the one a conventional
    /// `lo` carries on the systems that give it an address at all.
    const LOOPBACK_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// The largest frame it will carry.
    const LOOPBACK_MTU: usize = 1500;

    /// The most frames that can be waiting to be received.
    ///
    /// It is not a protocol limit: the stack receives a queued frame before it
    /// sends the next one, so this is the pipelining a caller could do — and
    /// one at a time is what happens today (see `blk-in-flight-high-water`,
    /// the same question asked of the block layer).
    const LOOPBACK_QUEUE_DEPTH: usize = 16;

    pub struct LoopbackDevice {
        rx_queue: Mutex<VecDeque<Vec<u8>>>,
    }

    impl LoopbackDevice {
        pub fn new() -> Self {
            Self {
                rx_queue: Mutex::new(VecDeque::new()),
            }
        }

        /// Frames sent and not yet received.
        pub fn pending(&self) -> usize {
            self.rx_queue.lock().len()
        }
    }

    impl Default for LoopbackDevice {
        fn default() -> Self {
            Self::new()
        }
    }

    impl NetworkDevice for LoopbackDevice {
        fn name(&self) -> &str {
            "lo"
        }

        fn mac_address(&self) -> [u8; 6] {
            LOOPBACK_MAC
        }

        fn mtu(&self) -> usize {
            LOOPBACK_MTU
        }

        fn send(&self, packet: &[u8]) -> Result<()> {
            if packet.len() > LOOPBACK_MTU {
                return Err(Error::InvalidArgument);
            }
            let mut queue = self.rx_queue.lock();
            if queue.len() >= LOOPBACK_QUEUE_DEPTH {
                return Err(Error::OutOfMemory);
            }
            queue.push_back(packet.to_vec());
            Ok(())
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
            let mut queue = self.rx_queue.lock();
            match queue.pop_front() {
                Some(packet) => {
                    let len = packet.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                None => Ok(0),
            }
        }

        fn device_health(&self) -> DeviceHealth {
            DeviceHealth::Healthy
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;

    use crate::fs::block::DeviceHealth;
    use crate::network::link::device::loopback::LoopbackDevice;
    use crate::network::link::device::mock::MockNetworkDevice;
    use crate::network::link::device::NetworkDevice;
    use crate::Error;

    #[test]
    fn mock_reports_name_mac_and_health() {
        let dev = MockNetworkDevice::new("mock0", [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(dev.name(), "mock0");
        assert_eq!(dev.mac_address(), [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(dev.mtu(), 1500);
        assert_eq!(dev.device_health(), DeviceHealth::Healthy);
    }

    #[test]
    fn mock_tracks_health_changes() {
        let dev = MockNetworkDevice::new("mock0", [0x02; 6]);
        assert_eq!(dev.device_health(), DeviceHealth::Healthy);
        dev.set_health(DeviceHealth::Degraded);
        assert_eq!(dev.device_health(), DeviceHealth::Degraded);
    }

    #[test]
    fn mock_round_trips_packets() {
        let dev = MockNetworkDevice::new("mock0", [0x02; 6]);
        dev.inject_rx(vec![1, 2, 3, 4]);
        let mut buf = [0_u8; 16];
        assert_eq!(dev.receive(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);

        dev.send(&buf[..4]).unwrap();
        assert_eq!(dev.drain_tx(), vec![vec![1, 2, 3, 4]]);
    }

    #[test]
    fn mock_rejects_oversized_frames() {
        let dev = MockNetworkDevice::new_with_mtu("small", [0x02; 6], 64);
        let big = vec![0_u8; 65];
        assert_eq!(dev.send(&big), Err(Error::InvalidArgument));
    }

    #[test]
    fn mock_receive_returns_zero_when_empty() {
        let dev = MockNetworkDevice::new("mock0", [0x02; 6]);
        let mut buf = [0_u8; 16];
        assert_eq!(dev.receive(&mut buf).unwrap(), 0);
    }

    #[test]
    fn mock_works_behind_arc_dyn_network_device() {
        let dev: Arc<dyn NetworkDevice> = Arc::new(MockNetworkDevice::new("jumbo", [0x02; 6]));
        assert_eq!(dev.mtu(), 1500);
        assert_eq!(dev.device_health(), DeviceHealth::Healthy);
    }

    #[test]
    fn loopback_reports_lo_and_a_locally_administered_mac() {
        let dev = LoopbackDevice::new();
        assert_eq!(dev.name(), "lo");
        assert_eq!(dev.mtu(), 1500);
        assert_eq!(dev.mac_address()[0] & 0x02, 0x02);
        assert_eq!(dev.device_health(), DeviceHealth::Healthy);
    }

    #[test]
    fn loopback_answers_its_own_send() {
        let dev = LoopbackDevice::new();
        let frame = [0xde_u8, 0xad, 0xbe, 0xef];
        dev.send(&frame).unwrap();
        assert_eq!(dev.pending(), 1);

        let mut buffer = [0_u8; 16];
        assert_eq!(dev.receive(&mut buffer).unwrap(), frame.len());
        assert_eq!(&buffer[..frame.len()], &frame);
        // And it is a queue, not a latch: the frame it handed back is gone.
        assert_eq!(dev.pending(), 0);
        assert_eq!(dev.receive(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn loopback_refuses_a_frame_over_its_mtu() {
        let dev = LoopbackDevice::new();
        let oversized = vec![0_u8; 1501];
        assert!(matches!(dev.send(&oversized), Err(Error::InvalidArgument)));
        assert_eq!(dev.pending(), 0);
    }

    #[test]
    fn loopback_refuses_to_queue_more_than_its_depth() {
        let dev = LoopbackDevice::new();
        let frame = [0x01_u8, 0x02, 0x03];
        for _ in 0..16 {
            dev.send(&frame).unwrap();
        }
        // The seventeenth is refused rather than making the queue grow: a
        // device that queues without limit leaks a packet at a time.
        assert!(matches!(dev.send(&frame), Err(Error::OutOfMemory)));
        assert_eq!(dev.pending(), 16);

        let mut buffer = [0_u8; 8];
        assert_eq!(dev.receive(&mut buffer).unwrap(), frame.len());
        dev.send(&frame).unwrap();
        assert_eq!(dev.pending(), 16);
    }

    #[test]
    fn loopback_truncates_into_a_small_receive_buffer() {
        let dev = LoopbackDevice::new();
        let frame = [0x01_u8, 0x02, 0x03, 0x04, 0x05];
        dev.send(&frame).unwrap();
        let mut buffer = [0_u8; 3];
        assert_eq!(dev.receive(&mut buffer).unwrap(), 3);
        assert_eq!(buffer, [0x01, 0x02, 0x03]);
    }
}
