//! src/kernel/network/link/device.rs
//!
//! `NetworkDevice` trait — hardware abstraction for network interface cards.
//!
//! Follows the same pattern as `BlockDevice` from `src/kernel/fs/block.rs`.

use crate::kernel::fs::block::DeviceHealth;
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

    use crate::kernel::fs::block::DeviceHealth;
    use crate::kernel::network::link::device::NetworkDevice;
    use crate::kernel::sync::Mutex;
    use crate::{Error, Result};

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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;

    use crate::kernel::fs::block::DeviceHealth;
    use crate::kernel::network::link::device::mock::MockNetworkDevice;
    use crate::kernel::network::link::device::NetworkDevice;
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
}
