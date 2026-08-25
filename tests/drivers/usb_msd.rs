//! tests/drivers/usb_msd.rs
//!
//! Host-side USB Mass Storage (MSD) data-plane tests.
//!
//! The kernel's `usb_msd` driver module is gated to x86_64 bare-metal
//! (`#![cfg(all(target_arch = "x86_64", target_os = "none"))]`), so it is not
//! compiled for host integration tests.  These tests exercise the
//! [`BlockDevice`] contract the driver builds on, plus a mock USB bulk
//! controller that mirrors the driver's OUT/IN endpoint routing.  The driver
//! itself is covered by bare-metal boot-time tests.

use std::sync::Mutex as StdMutex;

use protofire::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use protofire::{Error, Result};

// ── Mock USB Controller ─────────────────────────────────────────────────

/// Mock USB controller mirroring the bulk endpoint routing the MSD driver
/// uses: one bulk OUT endpoint that accumulates writes, and one bulk IN
/// endpoint that drains a queued receive buffer.
pub struct MockUsbController {
    /// Data written to the bulk OUT endpoint.
    pub bulk_out_data: Vec<u8>,
    /// Data queued for reads from the bulk IN endpoint.
    pub bulk_in_data: Vec<u8>,
    pub bulk_out_addr: u8,
    pub bulk_in_addr: u8,
    pub max_packet_size: u16,
}

impl MockUsbController {
    pub fn new() -> Self {
        Self {
            bulk_out_data: Vec::new(),
            bulk_in_data: Vec::new(),
            bulk_out_addr: 1,
            bulk_in_addr: 2,
            max_packet_size: 512,
        }
    }

    pub fn mock_bulk_send(&mut self, endpoint: u8, data: &[u8]) -> Result<()> {
        if endpoint == self.bulk_out_addr {
            self.bulk_out_data.extend_from_slice(data);
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    pub fn mock_bulk_recv(&mut self, endpoint: u8, buffer: &mut [u8]) -> Result<()> {
        if endpoint == self.bulk_in_addr {
            let copy_len = buffer.len().min(self.bulk_in_data.len());
            buffer[..copy_len].copy_from_slice(&self.bulk_in_data[..copy_len]);
            self.bulk_in_data.drain(..copy_len);
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

impl Default for MockUsbController {
    fn default() -> Self {
        Self::new()
    }
}

// ── Mock Block Device for Testing ───────────────────────────────────────

/// Mock block device that simulates a USB mass storage device.  The
/// [`BlockDevice`] methods take `&self`, so the backing store uses interior
/// mutability — the same pattern the real drivers use for `write_blocks`.
pub struct MockBlockDevice {
    data: StdMutex<Vec<u8>>,
    read_only: bool,
    fail_on_read: bool,
    fail_on_write: bool,
}

impl MockBlockDevice {
    pub fn new(size_mb: u32) -> Self {
        let size = (size_mb as usize) * 1024 * 1024;
        Self {
            data: StdMutex::new(vec![0u8; size]),
            read_only: false,
            fail_on_read: false,
            fail_on_write: false,
        }
    }

    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub fn set_fail_on_read(&mut self, fail: bool) {
        self.fail_on_read = fail;
    }

    pub fn set_fail_on_write(&mut self, fail: bool) {
        self.fail_on_write = fail;
    }

    pub fn verify_data(&self, offset: usize, expected: &[u8]) -> Result<()> {
        let data = self.data.lock().unwrap();
        let end = offset + expected.len();
        if end > data.len() {
            return Err(Error::InvalidArgument);
        }
        if &data[offset..end] != expected {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl BlockDevice for MockBlockDevice {
    fn name(&self) -> &str {
        "mock-usb-msd"
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn block_count(&self) -> u64 {
        self.data.lock().unwrap().len() as u64 / BLOCK_SIZE as u64
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        if self.fail_on_read {
            return Err(Error::DeviceError);
        }

        let block_offset = lba as usize * BLOCK_SIZE;
        let block_end = block_offset + buffer.len();
        let data = self.data.lock().unwrap();

        if block_end > data.len() {
            return Err(Error::InvalidArgument);
        }

        buffer.copy_from_slice(&data[block_offset..block_end]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, buffer: &[u8]) -> Result<()> {
        if self.fail_on_write {
            return Err(Error::DeviceError);
        }

        if self.read_only {
            return Err(Error::PermissionDenied);
        }

        let block_offset = lba as usize * BLOCK_SIZE;
        let block_end = block_offset + buffer.len();
        let mut data = self.data.lock().unwrap();

        if block_end > data.len() {
            return Err(Error::InvalidArgument);
        }

        data[block_offset..block_end].copy_from_slice(buffer);
        Ok(())
    }
}

// ── Test Cases ─────────────────────────────────────────────────────────

/// Test that the mock USB controller routes bulk OUT writes to the OUT data
/// buffer and drains the IN buffer on reads, rejecting wrong endpoints.
#[test]
fn test_mock_controller_bulk_io() {
    let mut ctrl = MockUsbController::new();
    let payload = [1u8, 2, 3, 4, 5];

    // OUT: data accumulates in bulk_out_data.
    assert!(ctrl.mock_bulk_send(ctrl.bulk_out_addr, &payload).is_ok());
    assert_eq!(ctrl.bulk_out_data.as_slice(), &payload);

    // IN: prime the receive queue, then drain it.
    ctrl.bulk_in_data = payload.to_vec();
    let mut rx = [0u8; 5];
    assert!(ctrl.mock_bulk_recv(ctrl.bulk_in_addr, &mut rx).is_ok());
    assert_eq!(rx, payload);

    // Wrong endpoints are rejected.
    assert!(ctrl.mock_bulk_send(ctrl.bulk_in_addr, &payload).is_err());
    assert!(ctrl.mock_bulk_recv(ctrl.bulk_out_addr, &mut rx).is_err());
}

/// The endpoint shape the MSD driver consumes (mirrored locally: the kernel
/// `usb_msd` module is bare-metal-only and cannot be imported on host).
struct MsdEndpoints {
    slot_id: u8,
    ep_out_addr: u8,
    ep_in_addr: u8,
    max_packet_size: u16,
}

/// Test MSD endpoint wiring derived from the mock controller.
#[test]
fn test_usb_msd_endpoint_shape() {
    let usb_ctrl = MockUsbController::new();
    let endpoints = MsdEndpoints {
        slot_id: 1,
        ep_out_addr: usb_ctrl.bulk_out_addr,
        ep_in_addr: usb_ctrl.bulk_in_addr,
        max_packet_size: usb_ctrl.max_packet_size,
    };

    assert_eq!(endpoints.slot_id, 1);
    assert_eq!(endpoints.ep_out_addr, 1);
    assert_eq!(endpoints.ep_in_addr, 2);
    assert_eq!(endpoints.max_packet_size, 512);
}

/// Test block device read operations.
#[test]
fn test_mock_block_device_read() {
    let device = MockBlockDevice::new(64);

    // Write test data
    let test_data = [0xAA, 0xBB, 0xCC, 0xDD];
    assert!(device.write_blocks(0, &test_data).is_ok());

    // Read back the data
    let mut read_buffer = [0u8; 4];
    assert!(device.read_blocks(0, &mut read_buffer).is_ok());
    assert_eq!(read_buffer, test_data);

    // Verify data with helper method
    assert!(device.verify_data(0, &test_data).is_ok());
}

/// Test block device write operations.
#[test]
fn test_mock_block_device_write() {
    let device = MockBlockDevice::new(64);

    // Test write to different blocks
    let test_data1 = [0x11, 0x22, 0x33, 0x44];
    let test_data2 = [0x55, 0x66, 0x77, 0x88];

    assert!(device.write_blocks(0, &test_data1).is_ok());
    assert!(device.write_blocks(1, &test_data2).is_ok());

    // Verify the writes (block 1 starts at byte 1 * BLOCK_SIZE)
    assert!(device.verify_data(0, &test_data1).is_ok());
    assert!(device.verify_data(BLOCK_SIZE, &test_data2).is_ok());
}

/// Test read-only behavior.
#[test]
fn test_mock_block_device_read_only() {
    let mut device = MockBlockDevice::new(64);
    device.set_read_only(true);

    // Attempt to write should fail
    let test_data = [0xAA, 0xBB, 0xCC, 0xDD];
    assert!(device.write_blocks(0, &test_data).is_err());

    // Read should still work
    let mut read_buffer = [0u8; 4];
    assert!(device.read_blocks(0, &mut read_buffer).is_ok());
}

/// Test error handling for read operations.
#[test]
fn test_mock_block_device_read_error() {
    let mut device = MockBlockDevice::new(64);
    device.set_fail_on_read(true);

    // Attempt to read should fail
    let mut read_buffer = [0u8; 4];
    assert!(device.read_blocks(0, &mut read_buffer).is_err());
}

/// Test error handling for write operations.
#[test]
fn test_mock_block_device_write_error() {
    let mut device = MockBlockDevice::new(64);
    device.set_fail_on_write(true);

    // Attempt to write should fail
    let test_data = [0xAA, 0xBB, 0xCC, 0xDD];
    assert!(device.write_blocks(0, &test_data).is_err());
}

/// Test block size and count calculations.
#[test]
fn test_mock_block_device_geometry() {
    let device = MockBlockDevice::new(64); // 64MB

    // For a 64MB device with 512-byte blocks:
    // 64MB = 64 * 1024 * 1024 bytes = 67,108,864 bytes
    // 67,108,864 / 512 = 131,072 blocks
    assert_eq!(device.block_size(), 512);
    assert_eq!(device.block_count(), 131072);
    assert_eq!(device.name(), "mock-usb-msd");
    assert!(!device.is_read_only());
}

/// Test edge cases for block operations.
#[test]
fn test_mock_block_device_edge_cases() {
    let device = MockBlockDevice::new(1); // 1MB device

    // Write to the last block
    let last_block = device.block_count() - 1;
    let test_data = [0xFF; BLOCK_SIZE];
    assert!(device.write_blocks(last_block, &test_data).is_ok());

    // Read from the last block
    let mut read_buffer = [0u8; BLOCK_SIZE];
    assert!(device.read_blocks(last_block, &mut read_buffer).is_ok());
    assert_eq!(read_buffer, test_data);

    // Attempt to write beyond the device should fail
    assert!(device.write_blocks(last_block + 1, &test_data).is_err());

    // Attempt to read beyond the device should fail
    assert!(device
        .read_blocks(last_block + 1, &mut read_buffer)
        .is_err());
}

/// Test sequential read/write operations.
#[test]
fn test_mock_block_device_sequential_operations() {
    let device = MockBlockDevice::new(64);

    // Write sequential data
    for i in 0..100 {
        let test_data = [i as u8; BLOCK_SIZE];
        assert!(device.write_blocks(i, &test_data).is_ok());
    }

    // Read back and verify
    for i in 0..100 {
        let mut read_buffer = [0u8; BLOCK_SIZE];
        assert!(device.read_blocks(i, &mut read_buffer).is_ok());
        let expected = [i as u8; BLOCK_SIZE];
        assert_eq!(read_buffer, expected);
    }
}

/// Integration test for the complete USB MSD block-device workflow.
#[test]
fn test_usb_msd_integration_workflow() {
    let device = MockBlockDevice::new(64);

    // Populate device with test data
    for i in 0..1000 {
        let test_data = [i as u8; BLOCK_SIZE];
        assert!(device.write_blocks(i, &test_data).is_ok());
    }

    // Verify the data
    for i in 0..1000 {
        let mut read_buffer = [0u8; BLOCK_SIZE];
        assert!(device.read_blocks(i, &mut read_buffer).is_ok());
        assert_eq!(read_buffer, [i as u8; BLOCK_SIZE]);
    }

    // Modify one block
    let modified_data = [0xAA; BLOCK_SIZE];
    assert!(device.write_blocks(500, &modified_data).is_ok());
    assert!(device.verify_data(500 * BLOCK_SIZE, &modified_data).is_ok());

    // Ensure other blocks are unchanged: block 501 still holds the value it was
    // populated with (`501 as u8` truncates to 245).
    let unchanged_data = [245u8; BLOCK_SIZE];
    assert!(device
        .verify_data(501 * BLOCK_SIZE, &unchanged_data)
        .is_ok());
}

/// Performance smoke test for USB MSD operations.
#[test]
fn test_usb_msd_performance() {
    let device = MockBlockDevice::new(64);

    // Sequential write performance
    let start = std::time::Instant::now();
    let num_blocks = 1000;

    for i in 0..num_blocks {
        let test_data = [i as u8; BLOCK_SIZE];
        assert!(device.write_blocks(i, &test_data).is_ok());
    }

    let write_elapsed = start.elapsed();

    // Generous bound: the mock is fully in-memory.  This is a smoke test, not
    // a benchmark — real throughput depends on the xHCI data path.
    println!(
        "Sequential write performance: {} blocks in {:?}",
        num_blocks, write_elapsed
    );
    assert!(write_elapsed.as_millis() < 10_000);

    // Sequential read performance
    let start = std::time::Instant::now();

    for i in 0..num_blocks {
        let mut read_buffer = [0u8; BLOCK_SIZE];
        assert!(device.read_blocks(i, &mut read_buffer).is_ok());
    }

    let read_elapsed = start.elapsed();

    println!(
        "Sequential read performance: {} blocks in {:?}",
        num_blocks, read_elapsed
    );
    assert!(read_elapsed.as_millis() < 10_000);
}
