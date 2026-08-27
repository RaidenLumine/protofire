//! tests/drivers/usb_msd.rs
//!
//! Host-side USB Mass Storage (MSD) data-plane tests.
//!
//! The kernel's `usb_msd` driver module is gated to x86_64 bare-metal
//! (`#![cfg(all(target_arch = "x86_64", target_os = "none"))]`), so it is not
//! compiled for host integration tests.  These tests exercise the
//! [`BlockDevice`] contract the driver builds on, plus a mock USB bulk
//! controller that mirrors the driver's OUT/IN endpoint routing, and the
//! storage-loop shape the driver feeds: MBR partition scan + mount of the
//! scanned partition.  The driver itself is covered by bare-metal boot-time
//! tests.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use protofire::kernel::fs::block::BlockDevice;
use protofire::kernel::fs::block::BlockSliceDevice;
use protofire::kernel::fs::block::MemoryBlockDevice;
use protofire::kernel::fs::block::BLOCK_SIZE;
use protofire::kernel::fs::fat32::FatVolume;
use protofire::kernel::fs::partition::read_mbr_partitions;
use protofire::kernel::fs::partition::write_mbr_partitions;
use protofire::kernel::fs::partition::MbrPartitionEntry;
use protofire::kernel::fs::partition::MbrPartitionTable;
use protofire::kernel::fs::vfs::FileSystem;
use protofire::Error;
use protofire::Result;

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

// ── MBR partition scan + mount workflow ──────────────────────────────────

/// A block device that reports a non-512-byte sector size (e.g. a 4K-native
/// USB stick).  Used to verify the partition scanner refuses — rather than
/// mis-parses — a device whose sector size is not the canonical 512 bytes,
/// so the boot-disk fallback chain skips cleanly to the next candidate.
pub struct NonStandardBlockDevice {
    data: StdMutex<Vec<u8>>,
    block_size: usize,
}

impl NonStandardBlockDevice {
    pub fn new(block_size: usize, size_blocks: usize) -> Self {
        Self {
            data: StdMutex::new(vec![0u8; block_size * size_blocks]),
            block_size,
        }
    }
}

impl BlockDevice for NonStandardBlockDevice {
    fn name(&self) -> &str {
        "nonstandard-msd"
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        (self.data.lock().unwrap().len() / self.block_size) as u64
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let start = lba as usize * self.block_size;
        let end = start + buffer.len();
        let data = self.data.lock().unwrap();
        if end > data.len() {
            return Err(Error::InvalidArgument);
        }
        buffer.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, bytes: &[u8]) -> Result<()> {
        let start = lba as usize * self.block_size;
        let end = start + bytes.len();
        let mut data = self.data.lock().unwrap();
        if end > data.len() {
            return Err(Error::InvalidArgument);
        }
        data[start..end].copy_from_slice(bytes);
        Ok(())
    }
}

/// The partition scanner must return `Ok(None)` for a non-512-byte device
/// rather than read an MBR through a wrong-sized window.  This guards the
/// storage loop's assumption that `usb-msd` block devices use the canonical
/// 512-byte sectors for partition scanning.
#[test]
fn test_mbr_scan_refuses_non_512_block_size() {
    let device = NonStandardBlockDevice::new(4096, 8);
    assert_eq!(device.block_size(), 4096);
    assert_eq!(read_mbr_partitions(&device).unwrap(), None);
}

/// MBR partition type for a FAT32 LBA partition.
const MBR_PARTITION_TYPE_FAT32: u8 = 0x0C;
/// Partition start LBA in the composite disk image (a typical 1 MiB-aligned
/// offset, matching the layout real usb-storage sticks present).
const PARTITION_START_LBA: u32 = 2048;

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_short_entry(
    image: &mut [u8],
    offset: usize,
    name11: &[u8; 11],
    attributes: u8,
    cluster: u32,
    size: u32,
) {
    image[offset..offset + 11].copy_from_slice(name11);
    image[offset + 11] = attributes;
    // Creation/modification dates and times left zeroed.
    image[offset + 20] = (cluster >> 16) as u8;
    image[offset + 21] = (cluster >> 24) as u8;
    image[offset + 26] = cluster as u8;
    image[offset + 27] = (cluster >> 8) as u8;
    image[offset + 28..offset + 32].copy_from_slice(&size.to_le_bytes());
}

/// Build a self-contained 240-sector FAT32 partition image, pre-seeded with a
/// single file (`README.TXT`, 12 bytes) so the whole partition-scan → mount →
/// read chain has concrete data to fetch.  Layout mirrors `tests/fat32.rs`:
///   sectors 0-31  reserved (boot sector in 0)
///   sectors 32-39 FATs (2 × 4 sectors)
///   sectors 40+   data (cluster 2 = root dir, cluster 3 = file data)
fn build_fat32_partition_image() -> Vec<u8> {
    const SECTORS: usize = 240;
    let mut image = vec![0u8; SECTORS * BLOCK_SIZE];

    // Boot sector.
    image[0..3].copy_from_slice(b"\xEB\x3C\x90");
    image[3..11].copy_from_slice(b"MSDOS5.0");
    put_u16(&mut image, 11, BLOCK_SIZE as u16);
    image[13] = 1; // sectors per cluster
    put_u16(&mut image, 14, 32); // reserved sectors
    image[16] = 2; // number of FATs
    put_u16(&mut image, 17, 0); // root entries (0 for FAT32)
    put_u16(&mut image, 19, 0); // total sectors 16 (0 for FAT32)
    image[21] = 0xF8; // media descriptor
    put_u16(&mut image, 22, 0); // sectors per FAT 16 (0 for FAT32)
    put_u32(&mut image, 32, SECTORS as u32); // total sectors 32
    put_u32(&mut image, 36, 4); // sectors per FAT
    put_u32(&mut image, 44, 2); // root cluster
    put_u16(&mut image, 48, 1); // FSInfo sector
    put_u16(&mut image, 50, 6); // backup boot sector
    image[66] = 0x29;
    put_u32(&mut image, 67, 0x1234_5678);
    image[71..82].copy_from_slice(b"USBMSDVOL  ");
    image[82..90].copy_from_slice(b"FAT32   ");
    image[510] = 0x55;
    image[511] = 0xAA;

    // FATs: FAT[0] media, FAT[1] reserved, FAT[2] root EOC, FAT[3] file EOC.
    let fat_base = 32 * BLOCK_SIZE;
    for fat in 0..2 {
        let base = fat_base + fat * 4 * BLOCK_SIZE;
        put_u32(&mut image, base, 0x0FFF_FFF8);
        put_u32(&mut image, base + 4, 0xFFFF_FFFF);
        put_u32(&mut image, base + 8, 0x0FFF_FFFF);
        put_u32(&mut image, base + 12, 0x0FFF_FFFF);
    }

    // Root directory: ".", "..", and README.TXT (cluster 3, 12 bytes).
    let root = 40 * BLOCK_SIZE;
    write_short_entry(&mut image, root, b".          ", 0x10, 2, 0);
    write_short_entry(&mut image, root + 32, b"..         ", 0x10, 2, 0);
    write_short_entry(&mut image, root + 64, b"README  TXT", 0x20, 3, 12);

    // File data lives in cluster 3 = sector 41.
    let data = 41 * BLOCK_SIZE;
    image[data..data + 12].copy_from_slice(b"usbmsd-mount");
    image
}

/// End-to-end storage-loop shape: an MBR in sector 0 points at a FAT32
/// partition at LBA 2048; the boot chain scans the whole disk, slices the
/// partition, mounts it as FAT32, and reads a file back.  This is the host
/// mirror of the `usb-msd` boot-disk path (`probe_boot_disk` → partition
/// scan → mount) that runs on bare metal after READ CAPACITY.
#[test]
fn test_usb_msd_mbr_partition_scan_and_mount() {
    let partition_image = build_fat32_partition_image();
    let partition_blocks = (partition_image.len() / BLOCK_SIZE) as u64;

    // Composite disk: MBR at sector 0 + FAT32 partition at LBA 2048.
    let total_blocks = PARTITION_START_LBA as u64 + partition_blocks;
    let mut disk = vec![0u8; total_blocks as usize * BLOCK_SIZE];

    let partitions: MbrPartitionTable = [
        Some(MbrPartitionEntry::new(
            true,
            MBR_PARTITION_TYPE_FAT32,
            PARTITION_START_LBA as u64,
            partition_blocks,
        )),
        None,
        None,
        None,
    ];
    let mut sector = [0u8; BLOCK_SIZE];
    write_mbr_partitions(&mut sector, &partitions).expect("write MBR");
    disk[..BLOCK_SIZE].copy_from_slice(&sector);

    let offset = PARTITION_START_LBA as usize * BLOCK_SIZE;
    disk[offset..offset + partition_image.len()].copy_from_slice(&partition_image);

    // Storage loop: scan the whole disk, slice the partition, mount it.
    let parent: Arc<dyn BlockDevice> = MemoryBlockDevice::new("usb-msd-disk", disk, false);
    let table = read_mbr_partitions(parent.as_ref())
        .expect("read MBR partitions")
        .expect("MBR signature present");
    let part = table[0].expect("first partition present");
    assert_eq!(part.partition_type, MBR_PARTITION_TYPE_FAT32);
    assert_eq!(part.start_block, PARTITION_START_LBA as u64);
    assert_eq!(part.block_count, partition_blocks);

    let slice = BlockSliceDevice::new(
        "usb-msd-part0",
        parent.clone(),
        part.start_block,
        part.block_count,
        false,
    );
    let volume = FatVolume::open(slice).expect("open FAT32 partition");

    // Read the pre-seeded file straight off the mounted partition.
    let node = volume.lookup("/README.TXT").expect("lookup README.TXT");
    assert_eq!(node.size(), 12);
    let mut buffer = [0u8; 16];
    let n = node.read(0, &mut buffer).expect("read file");
    assert_eq!(&buffer[..n], b"usbmsd-mount");
}
