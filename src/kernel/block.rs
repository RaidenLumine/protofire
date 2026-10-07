//! src/kernel/block.rs
//!
//! The block layer: the block-device interface, the in-memory devices that
//! implement it, and the slot a driver publishes a newly found device through.
//!
//! This sits below the filesystem on purpose.  A disk driver has to name the
//! device interface to implement it, and it must not have to name the
//! filesystem to do that — the filesystem is one consumer of the interface, not
//! its owner.

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

pub const BLOCK_SIZE: usize = 512;

/// What the layer above has asked the devices for, in requests and bytes.
///
/// This is the bottom of the three heights a read can be counted at: a
/// filesystem counts its own operations and the bytes they were asked for, a
/// cache counts what it served and what it passed on, and this counts what
/// actually left for a device.  The difference between the three is where a
/// boot's reads go, and it is not visible from any one of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceIo {
    pub read_ops: u64,
    pub read_bytes: u64,
    pub write_ops: u64,
    pub write_bytes: u64,
    /// The most requests that were ever in flight at once.
    ///
    /// An asynchronous interface is only worth having if some device can hold
    /// a second request while the first is outstanding, and this is the number
    /// that would show it: a high-water mark of one says every device the tree
    /// boots completes in place.  It counts reads and writes, the two requests
    /// the counters above count.
    pub in_flight_high_water: u64,
}

/// The machine's device traffic, counted only when the boot-work line is
/// compiled in: these counters sit on the I/O path, and a build that is not
/// measuring itself should not pay for them.
#[cfg(feature = "perf_baseline")]
mod io_counters {
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;

    use super::DeviceIo;

    pub(super) struct Counters {
        read_ops: AtomicU64,
        read_bytes: AtomicU64,
        write_ops: AtomicU64,
        write_bytes: AtomicU64,
        in_flight: AtomicU64,
        in_flight_high_water: AtomicU64,
    }

    impl Counters {
        pub(super) const fn new() -> Self {
            Self {
                read_ops: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
                write_ops: AtomicU64::new(0),
                write_bytes: AtomicU64::new(0),
                in_flight: AtomicU64::new(0),
                in_flight_high_water: AtomicU64::new(0),
            }
        }

        pub(super) fn snapshot(&self) -> DeviceIo {
            DeviceIo {
                read_ops: self.read_ops.load(Ordering::Relaxed),
                read_bytes: self.read_bytes.load(Ordering::Relaxed),
                write_ops: self.write_ops.load(Ordering::Relaxed),
                write_bytes: self.write_bytes.load(Ordering::Relaxed),
                in_flight_high_water: self.in_flight_high_water.load(Ordering::Relaxed),
            }
        }
    }

    pub(super) static DEVICE_IO: Counters = Counters::new();

    /// A request that is on a device right now, counted until it drops.
    ///
    /// It is a guard rather than a pair of calls so that an error return cannot
    /// leave the count up, and the mark it keeps is relaxed because it is read
    /// once at a tick, long after the requests it counted have finished.
    pub(super) struct InFlight;

    impl InFlight {
        pub(super) fn enter() -> Self {
            let now = DEVICE_IO.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
            DEVICE_IO
                .in_flight_high_water
                .fetch_max(now, Ordering::Relaxed);
            Self
        }
    }

    impl Drop for InFlight {
        fn drop(&mut self) {
            DEVICE_IO.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// One read, of `bytes`, asked of a device.
    pub(super) fn count_read(bytes: u64) {
        DEVICE_IO.read_ops.fetch_add(1, Ordering::Relaxed);
        DEVICE_IO.read_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// One write, of `bytes`, handed to a device.
    pub(super) fn count_write(bytes: u64) {
        DEVICE_IO.write_ops.fetch_add(1, Ordering::Relaxed);
        DEVICE_IO.write_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// The machine's device traffic so far, all zeros when the counters are not
/// compiled in.
pub fn device_io_snapshot() -> DeviceIo {
    #[cfg(feature = "perf_baseline")]
    {
        io_counters::DEVICE_IO.snapshot()
    }
    #[cfg(not(feature = "perf_baseline"))]
    {
        DeviceIo::default()
    }
}

/// Wrap a device in the counter the boot-work line reads.
///
/// The wrapper goes where a device *enters the filesystem's device map*, which
/// is the one place every device the filesystem can read through passes: a
/// driver's published disk, and the in-memory and sliced volumes the boot
/// installs.  A slice delegates to its parent, so a read through a slice is
/// counted once — at the slice, which is the device the filesystem was handed.
pub fn counting_device(device: Arc<dyn BlockDevice>) -> Arc<dyn BlockDevice> {
    #[cfg(feature = "perf_baseline")]
    {
        Arc::new(CountingDevice { inner: device })
    }
    #[cfg(not(feature = "perf_baseline"))]
    {
        device
    }
}

/// The wrapper [`counting_device`] installs.
#[cfg(feature = "perf_baseline")]
struct CountingDevice {
    inner: Arc<dyn BlockDevice>,
}

#[cfg(feature = "perf_baseline")]
impl BlockDevice for CountingDevice {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        io_counters::count_read(buffer.len() as u64);
        let _in_flight = io_counters::InFlight::enter();
        self.inner.read_blocks(lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        io_counters::count_write(data.len() as u64);
        let _in_flight = io_counters::InFlight::enter();
        self.inner.write_blocks(lba, data)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn device_health(&self) -> DeviceHealth {
        self.inner.device_health()
    }
}

/// Health classification for block devices so callers can distinguish
/// transient I/O glitches from permanent media failure without new
/// error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceHealth {
    /// The device is operating normally.
    Healthy,
    /// The device has reported transient errors but remains usable.
    Degraded,
    /// The device has suffered a permanent failure and should not be
    /// retried.
    Failed,
}

pub trait BlockDevice: Send + Sync {
    fn name(&self) -> &str;
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
    fn block_count(&self) -> u64;
    fn is_read_only(&self) -> bool;
    /// Read `buffer.len() / block_size()` blocks starting at `lba` into
    /// `buffer`.
    ///
    /// The request may cover more than one block: a filesystem reading a
    /// table, or a cache reading ahead, asks for a run in one call, and a
    /// device that answered only the first block would leave the rest of the
    /// buffer as it found it.
    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()>;
    /// Write `data.len() / block_size()` blocks starting at `lba`, with the
    /// same multi-block contract as [`BlockDevice::read_blocks`].
    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()>;

    /// Flush any device-side write caches to stable storage.
    ///
    /// The default implementation is a no-op.  Drivers that manage
    /// hardware write caches (ATA, VirtIO) should override this to
    /// issue the appropriate cache-flush command.
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Report the current device health.  The default implementation
    /// returns `Healthy`; real drivers should override this to reflect
    /// hardware status registers or accumulated error counts.
    fn device_health(&self) -> DeviceHealth {
        DeviceHealth::Healthy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub block_size: usize,
    pub block_count: u64,
    pub read_only: bool,
}

pub struct MemoryBlockDevice {
    name: String,
    storage: Mutex<Vec<u8>>,
    read_only: bool,
}

pub struct BlockSliceDevice {
    name: String,
    parent: Arc<dyn BlockDevice>,
    start_block: u64,
    block_count: u64,
    read_only: bool,
}

impl MemoryBlockDevice {
    pub fn new(name: &str, mut image: Vec<u8>, read_only: bool) -> Arc<Self> {
        let remainder = image.len() % BLOCK_SIZE;
        if remainder != 0 {
            image.resize(image.len() + (BLOCK_SIZE - remainder), 0);
        }

        Arc::new(Self {
            name: name.to_string(),
            storage: Mutex::new(image),
            read_only,
        })
    }
}

impl BlockSliceDevice {
    pub fn new(
        name: &str,
        parent: Arc<dyn BlockDevice>,
        start_block: u64,
        block_count: u64,
        read_only: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            parent,
            start_block,
            block_count,
            read_only,
        })
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_count(&self) -> u64 {
        (self.storage.lock().len() / BLOCK_SIZE) as u64
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        if !buffer.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidArgument);
        }

        let lba = usize::try_from(lba).map_err(|_| Error::InvalidArgument)?;
        let start = lba.checked_mul(BLOCK_SIZE).ok_or(Error::InvalidArgument)?;
        let end = start
            .checked_add(buffer.len())
            .ok_or(Error::InvalidArgument)?;
        let storage = self.storage.lock();
        if end > storage.len() {
            return Err(Error::InvalidArgument);
        }

        buffer.copy_from_slice(&storage[start..end]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }

        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidArgument);
        }

        let lba = usize::try_from(lba).map_err(|_| Error::InvalidArgument)?;
        let start = lba.checked_mul(BLOCK_SIZE).ok_or(Error::InvalidArgument)?;
        let end = start
            .checked_add(data.len())
            .ok_or(Error::InvalidArgument)?;
        let mut storage = self.storage.lock();
        if end > storage.len() {
            return Err(Error::InvalidArgument);
        }

        storage[start..end].copy_from_slice(data);
        Ok(())
    }

    fn device_health(&self) -> DeviceHealth {
        DeviceHealth::Healthy
    }
}

impl BlockDevice for BlockSliceDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        if !buffer.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidArgument);
        }

        let blocks = (buffer.len() / BLOCK_SIZE) as u64;
        let end = lba.checked_add(blocks).ok_or(Error::InvalidArgument)?;
        if end > self.block_count {
            return Err(Error::InvalidArgument);
        }

        let parent_lba = self
            .start_block
            .checked_add(lba)
            .ok_or(Error::InvalidArgument)?;
        self.parent.read_blocks(parent_lba, buffer)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }

        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidArgument);
        }

        let blocks = (data.len() / BLOCK_SIZE) as u64;
        let end = lba.checked_add(blocks).ok_or(Error::InvalidArgument)?;
        if end > self.block_count {
            return Err(Error::InvalidArgument);
        }

        let parent_lba = self
            .start_block
            .checked_add(lba)
            .ok_or(Error::InvalidArgument)?;
        self.parent.write_blocks(parent_lba, data)
    }

    fn flush(&self) -> Result<()> {
        self.parent.flush()
    }

    fn device_health(&self) -> DeviceHealth {
        self.parent.device_health()
    }
}

// ── Device publication ──────────────────────────────────────────────────

/// The sink a found device is handed to, installed once at boot.
///
/// A driver has to name the block interface to implement it, and it must not
/// have to name the filesystem to hand the device over.  The filesystem owns
/// the device map and sits *above* this layer, so the hand-off goes through a
/// slot the layer below can reach without naming it: whoever owns the map
/// installs itself here, and the driver calls [`publish_device`].
///
/// Deliberately a plain function pointer rather than a closure: no allocation,
/// no capture, and one sink — a second source of truth for "which devices
/// exist" is the thing this is here to avoid.
/// The sink a published device goes to: its name, and the device.
pub type DeviceSink = fn(&str, Arc<dyn BlockDevice>);

static DEVICE_PUBLISHER: Mutex<Option<DeviceSink>> = Mutex::new(None);

/// Install the sink for [`publish_device`].
pub fn set_device_publisher(publisher: DeviceSink) {
    *DEVICE_PUBLISHER.lock() = Some(publisher);
}

/// Hand a device to the installed sink.
///
/// Returns whether it was delivered.  With no sink installed the device is
/// dropped — that is the case in a build that never installs one, such as a
/// host test that builds its devices directly, and it is reported rather than
/// passed over in silence.
pub fn publish_device(name: &str, device: Arc<dyn BlockDevice>) -> bool {
    // Copy the sink out and release the lock before calling it: the publisher
    // takes the filesystem lock, and holding this one across that would put two
    // unrelated locks in a fixed order for no reason.
    let publisher = *DEVICE_PUBLISHER.lock();
    match publisher {
        Some(publish) => {
            publish(name, device);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::BlockDevice;
    use super::BlockSliceDevice;
    use super::MemoryBlockDevice;
    use super::BLOCK_SIZE;
    use crate::Error;

    #[test]
    fn memory_block_device_rejects_lba_multiplication_overflow() {
        let device = MemoryBlockDevice::new("memory", vec![0_u8; BLOCK_SIZE], false);
        let mut read_buffer = [0_u8; BLOCK_SIZE];

        assert_eq!(
            device.read_blocks(u64::MAX, &mut read_buffer),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            device.write_blocks(u64::MAX, &read_buffer),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn block_slice_device_rejects_parent_lba_overflow() {
        let parent: alloc::sync::Arc<dyn BlockDevice> =
            MemoryBlockDevice::new("parent", vec![0_u8; BLOCK_SIZE], false);
        let slice = BlockSliceDevice::new("slice", parent, u64::MAX, 1, false);
        let mut read_buffer = [0_u8; BLOCK_SIZE];

        assert_eq!(
            slice.read_blocks(0, &mut read_buffer),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            slice.write_blocks(0, &read_buffer),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn memory_block_device_flush_is_noop() {
        let device = MemoryBlockDevice::new("memory", vec![0_u8; BLOCK_SIZE], false);
        assert_eq!(device.flush(), Ok(()));
    }

    #[test]
    fn read_only_memory_device_flush_is_still_noop() {
        let device = MemoryBlockDevice::new("memory", vec![0_u8; BLOCK_SIZE], true);
        assert_eq!(device.flush(), Ok(()));
    }

    #[test]
    fn block_slice_device_flush_delegates_to_parent() {
        let parent: alloc::sync::Arc<dyn BlockDevice> =
            MemoryBlockDevice::new("parent", vec![0_u8; BLOCK_SIZE], false);
        let slice = BlockSliceDevice::new("slice", parent, 0, 1, false);
        assert_eq!(slice.flush(), Ok(()));
    }

    #[test]
    fn a_read_only_slice_refuses_writes_and_still_reads() {
        // This is how the read-only zone is enforced: `/system` is a slice of
        // the boot disk whose block device answers a write with a refusal,
        // whatever security token asks.  A running machine cannot change the
        // code it is running because it cannot write the blocks it lives on;
        // `/apps` is *not* cut this way, because installing writes it and the
        // gate for that is the zone's security descriptor.
        let parent: alloc::sync::Arc<dyn BlockDevice> =
            MemoryBlockDevice::new("parent", vec![0x5a_u8; BLOCK_SIZE], false);
        let slice = BlockSliceDevice::new("slice", parent, 0, 1, true);
        let mut buffer = [0_u8; BLOCK_SIZE];

        assert!(slice.is_read_only());
        assert_eq!(slice.write_blocks(0, &buffer), Err(Error::PermissionDenied));
        assert_eq!(slice.read_blocks(0, &mut buffer), Ok(()));
        assert_eq!(buffer, [0x5a_u8; BLOCK_SIZE]);
    }
}
