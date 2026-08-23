//! src/kernel/fs/block.rs
//! Block-device abstractions and in-memory block-device helpers.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::sync::Mutex;
use crate::{Error, Result};

pub const BLOCK_SIZE: usize = 512;

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
    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()>;
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{BlockDevice, BlockSliceDevice, MemoryBlockDevice, BLOCK_SIZE};
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
}
