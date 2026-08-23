//! src/kernel/memory/swap.rs
//! Swap area abstraction for paging anonymous pages to a block device.
//!
//! Each swap area is a contiguous range of blocks on a [`BlockDevice`].
//! Pages (4096 bytes = 8 × 512-byte blocks) are stored in fixed-size
//! slots.  Allocation uses a LIFO free list that is rebuilt from scratch
//! on every boot — swap data is only valid for the current boot session.

use core::fmt;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::block::{BlockDevice, BLOCK_SIZE};
use crate::kernel::memory::paging::PAGE_SIZE;
use crate::{Error, Result};

/// Number of 512-byte blocks per 4096-byte page slot.
const BLOCKS_PER_PAGE: u64 = (PAGE_SIZE / BLOCK_SIZE) as u64;

/// Magic signature written to block 0 of a swap device for boot-time
/// discovery.  A device whose first 8 bytes match this constant is
/// recognised as a valid swap area.
pub const SWAP_MAGIC: [u8; 8] = *b"ADASWAP\x00";

/// Probe a block device for a valid swap area signature at block 0.
///
/// Returns `Some((start_lba, page_count))` if the device contains a
/// recognised swap signature, or `None` if the device is not a swap
/// area (or an I/O error occurs).
pub fn probe_device(device: &dyn BlockDevice) -> Option<(u64, u64)> {
    let mut header = [0u8; 512];
    device.read_blocks(0, &mut header).ok()?;
    if header[..8] != SWAP_MAGIC {
        return None;
    }
    // Page count stored at offset 8..16 (little-endian u64).
    let page_count = u64::from_le_bytes(header[8..16].try_into().ok()?);
    if page_count == 0 {
        return None;
    }
    Some((0, page_count))
}

/// Identifies a page slot within a swap area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapSlot(pub u64);

/// A swap area backed by a block device.
///
/// Pages are stored in fixed-size slots.  Each slot spans 8 consecutive
/// 512-byte blocks (4096 bytes total).  Slots are allocated from a LIFO
/// free list and returned when the page is faulted back into memory or
/// the owning process terminates.
///
/// # Boot-cycle semantics
///
/// All slots are considered free at creation time.  Swap data from a
/// previous boot is ignored — the swap area is not persistent across
/// reboots.
pub struct SwapArea {
    device: Arc<dyn BlockDevice>,
    /// Starting LBA of the swap data region.
    start_lba: u64,
    /// Total number of page slots.
    total_pages: u64,
    /// LIFO stack of free slot indices.
    free_slots: Vec<u64>,
}

impl SwapArea {
    /// Create a new swap area on `device` starting at `start_lba` with
    /// capacity for `page_count` page slots.
    ///
    /// Returns `InvalidArgument` if the swap area would extend past the
    /// end of the device, or `OutOfMemory` if the free-slot stack cannot
    /// be allocated.
    pub fn new(device: Arc<dyn BlockDevice>, start_lba: u64, page_count: u64) -> Result<Self> {
        if page_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let blocks_needed = page_count
            .checked_mul(BLOCKS_PER_PAGE)
            .ok_or(Error::InvalidArgument)?;
        let end_lba = start_lba
            .checked_add(blocks_needed)
            .ok_or(Error::InvalidArgument)?;
        if end_lba > device.block_count() {
            return Err(Error::InvalidArgument);
        }

        let mut free_slots: Vec<u64> = Vec::new();
        free_slots
            .try_reserve(page_count as usize)
            .map_err(|_| Error::OutOfMemory)?;

        // Push in reverse so slot 0 is allocated first (FIFO-ish from the
        // bottom of the area upward).
        for i in (0..page_count).rev() {
            free_slots.push(i);
        }

        Ok(Self {
            device,
            start_lba,
            total_pages: page_count,
            free_slots,
        })
    }

    /// Allocate a free page slot.  Returns `None` when the area is full.
    pub fn allocate_slot(&mut self) -> Option<SwapSlot> {
        self.free_slots.pop().map(SwapSlot)
    }

    /// Return a previously allocated slot to the free pool.
    pub fn free_slot(&mut self, slot: SwapSlot) {
        self.free_slots.push(slot.0);
    }

    /// Write a page (4096 bytes) to a slot.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `data.len()` is not 4096, or
    /// propagates device errors from the underlying block device.
    pub fn write_page(&self, slot: SwapSlot, data: &[u8]) -> Result<()> {
        if data.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let lba = self.slot_lba(slot);
        self.device.write_blocks(lba, data)
    }

    /// Read a page (4096 bytes) from a slot.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `buffer.len()` is not 4096, or
    /// propagates device errors from the underlying block device.
    pub fn read_page(&self, slot: SwapSlot, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let lba = self.slot_lba(slot);
        self.device.read_blocks(lba, buffer)
    }

    /// Total number of page slots in this area.
    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Number of free (unallocated) page slots.
    pub fn free_pages(&self) -> u64 {
        self.free_slots.len() as u64
    }

    /// Number of currently allocated page slots.
    pub fn used_pages(&self) -> u64 {
        self.total_pages - self.free_slots.len() as u64
    }

    /// Compute the starting LBA for a slot.
    fn slot_lba(&self, slot: SwapSlot) -> u64 {
        self.start_lba + slot.0 * BLOCKS_PER_PAGE
    }
}

impl fmt::Debug for SwapArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwapArea")
            .field("start_lba", &self.start_lba)
            .field("total_pages", &self.total_pages)
            .field("free_slots", &self.free_slots.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::super::paging::PAGE_SIZE;
    use super::*;
    use crate::kernel::fs::block::MemoryBlockDevice;

    /// Create a MemoryBlockDevice large enough for `page_count` swap slots.
    fn make_swap_device(page_count: u64) -> Arc<MemoryBlockDevice> {
        let total_bytes = (page_count as usize) * PAGE_SIZE;
        // Pad to block size.
        let remainder = total_bytes % BLOCK_SIZE;
        let padded = if remainder != 0 {
            total_bytes + (BLOCK_SIZE - remainder)
        } else {
            total_bytes
        };
        MemoryBlockDevice::new("swap-device", vec![0u8; padded], false)
    }

    #[test]
    fn new_swap_area_zero_pages_is_invalid() {
        let device = make_swap_device(1);
        assert!(SwapArea::new(device, 0, 0).is_err());
    }

    #[test]
    fn new_swap_area_beyond_device_is_invalid() {
        let device = make_swap_device(2);
        // 3 pages = 24 blocks, but device only has 16 blocks.
        assert!(SwapArea::new(device, 0, 3).is_err());
    }

    #[test]
    fn allocate_and_free_slot_cycle() {
        let device = make_swap_device(4);
        let mut area = SwapArea::new(device, 0, 4).unwrap();

        assert_eq!(area.total_pages(), 4);
        assert_eq!(area.free_pages(), 4);
        assert_eq!(area.used_pages(), 0);

        let s0 = area.allocate_slot().unwrap();
        assert_eq!(s0.0, 0); // LIFO: first allocated is slot 0
        assert_eq!(area.free_pages(), 3);
        assert_eq!(area.used_pages(), 1);

        let s1 = area.allocate_slot().unwrap();
        assert_eq!(s1.0, 1);
        assert_eq!(area.used_pages(), 2);

        // Free s0 and re-allocate: should get s0 back (LIFO).
        area.free_slot(s0);
        assert_eq!(area.free_pages(), 3);
        let s2 = area.allocate_slot().unwrap();
        assert_eq!(s2.0, 0); // LIFO: most recently freed

        assert_eq!(area.used_pages(), 2);
    }

    #[test]
    fn allocate_exhausts_free_list() {
        let device = make_swap_device(2);
        let mut area = SwapArea::new(device, 0, 2).unwrap();

        assert!(area.allocate_slot().is_some());
        assert!(area.allocate_slot().is_some());
        assert!(area.allocate_slot().is_none()); // exhausted
    }

    #[test]
    fn write_and_read_page_round_trip() {
        let device = make_swap_device(4);
        let mut area = SwapArea::new(device, 0, 4).unwrap();

        let slot = area.allocate_slot().unwrap();

        let mut data = [0u8; PAGE_SIZE];
        for (i, item) in data.iter_mut().enumerate().take(PAGE_SIZE) {
            *item = (i & 0xff) as u8;
        }
        area.write_page(slot, &data).unwrap();

        let mut read_back = [0u8; PAGE_SIZE];
        area.read_page(slot, &mut read_back).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn multiple_pages_independent() {
        let device = make_swap_device(4);
        let mut area = SwapArea::new(device, 0, 4).unwrap();

        let s0 = area.allocate_slot().unwrap();
        let s1 = area.allocate_slot().unwrap();

        let page0 = [0xAAu8; PAGE_SIZE];
        let page1 = [0xBBu8; PAGE_SIZE];

        area.write_page(s0, &page0).unwrap();
        area.write_page(s1, &page1).unwrap();

        let mut buf = [0u8; PAGE_SIZE];
        area.read_page(s0, &mut buf).unwrap();
        assert_eq!(buf, page0);

        area.read_page(s1, &mut buf).unwrap();
        assert_eq!(buf, page1);
    }

    #[test]
    fn read_page_wrong_size_rejected() {
        let device = make_swap_device(1);
        let mut area = SwapArea::new(device, 0, 1).unwrap();
        let slot = area.allocate_slot().unwrap();

        let mut short_buf = [0u8; 512];
        assert_eq!(
            area.read_page(slot, &mut short_buf),
            Err(Error::InvalidArgument)
        );

        let mut long_buf = [0u8; 8192];
        assert_eq!(
            area.read_page(slot, &mut long_buf),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn write_page_wrong_size_rejected() {
        let device = make_swap_device(1);
        let mut area = SwapArea::new(device, 0, 1).unwrap();
        let slot = area.allocate_slot().unwrap();

        let short_data = [0u8; 512];
        assert_eq!(
            area.write_page(slot, &short_data),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn non_zero_start_lba() {
        // Create a device with extra space before the swap area.
        let device = MemoryBlockDevice::new(
            "offset-swap",
            vec![0u8; (8 + 16) * BLOCK_SIZE], // 8 blocks padding + 16 blocks for 2 pages
            false,
        );
        let mut area = SwapArea::new(device, 8, 2).unwrap();

        let slot = area.allocate_slot().unwrap();
        let page = [0xCCu8; PAGE_SIZE];
        area.write_page(slot, &page).unwrap();

        let mut buf = [0u8; PAGE_SIZE];
        area.read_page(slot, &mut buf).unwrap();
        assert_eq!(buf, page);
    }

    #[test]
    fn read_only_device_cannot_be_used_for_swap() {
        let device = MemoryBlockDevice::new("ro-swap", vec![0u8; 16 * BLOCK_SIZE], true);
        let mut area = SwapArea::new(device, 0, 2).unwrap();
        let slot = area.allocate_slot().unwrap();

        // write_page should fail because the device is read-only.
        let page = [0xDDu8; PAGE_SIZE];
        assert_eq!(area.write_page(slot, &page), Err(Error::PermissionDenied));
    }
}
