//! src/memory/dma.rs
//!
//! Physically-contiguous DMA buffer and virtual-to-physical address
//! translation.

use super::frame::FRAME_SIZE;
use super::global::global_mut;

/// Translate a virtual address to its physical address.
///
/// Whether the machine's mapping is the identity on an address is the
/// machine's answer — see [`crate::arch::mmu::phys_addr_of`], which is where
/// the range and the reason for it live.  `None` (from here or from there)
/// means the address cannot be used for DMA, and every caller refuses rather
/// than passing it on.
#[must_use]
pub fn phys_addr_of(va: usize) -> Option<usize> {
    crate::arch::mmu::phys_addr_of(va)
}

/// A physically-contiguous, page-aligned buffer suitable for device DMA.
///
/// The buffer is allocated from the frame allocator and its physical
/// address is known, so it can be used as a PRP page, queue memory, or
/// a bounce buffer for DMA I/O.
pub struct DmaBuffer {
    ptr: *mut u8,
    phys: usize,
    frame_count: usize,
}

// SAFETY: DmaBuffer owns the allocation; it is safe to Send across threads
// when the kernel migrates to SMP.  Sync is likewise safe because the buffer
// is not aliased.
unsafe impl Send for DmaBuffer {}
// SAFETY: a `DmaBuffer` owns its allocation and the physical address of it;
// moving that between threads moves the only handle.
unsafe impl Sync for DmaBuffer {}

impl DmaBuffer {
    /// Allocate `frame_count` frames (each `FRAME_SIZE` bytes) and return a
    /// zeroed DMA buffer.  Returns `None` if the frame allocator is exhausted
    /// or the address is not translatable to a physical address.
    #[must_use]
    pub fn allocate(frame_count: usize) -> Option<Self> {
        let ptr = global_mut()?.allocate_frames(frame_count)?;
        let phys = phys_addr_of(ptr as usize)?;
        // Zero the buffer so stale data never reaches a device.
        // SAFETY: the frame allocator returned `frame_count` contiguous frames
        // starting at `ptr`, which is exactly the range this zeroes.
        unsafe {
            core::ptr::write_bytes(ptr, 0, frame_count * FRAME_SIZE);
        }
        Some(Self {
            ptr,
            phys,
            frame_count,
        })
    }

    /// Physical address of the first byte, usable for NVMe PRP entries and
    /// PCI BAR queue-base registers.
    #[inline]
    pub fn phys_addr(&self) -> usize {
        self.phys
    }

    /// Virtual address of the first byte.
    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// View the buffer as a byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the buffer owns `frame_count` frames from the frame allocator
        // and `len()` is exactly their size, so the slice covers the allocation
        // and no more; the borrow keeps readers out while it is alive.
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.len()) }
    }

    /// View the buffer as a mutable byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice` — the same owned range, handed out through an
        // exclusive borrow.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len()) }
    }

    /// Total size in bytes (always a multiple of `FRAME_SIZE`).
    #[inline]
    pub fn len(&self) -> usize {
        self.frame_count * FRAME_SIZE
    }

    /// Always `false` — a `DmaBuffer` is allocated with at least one frame.
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Number of frames allocated.
    #[inline]
    pub fn frame_count(&self) -> usize {
        self.frame_count
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            if let Some(mut manager) = global_mut() {
                manager.deallocate_frames(self.ptr, self.frame_count);
            }
        }
    }
}
