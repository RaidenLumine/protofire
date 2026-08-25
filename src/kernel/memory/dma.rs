//! src/kernel/memory/dma.rs
//!
//! Physically-contiguous DMA buffer and virtual-to-physical address
//! translation.

use super::frame::FRAME_SIZE;
use super::global::global_mut;

/// Translate a virtual address to its physical address.
///
/// On x86_64 the kernel is identity-mapped within the bootstrap region
/// (0 – 1 GiB); the frame-allocator physical pool lives inside that range,
/// so virtual address equals physical address.
///
/// Returns `None` when the address is outside known identity-mapped RAM.
#[must_use]
pub fn phys_addr_of(va: usize) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        // The identity-map covers the first 1 GiB (see BOOTSTRAP_IDENTITY_MAP_END).
        if va < 0x4000_0000 {
            return Some(va);
        }
        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = va;
        None
    }
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
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.len()) }
    }

    /// View the buffer as a mutable byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
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
