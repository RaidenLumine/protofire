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
    /// The frames the allocator handed over, which `Drop` returns whole.
    allocation: *mut u8,
    /// Frames the allocator gave this buffer; at least `frame_count`.
    allocated_frames: usize,
    /// The buffer's first byte, at the alignment the caller asked for.
    ptr: *mut u8,
    /// Frames the buffer itself covers, starting at `ptr`.
    frame_count: usize,
    phys: usize,
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
            allocation: ptr,
            allocated_frames: frame_count,
            ptr,
            phys,
            frame_count,
        })
    }

    /// Allocate `frame_count` frames whose first byte is `alignment`-aligned.
    ///
    /// Some device registers do not hold a full address: the low bits are not
    /// implemented at all, and a table a device is pointed at has to start
    /// where the register can name it.  An AArch64 redistributor's LPI pending
    /// table is the one this kernel needs — `GICR_PENDBASER` keeps only bits
    /// [51:16] of the address, so a table that starts anywhere else is not the
    /// table the redistributor will read.
    ///
    /// `alignment` must be a power of two and at least `FRAME_SIZE`.  The
    /// frames in front of the aligned start belong to the buffer and are
    /// released with it, so the allocation is honest about what it took.
    #[must_use]
    pub fn allocate_aligned(frame_count: usize, alignment: usize) -> Option<Self> {
        if frame_count == 0 || !alignment.is_power_of_two() || alignment < FRAME_SIZE {
            return None;
        }

        // Worst case the first aligned address is one frame short of the end
        // of the extra run, so this much slack always leaves `frame_count`
        // frames from the aligned start.
        let slack_frames = alignment / FRAME_SIZE - 1;
        let allocated_frames = frame_count.checked_add(slack_frames)?;
        let allocation = global_mut()?.allocate_frames(allocated_frames)?;
        let allocation_phys = phys_addr_of(allocation as usize)?;

        let phys = aligned_start(allocation_phys, alignment);
        let ptr = (allocation as usize + (phys - allocation_phys)) as *mut u8;

        // Zero what the caller will see, so stale data never reaches a device.
        // SAFETY: the frame allocator returned `allocated_frames` contiguous
        // frames from `allocation`, and the aligned buffer plus its
        // `frame_count` frames lies inside them.
        unsafe {
            core::ptr::write_bytes(ptr, 0, frame_count * FRAME_SIZE);
        }

        Some(Self {
            allocation,
            allocated_frames,
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
        if !self.allocation.is_null() {
            if let Some(mut manager) = global_mut() {
                manager.deallocate_frames(self.allocation, self.allocated_frames);
            }
        }
    }
}

/// The first address at or after `base` that `alignment` can name.
///
/// The alignment is a device's requirement, not a convenience: a register
/// that holds only the high bits of an address can name one address per
/// `alignment` bytes, and this is which of them a buffer starting at `base`
/// is given.  `base` itself when it is already aligned, and `alignment` must
/// be a power of two.
fn aligned_start(base: usize, alignment: usize) -> usize {
    base.div_ceil(alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::aligned_start;
    use super::FRAME_SIZE;

    #[test]
    fn an_aligned_base_is_its_own_start() {
        assert_eq!(aligned_start(0, FRAME_SIZE), 0);
        assert_eq!(aligned_start(0x1_0000, 0x1_0000), 0x1_0000);
    }

    #[test]
    fn an_unaligned_base_rounds_up_within_one_alignment() {
        for offset in [1, 5, FRAME_SIZE - 1, 0x8000, 0xffff] {
            let base = 0x1_0000 + offset;
            assert_eq!(aligned_start(base, 0x1_0000), 0x2_0000);
            // The skip a caller pays for is strictly less than one alignment,
            // which is what makes the slack `allocate_aligned` reserves
            // enough.
            assert!(aligned_start(base, 0x1_0000) - base < 0x1_0000);
        }
    }
}
