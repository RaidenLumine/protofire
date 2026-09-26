//! src/arch/scanout.rs
//!
//! Memory a device draws into, and the address the device must be told.
//!
//! A scanout buffer is ordinary memory to the kernel and a *physical* address
//! to the device that scans it out.  Where that address comes from is the
//! machine's: x86_64 has a DMA window below 1 GiB and allocates from the frame
//! allocator through [`DmaBuffer`]; the identity-mapped machines have no such
//! window, and there a page-aligned heap region's virtual address *is* its
//! guest-physical address — the same property the VirtQueue rings and the
//! network driver already rely on.
//!
//! The driver asks for a buffer and for its physical address; which of those
//! two worlds it is in does not reach it.

/// Physical backing for a scanout.
pub(crate) struct Scanout {
    #[cfg(target_arch = "x86_64")]
    dma: crate::memory::dma::DmaBuffer,
    #[cfg(not(target_arch = "x86_64"))]
    base: usize,
    #[cfg(not(target_arch = "x86_64"))]
    len: usize,
}

impl Scanout {
    /// Allocate `bytes` of scanout backing, aligned for a device to scan.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn allocate(bytes: usize) -> Option<Self> {
        let frames = bytes.div_ceil(crate::memory::frame::FRAME_SIZE);
        let dma = crate::memory::dma::DmaBuffer::allocate(frames)?;
        Some(Self { dma })
    }

    /// Allocate `bytes` as a page-aligned, identity-mapped heap region.
    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) fn allocate(bytes: usize) -> Option<Self> {
        use core::alloc::Layout;
        let layout = Layout::from_size_align(bytes, 4096).ok()?;
        // SAFETY: the layout is non-zero and the region is never freed — it
        // backs the scanout for the kernel's whole lifetime.
        let base = unsafe { alloc::alloc::alloc(layout) };
        if base.is_null() {
            return None;
        }
        // SAFETY: `base` came from the allocator with `bytes` writable, and the
        // firmware hands the device a buffer it should see as black rather
        // than as whatever the heap last held.
        unsafe { core::ptr::write_bytes(base, 0u8, bytes) };
        Some(Self {
            base: base as usize,
            len: bytes,
        })
    }

    /// The buffer as the kernel writes it.
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        #[cfg(target_arch = "x86_64")]
        {
            self.dma.as_ptr()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.base as *mut u8
        }
    }

    /// The address the device is told to scan out.
    pub(crate) fn phys_addr(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            self.dma.phys_addr()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.base
        }
    }

    /// How many bytes were allocated.
    pub(crate) fn len(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            self.dma.len()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.len
        }
    }
}
