//! src/kernel/process/thread/kernel_stack.rs
//!
//! Kernel stack allocation and lifetime management with an optional
//! unmapped guard page below the usable region.

use alloc::boxed::Box;

/// Backing storage for a kernel stack.
enum KernelStackBacking {
    /// Frame-allocated: `base` points to the guard page, `total_frames` covers
    /// guard + usable stack.
    Frame { base: *mut u8, total_frames: usize },
    /// Heap-allocated fallback with no guard page.
    #[allow(dead_code)]
    Heap(Box<[u8]>),
}

/// Owns the kernel stack memory for a thread.
///
/// `stack_ptr()` returns the lowest *usable* address (guard page excluded).
/// `stack_len()` returns the usable byte count.
pub(crate) struct KernelStack {
    stack_ptr: *mut u8,
    stack_len: usize,
    backing: KernelStackBacking,
}

impl KernelStack {
    /// Allocate a kernel stack with a guard page when the frame allocator is
    /// available; otherwise fall back to a heap allocation.
    pub(crate) fn new(guard_size: usize, stack_size: usize) -> Self {
        // Try frame-backed allocation first so the guard page can be left
        // unmapped.
        if let Some(mut mm) = crate::kernel::memory::global_mut() {
            let total_size = guard_size + stack_size;
            let total_frames = total_size.div_ceil(crate::kernel::memory::frame::FRAME_SIZE);
            if let Some(base) = mm.allocate_frames(total_frames) {
                let stack_ptr = unsafe { base.add(guard_size) };
                // Map only the usable stack region; the guard page stays
                // unmapped so any access faults.
                if let Err(e) = mm.map_region(
                    stack_ptr as usize,
                    stack_size,
                    crate::kernel::memory::paging::PagePermissions::READ_WRITE,
                ) {
                    crate::println!(
                        "[thread] kernel stack map_region failed ({}); falling back to heap",
                        e.as_str()
                    );
                    mm.deallocate_frames(base, total_frames);
                } else {
                    // The guard region is kept out of the software PageTable
                    // above, but on bare metal the hardware page tables may
                    // still have a residual mapping (e.g. from the bootstrap
                    // identity map or a prepared coarse-grained entry).  Walk
                    // the live hardware tables and clear the present/valid bit
                    // for each guard page so that stack overflows fault
                    // immediately instead of corrupting memory silently.
                    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
                    {
                        let page_size = crate::kernel::memory::frame::FRAME_SIZE;
                        for offset in (0..guard_size).step_by(page_size) {
                            unsafe {
                                crate::arch::x86_64::paging::unmap_page(base.add(offset) as usize);
                            }
                        }
                    }
                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                    {
                        let page_size = crate::kernel::memory::frame::FRAME_SIZE;
                        for offset in (0..guard_size).step_by(page_size) {
                            unsafe {
                                crate::arch::aarch64::mmu::unmap_page(base.add(offset) as usize);
                            }
                        }
                    }

                    return Self {
                        stack_ptr,
                        stack_len: stack_size,
                        backing: KernelStackBacking::Frame { base, total_frames },
                    };
                }
            }
        }

        // Fallback: heap allocation with no guard page.
        let boxed: Box<[u8]> = alloc::vec![0_u8; stack_size].into_boxed_slice();
        let stack_ptr = boxed.as_ptr() as *mut u8;
        let stack_len = boxed.len();
        Self {
            stack_ptr,
            stack_len,
            backing: KernelStackBacking::Heap(boxed),
        }
    }

    pub(crate) fn stack_ptr(&self) -> *mut u8 {
        self.stack_ptr
    }

    pub(crate) fn stack_len(&self) -> usize {
        self.stack_len
    }

    pub(crate) fn stack_top(&self) -> usize {
        self.stack_ptr as usize + self.stack_len
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        match &self.backing {
            KernelStackBacking::Frame { base, total_frames } => {
                // Unmap the usable stack region from the software page table.
                if let Some(mut mm) = crate::kernel::memory::global_mut() {
                    let _ = mm.unmap(self.stack_ptr as usize, self.stack_len);
                    mm.deallocate_frames(*base, *total_frames);
                }
            }
            KernelStackBacking::Heap(_) => {
                // Box<[u8]> drops automatically.
            }
        }
    }
}

// Safety: the stack pointer is valid for the lifetime of the KernelStack.
unsafe impl Send for KernelStack {}
unsafe impl Sync for KernelStack {}
