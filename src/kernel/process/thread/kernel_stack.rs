//! src/kernel/process/thread/kernel_stack.rs
//!
//! Kernel stack allocation and lifetime management with an optional
//! unmapped guard page below the usable region.

use alloc::boxed::Box;

/// Clear the present/valid bit on every guard page, and report whether every
/// one of them was actually cleared.
///
/// The result is returned rather than discarded because a guard that silently
/// did not get installed is indistinguishable from one that did: the same boot
/// either way, and the difference only shows up much later as a stack overflow
/// that corrupts memory instead of faulting.  `unmap_page` refuses to act on a
/// page inside a large mapping, which it has no way to split, so a missing
/// guard is a real outcome here rather than a theoretical one.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn enforce_guard_pages(base: *mut u8, guard_size: usize) -> bool {
    let page_size = crate::kernel::memory::frame::FRAME_SIZE;
    let mut enforced = true;
    for offset in (0..guard_size).step_by(page_size) {
        let cleared = unsafe { crate::arch::x86_64::paging::unmap_page(base.add(offset) as usize) };
        enforced &= cleared;
    }
    enforced
}

/// aarch64 counterpart; see the x86_64 version for why the result is returned.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn enforce_guard_pages(base: *mut u8, guard_size: usize) -> bool {
    let page_size = crate::kernel::memory::frame::FRAME_SIZE;
    let mut enforced = true;
    for offset in (0..guard_size).step_by(page_size) {
        // `invalidate_page`, not `unmap_page`: the guard has to be
        // reversible, and `unmap_page` zeroes the descriptor.
        let cleared =
            unsafe { crate::arch::aarch64::mmu::invalidate_page(base.add(offset) as usize) };
        enforced &= cleared;
    }
    enforced
}

/// Host and other targets have no hardware guard pages to enforce.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none")
)))]
fn enforce_guard_pages(_base: *mut u8, _guard_size: usize) -> bool {
    true
}

/// Say once that the overflow hazard the guard exists for is not covered here.
///
/// Once is enough: the answer depends on where the frames landed, so every
/// later stack would report the same thing.
fn report_guard_not_enforced(guard_size: usize) {
    static REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if !REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
        crate::println!(
            "[thread] kernel stack guard pages are not enforced: the frames sit in a mapping \
             `unmap_page` will not split, so an overflow into {} byte(s) will not fault",
            guard_size
        );
    }
}

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
        // Why the frame-backed path was abandoned, reported once the
        // memory-manager guard has been released.
        //
        // The message cannot be printed where the failure is detected: that
        // would mean writing to the console while holding the global
        // memory-manager spinlock.  Console output goes through `format_args!`
        // and the serial writer, which can allocate, and an allocation that
        // needs frames re-enters the very lock being held.
        let mut mapping_failure: Option<crate::Error> = None;

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
                    mm.deallocate_frames(base, total_frames);
                    mapping_failure = Some(e);
                } else {
                    // The guard region is kept out of the software PageTable
                    // above, but on bare metal the hardware page tables may
                    // still hold a residual mapping, from the bootstrap
                    // identity map or a prepared coarse-grained entry.  Clear
                    // the present/valid bit for each guard page so an overflow
                    // faults instead of corrupting memory silently.
                    let guard_not_enforced = !enforce_guard_pages(base, guard_size);

                    // Report outside the critical section: this prints, and
                    // printing can allocate.
                    drop(mm);
                    if guard_not_enforced {
                        report_guard_not_enforced(guard_size);
                    }
                    return Self {
                        stack_ptr,
                        stack_len: stack_size,
                        backing: KernelStackBacking::Frame { base, total_frames },
                    };
                }
            }
        }

        if let Some(error) = mapping_failure {
            crate::println!(
                "[thread] kernel stack map_region failed ({}); falling back to heap",
                error.as_str()
            );
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
                    // The guard pages are left un-presented here.  Putting
                    // them back is the frame allocator's job rather than this
                    // one: it guarantees that a frame it hands out is
                    // writable, and keeping the repair there covers every
                    // caller instead of asking each subsystem to undo its own
                    // un-mapping before freeing frames.  See
                    // `memory::arch::ensure_identity_mapped_range`.
                    mm.deallocate_frames(*base, *total_frames);
                }
            }
            KernelStackBacking::Heap(_) => {
                // Box<[u8]> drops automatically.
            }
        }
    }
}

// SAFETY: the stack pointer is valid for the lifetime of the KernelStack.
unsafe impl Send for KernelStack {}
unsafe impl Sync for KernelStack {}
