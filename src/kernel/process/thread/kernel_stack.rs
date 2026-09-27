//! src/kernel/process/thread/kernel_stack.rs
//!
//! Kernel stack allocation and lifetime management.
//!
//! A stack is a window-backed allocation when its architecture has a stack
//! window: its pages are mapped inside a range nothing else is mapped in, and
//! its guard is a page that range's allocator never handed out.  Targets
//! without a window keep the older shape — frames at their own addresses, with
//! the guard cleared by the architecture's un-map routine — and a machine with
//! no frame allocator at all falls back to a heap buffer with no guard.
//!
//! All three bare-metal architectures have a window now.  The fallback is not a
//! leftover: it appears when the window or its translation-table budget is
//! exhausted, which is the honest answer there too — a stack that cannot be a
//! slice of the window is a stack whose guard this kernel cannot promise, and
//! the caller reports that rather than pretending.  It stops being needed on an
//! architecture when that architecture has a window *and* enough frames and
//! table pages for every stack it can ask for.

use alloc::boxed::Box;

use crate::memory::frame::FRAME_SIZE;

use super::stack_window::StackLayout;

/// Say once that the overflow hazard the guard exists for is not covered here.
///
/// Once is enough: the answer depends on where the frames landed, so every
/// later stack would report the same thing.
///
/// The wording covers both ways a caller gets here: a frame-backed stack was
/// allocated because the window could not serve it, and x86_64 additionally
/// found a mapping `unmap_page` will not split.  All three architectures come
/// here through the fallback and none of them through the window — a window
/// guard is a leaf nobody maps, so there is nothing to enforce and nothing to
/// report.
fn report_guard_not_enforced(guard_size: usize) {
    static REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if !REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
        crate::println!(
            "[thread] kernel stack guard pages are not enforced: the stack's frames sit in a \
             mapping with no guard page carved out of it, so an overflow into {} byte(s) will \
             not fault",
            guard_size
        );
    }
}

/// Backing storage for a kernel stack.
enum KernelStackBacking {
    /// Window-backed: `layout` names the stack inside the architecture's
    /// window and `frames` is the contiguous run its usable pages are mapped
    /// to.  There is no guard entry here because there is no guard memory:
    /// the pages the allocator did not hand out have nothing behind them.
    Window {
        layout: StackLayout,
        frames: *mut u8,
        page_count: usize,
    },
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
    /// Allocate a kernel stack.
    ///
    /// - a window-backed stack, when the architecture has a stack window and
    ///   the frame allocator can fill one;
    /// - otherwise the frame-backed shape the architecture used before windows
    ///   existed;
    /// - otherwise a heap buffer, when there is no frame allocator at all.
    pub(crate) fn new(guard_size: usize, stack_size: usize) -> Self {
        if let Some(stack) = Self::new_in_stack_window(guard_size, stack_size) {
            return stack;
        }
        Self::new_frame_backed(guard_size, stack_size)
    }

    /// Allocate a kernel stack inside the architecture's stack window.
    ///
    /// This is where a guard costs nothing.  The window hands out
    /// guard-then-usable slices, the usable pages get frames, and the guard
    /// gets nothing at all: no frame, no leaf, and no un-mapping step that
    /// could fail.  A page the kernel never allocated cannot be reached, which
    /// is a stronger statement than a page whose mapping someone removed.
    ///
    /// Answers `None` when the architecture names no window or when the window
    /// is full, which is how a target without one keeps its old shape.
    fn new_in_stack_window(guard_size: usize, stack_size: usize) -> Option<Self> {
        let layout = super::stack_window::allocate_in_kernel_window(guard_size, stack_size)?;
        let page_count = layout.usable_len() / FRAME_SIZE;

        let frames = match crate::memory::global_mut() {
            Some(mut memory) => memory.allocate_frames(page_count),
            None => None,
        };
        let Some(frames) = frames else {
            super::stack_window::retire_in_kernel_window(&layout);
            return None;
        };

        let mut mapped = 0;
        while mapped < page_count {
            let offset = mapped * FRAME_SIZE;
            if !crate::memory::arch::map_stack_page_arch(
                layout.usable_start + offset,
                frames as usize + offset,
            ) {
                break;
            }
            mapped += 1;
        }
        if mapped < page_count {
            // Half a stack is not a stack: undo the pages that did go in and
            // hand back both the frames and the addresses.
            while mapped > 0 {
                mapped -= 1;
                crate::memory::arch::unmap_stack_page_arch(
                    layout.usable_start + mapped * FRAME_SIZE,
                );
            }
            if let Some(mut memory) = crate::memory::global_mut() {
                memory.deallocate_frames(frames, page_count);
            }
            super::stack_window::retire_in_kernel_window(&layout);
            return None;
        }

        Some(Self {
            stack_ptr: layout.usable_start as *mut u8,
            stack_len: layout.usable_len(),
            backing: KernelStackBacking::Window {
                layout,
                frames,
                page_count,
            },
        })
    }

    /// Allocate frames at their own addresses, with the guard page cleared by
    /// the architecture's un-map routine.
    ///
    /// The guard here is a hole someone punched in the kernel's own storage
    /// rather than a page nobody allocated: the frames are identity mapped
    /// along with everything else, so the guard only exists if the walk that
    /// clears it can reach the leaf, which a coarse mapping stops it from
    /// doing.  That is why the answer is reported rather than assumed.
    fn new_frame_backed(guard_size: usize, stack_size: usize) -> Self {
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
        if let Some(mut mm) = crate::memory::global_mut() {
            let total_size = guard_size + stack_size;
            let total_frames = total_size.div_ceil(crate::memory::frame::FRAME_SIZE);
            if let Some(base) = mm.allocate_frames(total_frames) {
                // SAFETY: `base` is the first of the frames just allocated and `guard_size` is
                // inside that allocation, so the usable stack starts inside it.
                let stack_ptr = unsafe { base.add(guard_size) };
                // Map only the usable stack region; the guard page stays
                // unmapped so any access faults.
                // Mapped as a kernel stack, not as `Anonymous`: the reclaim
                // and relocation paths pick candidates by kind, and a stack
                // must never be one of them.
                if let Err(e) = mm.map_region_with_kind(
                    stack_ptr as usize,
                    stack_size,
                    crate::memory::paging::PagePermissions::READ_WRITE,
                    crate::memory::paging::MappingKind::KernelStack,
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
                    let guard_not_enforced =
                        !crate::arch::mmu::enforce_stack_guard(base, guard_size);

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

    /// Whether this stack came out of the architecture's stack window.
    ///
    /// A caller that wants to know whether the window could still serve it —
    /// the churn check does — has to ask, because allocation falls back rather
    /// than failing: a target without a window, a window with no room, and a
    /// frame pool with no frames all end up in one of the other two shapes.
    #[cfg(all(feature = "stack_churn", target_os = "none"))]
    pub(crate) fn is_window_backed(&self) -> bool {
        matches!(self.backing, KernelStackBacking::Window { .. })
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        match &self.backing {
            KernelStackBacking::Window {
                layout,
                frames,
                page_count,
            } => {
                // The guard is not in this list, and not because it was
                // skipped: the allocator never handed it out, so there is no
                // mapping to take back.
                for page in layout.usable_pages() {
                    crate::memory::arch::unmap_stack_page_arch(page);
                }
                if let Some(mut memory) = crate::memory::global_mut() {
                    memory.deallocate_frames(*frames, *page_count);
                }
                // The frames are free to go back now: an address is all a stale
                // translation can reach, and only the thread that owns this
                // stack ever walks into it — through its own stack pointer, or
                // as the TSS's RSP0 while it is the running thread.  The stack
                // is dropped when the last reference to that thread is gone, so
                // there is no path left to the frames through it.
                //
                // The slice is retired rather than freed: it comes back when
                // every CPU has dropped its translation for it, so a later
                // stack can be handed this address without a stale TLB entry
                // shadowing the new mapping (see `stack_window.rs`).  The
                // request goes out here, after the unmapping above, because
                // that is the first moment the slice is no longer in use.
                let _ = super::stack_window::retire_in_kernel_window(layout);
            }
            KernelStackBacking::Frame { base, total_frames } => {
                // Unmap the usable stack region from the software page table.
                if let Some(mut mm) = crate::memory::global_mut() {
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
// SAFETY: as the `Send` impl above — the stack pointer stays valid for the
// lifetime of the `KernelStack` and nothing else reaches it concurrently.
unsafe impl Sync for KernelStack {}
