//! src/kernel/process/thread/stack_window.rs
//!
//! Hand out addresses inside the kernel's stack window.
//!
//! The window itself is the architecture's declaration and is recorded in the
//! kernel's mapping facts; this hands out slices of it.  A stack gets its guard
//! page first and its usable pages after, which makes the guard a page this
//! allocator *never hands out* — as opposed to a page that is handed out and
//! then un-mapped somewhere else.
//!
//! That difference is the point.  A guard created by editing a shared mapping
//! is a hole in the kernel's own storage: neighbouring stacks and allocator
//! metadata live in the same blocks, so anything that changes one page is
//! changing what the rest of the kernel sees.  A page that was never allocated
//! cannot be reached by anything at all.
//!
//! Addresses come from a bump frontier and go back into a retirement queue, so
//! the window's budget is the stacks that are *out* — plus the ones waiting out
//! their retirement — rather than every stack the kernel has ever made.  The
//! window has a second budget too, the translation-table pages its third level
//! comes from; running out of either is not a failure, because allocation
//! falls back to the shape stacks had before the window existed, and the
//! kernel then says the guard is not installed, which is true.
//!
//! An address that has been given back is not free.  It is *retired*: it waits
//! until no CPU can still hold a translation for it, and only then can it be
//! handed out again.  Handing a dead stack's slice straight to a live one
//! would be wrong twice over — a stale TLB entry would shadow the new mapping
//! with the old frame on whichever CPU had not flushed yet, and a stale stack
//! pointer would write into a live stack instead of faulting.  The wait is
//! expressed as a stamp on the retirement and a predicate the caller supplies
//! ([`StackWindow::drain`]), so this file does not need to know how an
//! architecture establishes that a translation is gone — it only needs to
//! know that it is not allowed to guess.
//!
//! Waiting is never something the window *does*: a retirement that is not yet
//! safe to reuse simply stays in the queue, and allocation takes the next
//! address instead.  A CPU that never reports in costs address space, not
//! correctness, and the window cannot be made to block on one.

// The allocator and the layout are live now — they are what the kernel stack
// is made of.  What this covers is the read-only surface a check or a test
// uses to look at the window's state (`used_bytes`, `retired_bytes`,
// `recycled_bytes`, `reuse_count`, `guard_pages`): real parts of the
// interface, with no caller in the kernel proper yet.
#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::kernel::smp::InvalidationMark;
use crate::kernel::sync::Mutex;

/// Page size the window is divided into.
const WINDOW_PAGE: usize = 4096;

/// Where one stack lives inside the window.
///
/// Returned by [`StackWindow::allocate`] so the caller that maps the stack has
/// the guard's extent in hand.  The mapping step maps the usable pages and
/// never mentions the guard: a page this allocator did not hand out has no
/// mapping to remove, which is the difference between a guard and a hole that
/// someone punched in shared storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct StackLayout {
    pub(crate) guard_start: usize,
    pub(crate) usable_start: usize,
    pub(crate) usable_end: usize,
}

impl StackLayout {
    /// The address a kernel stack starts from: the top of the usable region.
    pub(crate) const fn stack_top(&self) -> usize {
        self.usable_end
    }

    pub(crate) const fn usable_len(&self) -> usize {
        self.usable_end - self.usable_start
    }

    /// The page-aligned starts of the usable region.
    pub(crate) fn usable_pages(&self) -> impl Iterator<Item = usize> + '_ {
        page_starts(self.usable_start, self.usable_end)
    }

    /// The page-aligned starts of the guard region.
    ///
    /// Nothing maps these; a caller that wants to *check* the guard is a hole
    /// (the coverage check, say) can enumerate them, which is why they are
    /// named rather than derived at each use.
    pub(crate) fn guard_pages(&self) -> impl Iterator<Item = usize> + '_ {
        page_starts(self.guard_start, self.usable_start)
    }
}

fn page_starts(start: usize, end: usize) -> impl Iterator<Item = usize> {
    (start..end).step_by(WINDOW_PAGE)
}

/// A slice that has been given back, waiting until it is safe to hand out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct RetiredSlice {
    layout: StackLayout,
    /// Opaque to this file: the caller's evidence about the translations of
    /// `layout`.  What it means is the caller's business — the window only
    /// asks the grace predicate whether it is spent.
    mark: InvalidationMark,
}

/// A snapshot of the window's state, for diagnostics.
///
/// `reserved` is the bump frontier: addresses handed out at least once.  The
/// rest are where those bytes are now — in a live stack, waiting out a
/// retirement, or back in the recycled list — and `reused` counts the
/// allocations that came from that list rather than from the frontier, which
/// is the number a machine that never reuses anything would leave at zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct WindowStats {
    pub(crate) base: usize,
    pub(crate) end: usize,
    pub(crate) reserved: usize,
    pub(crate) live: usize,
    pub(crate) retired: usize,
    pub(crate) recycled: usize,
    pub(crate) stacks: usize,
    pub(crate) reused: usize,
}

/// Hands out stack addresses from a fixed window.
#[derive(Debug)]
pub(crate) struct StackWindow {
    base: usize,
    end: usize,
    next: usize,
    /// Slices that are out, in the hands of a stack.  A slice comes back only
    /// if it is one of these — which is what makes "given back twice" and
    /// "given back something that was never handed out" detectable instead of
    /// silently corrupting whoever is using the address.
    live: Vec<StackLayout>,
    /// Retired slices the grace predicate has cleared, newest last.
    recycled: Vec<StackLayout>,
    /// Retired slices still waiting, oldest first.
    retired: VecDeque<RetiredSlice>,
    /// How many allocations have come from `recycled` rather than the bump.
    /// Zero for the life of the kernel means the grace predicate is never
    /// satisfied, which is worth saying out loud: everything would still work,
    /// on a window that only ever grows.
    reuses: usize,
}

impl StackWindow {
    pub(crate) fn new(base: usize, end: usize) -> Self {
        Self {
            base,
            end,
            next: base,
            live: Vec::new(),
            recycled: Vec::new(),
            retired: VecDeque::new(),
            reuses: 0,
        }
    }

    /// Reserve a guard region and a usable stack, in that order.
    ///
    /// Returns the stack's layout, or `None` when the window cannot fit another
    /// stack.  Both sizes are rounded up to whole pages and at least one page
    /// each: a stack without a guard, or a guard without a stack, is not a
    /// shape this hands out.
    ///
    /// `ready` is the grace predicate: it answers whether a slice retired with
    /// the given mark may be handed out again.  It is consulted on every
    /// allocation, so a slice waits exactly as long as it has to.
    pub(crate) fn allocate(
        &mut self,
        guard_bytes: usize,
        stack_bytes: usize,
        ready: impl Fn(InvalidationMark) -> bool,
    ) -> Option<StackLayout> {
        let guard = round_up_pages(guard_bytes).max(WINDOW_PAGE);
        let usable = round_up_pages(stack_bytes).max(WINDOW_PAGE);

        self.drain(&ready);
        // A recycled slice has the same shape as the one being asked for, so
        // the search is over the shapes, not over the addresses: a caller that
        // asks for a different shape must not be given this one.  Slices of
        // the wrong shape stay recycled rather than being dropped.
        if let Some(index) = self.recycled.iter().position(|slot| {
            slot.usable_len() == usable && slot.usable_start - slot.guard_start == guard
        }) {
            let slot = self.recycled.swap_remove(index);
            self.reuses += 1;
            self.live.push(slot);
            return Some(slot);
        }

        let guard_start = self.next;
        let usable_start = guard_start.checked_add(guard)?;
        let end = usable_start.checked_add(usable)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        let layout = StackLayout {
            guard_start,
            usable_start,
            usable_end: end,
        };
        self.live.push(layout);
        Some(layout)
    }

    /// Bytes of the window handed out so far, guard pages included.
    pub(crate) fn used_bytes(&self) -> usize {
        self.next - self.base
    }

    pub(crate) fn remaining_bytes(&self) -> usize {
        self.end - self.next
    }

    /// How many allocations have been served from the recycled list.
    pub(crate) fn reuse_count(&self) -> usize {
        self.reuses
    }

    /// Take a snapshot of the window's state.
    pub(crate) fn stats(&self) -> WindowStats {
        WindowStats {
            base: self.base,
            end: self.end,
            reserved: self.used_bytes(),
            live: self
                .live
                .iter()
                .map(|layout| layout.usable_end - layout.guard_start)
                .sum(),
            retired: self.retired_bytes(),
            recycled: self.recycled_bytes(),
            stacks: self.live.len(),
            reused: self.reuses,
        }
    }

    /// Bytes sitting in the retirement queue, waiting for the grace predicate.
    pub(crate) fn retired_bytes(&self) -> usize {
        self.retired
            .iter()
            .map(|slice| slice.layout.usable_end - slice.layout.guard_start)
            .sum()
    }

    /// Bytes that have come back and can be handed out again.
    pub(crate) fn recycled_bytes(&self) -> usize {
        self.recycled
            .iter()
            .map(|layout| layout.usable_end - layout.guard_start)
            .sum()
    }

    /// Retire an allocation that has been given back.
    ///
    /// `mark` is the caller's evidence about translations — see
    /// [`RetiredSlice`].  Only a slice that is currently out can be retired:
    /// the window knows what it handed out, so a slice given back twice, or a
    /// layout that was never handed out, is refused rather than quietly
    /// turning two stacks into one address.
    pub(crate) fn retire(&mut self, layout: &StackLayout, mark: InvalidationMark) -> bool {
        let Some(index) = self.live.iter().position(|slot| slot == layout) else {
            return false;
        };
        self.live.swap_remove(index);
        self.retired.push_back(RetiredSlice {
            layout: *layout,
            mark,
        });
        true
    }

    /// Move every retired slice the grace predicate has cleared into the
    /// recycled list.
    ///
    /// Readiness is asked of each slice on its own: one that is still waiting
    /// does not hold back a later one that is ready, because whether a mark is
    /// spent says nothing about the order the slices were retired in.
    pub(crate) fn drain(&mut self, ready: impl Fn(InvalidationMark) -> bool) -> usize {
        let mut moved = 0;
        let mut index = 0;
        while index < self.retired.len() {
            if ready(self.retired[index].mark) {
                let slice = self
                    .retired
                    .remove(index)
                    .expect("index is inside the queue");
                self.recycled.push(slice.layout);
                moved += 1;
            } else {
                index += 1;
            }
        }
        moved
    }
}

fn round_up_pages(bytes: usize) -> usize {
    bytes.div_ceil(WINDOW_PAGE) * WINDOW_PAGE
}

/// The kernel's window, once the architecture has named one.
///
/// Filled in on first use rather than at a fixed boot step: the architecture
/// answers with a range, the first stack gets the window, and every later one
/// gets the same allocator's next slice.  The lock covers one reservation and
/// is released before the caller reaches for anything else, so nothing here
/// can be waiting on this while holding the memory manager.
static KERNEL_STACK_WINDOW: Mutex<Option<StackWindow>> = Mutex::new(None);

/// Reserve a stack inside the kernel's window.
///
/// `None` when the architecture names no window, or when the window has no
/// room for another stack; the caller then keeps whatever shape its stacks had
/// before the window existed.  A caller that cannot back the reservation with
/// memory gives it back with [`retire_in_kernel_window`].
pub(crate) fn allocate_in_kernel_window(
    guard_bytes: usize,
    stack_bytes: usize,
) -> Option<StackLayout> {
    let (base, end) = crate::kernel::memory::arch::stack_window()?;
    let (layout, first_reuse) = {
        let mut slot = KERNEL_STACK_WINDOW.lock();
        let window = slot.get_or_insert_with(|| StackWindow::new(base, end));
        let before = window.reuse_count();
        let layout = window.allocate(
            guard_bytes,
            stack_bytes,
            crate::kernel::smp::all_cpus_flushed,
        )?;
        (layout, before == 0 && window.reuse_count() > 0)
    };
    // Said once, and said here rather than inside the lock: this prints, and
    // printing can allocate, which must not happen under a lock that the
    // allocator's own callers do not own.
    if first_reuse {
        crate::println!("[thread] kernel stack window: a retired slice is in use again");
    }
    Some(layout)
}

/// Give back a slice, and say whether the window recorded it.
///
/// The slice is retired, not freed: it becomes available again only once every
/// CPU has dropped its translation.  The request covers the usable pages and
/// stops there: the guard was never mapped, so there is no translation of it to
/// drop.  A reservation that was never backed is retired the same way — it is
/// simpler to have one rule for every slice that has left the window than to
/// keep a second, weaker rule for one case.
pub(crate) fn retire_in_kernel_window(layout: &StackLayout) -> bool {
    let mark =
        crate::kernel::smp::post_range_invalidation(layout.usable_start, layout.usable_len());
    match KERNEL_STACK_WINDOW.lock().as_mut() {
        Some(window) => window.retire(layout, mark),
        None => false,
    }
}

/// A snapshot of the kernel's stack window, or `None` where the architecture
/// names no window for kernel stacks to come from.
pub(crate) fn window_stats() -> Option<WindowStats> {
    KERNEL_STACK_WINDOW.lock().as_ref().map(StackWindow::stats)
}

#[cfg(test)]
mod tests {
    use super::InvalidationMark;
    use super::StackWindow;

    const BASE: usize = 0x8000_0000;
    const END: usize = BASE + 0x40_0000; // 4 MiB
    const GUARD: usize = 4096;
    const STACK: usize = 0x8000;

    /// Grace predicate for the cases where the wait is not what is being
    /// tested: every mark is spent.
    fn ready(_mark: InvalidationMark) -> bool {
        true
    }

    /// Grace predicate for "nothing has reported in yet".
    fn waiting(_mark: InvalidationMark) -> bool {
        false
    }

    fn posted(position: u64) -> InvalidationMark {
        InvalidationMark::Posted(position)
    }

    #[test]
    fn first_stack_starts_after_its_guard_page() {
        let mut window = StackWindow::new(BASE, END);
        let layout = window
            .allocate(GUARD, STACK, ready)
            .expect("room for one stack");
        assert_eq!(layout.guard_start, BASE);
        assert_eq!(layout.usable_start, BASE + 4096);
        assert_eq!(layout.usable_len(), 0x8000);
        assert_eq!(layout.stack_top(), BASE + 4096 + 0x8000);
        assert_eq!(layout.guard_pages().collect::<alloc::vec::Vec<_>>(), [BASE]);
        assert_eq!(
            layout.usable_pages().count(),
            8,
            "eight usable pages for 32 KiB"
        );
        assert_eq!(window.used_bytes(), 4096 + 0x8000);
    }

    #[test]
    fn guard_pages_are_never_handed_out() {
        let mut window = StackWindow::new(BASE, END);
        let first = window.allocate(GUARD, STACK, ready).expect("first");
        let second = window.allocate(GUARD, STACK, ready).expect("second");
        // The second guard begins where the first stack ends, and the second
        // usable page begins after that guard — so the two stacks' usable
        // ranges are separated by a page nobody owns.
        assert_eq!(second.guard_start, first.usable_end);
        assert_eq!(second.usable_start, first.usable_end + 4096);
        assert_eq!(second.usable_start - first.usable_start, 0x8000 + 4096);
        // And the guard page is not in either usable range.
        assert!(!first.usable_pages().any(|page| page == second.guard_start));
    }

    #[test]
    fn sizes_round_up_to_whole_pages() {
        let mut window = StackWindow::new(BASE, END);
        let layout = window.allocate(1, 1, ready).expect("one page each");
        assert_eq!(layout.usable_start, BASE + 4096);
        assert_eq!(layout.usable_len(), 4096);
        assert_eq!(window.remaining_bytes(), END - BASE - 2 * 4096);
    }

    #[test]
    fn an_exhausted_window_changes_nothing() {
        let mut window = StackWindow::new(BASE, BASE + 0x2000);
        assert!(window.allocate(GUARD, STACK, ready).is_none());
        assert_eq!(window.used_bytes(), 0);
        let layout = window.allocate(GUARD, 0, ready).expect("one page fits");
        assert_eq!(layout.usable_start, BASE + 4096);
        assert!(window.allocate(GUARD, 0, ready).is_none());
    }

    #[test]
    fn a_retired_slice_is_not_handed_out_while_it_waits() {
        let mut window = StackWindow::new(BASE, END);
        let first = window.allocate(GUARD, STACK, ready).expect("first");
        let second = window.allocate(GUARD, STACK, ready).expect("second");

        assert!(window.retire(&second, posted(1)));
        assert_eq!(window.retired_bytes(), GUARD + STACK);
        assert_eq!(window.recycled_bytes(), 0);

        // Nothing has reported in, so the retired slice must not come back:
        // the allocation takes the next address instead, and the slice stays
        // where it is rather than being dropped.
        let next = window.allocate(GUARD, STACK, waiting).expect("third");
        assert_ne!(next.guard_start, second.guard_start);
        assert_eq!(window.retired_bytes(), GUARD + STACK);
        assert_eq!(window.drain(waiting), 0);
        // Two stacks are out and one slice is waiting: the address that is
        // waiting is not among the ones the window will hand out.
        assert_eq!(window.live.len(), 2);

        // Once every CPU has reported in, the same bytes come back — with the
        // same guard, so the guard is still a page nothing is handed.
        assert_eq!(window.drain(ready), 1);
        assert_eq!(window.retired_bytes(), 0);
        assert_eq!(window.recycled_bytes(), GUARD + STACK);
        let again = window.allocate(GUARD, STACK, ready).expect("recycled");
        // The same slice, guard and all: recycling does not shrink the shape
        // or hand the guard page out as stack.
        assert_eq!(again, second);
        assert_ne!(again.guard_start, first.guard_start);
        assert_eq!(window.live.len(), 3);
    }

    #[test]
    fn a_slice_that_is_still_waiting_does_not_hold_back_a_ready_one() {
        let mut window = StackWindow::new(BASE, END);
        let first = window.allocate(GUARD, STACK, ready).expect("first");
        let second = window.allocate(GUARD, STACK, ready).expect("second");
        assert!(window.retire(&first, posted(1)));
        assert!(window.retire(&second, posted(2)));

        // The marks are asked about on their own: a request that was promoted,
        // or a CPU that reported in out of order, can leave a later slice
        // ready while an earlier one is not.
        assert_eq!(window.drain(|mark| mark == posted(2)), 1);
        assert_eq!(window.retired_bytes(), GUARD + STACK);
        assert_eq!(window.recycled_bytes(), GUARD + STACK);

        assert_eq!(window.drain(ready), 1);
        assert_eq!(window.retired_bytes(), 0);
        assert_eq!(window.recycled_bytes(), 2 * (GUARD + STACK));
    }

    #[test]
    fn only_a_slice_that_is_out_can_be_retired() {
        let mut window = StackWindow::new(BASE, END);
        let live = window.allocate(GUARD, STACK, ready).expect("first");
        assert!(window.retire(&live, posted(1)));
        assert_eq!(window.live.len(), 0);

        // Retiring it again would put one address in the queue twice, which is
        // the one thing the queue exists to prevent — and it is now caught by
        // identity rather than by hoping the shapes do not overlap.
        assert!(!window.retire(&live, posted(2)));

        // So is a layout the window never handed out, however close it looks.
        let alien = super::StackLayout {
            guard_start: live.guard_start + 0x10,
            usable_start: live.usable_start + 0x10,
            usable_end: live.usable_end + 0x10,
        };
        assert!(!window.retire(&alien, posted(3)));
        assert_eq!(window.retired_bytes(), GUARD + STACK);
    }

    /// Whether a mark has been spent, given how far every CPU has walked.
    fn spent(mark: InvalidationMark, walked_past: u64) -> bool {
        match mark {
            InvalidationMark::Posted(position) => position < walked_past,
            InvalidationMark::Flushed(_) | InvalidationMark::Nothing => true,
        }
    }

    /// The allocator under churn: stacks come and go for a long time, and the
    /// grace is spent at a different moment than the retirement.
    ///
    /// Two properties have to hold through all of it.  An address handed out
    /// may not belong to a live stack or be waiting its grace — that is the
    /// bug the queue exists to prevent, and one address handed out twice is
    /// two stacks writing over each other.  And the window has to keep working
    /// once it is full: a spent address comes back, so the same pointers go
    /// round instead of the window failing.
    #[test]
    fn churn_never_hands_out_an_address_twice() {
        let mut window = StackWindow::new(BASE, END);
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let mut out: alloc::vec::Vec<super::StackLayout> = alloc::vec::Vec::new();
        // The slices this test has retired and whose grace has not been spent:
        // what the window still has waiting, as far as the caller can tell.
        let mut waiting: alloc::vec::Vec<(super::StackLayout, u64)> = alloc::vec::Vec::new();
        let mut posted_count = 0u64;
        let mut walked_past = 0u64;
        let mut exhausted = 0usize;

        for _ in 0..20_000 {
            match random() % 4 {
                0 | 1 => {
                    let before = window.reuse_count();
                    match window.allocate(GUARD, STACK, |mark| spent(mark, walked_past)) {
                        Some(layout) => {
                            assert!(
                                !out.contains(&layout),
                                "an address was handed out while a stack was using it"
                            );
                            assert!(
                                !waiting.iter().any(|(other, _)| *other == layout),
                                "an address came back before its grace was spent"
                            );
                            // A reuse is only ever a spent slice.
                            assert!(before == window.reuse_count() || walked_past > 0);
                            out.push(layout);
                        }
                        None => exhausted += 1,
                    }
                }
                2 => {
                    if !out.is_empty() {
                        let index = (random() as usize) % out.len();
                        let layout = out.swap_remove(index);
                        posted_count += 1;
                        assert!(window.retire(&layout, InvalidationMark::Posted(posted_count)));
                        waiting.push((layout, posted_count));
                    }
                }
                _ => {
                    // Every CPU catches up with everything posted so far,
                    // which is also when the window may hand those slices out
                    // again.
                    walked_past = posted_count + 1;
                    waiting.retain(|(_, position)| *position >= walked_past);
                }
            }
        }

        // The window really did fill up at some point, and it kept going: the
        // spent addresses came back rather than the allocator giving up.
        assert!(exhausted > 0, "the churn never filled the window");
        assert!(
            window.reuse_count() > 0,
            "the churn never handed out a recycled slice"
        );

        // And once everything is spent, nothing is left waiting: every
        // address the window ever handed out is either in a stack or back in
        // the recycled list, with nothing stranded in between.
        walked_past = posted_count + 1;
        let drained = window.drain(|mark| spent(mark, walked_past));
        assert!(
            drained >= waiting.len(),
            "the window had less waiting than the caller retired"
        );
        assert_eq!(window.retired_bytes(), 0);
        let live_bytes: usize = window
            .live
            .iter()
            .map(|layout| layout.usable_end - layout.guard_start)
            .sum();
        assert_eq!(
            window.recycled_bytes() + live_bytes,
            window.used_bytes(),
            "addresses went missing between the window and its slices"
        );
    }
}
