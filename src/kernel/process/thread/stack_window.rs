// File: src/kernel/process/thread/stack_window.rs
// Purpose: hand out addresses inside the kernel's stack window.
//
// The window itself is the architecture's declaration and is recorded in the
// kernel's mapping facts; this hands out slices of it.  A stack gets its guard
// page first and its usable pages after, which makes the guard a page this
// allocator *never hands out* — as opposed to a page that is handed out and
// then un-mapped somewhere else.
//
// That difference is the point.  A guard created by editing a shared mapping
// is a hole in the kernel's own storage: neighbouring stacks and allocator
// metadata live in the same blocks, so anything that changes one page is
// changing what the rest of the kernel sees.  A page that was never allocated
// cannot be reached by anything at all.

// Introduced as an unused skeleton: the kernel stack allocation moves onto it
// next, and that step removes this line.
#![allow(dead_code)]

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

/// Hands out stack addresses from a fixed window.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StackWindow {
    base: usize,
    end: usize,
    next: usize,
}

impl StackWindow {
    pub(crate) const fn new(base: usize, end: usize) -> Self {
        Self {
            base,
            end,
            next: base,
        }
    }

    /// Reserve a guard region and a usable stack, in that order.
    ///
    /// Returns the stack's layout, or `None` when the window cannot fit another
    /// stack.  Both sizes are rounded up to whole pages and at least one page
    /// each: a stack without a guard, or a guard without a stack, is not a
    /// shape this hands out.
    pub(crate) fn allocate(
        &mut self,
        guard_bytes: usize,
        stack_bytes: usize,
    ) -> Option<StackLayout> {
        let guard = round_up_pages(guard_bytes).max(WINDOW_PAGE);
        let usable = round_up_pages(stack_bytes).max(WINDOW_PAGE);

        let guard_start = self.next;
        let usable_start = guard_start.checked_add(guard)?;
        let end = usable_start.checked_add(usable)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        Some(StackLayout {
            guard_start,
            usable_start,
            usable_end: end,
        })
    }

    /// Bytes of the window handed out so far, guard pages included.
    pub(crate) fn used_bytes(&self) -> usize {
        self.next - self.base
    }

    pub(crate) fn remaining_bytes(&self) -> usize {
        self.end - self.next
    }
}

fn round_up_pages(bytes: usize) -> usize {
    bytes.div_ceil(WINDOW_PAGE) * WINDOW_PAGE
}

#[cfg(test)]
mod tests {
    use super::StackWindow;

    const BASE: usize = 0x8000_0000;
    const END: usize = BASE + 0x40_0000; // 4 MiB

    #[test]
    fn first_stack_starts_after_its_guard_page() {
        let mut window = StackWindow::new(BASE, END);
        let layout = window.allocate(4096, 0x8000).expect("room for one stack");
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
        let first = window.allocate(4096, 0x8000).expect("first");
        let second = window.allocate(4096, 0x8000).expect("second");
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
        let layout = window.allocate(1, 1).expect("one page each");
        assert_eq!(layout.usable_start, BASE + 4096);
        assert_eq!(layout.usable_len(), 4096);
        assert_eq!(window.remaining_bytes(), END - BASE - 2 * 4096);
    }

    #[test]
    fn an_exhausted_window_changes_nothing() {
        let mut window = StackWindow::new(BASE, BASE + 0x2000);
        assert!(window.allocate(4096, 0x8000).is_none());
        assert_eq!(window.used_bytes(), 0);
        let layout = window.allocate(4096, 0).expect("one page fits");
        assert_eq!(layout.usable_start, BASE + 4096);
        assert!(window.allocate(4096, 0).is_none());
    }
}
