//! src/kernel/vm_churn.rs
//!
//! A boot-time stress of the two things kernel stacks lean on.
//!
//! The stack window and the posted-invalidation log are both allocation
//! structures with a fallback: the window hands out addresses until it has
//! none and then stacks come from frames at their own addresses, and the log
//! takes invalidations until it is full and then a request asks for a full
//! flush.  Neither fallback can be reached by an ordinary boot, and a fallback
//! that is never reached is a fallback nobody has tested — the code that
//! decides to take it may be wrong in a way that only shows up on a machine
//! running long enough to get there.
//!
//! So this asks for more than the window has, hands it all back, and then
//! posts more invalidations in one go than the log can hold.  What it is for
//! is the arithmetic, not the timing: the counts it prints say how many stacks
//! the window served, how many had to fall back, how many retirements went
//! through the log, and how many requests had to be promoted to a full flush.
//!
//! Off by default: filling the window costs tens of megabytes of frames for
//! the moment it runs and leaves the log full, which is a diagnostic, not a
//! thing a shipped boot should do.  Enable it with the `stack_churn` feature,
//! which `make check-x8664-churn` does.
//!
//! # What it found
//!
//! Running it, the demo after the churn stops making progress now and then:
//! the supervisor keeps looping, the CPU goes idle, one thread sits `Ready`
//! that nothing schedules, and a service that has terminated is never
//! restarted.  That is *not* this file's subject — a plain boot with an
//! ordinary delay added to init stalls the same way, and in the stalled runs
//! the window and the log are both healthy (everything retired came back, the
//! log is drained, `pending = 0`).  What the churn does is make init long
//! enough to trip it, which makes it the cheapest reproduction we have of a
//! pre-existing supervision/scheduling wedge.  The check that runs it
//! therefore asserts the churn's own arithmetic and the boot reaching the
//! shell, and leaves "the demo finishes" to the churn-free runtime check.

/// How many stacks to ask for.
///
/// The window is 64 MiB on x86_64 and a stack is a 4 KiB guard plus 32 KiB of
/// usable space, so this is a few hundred past what the window can serve —
/// which is the point: the fallback is only reached by asking for more than
/// the window has.  The loop also stops once the window has clearly given up,
/// so an architecture with a larger window does not pay for the whole count.
#[cfg(feature = "stack_churn")]
const CHURN_STACKS: usize = 3200;

/// How many stacks in a row have to come from somewhere else before the window
/// is counted as done.  One is not enough: a slice can be retired and not yet
/// recycled at the moment it is asked for.
#[cfg(feature = "stack_churn")]
const CHURN_FALLBACK_RUN: usize = 256;

/// How many invalidations to post in one go, past what the log can hold.
///
/// The log is 256 slots, so this is comfortably more; the requests that do not
/// fit become full flushes, which is the path being exercised.
#[cfg(all(feature = "stack_churn", target_arch = "x86_64", target_os = "none"))]
const CHURN_BURST: usize = 384;

#[cfg(feature = "stack_churn")]
pub(crate) fn run() {
    churn();
}

#[cfg(not(feature = "stack_churn"))]
pub(crate) fn run() {}

#[cfg(feature = "stack_churn")]
fn churn() {
    use alloc::vec::Vec;

    use crate::kernel::process::thread::constants::DEFAULT_KERNEL_STACK_SIZE;
    use crate::kernel::process::thread::constants::KERNEL_STACK_GUARD_SIZE;
    use crate::kernel::process::thread::kernel_stack::KernelStack;

    let tick = || {
        crate::kernel::process::Scheduler::global()
            .map(|scheduler| scheduler.current_tick())
            .unwrap_or(0)
    };
    let ticks_before = tick();
    let posted_before = crate::kernel::smp::posted_invalidation_stats();

    // ── More kernel stacks than the window can hold ────────────────────
    let mut held: Vec<KernelStack> = Vec::with_capacity(CHURN_STACKS);
    let mut window_backed = 0usize;
    let mut fallbacks = 0usize;
    let mut fallback_run = 0usize;
    for _ in 0..CHURN_STACKS {
        let stack = KernelStack::new(KERNEL_STACK_GUARD_SIZE, DEFAULT_KERNEL_STACK_SIZE);
        if stack.is_window_backed() {
            window_backed += 1;
            fallback_run = 0;
        } else {
            fallbacks += 1;
            fallback_run += 1;
            if fallback_run >= CHURN_FALLBACK_RUN {
                break;
            }
        }
        held.push(stack);
    }

    let window = crate::kernel::process::thread::window_stats();
    crate::println!(
        "[churn ] kernel stacks: window-backed={} fallbacks={} held={}",
        window_backed,
        fallbacks,
        held.len()
    );
    if let Some(window) = window {
        crate::println!(
            "[churn ] stack window: reserved={} live={} retired={} recycled={} stacks={} reused={}",
            window.reserved,
            window.live,
            window.retired,
            window.recycled,
            window.stacks,
            window.reused
        );
    }

    // ── Hand them all back, then overfill the invalidation log ─────────
    //
    // Retiring the stacks posts their ranges; dropping the last reference is
    // what does it.  The burst afterwards is on purpose: whether the log is
    // full at any instant depends on whether a CPU happened to take a kernel
    // entry in the middle of the loop, and this asks for the full-flush path
    // rather than hoping to catch it.
    drop(held);
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    post_burst();

    let posted_after = crate::kernel::smp::posted_invalidation_stats();
    crate::println!(
        "[churn ] invalidations: posted={} walked={} full-flushes={} pending={} lag={} ticks={}",
        posted_after.postings.saturating_sub(posted_before.postings),
        posted_after.walked.saturating_sub(posted_before.walked),
        posted_after
            .full_flushes
            .saturating_sub(posted_before.full_flushes),
        posted_after.pending,
        posted_after.lag,
        tick().saturating_sub(ticks_before)
    );
    if let Some(window) = crate::kernel::process::thread::window_stats() {
        crate::println!(
            "[churn ] stack window after the churn: reserved={} live={} retired={} recycled={} reused={}",
            window.reserved,
            window.live,
            window.retired,
            window.recycled,
            window.reused
        );
    }
}

/// Post more invalidations than the log can hold, inside one kernel entry.
///
/// Interrupts are held off for the duration so that no CPU can walk the log
/// while it is being filled: the condition being exercised is "a burst of
/// edits arrives before any CPU has caught up", which is what a kernel entry
/// that tears down a range of mappings looks like to the log.
#[cfg(feature = "stack_churn")]
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn post_burst() {
    use crate::kernel::memory::paging::PAGE_SIZE;

    /// An address nothing has mapped: the point is the bookkeeping, and
    /// invalidating an unmapped page is harmless.
    const BURST_ADDRESS: usize = 0x0000_7000_0000_0000;

    let interrupts_were_enabled = crate::arch::x86_64::interrupts::are_enabled();
    crate::arch::x86_64::interrupts::disable();
    for step in 0..CHURN_BURST {
        let start = BURST_ADDRESS + step * PAGE_SIZE;
        let _ = crate::kernel::smp::post_range_invalidation(start, PAGE_SIZE);
    }
    if interrupts_were_enabled {
        crate::arch::x86_64::interrupts::enable();
    }
}
