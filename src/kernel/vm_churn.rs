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
//!
//! One of the shapes in that family is understood and fixed: the starvation
//! boost took threads out of the ready queues by tid, every process numbers
//! its threads from one, and so promoting one service dropped its neighbour —
//! which is the "one thread sits `Ready` that nothing schedules" above.  A
//! second shape is still open, and this is the place to record it, because it
//! will not reproduce on demand: a plain boot with no churn stops the same way
//! in bursts (about one boot in ten in some windows, sixty consecutive clean
//! boots in others) and prints **no** `[sched ]` line at all — the placement
//! watchdog speaks only for a thread it cannot find in any queue, and this one
//! is somewhere it can find.  The last line before the silence is a page fault
//! delivered to the rust payload's handler; the line that never arrives is
//! that payload's `rust wait-exception-pid:`, which it prints between
//! `spawn_process_with` and `wait_process_blocking`.  So the demo stops inside
//! a launch, or in the return from that handler, and every service that should
//! have been restarted is still waiting when the log ends.
//!
//! It has not been reproduced on demand since, and the amplifiers that would
//! normally prise a race like this open have all been tried against it: sixty
//! odd boots in a row; four guests at once; a host loaded with four busy
//! cores; the churn build; a delay added to init, which is the recipe above; a
//! widened window inside the launch syscall; and stopping and continuing the
//! guest from the monitor every 120 ms for the whole boot.  Every one of them
//! came back clean, which is worth knowing before anyone spends a day
//! repeating them.  What is *not* known is where the guest is when it stops,
//! and that is the first question: `scripts/probe-x8664-demo-stall.sh` boots
//! this demo and, if it stops, asks the QEMU monitor for the guest's
//! registers — the instruction pointer says whether the stall is in user code
//! or in the kernel, which the log cannot say, because the log has stopped.
//!
//! Hunting it did turn up something in the same boot and the same code path:
//! the x86_64 demo's fault-recovery payload was moving its user stack pointer
//! 0x100 bytes on *every* recovery, so a child that took more than a dozen
//! faults walked out of its own stack, had its resume refused — the kernel
//! reported `invalid argument`, and it is right to — and fell into a `ud2`
//! storm that ended when the kernel killed it.  That is a dozen faults and an
//! invalid-opcode storm in place of the recovered round trip the payload's own
//! messages describe; with the stack pointer left where the fault found it,
//! the demo shows each of its three recoveries, two page faults and two
//! invalid-opcode deliveries, and its log is a hundred lines shorter.
//!
//! Whether that storm is also what stalls the boot is not known: the stall is
//! rare and cannot be scheduled, and one fault storm fewer is not proof.  It
//! is, at the very least, the noise the stall was observed inside of, and the
//! observer below is what will say so either way the next time it stops.

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
/// fit become full flushes, which is the path being exercised.  Architectures
/// whose edits never post anything — the ones whose invalidation already
/// reaches every CPU, like aarch64's inner-shareable `tlbi` — skip this half
/// by posting into a log that is never read, and the checks for them assert
/// the window's half only.
#[cfg(feature = "stack_churn")]
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
    post_burst();

    // Walk what was posted, here and now.  The receive side is the other half
    // of the message, and on a machine whose edits post, a slice that retired
    // stays retired until every CPU has walked it — so without this the
    // snapshot below would say "everything retired" and leave it at that.  One
    // CPU walking is enough to close that on a single-CPU boot, which is the
    // configuration this runs in; the snapshot is then the evidence that the
    // addresses came back rather than piling up.
    crate::kernel::smp::apply_remote_tlb_invalidations();

    // Ask for one stack back.  An address handed out from the recycled list is
    // one whose retirement finished, and the window announces the first such
    // reuse itself — which is why the checks assert on that line rather than on
    // a count printed here.  A machine whose grace never completes still works:
    // the window simply grows and never reuses.
    let recovered = KernelStack::new(KERNEL_STACK_GUARD_SIZE, DEFAULT_KERNEL_STACK_SIZE);
    drop(recovered);

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
fn post_burst() {
    use crate::memory::paging::PAGE_SIZE;

    /// An address nothing has mapped: the point is the bookkeeping, and
    /// invalidating an unmapped page is harmless.
    const BURST_ADDRESS: usize = 0x0000_7000_0000_0000;

    // Where an architecture posts nothing, this fills a log nobody reads; what
    // it costs is one function call per step, and what it saves is a second
    // version of this function per architecture.
    let interrupts_were_enabled = crate::arch::interrupts::save_and_disable();
    for step in 0..CHURN_BURST {
        let start = BURST_ADDRESS + step * PAGE_SIZE;
        let _ = crate::kernel::smp::post_range_invalidation(start, PAGE_SIZE);
    }
    crate::arch::interrupts::restore(interrupts_were_enabled);
}
