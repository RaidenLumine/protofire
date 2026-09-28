//! src/kernel/process/scheduler/timer.rs
//!
//! Timer tick handling and priority boosting.

use alloc::vec::Vec;

use crate::arch;
use crate::drivers::serial;

use super::super::thread::ThreadSchedPolicy;
use super::super::ThreadPriority;

use super::queue::*;
use super::Scheduler;
use super::BOOST_DURATION_TICKS;
use super::BOOST_THRESHOLD_TICKS;

impl Scheduler {
    /// How often the placement watchdog looks.  About a second at 100 Hz.
    const PLACEMENT_WATCHDOG_PERIOD_TICKS: u64 = 128;

    /// How many processes one pass of the watchdog looks at.
    ///
    /// Enough for a live process list; the demo runs a handful.  Fixed so that
    /// a watchdog running once a second never allocates.  It is also the size
    /// of the suspect list kept between passes, so the two cannot drift apart.
    pub(crate) const PLACEMENT_WATCHDOG_CAPACITY: usize = 64;

    /// Report every live process whose threads the scheduler cannot find.
    ///
    /// "Find" means what the rest of the scheduler means by it: the thread is
    /// in a ready queue, in the waiting queue, or running.  A thread in none
    /// of those is one no future tick will dispatch, so a process left in that
    /// state is a machine that has stopped with its work unfinished — the
    /// failure this scheduler has actually had.
    ///
    /// The process table is reachable, so the check runs from there: every
    /// process that is alive has to have at least one thread the scheduler can
    /// find.  A *lost* thread cannot be enumerated directly — that is what
    /// being lost means — which is why this asks the question from the
    /// process's side.
    ///
    /// One look is not enough to answer it.  A thread is out of every queue
    /// for the length of every move between them — `current` is taken before
    /// the thread is parked, and before it is back in a ready queue — and
    /// another CPU reading the queues during that window sees exactly what a
    /// lost thread looks like.  Being lost is *permanent* and being between
    /// queues is not, so the report waits for the next pass to see the same
    /// thread missing again; the passes are a second apart, which no window
    /// between two queues reaches.
    ///
    /// Not under the process lock while looking: the lookups take the queue
    /// locks, and the two are not taken in one fixed order anywhere else.
    pub(crate) fn watch_process_placement(&self) {
        use super::terminate::UnplacedDetail;
        use crate::kernel::process::ProcessState;
        const CAPACITY: usize = Scheduler::PLACEMENT_WATCHDOG_CAPACITY;

        // (pid, state, first tid, how many threads the process has)
        let mut watched = [(0u32, ProcessState::New, 0u32, 0usize); CAPACITY];
        let mut threadless = [(0u32, ProcessState::New, UnplacedDetail::NoThreads); CAPACITY];
        let mut count = 0usize;
        let mut threadless_count = 0usize;
        for process in self.process_table().lock().iter() {
            if count == CAPACITY && threadless_count == CAPACITY {
                break;
            }
            if matches!(
                process.state(),
                ProcessState::Terminated | ProcessState::New
            ) {
                continue;
            }
            let Some(first_tid) = process.thread_ids().first().copied() else {
                // A live process with no threads at all: also unplaced, and not
                // a matter of timing — nothing is on its way to being placed.
                if threadless_count < CAPACITY {
                    threadless[threadless_count] =
                        (process.pid(), process.state(), UnplacedDetail::NoThreads);
                    threadless_count += 1;
                }
                continue;
            };
            if count < CAPACITY {
                watched[count] = (
                    process.pid(),
                    process.state(),
                    first_tid,
                    process.thread_ids().len(),
                );
                count += 1;
            }
        }

        let mut missing = [(0u32, 0u32); CAPACITY];
        let mut missing_count = 0usize;
        for &(pid, _state, tid, _threads) in watched.iter().take(count) {
            if self.find_thread_anywhere_by_pid_and_tid(pid, tid).is_none() {
                missing[missing_count] = (pid, tid);
                missing_count += 1;
            }
        }

        // The same thread missing twice is the finding; missing once is a
        // thread halfway between two queues.
        let mut confirmed = [0u32; CAPACITY];
        let mut confirmed_count = 0usize;
        {
            let mut suspects = self.unplaced_suspects.lock();
            for &(pid, tid) in missing.iter().take(missing_count) {
                if suspects.contains(&(pid, tid)) && confirmed_count < CAPACITY {
                    confirmed[confirmed_count] = pid;
                    confirmed_count += 1;
                }
            }
            let mut next = [(0u32, 0u32); CAPACITY];
            next[..missing_count].copy_from_slice(&missing[..missing_count]);
            *suspects = next;
        }

        for &(pid, state, detail) in threadless.iter().take(threadless_count) {
            self.report_unplaced(pid, state, &detail);
        }
        for &pid in confirmed.iter().take(confirmed_count) {
            let (state, threads, holding_suspended) = self
                .process_by_pid(pid)
                .map(|process| {
                    (
                        process.state(),
                        process.thread_ids().len(),
                        process.has_suspended_thread(),
                    )
                })
                .unwrap_or((ProcessState::New, 0, false));
            self.report_unplaced(
                pid,
                state,
                &UnplacedDetail::NoPlacedThread {
                    threads,
                    holding_suspended,
                },
            );
        }
    }

    /// Name a process the watchdog has found unplaced, and count it.
    fn report_unplaced(
        &self,
        pid: crate::kernel::process::ProcessId,
        state: crate::kernel::process::ProcessState,
        detail: &super::terminate::UnplacedDetail,
    ) {
        let name = self
            .process_by_pid(pid)
            .map(|process| process.name())
            .unwrap_or_else(|| alloc::string::String::from("?"));
        self.record_unplaced_process(pid, &name, state, detail);
    }

    /// Handle a timer tick, including preemption by default.
    ///
    /// Convenience wrapper around [`handle_timer_tick_with_preemption`]
    /// with `allow_preemption = true`.
    ///
    /// Returns `true` if the current thread was preempted.
    pub fn handle_timer_tick(&self, ticks: u64) -> bool {
        self.handle_timer_tick_with_preemption(ticks, true)
    }

    /// Handle a timer tick with configurable preemption.
    ///
    /// Performs per-tick bookkeeping:
    /// - Updates per-thread CPU-ticks and scheduler stats.
    /// - Polls serial and USB HID hardware (stop-gap until IRQ wiring).
    /// - Drives network stack periodic maintenance.
    /// - Boosts starved Normal-priority threads.
    /// - Checks expired timerfds.
    /// - Monitors kernel stack usage.
    /// - Wakes expired timed-waiters.
    ///
    /// When `allow_preemption` is `true` and the time-slice boundary
    /// has elapsed, the current thread is preempted (FIFO threads are
    /// exempt).
    ///
    /// Returns `true` if the current thread was preempted.
    pub fn handle_timer_tick_with_preemption(&self, ticks: u64, allow_preemption: bool) -> bool {
        if !arch::supports_context_switch() {
            *self.simulated_ticks.lock() = ticks;
        }

        // Until a dedicated serial IRQ path exists, fold UART RX polling into
        // the timer tick so serial waits can observe hardware input and reuse
        // the existing device wait queue.
        let _ = serial::poll_hardware_rx();
        // Poll the xHCI event ring for USB HID keyboard reports.
        // This is a stop-gap until MSI-X interrupt wiring is in place.
        let _ = crate::drivers::xhci::xhci_poll();

        // Poll MMIO virtio-input keyboards (aarch64/riscv64 QEMU virt) and
        // flush the virtio-gpu scanout framebuffer when the console marked it
        // dirty.  Both are no-ops on hosts/x86 (no IRQ dispatch exists on
        // those arches, so device servicing is folded into the timer tick).
        crate::drivers::virtio_input::poll_hardware();
        crate::drivers::virtio_gpu::poll_flush();

        // Drive the native network stack's periodic maintenance (ARP cache
        // eviction, TCP retransmission timers, TimeWait cleanup) when a
        // network device is present.
        #[cfg(any(target_os = "none", test))]
        if let Some(stack) = crate::network::stack::NetworkStack::global() {
            stack.advance_tick();
        }

        // Persistent block cache: advance the dirty-block aging clock every
        // tick.  That is a single atomic add, so it belongs here.
        crate::fs::block_cache::advance_cache_tick();

        // The periodic jobs below are only *requested* here.
        //
        // Writing back aged blocks and persisting the audit ring both take the
        // global filesystem lock and touch a block device.  Doing that from the
        // timer interrupt meant issuing disk I/O with interrupts masked, which
        // stops the clock and everything scheduled from it for the length of a
        // flush.  The maintenance thread performs the work instead; see
        // `src/kernel/maintenance.rs`.
        if ticks.is_multiple_of(crate::fs::block_cache::WRITE_BACK_PERIOD_TICKS) {
            crate::kernel::maintenance::request_block_cache_write_back();
        }

        if ticks.is_multiple_of(crate::kernel::audit::persist::PERSIST_PERIOD_TICKS) {
            crate::kernel::maintenance::request_audit_persist();
        }

        // DHCP lease renewal — bare-metal only; there is no DHCP server in
        // test mode.  Check once per second (every 100 ticks at 100 Hz).
        #[cfg(target_os = "none")]
        if ticks.is_multiple_of(100) {
            crate::network::dhcp::try_renew_lease();
        }

        // Priority boosting: promote starved Normal-priority threads
        // (every tick so we catch stale waiters promptly).
        self.boost_starved_threads();

        // Check expired timerfds and wake their readers.
        crate::syscall::table::timer_fd::check_expired_timerfds(ticks);

        // Check expired POSIX timers and deliver signals.
        crate::kernel::process::posix_timer::check_expired_timers(ticks);

        // Increment the current thread's CPU-time tick counter for
        // per-thread usage accounting, and update scheduler stats.
        let cpu_id = crate::kernel::percpu::get().cpu_id;
        let current_is_idle = {
            if let Some(thread) = self.current.lock().as_ref() {
                thread.increment_cpu_ticks();
                // Boosted threads hold a High-priority quantum bounded by
                // BOOST_DURATION_TICKS.  Consume one tick of it per scheduler
                // tick so the boost eventually expires: once the remaining
                // slice reaches zero, boost_starved_threads demotes the thread
                // back to Normal priority.
                if thread.is_boosted() {
                    let remaining = thread.time_slice_remaining();
                    thread.set_time_slice_remaining(remaining.saturating_sub(1));
                }
                false
            } else {
                true
            }
        };

        {
            let mut stats = self.stats.lock();
            stats.total_ticks = stats.total_ticks.saturating_add(1);
            if current_is_idle {
                stats.record_idle_tick(cpu_id);
            }
        }

        // Update load average every 100 ticks (1 second at 100 Hz) and feed
        // the CPU-frequency governor.  The power subsystem skips platforms
        // without frequency scaling, so this is a cheap no-op elsewhere.
        if ticks.is_multiple_of(100) {
            self.update_load_average();
            let load = (self.stats.lock().last_load_sample() as u32 / 10).min(100) as u8;
            crate::kernel::power::update_policy(load);
        }

        // Interrupt load balancing: periodically migrate the hottest
        // migratable IRQ to the idlest CPU (no-op on single-CPU systems).
        if ticks.is_multiple_of(crate::kernel::irq_balance::REBALANCE_INTERVAL_TICKS) {
            crate::kernel::irq_balance::maybe_rebalance();
        }

        // Periodically check the current thread's kernel stack usage so
        // we can warn before a stack overflow silently corrupts heap memory.
        // This is the early warning; the guard page below the stack is what
        // stops the overflow itself.
        if ticks.trailing_zeros() >= 7 {
            // Check roughly every 128 ticks.
            if let Some(thread) = self.current.lock().as_ref() {
                if !thread.kernel_stack_usage_ok() {
                    #[cfg(target_os = "none")]
                    crate::println!(
                        "[sched ] kernel stack low pid={} tid={} sp={:#x} bottom={:#x}",
                        thread.pid(),
                        thread.tid(),
                        thread.context().stack_pointer,
                        thread.stack_bounds().0,
                    );
                }
            }
        }

        // Wake expired sleepers first so a just-readied thread can participate
        // in the same timeslice-boundary preemption decision.
        //
        // Before waking them, check that the threads the scheduler is
        // responsible for can still be found at all.  A thread that is in no
        // queue is a thread nothing will ever run, and the only time that can
        // be seen is when there is nothing else to run — which is exactly
        // when it matters.  Cheap: no allocation, one lookup per process,
        // about once a second.
        if ticks.is_multiple_of(Self::PLACEMENT_WATCHDOG_PERIOD_TICKS)
            && ready_queue_len(&self.ready_queues.lock()) == 0
        {
            self.watch_process_placement();
        }
        let _ = self.wake_expired_sleepers(ticks);

        if !allow_preemption {
            return false;
        }

        if !should_preempt_for_time_slice(ticks) {
            return false;
        }

        // FIFO threads are not preempted by time-slice expiry.
        if let Some(current) = self.current.lock().as_ref() {
            if current.sched_policy() == ThreadSchedPolicy::SchedFifo {
                return false;
            }
        }

        if arch::supports_context_switch() {
            self.preempt_current_thread_from_interrupt()
        } else if self.preempt_current_thread_simulated() {
            let _ = self.dispatch_next_simulated();
            true
        } else {
            false
        }
    }

    pub(crate) fn boost_starved_threads(&self) {
        let mut ready_queues = self.ready_queues.lock();
        let boost_threshold = BOOST_THRESHOLD_TICKS;
        let boost_duration = BOOST_DURATION_TICKS;
        // A boost only ever moves a thread from one queue to another.  The
        // count is checked at the end of the pass, because the way this went
        // wrong was a removal that took a thread out of every queue and never
        // put it back — and a queue that silently loses an entry is a machine
        // that stops one process later with nothing to show for it.
        let queued_before = ready_queue_len(&ready_queues);

        // Increment waiting ticks for ready Normal threads and check for boost.
        let mut boosted = Vec::new();
        for thread in ready_queues[ThreadPriority::Normal as usize].iter() {
            let waiting = thread.inc_waiting_ticks();
            if waiting >= boost_threshold {
                boosted.push(thread.clone());
            }
        }

        if !boosted.is_empty() {
            for thread in &boosted {
                thread.reset_waiting_ticks();
                thread.set_time_slice_remaining(boost_duration);
                thread.set_priority(ThreadPriority::High);
                thread.set_boosted(true);
            }
            // Promote each thread by *moving* it: out of every queue by its
            // identity, then back in at its new priority.  Matching the
            // promotion on the tid took every thread that shared one out of
            // the queue and put back only the promoted one — and every process
            // numbers its threads from one, so a service and its neighbour are
            // both tid 1.  The thread left behind was ready and in no queue,
            // which is the scheduler's one unrecoverable state.
            for thread in &boosted {
                remove_queued_thread(&mut ready_queues, thread);
            }
            for thread in &boosted {
                ready_queues[ThreadPriority::High as usize].push_back(thread.clone());
            }
        }

        // Demote boosted threads that have used up their boost time slice.
        let mut demoted = Vec::new();
        for thread in ready_queues[ThreadPriority::High as usize].iter() {
            if thread.is_boosted() && thread.time_slice_remaining() == 0 {
                demoted.push(thread.clone());
            }
        }
        if !demoted.is_empty() {
            for thread in &demoted {
                thread.set_boosted(false);
                thread.set_priority(ThreadPriority::Normal);
            }
            // The same move, the other way, for the same reason.
            for thread in &demoted {
                remove_queued_thread(&mut ready_queues, thread);
            }
            for thread in &demoted {
                ready_queues[ThreadPriority::Normal as usize].push_back(thread.clone());
            }
        }

        debug_assert_eq!(
            ready_queue_len(&ready_queues),
            queued_before,
            "the starvation boost moves threads between queues; it must not lose one"
        );
    }

    /// Compute the CPU-busy ratio over the last second and push it into
    /// the 5-minute load-history ring buffer.
    pub(crate) fn update_load_average(&self) {
        self.stats.lock().compute_and_push_load();
    }
}
