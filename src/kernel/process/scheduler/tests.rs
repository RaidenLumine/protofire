//! src/kernel/process/scheduler/tests.rs
//!
//! Ready-queue dispatch ordering, timed-wait bookkeeping, and preemption
//! predicates for the process scheduler.

use super::super::UserThreadStart;

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::api::idle_entry;
    use super::super::queue::enqueue_ready_thread;
    use super::super::queue::has_dispatchable_ready_thread;
    use super::super::queue::has_timed_wait_elapsed;
    use super::super::queue::process_elapsed_timed_waiter;
    use super::super::queue::prune_nondispatchable_ready_threads;
    use super::super::queue::remove_timed_waiters_by_identity;
    use super::super::queue::requeue_preempted_thread;
    use super::super::queue::should_dispatch_ready_thread;
    use super::super::queue::should_preempt_for_time_slice;
    use super::super::queue::should_requeue_simulated_preempted_thread;
    use super::super::queue::take_elapsed_timed_waiters;
    use super::super::queue::take_next_dispatchable_thread;
    use super::super::queue::take_stale_timed_waiters;
    use super::super::queue::thread_has_dispatch_address_space;
    use super::super::types::SchedulerHotspotStats;
    use super::super::types::TimedWaiter;
    use super::super::Scheduler;
    use super::UserThreadStart;

    use super::super::super::Process;
    use super::super::super::Thread;
    use super::super::super::ThreadPriority;
    use super::super::super::ThreadState;
    use super::super::super::THREAD_PRIORITY_COUNT;
    use crate::kernel::process::thread::ThreadSchedPolicy;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    // ── Deterministic PRNG for property tests ───────────────────────────────
    // Same LCG family as tests/simplefs/property.rs and tests/parsers/fuzz.rs,
    // kept local because the queue helpers behind `pub(crate)` are only
    // reachable from in-crate unit tests.

    struct Lcg {
        state: u64,
    }

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next(&mut self) -> u64 {
            self.state = self.state.wrapping_mul(6_364_136_223_846_793_005);
            self.state = self.state.wrapping_add(1_442_695_040_888_963_407);
            self.state
        }

        fn next_usize(&mut self, bound: usize) -> usize {
            if bound == 0 {
                return 0;
            }
            (self.next() as usize) % bound
        }
    }

    #[test]
    fn enqueue_then_take_next_dispatches_in_priority_order() {
        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        let process = Process::new(10, "queue-order");

        let idle = Thread::new_kernel(process.clone(), idle_entry);
        idle.set_priority(ThreadPriority::Idle);
        let normal = Thread::new_kernel(process.clone(), idle_entry);
        let high = Thread::new_kernel(process.clone(), idle_entry);
        high.set_priority(ThreadPriority::High);
        let realtime = Thread::new_kernel(process.clone(), idle_entry);
        realtime.set_priority(ThreadPriority::Realtime);

        // Enqueue in a scrambled order.
        assert!(enqueue_ready_thread(&mut queues, normal.clone()).enqueued());
        assert!(enqueue_ready_thread(&mut queues, idle.clone()).enqueued());
        assert!(enqueue_ready_thread(&mut queues, high.clone()).enqueued());
        assert!(enqueue_ready_thread(&mut queues, realtime.clone()).enqueued());

        // take_next dispatches highest-priority first.
        assert_eq!(
            take_next_dispatchable_thread(&mut queues)
                .expect("realtime")
                .tid(),
            realtime.tid()
        );
        assert_eq!(
            take_next_dispatchable_thread(&mut queues)
                .expect("high")
                .tid(),
            high.tid()
        );
        assert_eq!(
            take_next_dispatchable_thread(&mut queues)
                .expect("normal")
                .tid(),
            normal.tid()
        );
        assert_eq!(
            take_next_dispatchable_thread(&mut queues)
                .expect("idle")
                .tid(),
            idle.tid()
        );
        assert!(take_next_dispatchable_thread(&mut queues).is_none());
    }

    #[test]
    fn prune_removes_non_dispatchable_threads() {
        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        let process = Process::new(11, "prune");
        let ready = Thread::new_kernel(process.clone(), idle_entry);
        let stopped = Thread::new_kernel(process.clone(), idle_entry);
        assert!(stopped.suspend());

        assert!(enqueue_ready_thread(&mut queues, ready.clone()).enqueued());
        // A Stopped thread must never sit in the ready queue.
        queues[stopped.priority() as usize].push_back(stopped.clone());
        assert_eq!(prune_nondispatchable_ready_threads(&mut queues), 1);
        assert!(take_next_dispatchable_thread(&mut queues).is_some());
    }

    #[test]
    fn enqueue_rejects_nondispatchable_threads() {
        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        let process = Process::new(18, "enqueue-guard");
        let blocked = Thread::new_kernel(process.clone(), idle_entry);
        blocked.block_until(10);

        assert!(!enqueue_ready_thread(&mut queues, blocked.clone()).enqueued());
        assert!(!has_dispatchable_ready_thread(&mut queues));
    }

    #[test]
    fn timed_waiter_elapse_and_collection() {
        assert!(has_timed_wait_elapsed(Some(10), 10));
        assert!(!has_timed_wait_elapsed(Some(10), 9));
        assert!(!has_timed_wait_elapsed(None, 100));

        let process = Process::new(12, "timed-waiter");
        let early = Thread::new_kernel(process.clone(), idle_entry);
        let late = Thread::new_kernel(process.clone(), idle_entry);
        early.block_until(50);
        late.block_until(10);

        let mut waiting = vec![
            TimedWaiter {
                thread: early.clone(),
                cleanup: None,
            },
            TimedWaiter {
                thread: late.clone(),
                cleanup: None,
            },
        ];

        // At tick 20 only the late waiter (deadline 10) has elapsed.
        let woke = take_elapsed_timed_waiters(&mut waiting, 20);
        assert_eq!(woke.len(), 1);
        assert_eq!(woke[0].thread.tid(), late.tid());
        assert_eq!(waiting.len(), 1);

        // The early waiter stays parked until its own deadline.
        assert_eq!(take_elapsed_timed_waiters(&mut waiting, 49).len(), 0);
        let woke = take_elapsed_timed_waiters(&mut waiting, 50);
        assert_eq!(woke.len(), 1);
        assert_eq!(woke[0].thread.tid(), early.tid());
        assert!(waiting.is_empty());
    }

    #[test]
    fn process_elapsed_timed_waiter_wakes_and_enqueues() {
        let process = Process::new(14, "elapsed-wake");
        let thread = Thread::new_kernel(process.clone(), idle_entry);
        thread.block_until(5);
        assert_eq!(thread.state(), ThreadState::Waiting);

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        let waiter = TimedWaiter {
            thread: thread.clone(),
            cleanup: None,
        };
        assert!(process_elapsed_timed_waiter(waiter, &mut queues).enqueued());
        assert_eq!(thread.state(), ThreadState::Ready);
        assert_eq!(
            take_next_dispatchable_thread(&mut queues)
                .expect("woken")
                .tid(),
            thread.tid()
        );
    }

    #[test]
    fn stale_timed_waiters_are_collected() {
        let process = Process::new(16, "stale-waiter");
        let active = Thread::new_kernel(process.clone(), idle_entry);
        let stale = Thread::new_kernel(process.clone(), idle_entry);
        active.block_until(100);
        // `stale` blocks briefly, then yields back to ready: its waiter entry
        // is no longer active and must be collected.
        stale.block_until(200);
        stale.yield_back_to_ready();

        let mut waiting = vec![
            TimedWaiter {
                thread: active.clone(),
                cleanup: None,
            },
            TimedWaiter {
                thread: stale.clone(),
                cleanup: None,
            },
        ];
        let stale_waiters = take_stale_timed_waiters(&mut waiting);
        assert_eq!(stale_waiters.len(), 1);
        assert_eq!(stale_waiters[0].thread.tid(), stale.tid());
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].thread.tid(), active.tid());
    }

    #[test]
    fn remove_timed_waiters_by_identity_removes_matching_waiter() {
        use crate::kernel::process::wait::WaiterIdentity;

        let process = Process::new(17, "identity-remove");
        let a = Thread::new_kernel(process.clone(), idle_entry);
        let b = Thread::new_kernel(process.clone(), idle_entry);
        a.block_until(10);
        b.block_until(20);

        let mut waiting = vec![
            TimedWaiter {
                thread: a.clone(),
                cleanup: None,
            },
            TimedWaiter {
                thread: b.clone(),
                cleanup: None,
            },
        ];
        let identity = WaiterIdentity::from_thread(&a);
        assert_eq!(remove_timed_waiters_by_identity(&mut waiting, identity), 1);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].thread.tid(), b.tid());
    }

    #[test]
    fn preemption_time_slice_boundaries() {
        // TIME_SLICE_TICKS == 2 → preempt on even tick counts.
        assert!(should_preempt_for_time_slice(0));
        assert!(!should_preempt_for_time_slice(1));
        assert!(should_preempt_for_time_slice(2));
        assert!(!should_preempt_for_time_slice(3));
        assert!(should_preempt_for_time_slice(4));
    }

    #[test]
    fn requeue_preempted_fifo_thread_goes_to_front() {
        let process = Process::new(15, "fifo-requeue");
        let a = Thread::new_kernel(process.clone(), idle_entry);
        let b = Thread::new_kernel(process.clone(), idle_entry);
        a.set_sched_policy(ThreadSchedPolicy::SchedFifo);

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        assert!(enqueue_ready_thread(&mut queues, b.clone()).enqueued());
        requeue_preempted_thread(&mut queues, a.clone());

        // FIFO preemption: `a` jumps to the front, ahead of the queued `b`.
        assert_eq!(
            take_next_dispatchable_thread(&mut queues).expect("a").tid(),
            a.tid()
        );
        assert_eq!(
            take_next_dispatchable_thread(&mut queues).expect("b").tid(),
            b.tid()
        );
        assert!(take_next_dispatchable_thread(&mut queues).is_none());
    }

    #[test]
    fn a_priority_change_leaves_one_queued_copy() {
        let process = Process::new(41, "priority-move");
        let thread = Thread::new_kernel(process.clone(), idle_entry);

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        assert!(enqueue_ready_thread(&mut queues, thread.clone()).enqueued());

        // The starvation boost promotes a thread while it is sitting in the
        // queue.  Enqueueing it again must move it, not add a second copy:
        // two copies is one thread that two CPUs can dispatch at once.
        thread.set_priority(ThreadPriority::High);
        assert!(enqueue_ready_thread(&mut queues, thread.clone()).enqueued());

        let queued: usize = queues.iter().map(|queue| queue.len()).sum();
        assert_eq!(queued, 1, "the same thread was queued twice");
        assert_eq!(queues[ThreadPriority::High as usize].len(), 1);
        assert_eq!(queues[ThreadPriority::Normal as usize].len(), 0);

        // And it comes out once, at its new priority.
        assert_eq!(
            take_next_dispatchable_thread(&mut queues).map(|t| t.tid()),
            Some(thread.tid())
        );
        assert!(take_next_dispatchable_thread(&mut queues).is_none());
    }

    #[test]
    fn requeue_after_a_priority_change_moves_the_only_copy() {
        let process = Process::new(42, "priority-requeue");
        let thread = Thread::new_kernel(process.clone(), idle_entry);

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        assert!(enqueue_ready_thread(&mut queues, thread.clone()).enqueued());
        thread.set_priority(ThreadPriority::High);
        requeue_preempted_thread(&mut queues, thread.clone());

        let queued: usize = queues.iter().map(|queue| queue.len()).sum();
        assert_eq!(queued, 1, "the same thread was queued twice");
        assert_eq!(queues[ThreadPriority::High as usize].len(), 1);
    }

    #[test]
    fn thread_lookup_is_scoped_to_its_process() {
        // Every process numbers its threads from one, so two processes both
        // have a tid 1.  A lookup that matches the tid alone finds whichever
        // it sees first — this is how a per-process operation (ptrace) can end
        // up acting on another process's thread.
        let first = Scheduler::new();
        let process_a = Process::new(51, "lookup-a");
        let process_b = Process::new(52, "lookup-b");
        let thread_a = Thread::new_kernel(process_a.clone(), idle_entry);
        let thread_b = Thread::new_kernel(process_b.clone(), idle_entry);
        assert_eq!(thread_a.tid(), thread_b.tid());
        {
            let mut queues = first.ready_queues.lock();
            assert!(enqueue_ready_thread(&mut queues, thread_b.clone()).enqueued());
            assert!(enqueue_ready_thread(&mut queues, thread_a.clone()).enqueued());
        }

        assert_eq!(
            first
                .find_thread_by_pid_and_tid(51, thread_a.tid())
                .map(|thread| thread.pid()),
            Some(51)
        );
        assert_eq!(
            first
                .find_thread_by_pid_and_tid(52, thread_b.tid())
                .map(|thread| thread.pid()),
            Some(52)
        );
        assert!(first.find_thread_by_pid_and_tid(53, 1).is_none());
    }

    #[test]
    fn a_starvation_boost_leaves_a_tid_twin_queued() {
        use super::super::BOOST_THRESHOLD_TICKS;

        // Every process numbers its threads from one, so two of the demo
        // services are both pid=N tid=1.  The starvation boost promotes a
        // thread by *removing* it from the ready queues and putting it back at
        // a higher priority; that removal has to name the thread, not the
        // number it shares with another process's thread.
        let scheduler = Scheduler::new();
        let process_a = Process::new(71, "boost-a");
        let process_b = Process::new(72, "boost-b");
        let first = Thread::new_kernel(process_a.clone(), idle_entry);
        let second = Thread::new_kernel(process_b.clone(), idle_entry);
        assert_eq!(
            first.tid(),
            second.tid(),
            "the test is only interesting when the two threads share a tid"
        );

        {
            let mut queues = scheduler.ready_queues.lock();
            assert!(enqueue_ready_thread(&mut queues, first.clone()).enqueued());
        }
        // Bring the first thread to the edge of the boost threshold, then let
        // the second join the same queue behind it.  The pass that promotes
        // the first must not take the second with it.
        for _ in 0..BOOST_THRESHOLD_TICKS - 1 {
            scheduler.boost_starved_threads();
        }
        {
            let mut queues = scheduler.ready_queues.lock();
            assert!(enqueue_ready_thread(&mut queues, second.clone()).enqueued());
        }
        scheduler.boost_starved_threads();

        let queues = scheduler.ready_queues.lock();
        let queued: usize = queues.iter().map(|queue| queue.len()).sum();
        assert_eq!(
            queued, 2,
            "a starvation boost dropped a thread it did not promote: the \
             thread is ready and in no queue, so nothing will run it again"
        );
        assert_eq!(queues[ThreadPriority::High as usize].len(), 1);
        assert_eq!(queues[ThreadPriority::Normal as usize].len(), 1);
    }

    #[test]
    fn a_boost_expiry_leaves_a_tid_twin_queued() {
        use super::super::BOOST_THRESHOLD_TICKS;

        // The same removal on the way back down: a boosted thread that has
        // used up its slice returns to Normal, and the `retain` that takes it
        // out of the High queue must not take the other tid-1 thread with it.
        let scheduler = Scheduler::new();
        let process_a = Process::new(73, "expire-a");
        let process_b = Process::new(74, "expire-b");
        let first = Thread::new_kernel(process_a.clone(), idle_entry);
        let second = Thread::new_kernel(process_b.clone(), idle_entry);
        assert_eq!(first.tid(), second.tid());

        let enqueue = |thread: &Arc<Thread>| {
            let mut queues = scheduler.ready_queues.lock();
            assert!(enqueue_ready_thread(&mut queues, thread.clone()).enqueued());
        };

        enqueue(&first);
        for _ in 0..BOOST_THRESHOLD_TICKS {
            scheduler.boost_starved_threads();
        }
        assert!(first.is_boosted(), "the first thread should be boosted");
        enqueue(&second);
        for _ in 0..BOOST_THRESHOLD_TICKS {
            scheduler.boost_starved_threads();
        }
        assert!(second.is_boosted(), "the second thread should be boosted");

        // Spend the first thread's boost quantum; the pass that demotes it
        // must leave the second where it is.
        first.set_time_slice_remaining(0);
        scheduler.boost_starved_threads();

        let queues = scheduler.ready_queues.lock();
        let queued: usize = queues.iter().map(|queue| queue.len()).sum();
        assert_eq!(
            queued, 2,
            "a boost expiry dropped a thread it did not demote"
        );
        assert_eq!(queues[ThreadPriority::High as usize].len(), 1);
        assert_eq!(queues[ThreadPriority::Normal as usize].len(), 1);
    }

    #[test]
    fn thread_has_dispatch_address_space_predicates() {
        let process = Process::new(13, "dispatch-space");
        // Kernel threads share the kernel address space: always dispatchable.
        let kernel_thread = Thread::new_kernel(process.clone(), idle_entry);
        assert!(thread_has_dispatch_address_space(&kernel_thread));
        // User threads require an installed user address space.
        let user_thread =
            Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
        assert!(!process.has_user_address_space());
        assert!(!thread_has_dispatch_address_space(&user_thread));
    }

    #[test]
    fn scheduler_cycle_with_user_thread_entries() {
        let process = Process::new(19, "scheduler-cycle");
        let user = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
        let kernel = Thread::new_kernel(process.clone(), idle_entry);

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        assert!(enqueue_ready_thread(&mut queues, user.clone()).enqueued());
        assert!(enqueue_ready_thread(&mut queues, kernel.clone()).enqueued());
        assert_eq!(queues[ThreadPriority::Normal as usize].len(), 2);

        // A full dispatch cycle: every thread is taken exactly once.
        let first = take_next_dispatchable_thread(&mut queues).expect("first");
        let second = take_next_dispatchable_thread(&mut queues).expect("second");
        assert_ne!(first.tid(), second.tid());
        assert!(take_next_dispatchable_thread(&mut queues).is_none());
    }

    #[test]
    fn a_suspended_thread_in_a_ready_queue_is_dropped_and_unrecoverable() {
        // A ready queue is supposed to hold threads that can run.  A thread
        // suspended while it sits in one is exactly what it must not hold, and
        // the dispatch walk can only drop it — it goes out of the queue and
        // nowhere else.  What makes that worth a test is that the drop is not
        // recoverable: `continue_threads_of_process`, the path that resumes
        // stopped threads, looks for them *in* the queues.
        //
        // So this pins three things: the walk returns nothing, it says it
        // dropped one, and the thread is afterwards in no queue this scheduler
        // (or any of them) can find.
        let scheduler = Scheduler::new();
        let process = Process::new(71, "suspended-in-queue");
        let thread = Thread::new_kernel(process.clone(), idle_entry);
        process.set_state(super::super::super::ProcessState::Ready);
        {
            let mut processes = scheduler.processes.lock();
            processes.push(process.clone());
        }
        assert!(scheduler
            .enqueue_ready_thread_local(thread.clone())
            .enqueued());
        assert_eq!(scheduler.ready_count(), 1);

        thread.suspend();

        let mut queues = scheduler.ready_queues.lock();
        let (next, dropped) =
            super::super::queue::take_next_dispatchable_thread_with_dropped(&mut queues);
        drop(queues);

        assert!(next.is_none(), "a suspended thread is not dispatchable");
        assert_eq!(dropped, 1, "the walk has to say what it discarded");
        assert_eq!(scheduler.ready_count(), 0);
        assert!(
            scheduler
                .find_thread_by_pid_and_tid(process.pid(), thread.tid())
                .is_none(),
            "dropped out of the queue, the thread is in no queue at all"
        );
        assert_eq!(
            scheduler.continue_threads_of_process(&process),
            0,
            "and the resume path only walks queues, so it cannot find it"
        );
    }

    #[test]
    fn scheduler_new_has_zero_hotspot_stats() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.hotspot_stats(), SchedulerHotspotStats::default());
    }

    #[test]
    fn taking_a_registration_from_a_waiting_thread_is_counted() {
        // The shape of the wedge: a registration is removed while the thread
        // is still waiting for its deadline, which leaves nothing that will
        // ever wake it.  The counter is where that is supposed to show up.
        let scheduler = Scheduler::new();
        let process = Process::new(61, "lost-waiter");
        let thread = Thread::new_kernel(process.clone(), idle_entry);
        {
            let mut processes = scheduler.processes.lock();
            processes.push(process.clone());
        }

        thread.block_until(10_000);
        let identity = crate::kernel::process::wait::WaiterIdentity::from_thread(&thread);
        scheduler.register_timed_waiter(thread.clone(), None);
        assert_eq!(scheduler.waiting_count(), 1);

        scheduler.remove_timed_waiter(identity);

        assert_eq!(scheduler.waiting_count(), 0);
        assert_eq!(thread.state(), ThreadState::Waiting);
        assert_eq!(scheduler.hotspot_stats().waiter_lost_count, 1);
    }

    #[test]
    fn a_termination_with_no_current_thread_is_counted_once() {
        // The termination path hands the CPU to the scheduler, and it used to
        // do that from a CPU it had parked with interrupts masked when it
        // found no current thread to hand over *from*.  Masked interrupts are
        // never delivered to a halted CPU, so that machine never took another
        // timer tick and never printed again — a log that stops with nothing
        // in it to say why.  The counter is what makes the next one a finding,
        // and the print is gated on its first increment so a machine that
        // loops here cannot turn one bug into a serial flood.
        let scheduler = Scheduler::new();
        assert_eq!(
            scheduler.hotspot_stats().termination_without_thread_count,
            0
        );

        scheduler.record_termination_without_thread(
            "a thread was terminated with no current thread on this CPU",
            None,
        );
        assert_eq!(
            scheduler.hotspot_stats().termination_without_thread_count,
            1
        );

        // The site is carried through as text, so a second one from a
        // different place still counts even though it does not print.
        scheduler.record_termination_without_thread(
            "a thread that had already been terminated was dispatched again",
            None,
        );
        assert_eq!(
            scheduler.hotspot_stats().termination_without_thread_count,
            2
        );
    }

    #[test]
    fn a_live_process_with_no_placed_thread_is_counted() {
        // A process the scheduler can no longer find in any queue is a
        // process it will never run again — but one look cannot say so.  Every
        // block and every yield takes the thread out of `current` before it
        // lands in its next queue, and for that window it is in no queue at
        // all: identical to being lost, except that it ends.  The report is
        // therefore the second consecutive sighting.
        let scheduler = Scheduler::new();
        let process = Process::new(62, "unplaced");
        let thread = Thread::new_kernel(process.clone(), idle_entry);
        process.set_state(super::super::super::ProcessState::Ready);
        {
            let mut processes = scheduler.processes.lock();
            processes.push(process.clone());
        }
        let _unplaced = thread; // never enqueued, never waiting, never current

        scheduler.watch_process_placement();
        assert_eq!(
            scheduler.hotspot_stats().unplaced_process_count,
            0,
            "one sighting is a thread between two queues, not a lost one"
        );

        scheduler.watch_process_placement();
        assert_eq!(scheduler.hotspot_stats().unplaced_process_count, 1);

        // A thread the scheduler can find is not reported, even when nothing
        // is ready to run: the process is parked, not lost, and looking twice
        // does not change that.
        let scheduled = Scheduler::new();
        let parked = Process::new(63, "parked");
        parked.set_state(super::super::super::ProcessState::Waiting);
        let parked_thread = Thread::new_kernel(parked.clone(), idle_entry);
        {
            let mut processes = scheduled.processes.lock();
            processes.push(parked.clone());
        }
        parked_thread.block_until(500);
        scheduled.register_timed_waiter(parked_thread.clone(), None);

        scheduled.watch_process_placement();
        scheduled.watch_process_placement();
        assert_eq!(scheduled.hotspot_stats().unplaced_process_count, 0);
    }

    #[test]
    fn dispatch_and_requeue_predicates() {
        assert!(should_dispatch_ready_thread(ThreadState::Ready));
        assert!(!should_dispatch_ready_thread(ThreadState::Waiting));
        assert!(!should_dispatch_ready_thread(ThreadState::Terminated));

        assert!(should_requeue_simulated_preempted_thread(
            ThreadState::Running
        ));
        assert!(!should_requeue_simulated_preempted_thread(
            ThreadState::Waiting
        ));
        assert!(!should_requeue_simulated_preempted_thread(
            ThreadState::Terminated
        ));
    }

    // ── Process registry: registration, query, reap, signal ─────────────

    #[test]
    fn spawn_registers_process_and_pid_roundtrip() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.process_count(), 0);
        let thread = scheduler.spawn_named("registered", 0x1000);
        let pid = thread.process().pid();

        let found = scheduler.process_by_pid(pid).expect("registered process");
        assert_eq!(found.pid(), pid);
        assert_eq!(scheduler.process_count(), 1);

        let summaries = scheduler.list_process_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].pid, pid);
        assert_eq!(summaries[0].name, "registered");
    }

    #[test]
    fn process_by_pid_missing_returns_none() {
        let scheduler = Scheduler::new();
        assert!(scheduler.process_by_pid(1234).is_none());
    }

    #[test]
    fn reap_process_unregistered_returns_not_found() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.reap_process(999), Err(crate::Error::NotFound));
    }

    #[test]
    fn reap_process_rejects_live_process() {
        let scheduler = Scheduler::new();
        let thread = scheduler.spawn_named("live-reap", 0x1000);
        let pid = thread.process().pid();
        // A running (non-terminated) process cannot be reaped.
        assert_eq!(scheduler.reap_process(pid), Err(crate::Error::Busy));
        assert!(scheduler.process_by_pid(pid).is_some());
    }

    #[test]
    fn reap_process_returns_reason_and_unregisters() {
        use crate::kernel::process::TerminationReason;
        let scheduler = Scheduler::new();
        let thread = scheduler.spawn_named("reap-me", 0x1000);
        let pid = thread.process().pid();
        thread
            .process()
            .complete_termination(Some(TerminationReason::Exit { status: 42 }));

        assert_eq!(
            scheduler.reap_process(pid),
            Ok(Some(TerminationReason::Exit { status: 42 }))
        );
        assert!(scheduler.process_by_pid(pid).is_none());
        assert_eq!(scheduler.process_count(), 0);
    }

    #[test]
    fn send_signal_to_unregistered_process_is_not_found() {
        let scheduler = Scheduler::new();
        assert_eq!(
            scheduler.send_signal(0, 999, 10, 0),
            Err(crate::Error::NotFound)
        );
    }

    #[test]
    fn send_signal_enqueues_on_registered_process() {
        let scheduler = Scheduler::new();
        let thread = scheduler.spawn_named("signal-target", 0x1000);
        let process = thread.process();
        assert_eq!(scheduler.send_signal(7, process.pid(), 10, 0x1234), Ok(()));
        assert_eq!(process.pending_signal_count(), 1);
        let sig = process.take_pending_signal().unwrap();
        assert_eq!((sig.signal, sig.sender_pid, sig.payload), (10, 7, 0x1234));
    }

    #[test]
    fn stop_process_suspends_ready_threads() {
        let scheduler = Scheduler::new();
        let thread = scheduler.spawn_named("stop-target", 0x1000);
        let process = thread.process();
        let pid = process.pid();

        assert_eq!(scheduler.stop_process(pid), Ok(1));
        assert_eq!(thread.state(), ThreadState::Stopped);
        // The stopped thread was removed from the ready queue.
        assert_eq!(scheduler.ready_count(), 0);

        // `continue_process` only scans queues/current for stopped threads;
        // a thread stopped while Ready is no longer in any queue, so the
        // current implementation reports 0 resumed and leaves it Stopped.
        assert_eq!(scheduler.continue_process(pid), Ok(0));
        assert_eq!(thread.state(), ThreadState::Stopped);
    }

    #[test]
    fn stop_process_on_unregistered_process_is_not_found() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.stop_process(999), Err(crate::Error::NotFound));
        assert_eq!(scheduler.continue_process(999), Err(crate::Error::NotFound));
    }

    // ── Property tests (model oracle + fixed-seed LCG) ─────────────────────

    /// Random enqueue / dispatch / suspend+prune sequences against a model of
    /// the ready set.  Invariants checked after every operation:
    ///   - dispatch order matches the model's expectation (highest priority
    ///     first, FIFO within a priority);
    ///   - the model and the real queues hold exactly the same threads;
    ///   - no thread in a non-dispatchable state (Stopped/Waiting/Terminated)
    ///     ever sits in a ready queue.
    #[test]
    fn scheduler_ready_queue_random_ops_match_model() {
        use super::super::queue::enqueue_ready_thread;
        use super::super::queue::prune_nondispatchable_ready_threads;
        use super::super::queue::take_next_dispatchable_thread;

        let process = Process::new(100, "property-ready");
        let thread_count = 24;
        let threads: Vec<Arc<Thread>> = (0..thread_count)
            .map(|_| Thread::new_kernel(process.clone(), idle_entry))
            .collect();
        let mut rng = Lcg::new(0xF0F0_5020);
        for t in &threads {
            let prio = match rng.next_usize(THREAD_PRIORITY_COUNT) {
                0 => ThreadPriority::Idle,
                1 => ThreadPriority::Normal,
                2 => ThreadPriority::High,
                _ => ThreadPriority::Realtime,
            };
            t.set_priority(prio);
        }

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        // Model: ready threads in enqueue order as (index, tid, priority).
        let mut model: Vec<(usize, u32, usize)> = Vec::new();

        for step in 0..3000 {
            match rng.next_usize(3) {
                0 => {
                    // Enqueue a thread not currently ready.  Skip threads
                    // that are no longer dispatchable (e.g. suspended by an
                    // earlier op), which enqueue_ready_thread would reject.
                    let idx = rng.next_usize(thread_count);
                    if model.iter().any(|&(i, _, _)| i == idx) {
                        continue;
                    }
                    if !matches!(
                        threads[idx].state(),
                        ThreadState::Ready | ThreadState::Running
                    ) {
                        continue;
                    }
                    let prio = threads[idx].priority() as usize;
                    assert!(
                        enqueue_ready_thread(&mut queues, threads[idx].clone()).enqueued(),
                        "step {step}: enqueue of dispatchable thread {idx} rejected"
                    );
                    model.push((idx, threads[idx].tid(), prio));
                }
                1 => {
                    // Dispatch the next thread and compare with the model.
                    // The real queue pops the front of the highest-priority
                    // queue (FIFO within a priority), so the model must pick
                    // the earliest-enqueued thread among the highest-priority
                    // ones — `max_by_key` alone would pick the *last* on a
                    // tie and diverge from the scheduler.
                    let max_prio = model.iter().map(|&(_, _, prio)| prio).max();
                    let expected = max_prio.and_then(|max_prio| {
                        model
                            .iter()
                            .enumerate()
                            .filter(|&(_, &(_, _, prio))| prio == max_prio)
                            .min_by_key(|&(pos, _)| pos)
                            .map(|(_, &(_, tid, _))| tid)
                    });
                    let taken = take_next_dispatchable_thread(&mut queues);
                    let taken_tid = taken.as_ref().map(|t| t.tid());
                    match (taken, expected) {
                        (Some(t), Some(tid)) => {
                            assert_eq!(
                                t.tid(),
                                tid,
                                "step {step}: dispatch order diverged from model"
                            );
                            let pos = model
                                .iter()
                                .position(|&(_, m_tid, _)| m_tid == tid)
                                .unwrap();
                            model.remove(pos);
                        }
                        (None, None) => {}
                        _ => panic!(
                            "step {step}: real/model ready set diverged \
                             (taken={taken_tid:?}, expected={expected:?})"
                        ),
                    }
                }
                _ => {
                    // Suspend a random ready thread, prune it from the queues,
                    // and verify the ready set never retains a Stopped thread.
                    if model.is_empty() {
                        continue;
                    }
                    let pos = rng.next_usize(model.len());
                    let (idx, tid, _) = model.remove(pos);
                    assert!(
                        threads[idx].suspend(),
                        "step {step}: suspend of ready thread {idx} failed"
                    );
                    let pruned = prune_nondispatchable_ready_threads(&mut queues);
                    assert_eq!(
                        pruned, 1,
                        "step {step}: expected to prune exactly the suspended thread {tid}"
                    );
                }
            }

            // Model/real cardinality must agree after every operation.
            let real_count: usize = queues.iter().map(VecDeque::len).sum();
            assert_eq!(
                real_count,
                model.len(),
                "step {step}: ready-queue cardinality diverged from model"
            );
            // No non-dispatchable thread may remain in any ready queue.
            for q in &queues {
                for t in q {
                    assert!(
                        matches!(t.state(), ThreadState::Ready | ThreadState::Running),
                        "step {step}: non-dispatchable thread {:?} in ready queue",
                        t.state()
                    );
                }
            }
        }
    }

    /// The FIFO-within-priority rule the property-test oracle above relies on:
    /// threads enqueued at the same priority dispatch in enqueue order.  The
    /// LCG seed of the property test happens not to produce tied-max-priority
    /// dispatches, so this focused test pins the rule directly.
    #[test]
    fn dispatch_within_priority_is_fifo() {
        use super::super::queue::enqueue_ready_thread;
        use super::super::queue::take_next_dispatchable_thread;

        let process = Process::new(101, "property-fifo");
        let threads: Vec<Arc<Thread>> = (0..3)
            .map(|_| Thread::new_kernel(process.clone(), idle_entry))
            .collect();
        for t in &threads {
            t.set_priority(ThreadPriority::Normal);
        }

        let mut queues: [VecDeque<Arc<Thread>>; THREAD_PRIORITY_COUNT] = Default::default();
        // Enqueue A, B, C at the same priority — FIFO must dispatch A, B, C.
        for t in &threads {
            assert!(enqueue_ready_thread(&mut queues, t.clone()).enqueued());
        }
        let mut order = Vec::new();
        while let Some(t) = take_next_dispatchable_thread(&mut queues) {
            order.push(t.tid());
        }
        let expected: Vec<u32> = threads.iter().map(|t| t.tid()).collect();
        assert_eq!(order, expected, "same-priority dispatch must be FIFO");
    }

    /// Random sleep deadlines against a model: advancing simulated time must
    /// wake exactly the waiters whose deadline has elapsed — no early wakes,
    /// no missed wakes.
    #[test]
    fn timed_waiter_random_deadlines_match_elapse_model() {
        use super::super::queue::take_elapsed_timed_waiters;

        let process = Process::new(200, "property-wait");
        let count = 32;
        let mut rng = Lcg::new(0xF0F0_5030);
        let mut threads: Vec<Arc<Thread>> = Vec::with_capacity(count);
        let mut deadlines: Vec<u64> = Vec::with_capacity(count);
        for _ in 0..count {
            let thread = Thread::new_kernel(process.clone(), idle_entry);
            let deadline = rng.next_usize(200) as u64;
            thread.block_until(deadline);
            threads.push(thread);
            deadlines.push(deadline);
        }

        let mut waiting: Vec<TimedWaiter> = threads
            .iter()
            .map(|thread| TimedWaiter {
                thread: thread.clone(),
                cleanup: None,
            })
            .collect();
        let mut woke: Vec<u32> = Vec::new();

        for tick in 0..=210u64 {
            let batch = take_elapsed_timed_waiters(&mut waiting, tick);
            woke.extend(batch.iter().map(|w| w.thread.tid()));

            for (thread, &deadline) in threads.iter().zip(&deadlines) {
                if deadline <= tick {
                    assert!(
                        woke.contains(&thread.tid()),
                        "tick {tick}: thread {} (deadline {deadline}) missed",
                        thread.tid()
                    );
                } else {
                    assert!(
                        !woke.contains(&thread.tid()),
                        "tick {tick}: thread {} (deadline {deadline}) woke early",
                        thread.tid()
                    );
                }
            }
        }
        assert!(
            waiting.is_empty(),
            "all waiters should have been collected by the final tick"
        );
    }

    /// Preemption predicates over a range of tick counts: a time-slice
    /// boundary fires at tick 0 and then every `TIME_SLICE_TICKS`, and the
    /// simulated-requeue predicate only accepts Running threads.
    ///
    /// The expected boundary is derived from a small state machine (count
    /// ticks since the last boundary) rather than mirroring the
    /// implementation's own divisibility expression, so the oracle stays
    /// independent of the code under test.
    #[test]
    fn preemption_time_slice_property_random_ticks() {
        use super::super::queue::should_preempt_for_time_slice;
        use super::super::queue::should_requeue_simulated_preempted_thread;
        use super::super::TIME_SLICE_TICKS;

        let mut ticks_since_boundary = 0u64;
        for tick in 0..10_000u64 {
            let expect_boundary = ticks_since_boundary == 0;
            assert_eq!(
                should_preempt_for_time_slice(tick),
                expect_boundary,
                "tick {tick}: preemption boundary diverged from time-slice rule"
            );
            ticks_since_boundary += 1;
            if ticks_since_boundary >= TIME_SLICE_TICKS {
                ticks_since_boundary = 0;
            }
        }

        // A simulated preempted thread is requeued unless it has left the
        // ready domain entirely (Waiting / Stopped / Terminated).
        assert!(should_requeue_simulated_preempted_thread(
            ThreadState::Ready
        ));
        assert!(should_requeue_simulated_preempted_thread(
            ThreadState::Running
        ));
        for state in [
            ThreadState::Waiting,
            ThreadState::Stopped,
            ThreadState::Terminated,
        ] {
            assert!(
                !should_requeue_simulated_preempted_thread(state),
                "state {state:?} must not be requeued as preempted"
            );
        }
    }

    /// Where a thread the scheduler owns is: a ready queue, the current slot,
    /// or the timed-waiter queue.
    ///
    /// Returned as names so a failure says which places held the thread
    /// instead of leaving the reader to guess at a pair of booleans.
    fn placement_of(scheduler: &Scheduler, thread: &Arc<Thread>) -> Vec<&'static str> {
        let pointer = Arc::as_ptr(thread);
        let mut places = Vec::new();

        {
            let queues = scheduler.ready_queues.lock();
            if queues
                .iter()
                .any(|queue| queue.iter().any(|queued| Arc::as_ptr(queued) == pointer))
            {
                places.push("ready");
            }
        }
        if scheduler
            .current
            .lock()
            .as_ref()
            .is_some_and(|current| Arc::as_ptr(current) == pointer)
        {
            places.push("current");
        }
        if scheduler
            .waiting_queue
            .lock()
            .iter()
            .any(|waiter| Arc::as_ptr(&waiter.thread) == pointer)
        {
            places.push("waiting");
        }

        places
    }

    /// The whole-scheduler placement invariant.
    ///
    /// A thread the scheduler owns lives in **exactly one** place: a ready
    /// queue, the current slot, or the timed-waiter queue.  Two places is a
    /// thread two dispatchers can run; no place is a thread no future tick
    /// will ever reach — the wedge the placement watchdog exists to catch.
    /// And the place has to agree with the thread's own state, because every
    /// consumer reads one and acts on the other: the tick's sleeper sweep
    /// trusts `Waiting`, the dispatcher trusts `Ready`, the preemption
    /// predicate trusts `Running`.
    ///
    /// The operations are the scheduler's own host-callable ones — spawn,
    /// simulated dispatch and preemption, the real sleep path
    /// (`sleep_current_thread`), and the tick's sleeper sweep — so this drives
    /// the code a boot runs rather than a reimplementation of it.
    #[test]
    fn scheduler_placement_invariant_holds_across_random_operations() {
        const THREADS: usize = 12;
        const STEPS: usize = 4000;

        let scheduler = Scheduler::new();
        let threads: Vec<Arc<Thread>> = (0..THREADS)
            .map(|index| scheduler.spawn_named(&alloc::format!("placement-{index}"), 0x1000))
            .collect();

        let mut rng = Lcg::new(0xF0F0_5040);
        let mut now: u64 = 0;
        // The mix has to actually reach every place, or the invariant above
        // would be checked over a run that never exercised sleep or dispatch.
        let mut seen = [false; 3];

        for step in 0..STEPS {
            // Advance the simulated clock so deadlines can come due; the host
            // scheduler measures time in this counter, not the hardware timer.
            if rng.next_usize(4) == 0 {
                now += 1 + rng.next_usize(8) as u64;
                *scheduler.simulated_ticks.lock() = now;
            }

            match rng.next_usize(5) {
                // Move a ready thread into the current slot.  Dispatch does
                // not evict, so only ask when the slot is free.
                0 | 1 => {
                    if scheduler.current.lock().is_none() {
                        let _ = scheduler.dispatch_next_simulated();
                    }
                }
                // Preempt the current thread back to its ready queue.
                2 => {
                    let _ = scheduler.preempt_current_thread_simulated();
                }
                // Sleep the current thread down the real path: it parks on the
                // timed-waiter queue and whoever is next runs.
                3 => {
                    if scheduler.current.lock().is_some() {
                        scheduler.sleep_current_thread(1 + rng.next_usize(20) as u64);
                    }
                }
                // The timer tick's sleeper sweep.
                _ => {
                    let _ = scheduler.wake_expired_sleepers(now);
                }
            }

            for thread in &threads {
                let places = placement_of(&scheduler, thread);
                assert_eq!(
                    places.len(),
                    1,
                    "step {step}: thread {} is in {places:?}; exactly one place is required",
                    thread.tid(),
                );
                let expected = match places[0] {
                    "ready" => ThreadState::Ready,
                    "current" => ThreadState::Running,
                    "waiting" => ThreadState::Waiting,
                    other => panic!("step {step}: unknown place {other}"),
                };
                seen[match places[0] {
                    "ready" => 0,
                    "current" => 1,
                    _ => 2,
                }] = true;
                assert_eq!(
                    thread.state(),
                    expected,
                    "step {step}: thread {} is {:?} but placed in {}",
                    thread.tid(),
                    thread.state(),
                    places[0],
                );
            }
        }

        assert_eq!(
            seen, [true; 3],
            "the random mix did not reach every place: {seen:?}",
        );
    }
}
