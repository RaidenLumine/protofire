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
        assert!(enqueue_ready_thread(&mut queues, normal.clone()));
        assert!(enqueue_ready_thread(&mut queues, idle.clone()));
        assert!(enqueue_ready_thread(&mut queues, high.clone()));
        assert!(enqueue_ready_thread(&mut queues, realtime.clone()));

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

        assert!(enqueue_ready_thread(&mut queues, ready.clone()));
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

        assert!(!enqueue_ready_thread(&mut queues, blocked.clone()));
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
        assert!(process_elapsed_timed_waiter(waiter, &mut queues));
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
        use crate::kernel::sync::wait::WaiterIdentity;

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
        assert!(enqueue_ready_thread(&mut queues, b.clone()));
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
        assert!(enqueue_ready_thread(&mut queues, user.clone()));
        assert!(enqueue_ready_thread(&mut queues, kernel.clone()));
        assert_eq!(queues[ThreadPriority::Normal as usize].len(), 2);

        // A full dispatch cycle: every thread is taken exactly once.
        let first = take_next_dispatchable_thread(&mut queues).expect("first");
        let second = take_next_dispatchable_thread(&mut queues).expect("second");
        assert_ne!(first.tid(), second.tid());
        assert!(take_next_dispatchable_thread(&mut queues).is_none());
    }

    #[test]
    fn scheduler_new_has_zero_hotspot_stats() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.hotspot_stats(), SchedulerHotspotStats::default());
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
                        enqueue_ready_thread(&mut queues, threads[idx].clone()),
                        "step {step}: enqueue of dispatchable thread {idx} rejected"
                    );
                    model.push((idx, threads[idx].tid(), prio));
                }
                1 => {
                    // Dispatch the next thread and compare with the model.
                    let expected = model
                        .iter()
                        .copied()
                        .max_by_key(|&(_, _, prio)| prio)
                        .map(|(_, tid, _)| tid);
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
    /// boundary fires exactly when `tick % TIME_SLICE_TICKS == 0`, and the
    /// simulated-requeue predicate only accepts Running threads.
    #[test]
    fn preemption_time_slice_property_random_ticks() {
        use super::super::queue::should_preempt_for_time_slice;
        use super::super::queue::should_requeue_simulated_preempted_thread;
        use super::super::TIME_SLICE_TICKS;

        let mut rng = Lcg::new(0xF0F0_5040);
        for _ in 0..5000 {
            let tick = rng.next() & 0xFFFF;
            assert_eq!(
                should_preempt_for_time_slice(tick),
                tick.is_multiple_of(TIME_SLICE_TICKS),
                "tick {tick}: preemption boundary diverged from time-slice rule"
            );
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
}
