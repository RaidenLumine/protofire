//! src/kernel/process/thread/tests.rs
//!
//! Thread lifecycle invariants: construction, state transitions, block/wake,
//! suspend/resume, termination, join, and process handle behaviour after a
//! process terminates.
//!
//! Every assertion below pins behaviour of the *current* API.  Tests that need
//! a live scheduler (join blocking, termination-event waking) use a local
//! [`Scheduler`] installed through the thread-local global slot, matching the
//! pattern established by `syscall/test_support.rs`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;

use crate::kernel::fs::layout::DEFAULT_USER_ROOT;
use crate::kernel::fs::{FileSystem, OPEN_ALWAYS};
use crate::kernel::process::scheduler::api::idle_entry;
use crate::kernel::process::thread::ThreadSchedPolicy;
use crate::kernel::process::{
    HandleEntry, KernelObject, OpenFile, Process, ProcessState, Scheduler, TerminationReason,
    Thread, ThreadPriority, ThreadState, ThreadWaitOutcome, UserThreadStart, HANDLE_RIGHT_READ,
    HANDLE_RIGHT_WRITE, STDIN_FD, STDOUT_FD,
};
use crate::Error;

/// Create a scheduler with a single runnable kernel thread installed as the
/// current thread, plus that thread's process.  Mirrors
/// `syscall::test_support::scheduled_current_process`.
fn scheduled_current_thread(name: &str) -> (Box<Scheduler>, Arc<Thread>, Arc<Process>) {
    let scheduler = Box::new(Scheduler::new());
    let thread = scheduler.spawn_named(name, 0x1000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));
    let process = thread.process().clone();
    (scheduler, thread, process)
}

// ── Construction ───────────────────────────────────────────────────────

#[test]
fn new_kernel_thread_starts_ready_with_allocated_tid() {
    let process = Process::new(100, "new-kernel");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.pid(), process.pid());
    assert_eq!(thread.process().pid(), process.pid());
    // TIDs start at 1 for the first thread of a fresh process.
    assert_eq!(thread.tid(), 1);
    assert_eq!(process.thread_ids(), vec![1]);
    // Kernel threads share the kernel address space: no user start.
    assert_eq!(thread.user_start(), None);
}

#[test]
fn new_user_thread_seeds_user_start_and_entry_point() {
    let process = Process::new(101, "new-user");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));

    let start = thread.user_start().expect("user start");
    assert_eq!(start.instruction_pointer, 0x1000);
    assert_eq!(start.stack_pointer, 0x2000);
    assert_eq!(thread.entry_point(), 0x1000);
    assert_eq!(thread.state(), ThreadState::Ready);
}

#[test]
fn new_user_thread_registers_in_process() {
    let process = Process::new(102, "new-user-register");
    let first = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
    let second = Thread::new_user(process.clone(), UserThreadStart::new(0x3000, 0x4000, None));

    assert_eq!(first.tid(), 1);
    assert_eq!(second.tid(), 2);
    assert_eq!(process.thread_ids(), vec![1, 2]);
}

#[test]
fn try_new_user_rejects_null_instruction_pointer() {
    let process = Process::new(103, "try-user-null-ip");
    assert!(matches!(
        Thread::try_new_user(process.clone(), UserThreadStart::new(0, 0x2000, None)),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn try_new_user_rejects_null_stack_pointer() {
    let process = Process::new(104, "try-user-null-sp");
    assert!(matches!(
        Thread::try_new_user(process.clone(), UserThreadStart::new(0x1000, 0, None)),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn try_new_user_rejects_misaligned_stack_pointer() {
    let process = Process::new(105, "try-user-misaligned");
    // 0x2004 is not 16-byte aligned (USER_THREAD_STACK_ALIGNMENT).
    assert!(matches!(
        Thread::try_new_user(process.clone(), UserThreadStart::new(0x1000, 0x2004, None)),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn new_thread_on_terminated_process_is_terminated() {
    // Thread construction on a dead process cannot register the tid; the
    // freshly built thread is terminated instead of panicking.
    let process = Process::new(106, "thread-on-terminated");
    process.set_state(ProcessState::Terminated);
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    assert_eq!(thread.state(), ThreadState::Terminated);
}

// ── State transitions ──────────────────────────────────────────────────

#[test]
fn set_state_transitions_are_observable() {
    let process = Process::new(107, "set-state");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.set_state(ThreadState::Running);
    assert_eq!(thread.state(), ThreadState::Running);
    thread.set_state(ThreadState::Stopped);
    assert_eq!(thread.state(), ThreadState::Stopped);
    thread.set_state(ThreadState::Terminated);
    assert_eq!(thread.state(), ThreadState::Terminated);
}

#[test]
fn block_transitions_to_waiting_and_records_pending_outcome() {
    let process = Process::new(108, "block");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.block();
    assert_eq!(thread.state(), ThreadState::Waiting);
    assert_eq!(thread.process().state(), ProcessState::Waiting);
    assert_eq!(thread.wait_outcome(), ThreadWaitOutcome::Pending);
    assert_eq!(thread.wake_deadline(), None);
}

#[test]
fn block_until_records_wake_deadline() {
    let process = Process::new(109, "block-until");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.block_until(42);
    assert_eq!(thread.state(), ThreadState::Waiting);
    assert_eq!(thread.wake_deadline(), Some(42));
}

#[test]
fn wake_by_signal_from_waiting_sets_ready_and_completed() {
    let process = Process::new(110, "wake-signal");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.block();

    assert!(thread.wake_by_signal());
    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.process().state(), ProcessState::Ready);
    assert_eq!(thread.wait_outcome(), ThreadWaitOutcome::Completed);
    assert_eq!(thread.wake_deadline(), None);
}

#[test]
fn wake_by_timeout_from_waiting_sets_ready_and_timed_out() {
    let process = Process::new(111, "wake-timeout");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.block_until(5);

    assert!(thread.wake_by_timeout());
    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.wait_outcome(), ThreadWaitOutcome::TimedOut);
}

#[test]
fn wake_by_signal_on_non_waiting_thread_is_rejected() {
    let process = Process::new(112, "wake-reject");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    // Ready — not waiting — so the wake is refused.
    assert!(!thread.wake_by_signal());
    assert_eq!(thread.state(), ThreadState::Ready);
}

#[test]
fn wake_by_timeout_on_non_waiting_thread_is_rejected() {
    let process = Process::new(113, "wake-timeout-reject");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert!(!thread.wake_by_timeout());
}

#[test]
fn suspend_resume_roundtrip() {
    let process = Process::new(114, "suspend-resume");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    assert!(thread.suspend());
    assert_eq!(thread.state(), ThreadState::Stopped);
    assert!(thread.is_stopped());

    // Double suspend on an already-stopped thread is refused.
    assert!(!thread.suspend());

    assert!(thread.resume());
    assert_eq!(thread.state(), ThreadState::Ready);
    assert!(!thread.is_stopped());
}

#[test]
fn suspend_waiting_thread_defers_stop_until_wake() {
    let process = Process::new(115, "suspend-waiting");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.block();

    // Suspending a Waiting thread is accepted and records a pending stop.
    assert!(thread.suspend());
    assert_eq!(thread.state(), ThreadState::Waiting);

    // Waking honours the pending stop: the thread goes to Stopped, not Ready.
    assert!(thread.wake_by_signal());
    assert_eq!(thread.state(), ThreadState::Stopped);
}

#[test]
fn suspend_terminated_thread_is_rejected() {
    let process = Process::new(116, "suspend-terminated");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.terminate();
    assert!(!thread.suspend());
}

#[test]
fn resume_on_non_stopped_thread_is_a_no_op_transition() {
    // `resume()` runs `set_process_and_thread_state(Ready, Ready)`: on a
    // live Ready thread it succeeds as a no-op and keeps the thread Ready.
    let process = Process::new(117, "resume-noop");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert!(thread.resume());
    assert_eq!(thread.state(), ThreadState::Ready);

    // A resumed Terminated thread reports failure.
    thread.terminate();
    assert!(!thread.resume());
    assert_eq!(thread.state(), ThreadState::Terminated);
}

#[test]
fn terminate_moves_to_terminated_and_signals_event() {
    let process = Process::new(118, "terminate");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.terminate();
    assert_eq!(thread.state(), ThreadState::Terminated);
    assert_eq!(thread.termination_reason(), None);
    // The termination event is signalled: a later join reports "already
    // terminal" rather than blocking.
    let (_scheduler, _joiner, _) = scheduled_current_thread("terminate-signaled");
    assert!(!thread.join());
}

#[test]
fn terminate_with_reason_records_reason() {
    let process = Process::new(119, "terminate-reason");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.terminate_with_reason(TerminationReason::Exit { status: 42 });
    assert_eq!(thread.state(), ThreadState::Terminated);
    assert_eq!(
        thread.termination_reason(),
        Some(TerminationReason::Exit { status: 42 })
    );
}

#[test]
fn terminate_is_idempotent() {
    let process = Process::new(120, "terminate-idem");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    thread.terminate();
    thread.terminate();
    thread.terminate_with_reason(TerminationReason::Exit { status: 7 });
    assert_eq!(thread.state(), ThreadState::Terminated);
}

#[test]
fn terminating_last_thread_terminates_process() {
    let process = Process::new(121, "last-thread");
    let first = Thread::new_kernel(process.clone(), idle_entry);
    let second = Thread::new_kernel(process.clone(), idle_entry);
    assert_eq!(process.thread_ids().len(), 2);

    first.terminate();
    assert_eq!(process.thread_ids().len(), 1);
    assert_ne!(process.state(), ProcessState::Terminated);

    second.terminate_with_reason(TerminationReason::Exit { status: 5 });
    assert_eq!(process.thread_ids().len(), 0);
    assert_eq!(process.state(), ProcessState::Terminated);
    // The process inherits the final thread's exit reason.
    assert_eq!(
        process.termination_reason(),
        Some(TerminationReason::Exit { status: 5 })
    );
}

// ── Join / termination event ───────────────────────────────────────────

#[test]
fn join_on_live_thread_blocks_and_registers_waiter() {
    let (_scheduler, _joiner, _) = scheduled_current_thread("join-live");
    let process = Process::new(122, "join-target");
    let target = Thread::new_kernel(process.clone(), idle_entry);

    // The current thread blocks on the target's termination event.
    assert!(target.join());
    assert_eq!(target.termination_waiter_count(), 1);

    // Terminating the target wakes the waiter and clears the wait queue.
    target.terminate();
    assert_eq!(target.termination_waiter_count(), 0);
}

#[test]
fn join_on_terminated_thread_returns_false_without_blocking() {
    let (_scheduler, _joiner, _) = scheduled_current_thread("join-done");
    let process = Process::new(123, "join-done-target");
    let target = Thread::new_kernel(process.clone(), idle_entry);
    target.terminate();

    // Already in a terminal state: join does not block and reports false.
    assert!(!target.join());
    assert_eq!(target.termination_waiter_count(), 0);
}

#[test]
fn join_without_scheduler_does_not_block() {
    // No global scheduler is installed: blocking primitives short-circuit.
    let process = Process::new(124, "join-no-sched");
    let target = Thread::new_kernel(process.clone(), idle_entry);

    assert!(!target.join());
}

#[test]
fn join_timeout_zero_probes_without_blocking() {
    let (_scheduler, _joiner, _) = scheduled_current_thread("join-timeout-zero");
    let process = Process::new(125, "join-timeout-zero-target");
    let target = Thread::new_kernel(process.clone(), idle_entry);

    // A zero-timeout join is a non-blocking probe of the termination event.
    assert!(!target.join_timeout(0));
    assert_eq!(target.termination_waiter_count(), 0);
}

#[test]
fn join_timeout_on_terminated_thread_returns_false() {
    let (_scheduler, _joiner, _) = scheduled_current_thread("join-timeout-done");
    let process = Process::new(126, "join-timeout-done-target");
    let target = Thread::new_kernel(process.clone(), idle_entry);
    target.terminate();

    assert!(!target.join_timeout(10));
}

#[test]
fn process_wait_for_termination_blocks_then_wakes() {
    let (_scheduler, _joiner, _) = scheduled_current_thread("proc-wait-term");
    let process = Process::new(127, "proc-wait-term-target");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    // The current thread blocks on the process termination event.
    assert!(process.wait_for_termination());
    assert_eq!(process.termination_waiter_count(), 1);

    thread.terminate(); // last thread -> process terminates -> event signals
    assert_eq!(process.state(), ProcessState::Terminated);
    assert_eq!(process.termination_waiter_count(), 0);
}

// ── Scheduling metadata accessors ──────────────────────────────────────

#[test]
fn priority_accessors_roundtrip() {
    let process = Process::new(128, "priority");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert_eq!(thread.priority(), ThreadPriority::Normal);

    thread.set_priority(ThreadPriority::High);
    assert_eq!(thread.priority(), ThreadPriority::High);
    thread.set_priority(ThreadPriority::Realtime);
    assert_eq!(thread.priority(), ThreadPriority::Realtime);
}

#[test]
fn sched_policy_accessors_roundtrip() {
    let process = Process::new(129, "sched-policy");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert_eq!(thread.sched_policy(), ThreadSchedPolicy::SchedDefault);

    thread.set_sched_policy(ThreadSchedPolicy::SchedFifo);
    assert_eq!(thread.sched_policy(), ThreadSchedPolicy::SchedFifo);
    thread.set_sched_policy(ThreadSchedPolicy::SchedRoundRobin);
    assert_eq!(thread.sched_policy(), ThreadSchedPolicy::SchedRoundRobin);
}

#[test]
fn cpu_affinity_accessors_roundtrip() {
    let process = Process::new(130, "affinity");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert_eq!(thread.cpu_affinity(), 0);

    thread.set_cpu_affinity(2);
    assert_eq!(thread.cpu_affinity(), 2);
    // u32::MAX removes the pin.
    thread.set_cpu_affinity(u32::MAX);
    assert_eq!(thread.cpu_affinity(), u32::MAX);
}

#[test]
fn time_slice_ticks_are_clamped_to_range() {
    let process = Process::new(131, "time-slice");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert!(thread.time_slice_ticks() >= 1);

    thread.set_time_slice_ticks(0);
    assert_eq!(thread.time_slice_ticks(), 1);
    thread.set_time_slice_ticks(100);
    assert_eq!(thread.time_slice_ticks(), 20);
    thread.set_time_slice_ticks(7);
    assert_eq!(thread.time_slice_ticks(), 7);
}

#[test]
fn summary_reflects_priority_and_state() {
    let process = Process::new(132, "summary");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.set_priority(ThreadPriority::High);

    let summary = thread.summary();
    assert_eq!(summary.tid, thread.tid());
    assert_eq!(summary.priority, ThreadPriority::High);
    assert_eq!(summary.state, ThreadState::Ready);
    assert_eq!(summary.cpu_ticks, 0);
}

#[test]
fn kernel_stack_bounds_are_sane() {
    let process = Process::new(133, "stack-bounds");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    let (bottom, top) = thread.stack_bounds();
    assert!(bottom < top);
    assert_eq!(thread.kernel_stack_top(), top);
    // A freshly built thread's stack pointer should be safe.
    assert!(thread.kernel_stack_usage_ok());
}

#[test]
fn context_accessor_returns_initial_context() {
    // Kernel threads seed the saved context with the raw entry point.
    let process = Process::new(134, "context");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    let context = thread.context();
    assert_eq!(context.instruction_pointer, thread.entry_point());
    assert!(context.stack_pointer != 0);
}

#[test]
fn save_and_restore_context_update_switch_count_and_state() {
    let process = Process::new(135, "save-restore");
    let thread = Thread::new_kernel(process.clone(), idle_entry);

    assert_eq!(thread.switch_count(), 0);
    thread.save_context();
    assert_eq!(thread.switch_count(), 1);

    thread.restore_context();
    assert_eq!(thread.state(), ThreadState::Running);
    assert_eq!(thread.process().state(), ProcessState::Running);
}

#[test]
fn yield_back_to_ready_moves_thread_to_ready() {
    let process = Process::new(136, "yield-ready");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    thread.restore_context();
    assert_eq!(thread.state(), ThreadState::Running);

    thread.yield_back_to_ready();
    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.process().state(), ProcessState::Ready);
}

#[test]
fn wait_outcome_defaults_to_completed_for_fresh_thread() {
    let process = Process::new(137, "wait-outcome-default");
    let thread = Thread::new_kernel(process.clone(), idle_entry);
    assert_eq!(thread.wait_outcome(), ThreadWaitOutcome::Completed);
}

// ── Process handle lifecycle ───────────────────────────────────────────

#[test]
fn terminated_process_handle_operations_return_busy() {
    // Set up a live process with a bound, duplicated stdin handle.
    let process = Process::new(1, "terminated-handle-test");
    let mut stdin_fs = FileSystem::new();
    stdin_fs.init();
    let stdin_file = stdin_fs
        .create_file_from(
            "/data/users/guest/downloads/terminated-stdin.log",
            DEFAULT_USER_ROOT,
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create stdin file");
    let stdin = process
        .open_file_handle(
            "/data/users/guest/downloads/terminated-stdin.log",
            stdin_file,
            HANDLE_RIGHT_READ | HANDLE_RIGHT_WRITE,
        )
        .expect("open stdin file handle");
    process
        .bind_standard_handle(STDIN_FD, stdin)
        .expect("bind stdin handle");
    let duplicated_stdin = process
        .duplicate_fd(STDIN_FD)
        .expect("duplicate stdin descriptor");

    // Terminate the process: handle mutation is now permanently denied.
    process.set_state(ProcessState::Terminated);

    assert_eq!(process.user_address_space_summary(), None);
    let mut fs = FileSystem::new();
    fs.init();
    let file = fs
        .create_file_from(
            "/data/users/guest/downloads/terminated-open.log",
            DEFAULT_USER_ROOT,
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create terminated-process file handle backing");
    assert_eq!(
        process.bind_standard_handle(STDIN_FD, stdin),
        Err(Error::Busy)
    );
    assert_eq!(process.duplicate_fd(STDIN_FD), Err(Error::Busy));
    assert_eq!(process.close_fd(STDIN_FD), Err(Error::Busy));
    assert_eq!(process.close_fd(duplicated_stdin), Err(Error::Busy));
    assert_eq!(
        process.open_file_handle(
            "/data/users/guest/downloads/terminated-open.log",
            file,
            HANDLE_RIGHT_WRITE,
        ),
        Err(Error::Busy)
    );
    let entry_file = fs
        .create_file_from(
            "/data/users/guest/downloads/terminated-install.log",
            DEFAULT_USER_ROOT,
            0,
            0,
            OPEN_ALWAYS,
        )
        .expect("create install entry file backing");
    let entry = HandleEntry {
        object: KernelObject::File(OpenFile::new(
            "/data/users/guest/downloads/terminated-install.log",
            entry_file,
        )),
        rights: HANDLE_RIGHT_WRITE,
    };
    assert_eq!(
        process.install_standard_handle_entry(STDOUT_FD, entry),
        Err(Error::Busy)
    );
}
