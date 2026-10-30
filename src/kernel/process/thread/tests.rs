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

use crate::fs::layout::DEFAULT_USER_ROOT;
use crate::fs::FileSystem;
use crate::fs::OPEN_ALWAYS;
use crate::kernel::process::scheduler::api::idle_entry;
use crate::kernel::process::thread::ThreadSchedPolicy;
use crate::kernel::process::HandleEntry;
use crate::kernel::process::KernelObject;
use crate::kernel::process::OpenFile;
use crate::kernel::process::Process;
use crate::kernel::process::ProcessState;
use crate::kernel::process::Scheduler;
use crate::kernel::process::TerminationReason;
use crate::kernel::process::Thread;
use crate::kernel::process::ThreadPriority;
use crate::kernel::process::ThreadState;
use crate::kernel::process::ThreadWaitOutcome;
use crate::kernel::process::UserThreadStart;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;
use crate::kernel::process::STDIN_FD;
use crate::kernel::process::STDOUT_FD;
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

/// A resume accepts the stack pointer a fork actually captures.
///
/// x86_64's ABI puts `rsp` at 8 mod 16 inside a function body and at 0 mod 16
/// only at a call instruction, so a context captured at a syscall from
/// mid-function — which is where `fork` runs — is misaligned by the
/// fresh-entry rule's own definition.  Applying that rule to a resume refused
/// every fork whose parent was not at a call site, which from the console is
/// all of them; measured, `fork` printed `fork: refused` on 9 of 9 boots
/// before this test existed.
#[test]
fn resumed_start_accepts_a_captured_stack_pointer() {
    let start = UserThreadStart::new(0x1000, 0x2004, None);
    assert!(matches!(start.validate(), Err(Error::InvalidArgument)));
    assert_eq!(start.validate_resumed().unwrap().stack_pointer, 0x2004);
}

/// A resume still refuses addresses no thread could run at.
///
/// The alignment is the only check the two rules disagree about; dropping it
/// must not drop the rest.  A zero or non-canonical pointer is as invalid on a
/// resume as on a fresh entry, and a resume that accepted one would put the
/// machine somewhere it cannot come back from.
#[test]
fn resumed_start_still_refuses_unusable_addresses() {
    assert!(UserThreadStart::new(0x1000, 0, None)
        .validate_resumed()
        .is_err());
    assert!(UserThreadStart::new(0, 0x2000, None)
        .validate_resumed()
        .is_err());
    assert!(UserThreadStart::new(0x0000_8000_0000_0000, 0x2000, None)
        .validate_resumed()
        .is_err());
    assert!(UserThreadStart::new(0x1000, 0x7fff_ffff_ffff_fffc, None)
        .validate_resumed()
        .is_err());
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

// ── riscv64 user-exception handler installation ─────────────────────────
//
// The trap glue that *delivers* an exception runs only on the machine, so the
// evidence for that half is `make check-riscv64-runtime`'s boot.  What a host
// can check is the half a program calls: that installing a handler records
// it, that a code this machine does not deliver to user space is refused, and
// that installing zero clears the slot.  These are the assertions that would
// have failed while riscv64 answered `Unsupported` to every install.

#[test]
fn riscv64_install_records_the_handler_it_was_given() {
    use crate::abi::exception::RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR;
    use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_NONE;

    let process = Process::new(201, "riscv64-install");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));

    let handler = 0xdead_0000usize;
    thread
        .install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
            handler,
            0,
            RISCV64_USER_EXCEPTION_HANDLER_FLAG_NONE,
        )
        .expect("a load page fault is a vector this machine delivers");

    let registration = thread
        .riscv64_exception_handler_registration(RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR)
        .expect("the handler is recorded");
    assert_eq!(registration.handler, handler);
    assert_eq!(registration.stack_pointer, None);

    // Its neighbours are untouched: the table is indexed by scause code, not
    // a single slot.
    assert_eq!(
        thread.riscv64_exception_handler_registration(
            crate::abi::exception::RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR
        ),
        None
    );
}

#[test]
fn riscv64_install_refuses_a_code_it_does_not_deliver() {
    use crate::abi::exception::RISCV64_EXCEPTION_ILLEGAL_INSTRUCTION_VECTOR;

    let process = Process::new(202, "riscv64-install-refuse");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));

    assert_eq!(
        thread.install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_ILLEGAL_INSTRUCTION_VECTOR,
            0x1000,
            0,
            0,
        ),
        Err(Error::Unsupported),
        "an illegal instruction is not a fault this machine hands to a program"
    );
}

#[test]
fn riscv64_installing_zero_clears_the_slot() {
    use crate::abi::exception::RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR;

    let process = Process::new(203, "riscv64-install-clear");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));

    thread
        .install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
            0x1000,
            0,
            0,
        )
        .expect("install");
    thread
        .install_riscv64_exception_handler_with(RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR, 0, 0, 0)
        .expect("clearing an installed handler is an install of none");

    assert_eq!(
        thread.riscv64_exception_handler_registration(RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR),
        None
    );
}

/// An exception frame's registers survive a round trip through the context.
///
/// `into_user_context` is the reverse of `from_user_context`, and a mismatch
/// between them would resume a handler's return at the wrong register — the
/// class of defect a boot shows as a corrupted program rather than as an
/// error.  The frame is what the kernel hands a handler and what a handler
/// hands back, so both directions are pinned here.
#[test]
fn riscv64_exception_frame_round_trips_its_registers() {
    use crate::abi::exception::RiscV64UserExceptionFrame;
    use crate::arch::thread::RiscV64UserThreadContext;

    let mut context =
        RiscV64UserThreadContext::from_start(UserThreadStart::new(0x1000_0000, 0x2000_0000, None));
    // Distinct values per register, so a swap is visible rather than masked by
    // two registers that happened to hold the same number.
    for (index, value) in context.regs().iter().enumerate() {
        let _ = (index, value);
    }
    context.set_regs(core::array::from_fn(|index| 0x1000 + index as u64));

    let frame = RiscV64UserExceptionFrame::from_user_context(context, 15, 0xdead, 0xbeef);
    assert_eq!(frame.vector, 15);
    assert_eq!(frame.error_code, 0xdead);
    assert_eq!(frame.fault_address, 0xbeef);
    assert_eq!(frame.instruction_pointer, context.instruction_pointer);
    assert_eq!(frame.saved_program_status, context.saved_program_status);

    let restored = frame.into_user_context();
    assert_eq!(restored.regs(), context.regs(), "every register came back");
    assert_eq!(restored.instruction_pointer, context.instruction_pointer);
    assert_eq!(restored.saved_program_status, context.saved_program_status);
}

/// Delivery reserves a frame on the stack and records it, on any host.
///
/// The trap half of delivery runs only on the machine, and the boot is its
/// evidence.  This is the half a host can hold still: the handler is looked
/// up, the delivery arithmetic places a frame below the interrupted stack
/// pointer, and the pending stack gains one entry — the bookkeeping that a
/// handler's later `return_from_exception` finds.  Without it, a `write` of
/// the frame would land somewhere the resume path could not match.
#[test]
fn riscv64_delivery_records_the_frame_it_placed() {
    use crate::abi::exception::RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR;
    use crate::arch::thread::RiscV64UserThreadContext;

    let process = Process::new(204, "riscv64-deliver");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
    let handler = 0x5000_0000usize;
    thread
        .install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
            handler,
            0,
            0,
        )
        .expect("install");

    let resume =
        RiscV64UserThreadContext::from_start(UserThreadStart::new(0x1000_0000, 0x2000_0000, None));
    let delivered = thread
        .deliver_riscv64_user_exception_from_context(
            resume,
            RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
            0xdead_0000,
            Some(0xdead_0000),
        )
        .expect("delivery");
    let handler_context = delivered.expect("a registered handler takes the fault");

    // The handler runs at the address it registered, with the frame as its
    // first argument and its stack top.
    assert_eq!(handler_context.instruction_pointer, handler as u64);
    assert_eq!(handler_context.x10, handler_context.x2);
    assert!(
        handler_context.x2 < resume.x2,
        "the frame is placed below the interrupted stack pointer"
    );
    assert_eq!(
        thread.riscv64_pending_exception_depth(),
        1,
        "the delivery is recorded so a return can find it"
    );

    // And the return is refused for a pointer that is not the one delivered.
    assert_eq!(
        thread.pop_riscv64_user_exception_frame(handler_context.x2 as usize + 8),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        thread.pop_riscv64_user_exception_frame(handler_context.x2 as usize),
        Ok(true)
    );
    assert_eq!(thread.riscv64_pending_exception_depth(), 0);
}

/// A fault with no registered handler is not delivered, and says so.
#[test]
fn riscv64_delivery_declines_a_fault_nobody_registered_for() {
    use crate::abi::exception::RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR;
    use crate::arch::thread::RiscV64UserThreadContext;

    let process = Process::new(205, "riscv64-deliver-none");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));

    let resume =
        RiscV64UserThreadContext::from_start(UserThreadStart::new(0x1000_0000, 0x2000_0000, None));
    assert_eq!(
        thread
            .deliver_riscv64_user_exception_from_context(
                resume,
                RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
                0,
                None,
            )
            .expect("delivery answers rather than failing"),
        None,
        "no handler is the caller's signal to terminate, not an error"
    );
    assert_eq!(thread.riscv64_pending_exception_depth(), 0);
}

/// A handler that faults inside itself is nested, or declined, by its flags.
///
/// This is the path RFC 0034 records as implemented but unexercised: the
/// pending stack, the `ALLOW_NESTED` bit and the `Blocked` answer.  A boot
/// would be better evidence and there is not one yet, so what is pinned here
/// is the part a host can hold still — that the three flag combinations give
/// the three different answers, and that the nested frame is placed above the
/// outer one so returns unwind in LIFO order.
#[test]
fn riscv64_nested_delivery_follows_the_two_flags() {
    use crate::abi::exception::RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR;
    use crate::abi::exception::RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR;
    use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED;
    use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_NONE;
    use crate::abi::exception::RISCV64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
    use crate::arch::thread::RiscV64UserThreadContext;

    fn user_context() -> RiscV64UserThreadContext {
        RiscV64UserThreadContext::from_start(UserThreadStart::new(0x1000_0000, 0x2000_0000, None))
    }

    /// Every registration below carries a dedicated exception stack, because
    /// the install refuses `ALLOW_NESTED` without one: nested delivery on the
    /// interrupted program's own stack would let the inner handler trample it.
    const NESTED_FLAGS: usize = RISCV64_USER_EXCEPTION_HANDLER_FLAG_ALLOW_NESTED
        | RISCV64_USER_EXCEPTION_HANDLER_FLAG_REQUIRE_EXCEPTION_STACK;
    const EXCEPTION_STACK: usize = 0x3000_0000;

    // Both the outer handler and the inner one allow nesting: the inner fault
    // is delivered, and its frame sits below the outer handler's stack, which
    // is what makes the two returns unwind in order.
    let process = Process::new(206, "riscv64-nested-allowed");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
    for vector in [
        RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
        RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
    ] {
        thread
            .install_riscv64_exception_handler_with(
                vector,
                0x5000_0000usize,
                EXCEPTION_STACK,
                NESTED_FLAGS,
            )
            .expect("install allowing nested delivery");
    }

    let outer = thread
        .deliver_riscv64_user_exception_from_context(
            user_context(),
            RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
            0,
            None,
        )
        .expect("outer delivery")
        .expect("the outer handler takes it");

    let inner = thread
        .deliver_riscv64_user_exception_from_context(
            outer,
            RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
            0,
            None,
        )
        .expect("inner delivery")
        .expect("a handler that allows nesting takes a fault inside itself");

    assert_eq!(thread.riscv64_pending_exception_depth(), 2);
    assert!(
        inner.x2 < outer.x2,
        "the nested frame is placed below the handler it interrupted"
    );

    // Returns unwind in LIFO order: the inner frame is the top, so the outer
    // one is refused until the inner has been popped.
    assert_eq!(
        thread.pop_riscv64_user_exception_frame(outer.x2 as usize),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        thread.pop_riscv64_user_exception_frame(inner.x2 as usize),
        Ok(true)
    );
    assert_eq!(
        thread.pop_riscv64_user_exception_frame(outer.x2 as usize),
        Ok(true)
    );
    assert_eq!(thread.riscv64_pending_exception_depth(), 0);

    // The outer handler not allowing nesting is the `Blocked` answer: the
    // delivery declines rather than stacking a second frame.
    let process = Process::new(207, "riscv64-nested-blocked");
    let thread = Thread::new_user(process.clone(), UserThreadStart::new(0x1000, 0x2000, None));
    thread
        .install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
            0x5000_0000usize,
            EXCEPTION_STACK,
            RISCV64_USER_EXCEPTION_HANDLER_FLAG_NONE,
        )
        .expect("install without nesting");
    thread
        .install_riscv64_exception_handler_with(
            RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
            0x5000_0000usize,
            EXCEPTION_STACK,
            NESTED_FLAGS,
        )
        .expect("install allowing nesting");

    let outer = thread
        .deliver_riscv64_user_exception_from_context(
            user_context(),
            RISCV64_EXCEPTION_LOAD_PAGE_FAULT_VECTOR,
            0,
            None,
        )
        .expect("outer delivery")
        .expect("the outer handler takes it");

    assert_eq!(
        thread
            .deliver_riscv64_user_exception_from_context(
                outer,
                RISCV64_EXCEPTION_STORE_PAGE_FAULT_VECTOR,
                0,
                None,
            )
            .expect("a blocked delivery is an answer, not an error"),
        None,
        "the outer handler did not allow nesting, so the inner fault is refused"
    );
    assert_eq!(
        thread.riscv64_pending_exception_depth(),
        1,
        "a blocked delivery leaves the outer frame where it was"
    );
}
