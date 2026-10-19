//! tests/net/udp_wait.rs
//!
//! Host-side integration tests for waiting on a UDP socket's receive queue:
//! a delivery wakes a parked waiter, a deadline ends the wait, a delivery that
//! arrives before the wait is not lost, and unbinding wakes the waiter.

use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;

use protofire::kernel::process::Scheduler;
use protofire::kernel::process::ThreadWaitOutcome;
use protofire::network::internet::ip::IpAddress;
use protofire::network::udp::UdpSocketTable;

/// Serialise the tests in this file.
///
/// `Scheduler::global()` reads the per-CPU slot, and on the host that slot is
/// the single early-boot fallback block rather than a real per-thread one — so
/// two tests running in parallel would both install into it and each would
/// schedule the other's threads.  Every test holds this for its duration; the
/// same lock, for the same reason, is in `tests/process/condvar.rs`.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Install a scheduler this test owns.
///
/// One per test rather than one per process: a scheduler's queues are not
/// per-thread, so tests sharing one would schedule each other's threads even
/// when serialised.  It is leaked because the slot points at it and the next
/// test's install replaces the pointer without dropping it — the same
/// reasoning the scheduler's own host tests rely on.
fn install_scheduler() -> &'static Scheduler {
    let scheduler: &'static Scheduler = Box::leak(Box::new(Scheduler::new()));
    // SAFETY: the scheduler is leaked, so it outlives every global lookup in
    // this thread, and the slot only visible to this thread points at it.
    unsafe {
        scheduler.install_global_unchecked();
    }
    scheduler
}

#[test]
fn deliver_wakes_a_waiter() {
    let _guard = test_lock();
    let scheduler = install_scheduler();
    let waiter = scheduler.spawn_named("udp-waiter", 0x1000);
    let sender = scheduler.spawn_named("udp-sender", 0x2000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));

    let mut table = UdpSocketTable::new();
    table.bind(9000).expect("bind");
    let wait = table.readiness(9000).expect("readiness handle");
    let mut buffer = [0u8; 64];
    assert_eq!(
        table.recv_from(9000, &mut buffer),
        Err(protofire::Error::TimedOut)
    );

    // Parks the waiter; the sender becomes the next thread to run.
    wait.wait(u64::MAX);
    assert_eq!(scheduler.current_thread_id(), Some(sender.tid()));
    assert_eq!(scheduler.waiting_count(), 1);

    assert!(table.deliver([10, 0, 2, 100], 53, 9000, b"answer".to_vec()));
    assert_eq!(wait.queued(), 1);
    assert_eq!(scheduler.waiting_count(), 0);

    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));
    assert_eq!(waiter.wait_outcome(), ThreadWaitOutcome::Completed);

    let (n, source, source_port) = table.recv_from(9000, &mut buffer).expect("datagram");
    assert_eq!(&buffer[..n], b"answer");
    assert_eq!(source, IpAddress::V4([10, 0, 2, 100]));
    assert_eq!(source_port, 53);
    assert_eq!(wait.queued(), 0);
}

#[test]
fn wait_times_out_when_nothing_is_delivered() {
    let _guard = test_lock();
    let scheduler = install_scheduler();
    let waiter = scheduler.spawn_named("udp-timeout-waiter", 0x3000);
    let other = scheduler.spawn_named("udp-timeout-other", 0x4000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));

    let mut table = UdpSocketTable::new();
    table.bind(9001).expect("bind");
    let wait = table.readiness(9001).expect("readiness handle");

    // The host scheduler reads its simulated clock, which starts at zero and
    // is advanced by the tick below.
    const DEADLINE: u64 = 3;
    wait.wait(DEADLINE);
    // The waiter is parked; the host's simulated scheduler has put the other
    // thread in the current slot, which is what this test now runs as.
    assert_eq!(scheduler.current_thread_id(), Some(other.tid()));
    assert_eq!(wait.queued(), 0);
    assert_eq!(scheduler.waiting_count(), 1);

    scheduler.handle_timer_tick(DEADLINE);
    assert_eq!(scheduler.waiting_count(), 0);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));
    assert_eq!(waiter.wait_outcome(), ThreadWaitOutcome::TimedOut);

    // The timeout handed ownership back with an empty queue, which is what
    // the caller's recheck has to see.
    let mut buffer = [0u8; 8];
    assert_eq!(
        table.recv_from(9001, &mut buffer),
        Err(protofire::Error::TimedOut)
    );
}

#[test]
fn delivery_before_waiting_is_not_lost() {
    let _guard = test_lock();
    let scheduler = install_scheduler();
    let thread = scheduler.spawn_named("udp-already-ready", 0x5000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));

    let mut table = UdpSocketTable::new();
    table.bind(9002).expect("bind");
    let wait = table.readiness(9002).expect("readiness handle");
    assert!(table.deliver([10, 0, 2, 7], 53, 9002, b"early".to_vec()));
    assert_eq!(wait.queued(), 1);

    // The count is checked under the wait queue's own lock before the thread
    // is added to it, so a datagram already queued makes this a probe: the
    // same thread is still current afterwards, and it did not park.
    wait.wait(u64::MAX);
    assert_eq!(scheduler.current_thread_id(), Some(thread.tid()));
    assert_eq!(scheduler.waiting_count(), 0);
}

#[test]
fn unbinding_wakes_a_parked_waiter() {
    let _guard = test_lock();
    let scheduler = install_scheduler();
    let waiter = scheduler.spawn_named("udp-unbind-waiter", 0x6000);
    let unbinder = scheduler.spawn_named("udp-unbinder", 0x7000);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));

    let mut table = UdpSocketTable::new();
    table.bind(9003).expect("bind");
    let wait = table.readiness(9003).expect("readiness handle");

    wait.wait(u64::MAX);
    assert_eq!(scheduler.current_thread_id(), Some(unbinder.tid()));
    assert_eq!(scheduler.waiting_count(), 1);

    table.unbind(9003);
    assert_eq!(scheduler.waiting_count(), 0);
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(waiter.tid()));
    assert_eq!(
        waiter.wait_outcome(),
        ThreadWaitOutcome::Completed,
        "unbinding wakes the waiter rather than leaving it to its deadline"
    );

    // Woken without a datagram: the caller observes the socket is gone, and
    // the handle's count does not say there is anything to read.
    assert_eq!(wait.queued(), 0);
    let mut buffer = [0u8; 8];
    assert_eq!(
        table.recv_from(9003, &mut buffer),
        Err(protofire::Error::NotFound)
    );
}
