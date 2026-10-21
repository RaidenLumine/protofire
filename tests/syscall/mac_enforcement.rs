//! tests/syscall/mac_enforcement.rs
//!
//! The MAC engine's process and network checks are reached from the syscall
//! boundary, so a policy that denies them has an effect rather than a document.
//!
//! Each case is run three ways against the same handler: denied (the effect
//! must not happen), allowed by a rule (it must), and with enforcement off (it
//! must, because a boot with no policy is the default).  The middle and last
//! runs are what keep a test from passing merely because a handler refuses
//! everything.
//!
//! This drives the real syscall table through `Table::dispatch`, not the
//! handlers' internals, because the question is whether the check is *on the
//! path* — a unit test of `check_process` would pass with no call site at all,
//! which is exactly the state RFC 0033 removed.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use protofire::kernel::process::mac;
use protofire::kernel::process::mac::MacRule;
use protofire::kernel::process::Process;
use protofire::kernel::process::Scheduler;
use protofire::kernel::process::SecurityToken;
use protofire::syscall::SyscallContext;
use protofire::syscall::SyscallNumber;
use protofire::syscall::Table;
use protofire::Error;

/// These tests share the scheduler global, the syscall table and the MAC
/// policy, so they run one at a time.
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reset the global policy to the permissive default, which is what a boot
/// has.
fn reset_policy() {
    let mut state = mac::policy_state().lock();
    state.policy.enabled = false;
    state.policy.default_deny = true;
    state.policy.rules.clear();
    state.path_types.clear();
}

/// Turn enforcement on with deny-by-default and no rules.
fn enforce() {
    let mut state = mac::policy_state().lock();
    state.policy.enabled = true;
    state.policy.default_deny = true;
    state.policy.rules.clear();
}

/// Add one allow rule.
fn allow(subject: u32, object: u32, class: u32, perms: u32) {
    mac::policy_state().lock().policy.add_rule(
        MacRule {
            subject,
            object,
            class,
            perms,
        },
        false,
    );
}

/// Install a scheduler whose current process carries `token`, and hand back
/// the scheduler and a target process the caller does not own.
fn fixture(name: &str, token: SecurityToken) -> (&'static Scheduler, Arc<Process>, Arc<Process>) {
    // Leaked deliberately: the global slot points at the scheduler for the life
    // of the test binary, so freeing either would leave it advertising storage
    // that no longer exists.
    let scheduler: &'static Scheduler = Box::leak(Box::new(Scheduler::new()));
    let caller = scheduler.spawn_named_with_security_token(name, token, 0x1000);
    let target = scheduler.spawn_kernel_named_with_security_token(
        "mac-target",
        SecurityToken::guest(),
        || {},
    );
    // SAFETY: the scheduler is leaked, so it outlives every global lookup in
    // this test, and the test lock keeps a second test from installing its own
    // over this one.
    unsafe { scheduler.install_global_unchecked() };
    scheduler.schedule();
    assert_eq!(scheduler.current_thread_id(), Some(caller.tid()));

    (
        scheduler,
        caller.process().clone(),
        target.process().clone(),
    )
}

fn dispatch(table: &Table, number: SyscallNumber, args: [usize; 6]) -> Result<usize, Error> {
    let mut context = SyscallContext::new(number as usize, args);
    table.dispatch(&mut context)
}

fn table() -> Table {
    let mut table = Table::new();
    table.init();
    table
}

// ── signals ─────────────────────────────────────────────────────────────

#[test]
fn a_denied_signal_is_not_delivered() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, target) = fixture("mac-signal-sender", SecurityToken::guest());
    let table = table();

    // An untrusted subject signalling a process whose label nothing allows is
    // denied by deny-by-default.
    enforce();
    let pid = target.pid() as usize;
    assert_eq!(
        dispatch(&table, SyscallNumber::SendSignal, [pid, 10, 0, 0, 0, 0]),
        Err(Error::PermissionDenied)
    );
    // The denial has to mean the signal did not arrive: a handler that checked
    // and then delivered anyway would pass the assertion above.
    assert_eq!(target.pending_signal_count(), 0);

    // Allowed by a rule, the same call reaches the target.
    allow(
        mac::MAC_TYPE_UNTRUSTED,
        mac::MAC_TYPE_UNTRUSTED,
        mac::MAC_CLASS_PROCESS,
        mac::MAC_PERM_SIGNAL,
    );
    assert_eq!(
        dispatch(&table, SyscallNumber::SendSignal, [pid, 10, 0, 0, 0, 0]),
        Ok(0)
    );
    assert_eq!(target.pending_signal_count(), 1);
}

#[test]
fn a_signal_with_enforcement_off_is_delivered() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, target) = fixture("mac-signal-off", SecurityToken::guest());
    let table = table();

    assert_eq!(
        dispatch(
            &table,
            SyscallNumber::SendSignal,
            [target.pid() as usize, 10, 0, 0, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(target.pending_signal_count(), 1);
}

#[test]
fn a_process_may_signal_itself_under_a_denying_policy() {
    let _guard = test_lock();
    reset_policy();
    // The shell's `sigasync` builtin signals itself; a policy written for
    // process boundaries must not refuse that.
    let (_scheduler, caller, _target) = fixture("mac-signal-self", SecurityToken::guest());
    let table = table();
    enforce();

    assert_eq!(
        dispatch(
            &table,
            SyscallNumber::SendSignal,
            [caller.pid() as usize, 10, 0, 0, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(caller.pending_signal_count(), 1);
}

#[test]
fn a_signal_to_an_unknown_pid_stays_not_found_under_a_denying_policy() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, _target) = fixture("mac-signal-unknown", SecurityToken::guest());
    let table = table();
    enforce();

    // The policy must not turn a missing target into a denial: a denial for
    // pids that do not exist would make the returned error a way to ask
    // whether one does.
    assert_eq!(
        dispatch(&table, SyscallNumber::SendSignal, [999, 10, 0, 0, 0, 0]),
        Err(Error::NotFound)
    );
}

// ── network ─────────────────────────────────────────────────────────────

#[test]
fn a_denied_connect_does_not_reach_a_listener() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, _target) = fixture("mac-connect", SecurityToken::guest());
    let table = table();

    // A listener the test owns, so "the connection was refused" cannot be
    // confused with "nothing was listening".
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let port = listener.local_addr().expect("listener addr").port();
    let host = b"127.0.0.1";
    let args = [host.as_ptr() as usize, host.len(), port as usize, 0, 0, 0];

    enforce();
    assert_eq!(
        dispatch(&table, SyscallNumber::ConnectTcp, args),
        Err(Error::PermissionDenied)
    );
    // The refusal is the policy's, not the machine's: with no policy loaded the
    // same call gets as far as the loopback listener.
    reset_policy();
    let fd = dispatch(&table, SyscallNumber::ConnectTcp, args).expect("connect with no policy");
    assert!(fd > 0);
    assert!(
        listener.accept().is_ok(),
        "the allowed connection must reach the listener"
    );
}

#[test]
fn the_network_object_is_the_network_and_not_the_subject() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, _target) = fixture("mac-network-object", SecurityToken::guest());
    let table = table();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let port = listener.local_addr().expect("listener addr").port();
    let host = b"127.0.0.1";
    let args = [host.as_ptr() as usize, host.len(), port as usize, 0, 0, 0];

    // A rule naming the network as the object is what an administrator would
    // write.  If `check_network` still passed the subject as its own object,
    // this rule would not match and the call would be denied.
    enforce();
    allow(
        mac::MAC_TYPE_UNTRUSTED,
        mac::MAC_TYPE_NETWORK,
        mac::MAC_CLASS_NETWORK,
        mac::MAC_PERM_CONNECT,
    );
    let fd = dispatch(&table, SyscallNumber::ConnectTcp, args)
        .expect("a rule over the network admits the connection");
    assert!(fd > 0);
}

#[test]
fn a_denied_bind_is_refused_before_the_stack_is_asked() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, _caller, _target) = fixture("mac-bind", SecurityToken::guest());
    let table = table();

    enforce();
    assert_eq!(
        dispatch(&table, SyscallNumber::BindUdp, [47000, 0, 0, 0, 0, 0]),
        Err(Error::PermissionDenied)
    );

    // With a rule, the request reaches the stack — which on a host build with
    // no stack answers `Unsupported`.  The point is that the answer is no
    // longer the policy's.
    allow(
        mac::MAC_TYPE_UNTRUSTED,
        mac::MAC_TYPE_NETWORK,
        mac::MAC_CLASS_NETWORK,
        mac::MAC_PERM_BIND,
    );
    assert_ne!(
        dispatch(&table, SyscallNumber::BindUdp, [47000, 0, 0, 0, 0, 0]),
        Err(Error::PermissionDenied)
    );
}

// ── ptrace ──────────────────────────────────────────────────────────────

#[test]
fn a_denied_attach_leaves_the_tracer_link_unset() {
    let _guard = test_lock();
    reset_policy();
    let (_scheduler, caller, target) = fixture("mac-ptrace", SecurityToken::root());
    let table = table();

    // The caller is root, so the integrity check `ptrace_attach` already did
    // would pass; only the policy stands in the way.
    enforce();
    assert_eq!(
        dispatch(
            &table,
            SyscallNumber::Ptrace,
            [
                protofire::abi::ptrace::PTRACE_ATTACH as usize,
                target.pid() as usize,
                0,
                0,
                0,
                0
            ]
        ),
        Err(Error::PermissionDenied)
    );
    assert_eq!(target.pending_signal_count(), 0);
    // With enforcement off the same attach succeeds, which is what says the
    // refusal above came from the policy and not from the tracer machinery.
    reset_policy();
    assert_eq!(
        dispatch(
            &table,
            SyscallNumber::Ptrace,
            [
                protofire::abi::ptrace::PTRACE_ATTACH as usize,
                target.pid() as usize,
                0,
                0,
                0,
                0
            ]
        ),
        Ok(0)
    );
    let _ = caller;
}
