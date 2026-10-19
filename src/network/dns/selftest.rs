//! src/network/dns/selftest.rs
//!
//! A boot walks the resolver's wait path once, because no machine a gate boots
//! sends a DNS answer.
//!
//! Two threads: one binds a port and parks in the resolver's real wait loop;
//! the other waits a few ticks and then delivers a synthetic A record to that
//! port, which is what the demux would have done with a frame from a
//! nameserver.  The waiter then has to parse the record, cache it, and report
//! the address — and the park counter is what distinguishes that from a loop
//! that merely returned the right answer after spinning.
//!
//! This is the same reasoning RFC 0023's IMSIC self-test follows: a delivery
//! path no gate can reach from outside is walked from inside once, and the
//! boot prints the line the gate asserts.

use alloc::vec::Vec;

use crate::kernel::process::Scheduler;

use super::resolve::DNS_PARK_COUNT;

/// Port the self-test owns.
///
/// Not one the resolver would pick: a lookup allocates from the dynamic range
/// (`UDP_EPHEMERAL_PORT_START..=UDP_EPHEMERAL_PORT_END`) now, and this sits
/// below it, so the test can name a port before the allocator is asked for
/// anything and can never take one a real lookup was given.
const SELFTEST_PORT: u16 = 53001;

/// The name the synthetic answer is for, and the address it carries.
const SELFTEST_HOST: &str = "selftest.protofire";
const SELFTEST_ADDR: [u8; 4] = [192, 0, 2, 7];

/// Transaction id the synthetic answer echoes.
const SELFTEST_TXID: [u8; 2] = [0x53, 0x46];

/// Ticks the injector waits before delivering.
///
/// Long enough that the waiter has bound the port and parked, so the delivery
/// exercises the wake rather than the "data was already queued" probe.  Five
/// ticks is 50 ms at 100 Hz, and the waiter's own budget is far longer.
const INJECT_DELAY_TICKS: u64 = 5;

/// Start both halves of the self-test.
pub(crate) fn start() {
    let Some(scheduler) = Scheduler::global() else {
        return;
    };
    scheduler.spawn_kernel_named("dns-selftest-wait", wait_for_answer);
    scheduler.spawn_kernel_named("dns-selftest-inject", deliver_answer);
}

/// The waiter: bind the test port and run the resolver's own wait loop.
fn wait_for_answer() {
    let Some(stack) = crate::network::stack::NetworkStack::global() else {
        crate::println!("[net   ] DNS self-test FAILED: no network stack");
        return;
    };

    {
        let mut table = stack.udp_table().lock();
        if table.is_bound(SELFTEST_PORT) {
            // A second boot of the same kernel object cannot happen, but a
            // stale binding is not something this test can reason about.
            crate::println!(
                "[net   ] DNS self-test FAILED: port {} is already bound",
                SELFTEST_PORT
            );
            return;
        }
        if table.bind(SELFTEST_PORT).is_err() {
            crate::println!(
                "[net   ] DNS self-test FAILED: could not bind port {}",
                SELFTEST_PORT
            );
            return;
        }
    }

    let parks_before = DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let deadline = stack
        .current_tick()
        .saturating_add(super::resolve::DNS_QUERY_TIMEOUT_TICKS);
    let result = super::resolve::await_a_record(
        stack,
        SELFTEST_PORT,
        stack.dns_server(),
        &SELFTEST_TXID,
        SELFTEST_HOST,
        deadline,
    );
    let parked = DNS_PARK_COUNT.load(core::sync::atomic::Ordering::Relaxed) - parks_before;

    stack.udp_table().lock().unbind(SELFTEST_PORT);

    match result {
        Ok(addr) if addr == SELFTEST_ADDR => {
            // The cache is the half of the claim that is not "the wait
            // returned": a resolution that skipped caching would still parse
            // and return the right address.
            let cached = super::cache::cache_lookup(SELFTEST_HOST, stack.current_tick());
            crate::println!(
                "[net   ] DNS self-test: parked {} time(s), resolved {} to {}.{}.{}.{}, cache {}",
                parked,
                SELFTEST_HOST,
                addr[0],
                addr[1],
                addr[2],
                addr[3],
                if cached == Some(addr) {
                    "holds it"
                } else {
                    "MISSED IT"
                }
            );
        }
        Ok(addr) => {
            crate::println!(
                "[net   ] DNS self-test FAILED: resolved {} to {}.{}.{}.{}, expected {}.{}.{}.{}",
                SELFTEST_HOST,
                addr[0],
                addr[1],
                addr[2],
                addr[3],
                SELFTEST_ADDR[0],
                SELFTEST_ADDR[1],
                SELFTEST_ADDR[2],
                SELFTEST_ADDR[3]
            );
        }
        Err(error) => {
            crate::println!(
                "[net   ] DNS self-test FAILED: {} after parking {} time(s): {:?}",
                SELFTEST_HOST,
                parked,
                error
            );
        }
    }
}

/// The injector: wait for the waiter to park, then deliver a synthetic answer.
fn deliver_answer() {
    crate::kernel::process::sleep_current(INJECT_DELAY_TICKS);

    let Some(stack) = crate::network::stack::NetworkStack::global() else {
        crate::println!("[net   ] DNS self-test FAILED: injector found no stack");
        return;
    };
    let response = build_a_response(SELFTEST_TXID, SELFTEST_HOST, SELFTEST_ADDR);
    // The source the resolver filters on: the configured nameserver, port 53.
    stack.udp_table().lock().deliver(
        stack.dns_server(),
        super::resolve::DNS_PORT,
        SELFTEST_PORT,
        response,
    );
}

/// Build a minimal one-question, one-answer A record response.
fn build_a_response(txid: [u8; 2], host: &str, addr: [u8; 4]) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&txid);
    // Response + recursion desired, no error.
    message.extend_from_slice(&(super::DNS_FLAGS_QR_RESPONSE | super::DNS_FLAGS_RD).to_be_bytes());
    // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = ARCOUNT = 0.
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0u8; 4]);

    let name = super::query::encode_dns_name(host);
    message.extend_from_slice(&name);
    message.extend_from_slice(&super::DNS_TYPE_A.to_be_bytes());
    message.extend_from_slice(&super::DNS_CLASS_IN.to_be_bytes());

    message.extend_from_slice(&name);
    message.extend_from_slice(&super::DNS_TYPE_A.to_be_bytes());
    message.extend_from_slice(&super::DNS_CLASS_IN.to_be_bytes());
    // TTL 60 s, which the cache clamps up to its minimum.
    message.extend_from_slice(&60u32.to_be_bytes());
    message.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    message.extend_from_slice(&addr);
    message
}
