//! tests/net/fuzz.rs
//! Network fuzzing — exercises the local socket infrastructure
//! with edge-case inputs to verify graceful error handling.

use protofire::kernel::network::local;

#[test]
fn local_socket_bind_twice_fails() {
    let path = "/tmp/fuzz-bind-twice";
    local::unbind_local(path);

    let s1 = local::bind_local(path).expect("first bind");
    assert!(local::bind_local(path).is_err(), "second bind should fail");

    drop(s1);
    local::unbind_local(path);
}

#[test]
fn local_socket_connect_without_bind_fails() {
    let path = "/tmp/fuzz-connect-no-bind";
    local::unbind_local(path);

    assert!(local::connect_local(path).is_err());
}

#[test]
fn local_socket_accept_empty_fails() {
    let path = "/tmp/fuzz-accept-empty";
    local::unbind_local(path);

    let socket = local::bind_local(path).expect("bind");
    assert!(local::accept_local(&socket).is_err());

    local::unbind_local(path);
}

#[test]
fn local_socket_unbind_then_rebind() {
    let path = "/tmp/fuzz-rebind";
    local::unbind_local(path);

    let s1 = local::bind_local(path).expect("bind 1");
    drop(s1);
    local::unbind_local(path);

    let s2 = local::bind_local(path).expect("bind 2");
    drop(s2);
    local::unbind_local(path);
}

#[test]
fn local_socket_rapid_bind_unbind_cycle() {
    let path = "/tmp/fuzz-rapid-cycle";
    local::unbind_local(path);

    for _ in 0..50 {
        let s = local::bind_local(path).expect("bind");
        drop(s);
        local::unbind_local(path);
    }
}

#[test]
fn local_socket_multiple_connect_accept() {
    let path = "/tmp/fuzz-multi-connect";
    local::unbind_local(path);

    let socket = local::bind_local(path).expect("bind");

    let mut clients = Vec::new();
    for _ in 0..5 {
        let client = local::connect_local(path).expect("connect");
        clients.push(client);
    }

    let mut servers = Vec::new();
    for _ in 0..5 {
        let server = local::accept_local(&socket).expect("accept");
        servers.push(server);
    }

    assert!(local::accept_local(&socket).is_err());

    drop(clients);
    drop(servers);
    local::unbind_local(path);
}

#[test]
fn local_socket_unique_ids() {
    let path1 = "/tmp/fuzz-id-1";
    let path2 = "/tmp/fuzz-id-2";
    local::unbind_local(path1);
    local::unbind_local(path2);

    let s1 = local::bind_local(path1).expect("bind 1");
    let s2 = local::bind_local(path2).expect("bind 2");

    assert_ne!(s1.id, s2.id, "different sockets should get different ids");

    drop(s1);
    drop(s2);
    local::unbind_local(path1);
    local::unbind_local(path2);
}
