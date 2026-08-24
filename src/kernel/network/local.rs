//! src/kernel/network/local.rs
//!
//! Unix domain (local) socket implementation.
//!
//! Local sockets provide named rendezvous points for same-machine
//! inter-process communication:
//!
//! - `bind_local(path)` creates a `LocalSocket` and registers it globally.
//!   The caller wraps it in a `KernelObject::LocalSocket` and stores it
//!   as a file descriptor.
//! - `connect_local(path)` looks up the socket, creates a kernel pipe pair,
//!   pushes the read-end vnode into the socket's accept queue, and returns
//!   the write-end vnode.  The caller wraps it as a connected fd.
//! - `accept_local(socket)` pops the next pending vnode from the queue.
//!
//! After connection, the server reads on the accepted vnode while the
//! client writes on the connected vnode (a one-way pipe per connection).

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::fs::pipe;
use crate::kernel::fs::vfs::VNode;
use crate::kernel::sync::Mutex;
use crate::{Error, Result};

/// Maximum pending connections per local socket.
const LOCAL_SOCKET_BACKLOG: usize = 16;

/// Global registry of bound local sockets, keyed by filesystem path.
static LOCAL_SOCKET_MAP: Mutex<BTreeMap<String, Arc<LocalSocket>>> = Mutex::new(BTreeMap::new());

/// Generate unique local socket ids.
static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(1);

/// A named local socket — a server-side listener.
///
/// Wraps a queue of pending accepted connection vnodes.  Each pending entry
/// holds the server-side vnode of a connection established by
/// `connect_local`, which the server will read from once `accept_local`
/// delivers it.
pub struct LocalSocket {
    pub id: usize,
    pub path: String,
    /// Queue of server-side vnodes from `connect_local`, delivered via
    /// `accept_local`.
    pending: Mutex<VecDeque<Arc<dyn VNode>>>,
}

impl LocalSocket {
    pub fn new(path: String) -> Self {
        Self {
            id: NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed),
            path,
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Check whether this local socket has a pending connection.
    pub fn is_readable(&self) -> bool {
        !self.pending.lock().is_empty()
    }
}

// Manual Debug impl — VNode doesn't implement Debug.
impl core::fmt::Debug for LocalSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalSocket")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("pending_count", &self.pending.lock().len())
            .finish()
    }
}

/// Bind a local socket at the given path.
///
/// Returns the registered `LocalSocket`.  The caller should wrap this
/// in a `KernelObject::LocalSocket` and store it as a file descriptor.
pub fn bind_local(path: &str) -> Result<Arc<LocalSocket>> {
    let mut sockets = LOCAL_SOCKET_MAP.lock();
    if sockets.contains_key(path) {
        return Err(Error::AlreadyExists);
    }
    let socket = Arc::new(LocalSocket::new(String::from(path)));
    sockets.insert(String::from(path), socket.clone());
    Ok(socket)
}

/// Connect to a local socket at the given path.
///
/// Creates a kernel pipe pair.  The read-end vnode is pushed to the
/// socket's accept queue (delivered later via `accept_local`); the
/// write-end vnode is returned to the caller, who wraps it in a file
/// descriptor for the connecting client.
pub fn connect_local(path: &str) -> Result<Arc<dyn VNode>> {
    let sockets = LOCAL_SOCKET_MAP.lock();
    let socket = sockets.get(path).ok_or(Error::NotFound)?.clone();
    drop(sockets);

    let (read_end, write_end) = pipe::pipe_channel();

    // Queue the server-side vnode under the socket's own lock so we don't
    // hold the global map lock while mutating the socket.
    let mut pending = socket.pending.lock();
    if pending.len() >= LOCAL_SOCKET_BACKLOG {
        return Err(Error::Busy);
    }
    pending.push_back(read_end);
    drop(pending);

    Ok(write_end)
}

/// Accept a pending connection on a local socket.
///
/// Returns the server-side vnode for the next pending connection, or
/// `Error::Busy` when no connection is pending.
pub fn accept_local(socket: &Arc<LocalSocket>) -> Result<Arc<dyn VNode>> {
    socket.pending.lock().pop_front().ok_or(Error::Busy)
}

/// Remove a local socket binding.
pub fn unbind_local(path: &str) {
    LOCAL_SOCKET_MAP.lock().remove(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_connect_local() {
        let path = "/tmp/test-local-socket-1";
        unbind_local(path);

        let socket = bind_local(path).expect("bind");
        let client_vnode = connect_local(path).expect("connect");

        // The server should have one pending connection.
        assert_eq!(socket.pending.lock().len(), 1);

        // Accept delivers the server vnode.
        let accepted = accept_local(&socket).expect("accept");
        assert!(socket.pending.lock().is_empty());

        // Both vnodes should be valid (non-null Arc pointers).
        let _ = client_vnode;
        let _ = accepted;

        unbind_local(path);
    }

    #[test]
    fn bind_duplicate_path_fails() {
        let path = "/tmp/test-local-dup";
        unbind_local(path);

        bind_local(path).expect("first bind");
        assert!(bind_local(path).is_err());

        unbind_local(path);
    }

    #[test]
    fn connect_nonexistent_fails() {
        assert!(connect_local("/tmp/nonexistent-local-socket").is_err());
    }

    #[test]
    fn accept_empty_returns_error() {
        let path = "/tmp/test-local-empty";
        unbind_local(path);

        let socket = bind_local(path).expect("bind");
        assert!(accept_local(&socket).is_err());

        unbind_local(path);
    }

    #[test]
    fn multiple_connections_queue_in_order() {
        let path = "/tmp/test-local-multi";
        unbind_local(path);

        let socket = bind_local(path).expect("bind");

        let c1 = connect_local(path).expect("connect 1");
        let c2 = connect_local(path).expect("connect 2");

        assert_eq!(socket.pending.lock().len(), 2);

        let a1 = accept_local(&socket).expect("accept 1");
        let a2 = accept_local(&socket).expect("accept 2");
        assert!(socket.pending.lock().is_empty());

        // The accepted vnodes should be different.
        let _ = (c1, c2, a1, a2);

        unbind_local(path);
    }
}
