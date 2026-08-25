//! src/kernel/process/process/handle_entry.rs
//!
//! Handle entry methods: stream I/O, stat, handle/fd reopening.

use alloc::string::String;

use crate::abi::fs as fs_abi;
use crate::kernel::device;
use crate::kernel::fs::{FileMetadata, NodeKind};
use crate::{Error, Result};

use super::constants::*;
use super::types::*;
use super::Process;

pub fn home_dir_for_uid(uid: UserId) -> String {
    match uid {
        ROOT_USER_ID => String::from("/root"),
        DEFAULT_GUEST_USER_ID => String::from("/data/users/guest"),
        other => {
            // Fallback: numeric uid under /data/users.
            let mut path = String::with_capacity(24);
            use ::core::fmt::Write;
            write!(path, "/data/users/uid-{other}").ok();
            path
        }
    }
}

impl HandleEntry {
    pub(crate) fn is_directory_like(&self) -> bool {
        match &self.object {
            KernelObject::Directory(_) => true,
            KernelObject::File(file) => file.kind() == crate::kernel::fs::NodeKind::Directory,
            KernelObject::Device(_)
            | KernelObject::Network(_)
            | KernelObject::TlsConnection(_)
            | KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_)
            | KernelObject::Process(_)
            | KernelObject::Thread(_)
            | KernelObject::EventFd(_)
            | KernelObject::SignalFd(_)
            | KernelObject::TimerFd(_)
            | KernelObject::Mqueue(_)
            | KernelObject::Epoll(_)
            | KernelObject::IoUring(_) => false,
        }
    }

    pub(crate) fn directory_backing_path(&self) -> Result<&str> {
        match &self.object {
            KernelObject::Directory(path) => Ok(path.as_str()),
            KernelObject::File(file) if file.kind() == crate::kernel::fs::NodeKind::Directory => {
                Ok(file.path())
            }
            KernelObject::File(_)
            | KernelObject::Device(_)
            | KernelObject::Network(_)
            | KernelObject::TlsConnection(_)
            | KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_) => Err(Error::InvalidArgument),
            KernelObject::Process(_)
            | KernelObject::Thread(_)
            | KernelObject::EventFd(_)
            | KernelObject::SignalFd(_)
            | KernelObject::TimerFd(_)
            | KernelObject::Mqueue(_)
            | KernelObject::Epoll(_)
            | KernelObject::IoUring(_) => Err(Error::Unsupported),
        }
    }

    pub(crate) fn metadata_backing_path(&self) -> Result<&str> {
        match &self.object {
            KernelObject::Directory(path) => Ok(path.as_str()),
            KernelObject::File(file) => Ok(file.path()),
            KernelObject::Device(_)
            | KernelObject::Network(_)
            | KernelObject::TlsConnection(_)
            | KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_) => Err(Error::InvalidArgument),
            KernelObject::Process(_)
            | KernelObject::Thread(_)
            | KernelObject::EventFd(_)
            | KernelObject::SignalFd(_)
            | KernelObject::TimerFd(_)
            | KernelObject::Mqueue(_)
            | KernelObject::Epoll(_)
            | KernelObject::IoUring(_) => Err(Error::Unsupported),
        }
    }

    pub(crate) fn public_file_stat_record(
        &self,
        stat_directory: impl FnOnce(&str) -> Result<fs_abi::FileStat>,
    ) -> Result<fs_abi::FileStat> {
        match &self.object {
            KernelObject::File(file) => {
                Ok(synthetic_public_file_stat_record(file.kind(), file.size()))
            }
            KernelObject::Directory(path) => stat_directory(path),
            KernelObject::Device(name) => Ok(device::device_metadata(name)
                .map(|metadata| metadata.public_stat_record())
                .unwrap_or_else(|| synthetic_public_file_stat_record(NodeKind::Device, 0))),
            KernelObject::Network(_)
            | KernelObject::TlsConnection(_)
            | KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_) => {
                Ok(synthetic_public_file_stat_record(NodeKind::Device, 0))
            }
            KernelObject::Process(_)
            | KernelObject::Thread(_)
            | KernelObject::EventFd(_)
            | KernelObject::SignalFd(_)
            | KernelObject::TimerFd(_)
            | KernelObject::Mqueue(_)
            | KernelObject::Epoll(_)
            | KernelObject::IoUring(_) => Err(Error::Unsupported),
        }
    }

    pub(crate) fn reopen_handle_in(self, process: &Process) -> Result<Handle> {
        let Self { object, rights } = self;
        process.reopen_object_handle(object, rights)
    }

    pub(crate) fn reopen_descriptor_in(self, process: &Process) -> Result<FileDescriptor> {
        let Self { object, rights } = self;
        process.reopen_object_descriptor(object, rights)
    }

    pub(crate) fn read_stream(self, buffer: &mut [u8], timeout_ticks: u64) -> Result<usize> {
        match self.object {
            KernelObject::Device(name) => {
                device::dispatch_device_read(&name, buffer, timeout_ticks)
            }
            KernelObject::Network(connection) => connection.read(buffer, timeout_ticks),
            KernelObject::TlsConnection(connection) => connection.read(buffer, timeout_ticks),
            KernelObject::EventFd(state) => eventfd_read(state, buffer, timeout_ticks),
            KernelObject::SignalFd(state) => signalfd_read(state, buffer, timeout_ticks),
            KernelObject::TimerFd(state) => timerfd_read(state, buffer, timeout_ticks),
            KernelObject::Mqueue(state) => mqueue_read(state, buffer, timeout_ticks),
            KernelObject::Epoll(_) => Err(Error::Unsupported),
            KernelObject::TcpListener(_) => Err(Error::InvalidArgument),
            KernelObject::UdpSocket(socket) => {
                let _ = timeout_ticks;
                match crate::kernel::network::recv_from_udp(&socket, buffer) {
                    Ok((n, _, _)) => Ok(n),
                    Err(Error::TimedOut) => Ok(0),
                    Err(e) => Err(e),
                }
            }
            KernelObject::DccpSocket(socket) => {
                let _ = timeout_ticks;
                match crate::kernel::network::recv_dccp(&socket, buffer) {
                    Ok((n, _, _)) => Ok(n),
                    Err(Error::TimedOut) => Ok(0),
                    Err(e) => Err(e),
                }
            }
            KernelObject::File(file) => file.read(buffer),
            KernelObject::Directory(_) => Err(Error::InvalidArgument),
            KernelObject::RawSocket(_) => Err(Error::InvalidArgument),
            KernelObject::LocalSocket(_) => Err(Error::InvalidArgument),
            KernelObject::Process(_) | KernelObject::Thread(_) => Err(Error::Unsupported),
            KernelObject::IoUring(_) => Err(Error::Unsupported),
        }
    }

    pub(crate) fn write_stream(self, buffer: &[u8]) -> Result<usize> {
        match self.object {
            KernelObject::Device(name) => device::dispatch_device_write(&name, buffer),
            KernelObject::Network(connection) => connection.write(buffer),
            KernelObject::TlsConnection(connection) => connection.write(buffer),
            KernelObject::EventFd(state) => eventfd_write(state, buffer),
            KernelObject::SignalFd(_) => Err(Error::InvalidArgument),
            KernelObject::TimerFd(_) => Err(Error::InvalidArgument),
            KernelObject::Mqueue(state) => mqueue_write(state, buffer),
            KernelObject::Epoll(_) => Err(Error::Unsupported),
            KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_) => Err(Error::InvalidArgument),
            KernelObject::File(file) => file.write(buffer),
            KernelObject::Directory(_) => Err(Error::InvalidArgument),
            KernelObject::Process(_) | KernelObject::Thread(_) => Err(Error::Unsupported),
            KernelObject::IoUring(_) => Err(Error::Unsupported),
        }
    }

    /// Check whether this handle has data available to read without blocking.
    pub(crate) fn is_readable(&self) -> Result<bool> {
        match &self.object {
            KernelObject::File(_) => Ok(true),
            KernelObject::Network(conn) => conn.is_readable(),
            KernelObject::TlsConnection(conn) => conn.is_readable(),
            KernelObject::TcpListener(listener) => listener.is_readable(),
            KernelObject::UdpSocket(socket) => socket.is_readable(),
            KernelObject::DccpSocket(socket) => Ok(socket.is_readable()),
            KernelObject::LocalSocket(socket) => Ok(socket.is_readable()),
            KernelObject::EventFd(state) => {
                Ok(state.counter.load(core::sync::atomic::Ordering::Acquire) > 0)
            }
            KernelObject::SignalFd(state) => signalfd_readable(state),
            KernelObject::TimerFd(state) => timerfd_readable(state),
            KernelObject::Mqueue(state) => Ok(!state.lock().is_empty()),
            KernelObject::Epoll(_) => Ok(false),
            KernelObject::Device(_) => Ok(true),
            KernelObject::Directory(_) => Err(Error::InvalidArgument),
            KernelObject::RawSocket(_) | KernelObject::Process(_) | KernelObject::Thread(_) => {
                Err(Error::Unsupported)
            }
            KernelObject::IoUring(state) => Ok(!state.completion_queue.lock().is_empty()),
        }
    }

    /// Check whether this handle can accept data for writing without blocking.
    pub(crate) fn is_writable(&self) -> Result<bool> {
        match &self.object {
            KernelObject::File(_) => Ok(true),
            KernelObject::Network(conn) => conn.is_writable(),
            KernelObject::TlsConnection(conn) => conn.is_writable(),
            KernelObject::TcpListener(_) => Ok(false),
            KernelObject::UdpSocket(_) => Ok(true),
            KernelObject::DccpSocket(socket) => Ok(socket.is_writable()),
            KernelObject::LocalSocket(_) => Ok(false),
            KernelObject::EventFd(_) => Ok(true),
            KernelObject::SignalFd(_) => Ok(false),
            KernelObject::TimerFd(_) => Ok(false),
            KernelObject::Mqueue(state) => Ok(!state.lock().is_full()),
            KernelObject::Epoll(_) => Ok(false),
            KernelObject::Device(_) => Ok(true),
            KernelObject::Directory(_) => Err(Error::InvalidArgument),
            KernelObject::RawSocket(_) | KernelObject::Process(_) | KernelObject::Thread(_) => {
                Err(Error::Unsupported)
            }
            KernelObject::IoUring(_) => Ok(false),
        }
    }

    pub(crate) fn into_file(self) -> Result<OpenFile> {
        match self.object {
            KernelObject::File(file) => Ok(file),
            KernelObject::Network(_)
            | KernelObject::TlsConnection(_)
            | KernelObject::TcpListener(_)
            | KernelObject::UdpSocket(_)
            | KernelObject::DccpSocket(_)
            | KernelObject::RawSocket(_)
            | KernelObject::LocalSocket(_)
            | KernelObject::Device(_)
            | KernelObject::Process(_)
            | KernelObject::Thread(_)
            | KernelObject::EventFd(_)
            | KernelObject::SignalFd(_)
            | KernelObject::TimerFd(_)
            | KernelObject::Mqueue(_)
            | KernelObject::Epoll(_)
            | KernelObject::IoUring(_) => Err(Error::Unsupported),
            KernelObject::Directory(_) => Err(Error::InvalidArgument),
        }
    }
}

fn synthetic_public_file_stat_record(kind: NodeKind, size: usize) -> fs_abi::FileStat {
    FileMetadata::new(kind, size).public_stat_record()
}

// ── eventfd helpers ───────────────────────────────────────────────────────

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::kernel::sync::wait::{plan_timed_wait, TimedWaitPlan};

/// Read from an eventfd: return the 8-byte counter value and reset (or
/// decrement in semaphore mode).
///
/// When the counter is zero the reader blocks on the wait queue (up to
/// `timeout_ticks`) unless the eventfd was created with `EFD_NONBLOCK`, in
/// which case it reports `Busy` (EAGAIN) immediately.
pub(super) fn eventfd_read(
    state: Arc<super::types::EventFdState>,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    if buffer.len() < 8 {
        return Err(Error::InvalidArgument);
    }

    let is_semaphore = (state.flags & EFD_SEMAPHORE) != 0;
    let is_nonblock = (state.flags & EFD_NONBLOCK) != 0;

    loop {
        let val = state.counter.load(Ordering::Acquire);
        if val > 0 {
            let result = if is_semaphore {
                // Decrement by 1
                match state.counter.compare_exchange(
                    val,
                    val - 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => 1u64,
                    Err(_) => continue,
                }
            } else {
                // Read and reset to 0
                match state
                    .counter
                    .compare_exchange(val, 0, Ordering::AcqRel, Ordering::Relaxed)
                {
                    Ok(_) => val,
                    Err(_) => continue,
                }
            };
            buffer[..8].copy_from_slice(&result.to_ne_bytes());
            return Ok(8);
        }

        // Counter is zero — EFD_NONBLOCK means report EAGAIN instead of
        // blocking, regardless of the caller's timeout.
        if is_nonblock {
            return Err(Error::Busy);
        }

        // Determine wait strategy.
        match plan_timed_wait(timeout_ticks) {
            TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => {
                return Err(Error::Busy);
            }
            TimedWaitPlan::Deadline(deadline) => {
                state
                    .wait_queue
                    .block_current_until_if(deadline, |_, _waiters, _thread| {
                        // Re-check counter inside the queue lock so we don't miss
                        // a concurrent wakeup.
                        if state.counter.load(Ordering::Acquire) > 0 {
                            return false; // don't block, data is available
                        }
                        true // proceed to block
                    });
                // Woken up — loop back to read the counter.
                continue;
            }
        }
    }
}

/// Write to an eventfd: add an 8-byte u64 value to the counter.
///
/// Mirrors Linux `eventfd` write semantics:
/// - the value `0xffff_ffff_ffff_ffff` is rejected with `EINVAL`;
/// - adding a value that would push the counter past `u64::MAX - 1` is reported
///   as `Busy` (EAGAIN). The counter saturates at that bound, so writes are
///   effectively non-blocking in this kernel.
pub(super) fn eventfd_write(
    state: Arc<super::types::EventFdState>,
    buffer: &[u8],
) -> Result<usize> {
    if buffer.len() < 8 {
        return Err(Error::InvalidArgument);
    }

    let val = u64::from_ne_bytes(buffer[..8].try_into().unwrap());

    // Linux rejects the sentinel value 0xffff_ffff_ffff_ffff.
    if val == u64::MAX {
        return Err(Error::InvalidArgument);
    }

    // The counter saturates at u64::MAX - 1 (Linux's documented maximum).
    const EVENTFD_MAX: u64 = u64::MAX - 1;
    let mut current = state.counter.load(Ordering::Relaxed);
    loop {
        if current > EVENTFD_MAX - val {
            return Err(Error::Busy);
        }
        match state.counter.compare_exchange_weak(
            current,
            current + val,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }

    // Wake one waiting reader.
    state.wait_queue.wake_one();

    Ok(8)
}

// ── signalfd helpers ─────────────────────────────────────────────────────

/// Read from a signalfd: dequeue the next pending signal matching the fd's
/// signal mask and return it as a `ProcessSignalRecord`.
pub(super) fn signalfd_read(
    state: Arc<super::types::SignalFdState>,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    let record_size = core::mem::size_of::<crate::abi::process::ProcessSignalRecord>();
    if buffer.len() < record_size {
        return Err(Error::InvalidArgument);
    }

    // Upgrade the weak process reference.
    let process = state.process.upgrade().ok_or(Error::InternalError)?;
    let sigset = state.sigset;

    // Helper: find and remove the first pending signal matching `sigset`.
    let try_take = |queue_state: &mut super::types::PendingProcessSignalState| -> Option<crate::abi::process::ProcessSignalRecord> {
        let idx = queue_state.pending.iter().position(|s| (sigset & (1 << s.signal)) != 0)?;
        let sig = queue_state.pending.remove(idx).unwrap();
        Some(sig.record())
    };

    // 1. Non-blocking attempt.
    let record = process
        .signal_queue
        .with_lock(|queue_state, _| try_take(queue_state));

    if let Some(record) = record {
        write_signal_record(buffer, &record);
        return Ok(record_size);
    }

    // 2. No signal available — decide whether to block.
    match plan_timed_wait(timeout_ticks) {
        TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => Err(Error::Busy),
        TimedWaitPlan::Deadline(deadline) => {
            // Block on the process's signal_queue.  The prepare closure
            // re-checks for a matching signal under the queue lock so we
            // don't miss a concurrent enqueue.  We only CHECK in the
            // prepare closure — actual dequeuing happens after wakeup.
            let had_signal = process.signal_queue.block_current_until_if(
                deadline,
                |queue_state, waiters, thread| {
                    if queue_state
                        .pending
                        .iter()
                        .any(|s| (sigset & (1 << s.signal)) != 0)
                    {
                        return false; // don't block, signal available
                    }
                    waiters.push_back(thread.clone());
                    true // block and wait for wakeup
                },
            );

            // Woken up (or prepare returned false for immediate retry).
            if had_signal {
                // We were woken — try to take one.
                let record = process
                    .signal_queue
                    .with_lock(|queue_state, _| try_take(queue_state));
                if let Some(r) = record {
                    write_signal_record(buffer, &r);
                    return Ok(record_size);
                }
            }

            // Timeout or signal was consumed by another waiter, loop back.
            Err(Error::TimedOut)
        }
    }
}

/// Check whether any pending signal matches the signalfd's mask.
pub(super) fn signalfd_readable(state: &Arc<super::types::SignalFdState>) -> Result<bool> {
    let process = match state.process.upgrade() {
        Some(p) => p,
        None => return Ok(false),
    };
    let sigset = state.sigset;
    process.signal_queue.with_lock(|queue_state, _| {
        Ok(queue_state
            .pending
            .iter()
            .any(|s| (sigset & (1 << s.signal)) != 0))
    })
}

/// Write a `ProcessSignalRecord` into the byte buffer.
fn write_signal_record(buffer: &mut [u8], record: &crate::abi::process::ProcessSignalRecord) {
    let ptr = record as *const _ as *const u8;
    let len = core::mem::size_of::<crate::abi::process::ProcessSignalRecord>();
    // Safety: the buffer is guaranteed to be at least `len` bytes by callers.
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, buffer.as_mut_ptr(), len);
    }
}

// ── timerfd helpers ──────────────────────────────────────────────────────

use core::sync::atomic::Ordering as AtomicOrdering;

/// Read from a timerfd: return the number of expirations since the last read.
pub(super) fn timerfd_read(
    state: Arc<super::types::TimerFdState>,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    if buffer.len() < 8 {
        return Err(Error::InvalidArgument);
    }

    loop {
        // Try to consume any pending expirations.
        let exp = state.expirations.swap(0, AtomicOrdering::AcqRel);
        if exp > 0 {
            buffer[..8].copy_from_slice(&exp.to_ne_bytes());
            return Ok(8);
        }

        // No expirations — determine wait strategy.
        match plan_timed_wait(timeout_ticks) {
            TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => {
                return Err(Error::Busy);
            }
            TimedWaitPlan::Deadline(deadline) => {
                // Block on the timerfd's WaitQueue.  The scheduler's
                // tick handler will wake us when the timer expires.
                // prepare returns `false` (don't block) if data appeared,
                // `true` (block) if we need to wait.
                state
                    .wait_queue
                    .block_current_until_if(deadline, |_, waiters, thread| {
                        if state.expirations.load(AtomicOrdering::Acquire) > 0 {
                            return false; // don't block, data available
                        }
                        waiters.push_back(thread.clone());
                        true // proceed to block
                    });
                // Woken up — loop back to read expirations.
                continue;
            }
        }
    }
}

/// Check whether a timerfd has pending expirations.
pub(super) fn timerfd_readable(state: &Arc<super::types::TimerFdState>) -> Result<bool> {
    Ok(state.expirations.load(AtomicOrdering::Acquire) > 0)
}

// ── mqueue helpers ─────────────────────────────────────────────────────────

/// Read from a message queue: dequeue one message.
pub(super) fn mqueue_read(
    state: Arc<crate::kernel::sync::Mutex<MqState>>,
    buffer: &mut [u8],
    timeout_ticks: u64,
) -> Result<usize> {
    let mut mq = state.lock();
    if buffer.len() < mq.msg_size as usize {
        return Err(Error::InvalidArgument);
    }

    // Try immediate receive.
    if let Some(msg) = mq.messages.pop_front() {
        let n = msg.len().min(buffer.len());
        buffer[..n].copy_from_slice(&msg[..n]);
        mq.wait_send.wake_one();
        return Ok(n);
    }

    // Queue empty — determine wait strategy.
    match plan_timed_wait(timeout_ticks) {
        TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => Err(Error::Busy),
        TimedWaitPlan::Deadline(deadline) => {
            drop(mq);
            // Clone the Arc so the closure doesn't capture the original.
            let state_clone = state.clone();
            let did_wake = state.lock().wait_recv.block_current_until_if(
                deadline,
                |_queue_state, waiters, thread| {
                    let mq = state_clone.lock();
                    if !mq.is_empty() {
                        return false;
                    }
                    drop(mq);
                    waiters.push_back(thread.clone());
                    true
                },
            );

            if !did_wake {
                return Err(Error::TimedOut);
            }

            let mut mq = state.lock();
            let msg = mq.messages.pop_front().ok_or(Error::TimedOut)?;
            let n = msg.len().min(buffer.len());
            buffer[..n].copy_from_slice(&msg[..n]);
            mq.wait_send.wake_one();
            Ok(n)
        }
    }
}

/// Write to a message queue: enqueue one message.
pub(super) fn mqueue_write(
    state: Arc<crate::kernel::sync::Mutex<MqState>>,
    buffer: &[u8],
) -> Result<usize> {
    let mut mq = state.lock();
    if buffer.len() > mq.msg_size as usize {
        return Err(Error::InvalidArgument);
    }

    // Try immediate send.
    if !mq.is_full() {
        mq.messages.push_back(buffer.to_vec());
        mq.wait_recv.wake_one();
        return Ok(buffer.len());
    }

    // Queue full — block (unlimited wait for now).
    match plan_timed_wait(u64::MAX) {
        TimedWaitPlan::Unavailable | TimedWaitPlan::ZeroTimeout => Err(Error::Busy),
        TimedWaitPlan::Deadline(deadline) => {
            drop(mq);
            // Clone the Arc so the closure doesn't capture the original.
            let state_clone = state.clone();
            let did_wake = state.lock().wait_send.block_current_until_if(
                deadline,
                |_queue_state, waiters, thread| {
                    let mq = state_clone.lock();
                    if !mq.is_full() {
                        return false;
                    }
                    drop(mq);
                    waiters.push_back(thread.clone());
                    true
                },
            );

            if !did_wake {
                return Err(Error::TimedOut);
            }

            let mut mq = state.lock();
            mq.messages.push_back(buffer.to_vec());
            mq.wait_recv.wake_one();
            Ok(buffer.len())
        }
    }
}

// ── eventfd tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::eventfd_read;
    use super::eventfd_write;
    use crate::kernel::process::process::types::{EventFdState, EFD_NONBLOCK, EFD_SEMAPHORE};
    use crate::kernel::sync::wait::WaitQueue;
    use crate::Error;
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicU64;

    fn state(initval: u64, flags: u32) -> Arc<EventFdState> {
        Arc::new(EventFdState {
            counter: AtomicU64::new(initval),
            wait_queue: WaitQueue::new(),
            flags,
        })
    }

    fn read_counter(s: &Arc<EventFdState>) -> u64 {
        let mut buf = [0u8; 8];
        let n = eventfd_read(s.clone(), &mut buf, 0).expect("read should succeed");
        assert_eq!(n, 8);
        u64::from_ne_bytes(buf)
    }

    fn write_value(s: &Arc<EventFdState>, val: u64) {
        let buf = val.to_ne_bytes();
        assert_eq!(
            eventfd_write(s.clone(), &buf).expect("write should succeed"),
            8
        );
    }

    #[test]
    fn eventfd_read_returns_and_resets_counter() {
        let s = state(42, 0);
        assert_eq!(read_counter(&s), 42);
        // Counter was reset — a zero-timeout read now reports Busy.
        let mut buf = [0u8; 8];
        assert_eq!(eventfd_read(s, &mut buf, 0), Err(Error::Busy));
    }

    #[test]
    fn eventfd_semaphore_read_decrements_by_one() {
        let s = state(3, EFD_SEMAPHORE);
        for _ in 0..3 {
            assert_eq!(read_counter(&s), 1);
        }
        let mut buf = [0u8; 8];
        assert_eq!(eventfd_read(s, &mut buf, 0), Err(Error::Busy));
    }

    #[test]
    fn eventfd_nonblock_read_reports_busy_on_zero_counter() {
        let s = state(0, EFD_NONBLOCK);
        let mut buf = [0u8; 8];
        // Even with an effectively-infinite timeout, EFD_NONBLOCK must not block.
        assert_eq!(eventfd_read(s, &mut buf, u64::MAX), Err(Error::Busy));
    }

    #[test]
    fn eventfd_write_adds_to_counter() {
        let s = state(0, 0);
        write_value(&s, 10);
        write_value(&s, 5);
        assert_eq!(read_counter(&s), 15);
    }

    #[test]
    fn eventfd_write_rejects_sentinel_value() {
        let s = state(0, 0);
        let buf = u64::MAX.to_ne_bytes();
        assert_eq!(eventfd_write(s, &buf), Err(Error::InvalidArgument));
    }

    #[test]
    fn eventfd_write_reports_busy_on_counter_overflow() {
        let s = state(u64::MAX - 1, 0);
        assert_eq!(eventfd_write(s, &1u64.to_ne_bytes()), Err(Error::Busy));
    }

    #[test]
    fn eventfd_read_requires_eight_byte_buffer() {
        let s = state(1, 0);
        let mut small = [0u8; 7];
        assert_eq!(
            eventfd_read(s.clone(), &mut small, 0),
            Err(Error::InvalidArgument)
        );
        let mut buf = [0u8; 8];
        assert_eq!(eventfd_read(s, &mut buf, 0), Ok(8));
    }
}
