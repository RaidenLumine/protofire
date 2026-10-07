//! src/kernel/workload.rs
//!
//! A defined storage workload, run once at boot, so the counters have a
//! workload to be read against rather than only a boot.
//!
//! Why this exists
//! ---------------
//! The boot-work line says what the machine did on the way up: opening volumes,
//! reading the layout, starting programs.  That is a workload of a kind, but it
//! changes every time the boot changes, so "did this do less work" could only
//! ever be answered for the whole boot.  This runs a fixed piece of filesystem
//! work instead — the same paths, the same sizes, the same number of passes —
//! and the boot-work line reports what that work cost on its own, as `wl-*`
//! counters beside the boot's.  A change that makes the filesystem do more work
//! per write now names the workload it did it in.
//!
//! What it does *not* do is measure seconds.  It does record the cycles the run
//! took, and that number is printed, but the gate does not compare it: a gate
//! that measures cycles measures the machine it ran on, which is why no gate in
//! this tree compares a duration.  The counters are what a ratchet can hold,
//! and the cycles are what a person reads when a counter needs explaining.
//!
//! The shape is deliberately small and in-memory: the scratch volume comes from
//! `MemoryBlockDevice`, so a run is a test of the filesystem, the cache and the
//! commit protocol rather than of a disk, and it costs a boot a few
//! milliseconds.  A run on a real device belongs to a gate that boots one.

use alloc::format;
use alloc::vec;

use crate::fs::layout::StorageZone;
use crate::fs::FileSystem;
use crate::fs::OPEN_ALWAYS;
use crate::kernel::block::BlockDevice;
use crate::kernel::block::DeviceIo;
use crate::kernel::block::RequestState;
use crate::kernel::block::BLOCK_SIZE;
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;

/// Where the workload keeps its files: a directory of its own under the data
/// zone, which is the writable volume every boot that installs the standard
/// zones has — `/tmp` is only mounted by the default layout, and a workload
/// that ran in one boot and not another would make its counters incomparable.
pub(crate) const DIR: &str = "/data/workload";

/// The workload's shape, fixed on purpose: two boots have to do the same work
/// for a counter delta to mean anything.
pub(crate) const FILES: usize = 8;
pub(crate) const FILE_BYTES: usize = 2048;
pub(crate) const PASSES: usize = 3;

/// The network exchange's shape: one datagram, to itself.
pub(crate) const NET_PORT: u16 = 4321;
pub(crate) const NET_BYTES: usize = 512;

/// The most receive-path polls the exchange waits for its own datagram.
///
/// A bound, because an unbounded wait is a hang, and a workload that hangs the
/// boot is worse than one that reports it never saw its own datagram.  The
/// loopback queues what it is sent and the stack's receive path is polled, so
/// the frame waits for `poll` the way a real device's frame waits for its
/// interrupt; sixty-four polls is far more than a frame needs and far less
/// than a boot would take to time out.
pub(crate) const NET_POLL_LIMIT: usize = 64;

/// The most times one queued read is polled before the probe gives up.
///
/// A bound, for the same reason the exchange has one: a device that never
/// completes a request must not hang the boot.  Fifty million polls is far
/// more than a real device needs and far less than a boot would take to time
/// out on its own.
const QUEUED_READ_POLL_LIMIT: u32 = 50_000_000;

/// What one run cost, in the counters the boot-work line already prints.
///
/// Written when the workload runs and read when that line is printed, so a
/// change in the workload's cost is attributed to the workload rather than
/// disappearing into the boot's totals.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WorkloadDelta {
    pub(crate) files: u64,
    pub(crate) bytes: u64,
    pub(crate) ops: u64,
    pub(crate) fs_reads: u64,
    pub(crate) fs_read_bytes: u64,
    pub(crate) fs_writes: u64,
    pub(crate) fs_write_bytes: u64,
    pub(crate) fs_transactions: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) blk_reads: u64,
    pub(crate) blk_read_bytes: u64,
    pub(crate) blk_writes: u64,
    pub(crate) blk_write_bytes: u64,
    /// The network exchange: datagrams the stack sent and received, the bytes
    /// the exchange got back, and the polls it took to get them.
    pub(crate) net_datagrams_tx: u64,
    pub(crate) net_datagrams_rx: u64,
    pub(crate) net_bytes: u64,
    pub(crate) net_polls: u64,
    /// One when the datagram came back whole.  A counter rather than a
    /// comment, because "the exchange completed" is the property, and a boot
    /// whose peer never answered should fail a baseline rather than pass it
    /// quietly.
    pub(crate) net_completed: u64,
    /// Cycles the run took, printed on a line of its own and not compared.
    pub(crate) cycles: u64,
}

impl WorkloadDelta {
    /// Whether the workload ran.  A boot with nowhere to put the files reports
    /// zeroes, which is a shape no run can produce: the counter keys would
    /// otherwise look like a workload that cost nothing.
    pub(crate) fn ran(&self) -> bool {
        self.files > 0
    }

    /// The work one run was asked for — the files it wrote and the bytes it
    /// handed to `write` — as a ratio against the bytes a device moved for it.
    /// Integers, because this is a counter and not a benchmark.
    pub(crate) fn device_bytes_per_asked_byte(&self) -> u64 {
        if self.bytes == 0 {
            return 0;
        }
        (self.blk_write_bytes + self.blk_read_bytes) / self.bytes
    }
}

/// The last run's delta, read when the boot-work line is printed.  It is
/// `None` until the workload has run, which is how a boot that never reached
/// the scratch volume is told apart from one whose workload cost nothing.
static LAST: crate::kernel::sync::Mutex<Option<WorkloadDelta>> =
    crate::kernel::sync::Mutex::new(None);

/// What the workload cost, or zeroes if it never ran.
pub(crate) fn last() -> WorkloadDelta {
    LAST.lock().unwrap_or_default()
}

/// Publish a delta for the boot-work line to read.
pub(crate) fn publish(delta: WorkloadDelta) {
    *LAST.lock() = Some(delta);
}

/// Run the workload against `fs`, which the caller has locked.
///
/// The aggregate is passed in rather than looked up because the caller holds
/// the filesystem lock: the counters have to be read around the work, and
/// taking the lock twice would deadlock.
pub(crate) fn run(fs: &FileSystem) -> WorkloadDelta {
    let before = Snapshot::take(fs);
    let started = crate::arch::timer::monotonic_cycles();

    let (files, bytes, ops) = write_and_read(fs);
    // The queued-read probe runs inside the same window, so its two reads are
    // attributed to the workload rather than disappearing into the boot's
    // totals.  It reports nothing on a device that cannot hold two.
    if let Some(report) = probe_queued_read(fs) {
        crate::println!(
            "[perf  ] queued read: depth={} submitted={} read-high-water={}",
            report.depth,
            report.submitted,
            report.high_water
        );
    }

    let after = Snapshot::take(fs);
    WorkloadDelta {
        files: files as u64,
        bytes: bytes as u64,
        ops: ops as u64,
        fs_reads: after.fs.reads.saturating_sub(before.fs.reads),
        fs_read_bytes: after.fs.read_bytes.saturating_sub(before.fs.read_bytes),
        fs_writes: after.fs.writes.saturating_sub(before.fs.writes),
        fs_write_bytes: after.fs.write_bytes.saturating_sub(before.fs.write_bytes),
        fs_transactions: after.fs.transactions.saturating_sub(before.fs.transactions),
        cache_hits: after.cache.hits.saturating_sub(before.cache.hits),
        cache_misses: after.cache.misses.saturating_sub(before.cache.misses),
        blk_reads: after.device.read_ops.saturating_sub(before.device.read_ops),
        blk_read_bytes: after
            .device
            .read_bytes
            .saturating_sub(before.device.read_bytes),
        blk_writes: after
            .device
            .write_ops
            .saturating_sub(before.device.write_ops),
        blk_write_bytes: after
            .device
            .write_bytes
            .saturating_sub(before.device.write_bytes),
        cycles: crate::arch::timer::monotonic_cycles().wrapping_sub(started),
        // The network half is filled by `run_network`, which only a boot with
        // a loopback calls.
        ..WorkloadDelta::default()
    }
}

/// What the queued-read probe saw, when it had a device to run on.
struct QueuedReadReport {
    /// The device's advertised depth.
    depth: u16,
    /// How many reads were handed to it before either was polled.
    submitted: u64,
    /// The most requests that were in flight at once, read while both were
    /// outstanding — the probe's own evidence that it was not serialized.
    high_water: u64,
}

/// Submit two reads to a device that can hold them, then wait for both.
///
/// This is RFC 0007's first caller, and deliberately the smallest one: it
/// exists so the queued interface is *executed* by a gate rather than merely
/// implemented, which is what this tree asks of a mechanism before anything
/// depends on it.  What it does not do is measure a benefit — that is a
/// question for real hardware, not for a device model whose latency is the
/// host's — so its counters are the proof that the mechanism ran, and the
/// duration no gate compares is the only thing a reader can use to ask
/// whether it was worth it.
///
/// A read-ahead that overlaps its own wait is the caller the RFC settles on;
/// this probe is the step before it, and it is why the interface can be
/// verified at all.
fn probe_queued_read(fs: &FileSystem) -> Option<QueuedReadReport> {
    // The data zone's device is a slice of the boot disk, and a slice of a
    // device that queues is itself a queued device, so the depth that comes
    // back is the disk's.  A boot with no data zone has nothing to ask.
    let device = fs.block_device(StorageZone::Data.device())?;
    queued_read(&*device)
}

/// The device half of the probe, so it can be exercised without a filesystem.
fn queued_read(device: &dyn BlockDevice) -> Option<QueuedReadReport> {
    if device.queue_depth() < 2 || device.block_size() != BLOCK_SIZE || device.block_count() < 2 {
        return None;
    }

    let mut first = [0_u8; BLOCK_SIZE];
    let mut second = [0_u8; BLOCK_SIZE];

    // SAFETY: both buffers are locals that outlive the tickets — the polls
    // below run before either goes out of scope — and each is named by exactly
    // one of the two outstanding reads.
    let first_ticket = unsafe { device.submit_read(0, &mut first) }.ok()?;
    // SAFETY: as above — `second` is the other local, named by this read
    // alone.
    let second_ticket = unsafe { device.submit_read(1, &mut second) }.ok()?;

    // Read the counter while both are outstanding: this is the number the
    // gate holds, and the probe reading it here is what makes the claim
    // "the mechanism ran" rather than "the read returned".
    let high_water = crate::kernel::block::device_io_snapshot().read_in_flight_high_water;

    for ticket in [first_ticket, second_ticket] {
        let mut polls = 0u32;
        loop {
            match device.poll(ticket) {
                RequestState::Pending => {
                    polls += 1;
                    if polls > QUEUED_READ_POLL_LIMIT {
                        return None;
                    }
                    core::hint::spin_loop();
                }
                RequestState::Done(result) => {
                    result.ok()?;
                    break;
                }
            }
        }
    }

    Some(QueuedReadReport {
        depth: device.queue_depth(),
        submitted: 2,
        high_water,
    })
}

/// Run the network half: one datagram to itself over whatever device the stack
/// was given, and the polls it took to see it come back.
///
/// Only a boot built with `net_loopback` calls this, and only such a boot has
/// a peer that answers without a host; the counters it fills stay zero
/// everywhere else, which is the honest reading of "no exchange happened".
pub(crate) fn run_network(delta: &mut WorkloadDelta) {
    use crate::network::link::device::loopback::LOOPBACK_IPV4;

    let Some(stack) = crate::network::stack::NetworkStack::global() else {
        return;
    };
    let before = stack.profiler_snapshot();
    let Ok(socket) = crate::network::bind_udp(NET_PORT) else {
        return;
    };

    let payload = vec![0xA5_u8; NET_BYTES];
    let sent = crate::network::send_to_udp(&socket, LOOPBACK_IPV4, NET_PORT, &payload).is_ok();

    let mut buffer = vec![0_u8; NET_BYTES];
    let mut polls = 0u64;
    let mut received = 0usize;
    while polls < NET_POLL_LIMIT as u64 {
        polls += 1;
        // A poll that processed some other frame leaves the socket empty, so
        // the receive is tried again rather than assumed.
        if let Ok(true) = stack.poll() {
            if let Ok((count, _, _)) = crate::network::recv_from_udp(&socket, &mut buffer) {
                received = count;
                break;
            }
        }
    }

    let after = stack.profiler_snapshot();
    delta.net_datagrams_tx = after
        .udp_datagrams_tx
        .saturating_sub(before.udp_datagrams_tx);
    delta.net_datagrams_rx = after
        .udp_datagrams_rx
        .saturating_sub(before.udp_datagrams_rx);
    delta.net_bytes = received as u64;
    delta.net_polls = polls;
    delta.net_completed = u64::from(sent && received == NET_BYTES);
}

/// The counters the workload is measured with, in one place each.
struct Snapshot {
    fs: crate::fs::filesystem::profiler::FsProfilerSnapshot,
    cache: crate::fs::block_cache::CacheStats,
    device: DeviceIo,
}

impl Snapshot {
    fn take(fs: &FileSystem) -> Self {
        Self {
            fs: fs.fs_profiler_snapshot(),
            cache: fs.cache_stats(),
            device: crate::kernel::block::device_io_snapshot(),
        }
    }
}

/// Write the workload's files, then read them back, and return how much work
/// that was: files, bytes written, and operations.
fn write_and_read(fs: &FileSystem) -> (usize, usize, usize) {
    match fs.create_dir(DIR) {
        Ok(()) | Err(crate::Error::AlreadyExists) => {}
        // No scratch volume, or no room in it: the workload did not run, and
        // saying so is better than reporting a smaller run as if it meant
        // something.  The reason goes in the boot log because a workload that
        // silently does nothing is the failure this module exists to avoid.
        Err(error) => {
            crate::println!("[perf  ] workload: {} unusable: {}", DIR, error.as_str());
            return (0, 0, 0);
        }
    }

    let mut payload = vec![0_u8; FILE_BYTES];
    let mut files = 0usize;
    let mut bytes = 0usize;
    let mut ops = 0usize;

    for pass in 0..PASSES {
        for index in 0..FILES {
            // Deterministic content, so the filesystem sees the same bytes on
            // every boot: a checksum or a compression path that behaves
            // differently per input would show up as noise.
            for (offset, byte) in payload.iter_mut().enumerate() {
                *byte = (index as u8) ^ (pass as u8) ^ (offset as u8);
            }
            let path = format!("{DIR}/f{index}.bin");
            let Ok(mut handle) = fs.create_file(&path, HANDLE_RIGHT_WRITE, 0, OPEN_ALWAYS) else {
                continue;
            };
            if handle.set_len(0).is_err() {
                continue;
            }
            if let Ok(written) = fs.write(&mut handle, &payload) {
                ops += 1;
                bytes += written;
                if pass == 0 {
                    files += 1;
                }
            }
        }
    }

    // Read every file back through a handle of its own, so the workload has a
    // read path as well as a write path and the cache's hits show up in it.
    let mut buffer = vec![0_u8; FILE_BYTES];
    for index in 0..FILES {
        let path = format!("{DIR}/f{index}.bin");
        let Ok(mut handle) = fs.create_file(&path, HANDLE_RIGHT_READ, 0, OPEN_ALWAYS) else {
            continue;
        };
        if fs.read(&mut handle, &mut buffer).is_ok() {
            ops += 1;
        }
    }

    (files, bytes, ops)
}
