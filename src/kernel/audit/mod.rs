//! src/kernel/audit/mod.rs
//!
//! Kernel audit subsystem: event emission and ring buffer.
//! Audit subsystem — event logging ring buffer and per-process enable mask.
//!
//! The audit subsystem provides a fixed-size lock-free ring buffer into which
//! kernel components (primarily the syscall dispatcher) emit structured event
//! records.  Each process has an `audit_enable_mask` that gates which event
//! types are logged, keeping overhead at zero when auditing is disabled.

use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use alloc::boxed::Box;

pub mod buffer;
pub mod persist;
pub mod types;

use buffer::AuditBuffer;

// ── Global audit buffer ───────────────────────────────────────────────────

static GLOBAL_AUDIT_BUFFER: AtomicPtr<AuditBuffer> = AtomicPtr::new(ptr::null_mut());

/// Install the global audit buffer.  Called once during kernel init.
///
/// # Safety
///
/// The caller must guarantee that `buffer` outlives every future access.
pub unsafe fn install_global(buffer: &'static AuditBuffer) {
    GLOBAL_AUDIT_BUFFER.store(buffer as *const _ as *mut _, Ordering::SeqCst);
}

/// Install a heap-allocated buffer as the global audit ring buffer.
/// Returns `true` if the buffer was installed, `false` if one was already set.
pub fn try_install(buffer: Box<AuditBuffer>) -> bool {
    let raw = Box::into_raw(buffer);
    match GLOBAL_AUDIT_BUFFER.compare_exchange(
        ptr::null_mut(),
        raw,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => true,
        Err(existing) => {
            // Another thread installed a buffer already — drop ours.
            // SAFETY: `raw` came from the `Box::into_raw` above, so this
            // rebuilds exactly the allocation that box owned and nothing else
            // holds a reference to it.
            drop(unsafe { Box::from_raw(raw) });
            // Only race if called concurrently; use the existing pointer.
            let _ = existing;
            false
        }
    }
}

/// Return a reference to the global audit buffer, or `None` if not installed.
pub fn global() -> Option<&'static AuditBuffer> {
    let ptr = GLOBAL_AUDIT_BUFFER.load(Ordering::SeqCst);
    // SAFETY: the pointer is either null or the address of a buffer that was
    // published through that atomic and never freed, so a non-null one names a
    // live allocation for the life of the kernel.
    unsafe { ptr.as_ref() }
}

/// Initialize the global audit subsystem.  Allocates the ring buffer, stores
/// it as the global singleton, and applies the boot's `audit=` option.  Safe to
/// call multiple times — the second and subsequent calls are no-ops.
///
/// Persistence is **opt-in**, and the kernel command line is what asks for it:
/// `audit=persist` (or `audit=all`) turns on the maintenance thread's drain of
/// the ring to [`persist::AUDIT_LOG_PATH`], and a boot without it keeps records
/// in memory only.  That default is deliberate — writing a durable trace of
/// every audited event is a decision the operator makes, not one a boot makes
/// for the machine — and the boot says which of the two it ran, so a log tells
/// them apart.
///
/// The option is read **here** rather than by the caller so the boot path names
/// one audit entry point, and because the command line may arrive on either PC
/// hand-off (`boot_command_line`), which is not this module's business to know.
///
/// A boot that turned persistence on emits one `ConfigChange` record saying so,
/// which is both an honest entry — enabling a durable audit trail is a
/// configuration change worth recording — and the record that makes the ring
/// non-empty on a machine whose processes have not asked for any capture of
/// their own (a per-process decision, `AuditSetEnable` #143).
pub fn init() {
    if global().is_some() {
        return;
    }
    let buf = Box::new(AuditBuffer::new());
    if !try_install(buf) {
        // Another thread won the race; enable nothing.
        return;
    }

    let option = crate::arch::boot::boot_command_line().and_then(|cl| {
        crate::arch::boot::command_line_option(&cl, "audit").map(alloc::string::String::from)
    });
    let persist = matches!(option.as_deref(), Some("persist") | Some("all"));
    persist::set_persistence(persist);
    if persist {
        crate::println!(
            "[audit ] persistence enabled (audit={}); recording to {}",
            option.as_deref().unwrap_or(""),
            persist::AUDIT_LOG_PATH
        );
        record_the_configuration_change(persist::AUDIT_LOG_PATH);
    } else {
        crate::println!(
            "[audit ] memory-only; pass audit=persist to record to {}",
            persist::AUDIT_LOG_PATH
        );
    }
}

/// Emit the `ConfigChange` record that says persistence was enabled.
///
/// The payload is the path the records go to, so a reader of `audit.log` sees
/// the file name the boot chose rather than only that "something" changed.
/// `fill` bounds the payload to the record's own data field, so passing the
/// path whole is safe whatever its length.
fn record_the_configuration_change(path: &str) {
    let (pid, timestamp) = current_actor();
    let mut record = types::AuditRecord::zeroed();
    record.fill(
        CONFIG_AUDIT_ID.fetch_add(1, Ordering::Relaxed),
        0,
        timestamp,
        types::AuditEventType::ConfigChange,
        pid,
        0,
        0,
        path.as_bytes(),
    );
    let _ = emit_record(record);
}

/// Instance numbers for the records this module emits itself.
static CONFIG_AUDIT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Emit an audit record into the global buffer.
/// Returns `false` if the buffer is full or not yet initialised.
pub fn emit_record(record: types::AuditRecord) -> bool {
    global().map(|buffer| buffer.emit(record)).unwrap_or(false)
}

/// Who is running, and when: the actor fields an audit record carries.
///
/// Resolved here rather than by each producer.  Audit is the layer that
/// reaches the scheduler anyway; a producer below it — the MAC checks in the
/// security layer, for instance — should be able to say *what* happened
/// without also having to know how to find the current process.
///
/// Returns `(pid, tick)`, both zero when no scheduler is installed (host
/// tests).
pub fn current_actor() -> (u32, u64) {
    let Some(scheduler) = crate::kernel::process::Scheduler::global() else {
        return (0, 0);
    };
    let pid = scheduler
        .current_thread()
        .map(|thread| thread.process().pid())
        .unwrap_or(0);
    (pid, scheduler.current_tick())
}

/// Read up to `max` audit records from the global buffer into `records`.
/// Returns the number of records actually copied, or 0 if not initialised.
pub fn read_records(records: &mut [types::AuditRecord]) -> usize {
    global()
        .map(|buffer| buffer.read_events(records))
        .unwrap_or(0)
}
