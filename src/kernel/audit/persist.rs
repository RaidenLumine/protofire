//! src/kernel/audit/persist.rs
//!
//! Optional audit-log persistence: drains the ring buffer to a file on the
//! root filesystem.
//!
//! Persistence is opt-in (`set_persistence(true)`).  When enabled, a periodic
//! maintenance path (the scheduler timer tick) calls [`persist_to_file`],
//! which peeks a batch of records from the ring buffer, serializes them as
//! text lines, appends them to the audit log file, syncs, and only then
//! advances the ring consumer index — a failed write never drops records.
//! If the root filesystem is not mounted the flush is skipped and the buffer
//! keeps working in pure in-memory mode.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use alloc::format;
use alloc::string::String;
#[cfg(test)]
use alloc::vec::Vec;

use crate::kernel::audit::buffer::AuditBuffer;
use crate::kernel::audit::types::AuditRecord;
use crate::kernel::fs::FileSystem;
use crate::kernel::fs::OPEN_ALWAYS;
use crate::kernel::fs::SEEK_END;
#[cfg(test)]
use crate::kernel::process::HANDLE_RIGHT_READ;
use crate::kernel::process::HANDLE_RIGHT_WRITE;

/// How many records to persist in one flush.
const PERSIST_BATCH_SIZE: usize = 256;

/// Audit log file location.
///
/// `/system/logs` is a read-only virtual mount (kernel-logs), so the durable
/// writable location is the `/data` zone.  Writes use the system security
/// token; the file is created on first flush.
pub const AUDIT_LOG_PATH: &str = "/data/audit.log";

/// Flush the audit ring buffer to disk every N scheduler ticks.
pub const PERSIST_PERIOD_TICKS: u64 = 200;

static PERSISTENCE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable periodic audit-log persistence.  Off by default.
pub fn set_persistence(enabled: bool) {
    PERSISTENCE_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Whether audit-log persistence is currently enabled.
pub fn persistence_enabled() -> bool {
    PERSISTENCE_ENABLED.load(Ordering::SeqCst)
}

/// Serialize one record into a single text line (no trailing newline).
fn serialize_record(rec: &AuditRecord) -> String {
    let payload = rec.payload();
    let mut data_hex = String::with_capacity(payload.len() * 2);
    for b in payload {
        data_hex.push(hex_digit(b >> 4));
        data_hex.push(hex_digit(b & 0x0f));
    }
    format!(
        "{} {} pid={} uid={} result={} seq={} data={}",
        rec.timestamp,
        rec.event_type_enum().as_str(),
        rec.pid,
        rec.uid,
        rec.result,
        rec.sequence,
        data_hex,
    )
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

/// Flush a batch of records from `buffer` to the audit log on `fs`.
///
/// Returns the number of records durably persisted (0 on any failure).
/// The ring consumer index is advanced only after the write and sync
/// succeed, so nothing is dropped on error.
pub(crate) fn persist_buffer_to_fs(buffer: &AuditBuffer, fs: &mut FileSystem) -> usize {
    let mut batch = [AuditRecord::zeroed(); PERSIST_BATCH_SIZE];
    let n = buffer.peek_records(&mut batch);
    if n == 0 {
        return 0;
    }

    let mut payload = String::new();
    for rec in &batch[..n] {
        payload.push_str(&serialize_record(rec));
        payload.push('\n');
    }
    let bytes = payload.as_bytes();

    // Open or create the audit log and append.
    let mut file =
        match fs.create_file_normalized(AUDIT_LOG_PATH, HANDLE_RIGHT_WRITE, 0, OPEN_ALWAYS) {
            Ok(file) => file,
            Err(_) => return 0,
        };
    if file.seek(0, SEEK_END).is_err() {
        return 0;
    }
    let written = match fs.write(&mut file, bytes) {
        Ok(written) => written,
        Err(_) => return 0,
    };
    if written != bytes.len() {
        return 0;
    }
    if file.sync().is_err() {
        return 0;
    }

    // Durably on disk: commit the batch.
    buffer.commit_read(n);
    n
}

/// Periodic persistence entry point: flush the global audit ring buffer to
/// the global root filesystem.
///
/// No-op (returns 0) when persistence is disabled, no audit buffer is
/// installed, or the root filesystem is not mounted.
pub fn persist_to_file() -> usize {
    if !persistence_enabled() {
        return 0;
    }
    let Some(buffer) = super::global() else {
        return 0;
    };
    let Some(fs) = crate::kernel::fs::global() else {
        return 0;
    };
    let mut fs = fs.lock();
    persist_buffer_to_fs(buffer, &mut fs)
}

/// Read the entire audit log file into a `Vec` (test/diagnostic helper).
#[cfg(test)]
fn read_audit_log(fs: &mut FileSystem) -> Vec<u8> {
    use crate::kernel::fs::OPEN_EXISTING;

    let mut file = fs
        .create_file_normalized(AUDIT_LOG_PATH, HANDLE_RIGHT_READ, 0, OPEN_EXISTING)
        .expect("open audit log");
    let mut out = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        let n = fs.read(&mut file, &mut chunk).expect("read audit log");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::audit::buffer::AuditBuffer;
    use crate::kernel::audit::types::AuditEventType;
    use crate::kernel::fs::OPEN_EXISTING;

    fn sample_record(payload: &[u8]) -> AuditRecord {
        let mut rec = AuditRecord::zeroed();
        rec.fill(0, 0, 1234, AuditEventType::Syscall, 7, 0, 0, payload);
        rec
    }

    fn new_test_fs() -> FileSystem {
        let mut fs = FileSystem::new();
        fs.init();
        fs
    }

    #[test]
    fn persist_writes_serialized_records_and_commits() {
        let buf = AuditBuffer::new();
        buf.emit(sample_record(b"first"));
        buf.emit(sample_record(b"second"));
        assert_eq!(buf.len(), 2);

        let mut fs = new_test_fs();
        let n = persist_buffer_to_fs(&buf, &mut fs);
        assert_eq!(n, 2);
        // The batch was committed only after a successful write.
        assert!(buf.is_empty());

        let text = String::from_utf8(read_audit_log(&mut fs)).expect("utf8 log");
        assert!(text.contains("seq=1"), "log: {text}");
        assert!(text.contains("seq=2"), "log: {text}");
        assert!(text.contains("data=6669727374"), "log: {text}"); // "first"
        assert!(text.contains("data=7365636f6e64"), "log: {text}"); // "second"
    }

    #[test]
    fn persist_appends_across_flushes() {
        let buf = AuditBuffer::new();
        buf.emit(sample_record(b"one"));

        let mut fs = new_test_fs();
        assert_eq!(persist_buffer_to_fs(&buf, &mut fs), 1);

        // A second flush appends, it does not overwrite the first.
        buf.emit(sample_record(b"two"));
        assert_eq!(persist_buffer_to_fs(&buf, &mut fs), 1);

        let text = String::from_utf8(read_audit_log(&mut fs)).expect("utf8 log");
        assert_eq!(text.matches("data=").count(), 2);
    }

    #[test]
    fn persist_skips_when_buffer_empty() {
        let buf = AuditBuffer::new();
        let mut fs = new_test_fs();
        assert_eq!(persist_buffer_to_fs(&buf, &mut fs), 0);
        // No file should have been created by an empty flush: opening it with
        // OPEN_EXISTING must fail.
        assert!(fs
            .create_file_normalized(AUDIT_LOG_PATH, HANDLE_RIGHT_READ, 0, OPEN_EXISTING)
            .is_err());
    }
}
