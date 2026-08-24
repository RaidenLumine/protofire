//! src/kernel/syscall/audit.rs
//!
//! Syscall handlers for audit subsystem control (AuditSetEnable, AuditReadLog).

use crate::kernel::audit;
use crate::kernel::audit::types::{AuditRecord, AUDIT_ENABLE_ALL};
use crate::kernel::process::Process;
use crate::{Error, Result};

use super::runtime;
use super::user_memory;
use super::SyscallContext;
use super::SyscallDispatch;

/// AuditSetEnable (#143) — enable or disable audit event types for the
/// current process.
///
/// Arguments:
///   arg0 = enable mask (u64) — OR of `AUDIT_ENABLE_*` bits.
///
/// Returns the previous enable mask.
pub(super) fn audit_set_enable(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let mask = context.arg(0) as u64;

    // Reject unknown bits.
    if mask & !AUDIT_ENABLE_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    super::validate_zeroed_args(context, 1)?;

    let prev = runtime::with_current_process(|process: &Process| Ok(process.audit_enable_mask()))?;

    runtime::with_current_process(|process: &Process| {
        process.set_audit_enable_mask(mask);
        Ok(())
    })?;

    Ok(SyscallDispatch::complete(prev as usize))
}

/// AuditReadLog (#144) — read pending audit events from the global ring
/// buffer.
///
/// Arguments:
///   arg0 = output buffer pointer (caller address space)
///   arg1 = max number of audit records to read
///   arg2 = size of each record (must equal `size_of::<AuditRecord>()`)
///
/// Returns the number of records actually written.
pub(super) fn audit_read_log(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let buf_ptr = context.arg(0) as *mut u8;
    let max_records = context.arg(1);
    let record_size = context.arg(2);

    if buf_ptr.is_null() || max_records == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate record size.
    let expected_size = core::mem::size_of::<AuditRecord>();
    if record_size != expected_size {
        return Err(Error::InvalidArgument);
    }
    super::validate_zeroed_args(context, 3)?;

    // Read records from the audit buffer into a temporary kernel buffer.
    // The read is bounded by the ring capacity, so allocate for the smaller
    // of the request and the buffer capacity to keep the allocation bounded.
    let capacity = audit::global().map(|buffer| buffer.capacity()).unwrap_or(0);
    let count = max_records.min(capacity as usize);
    let mut records: alloc::vec::Vec<AuditRecord> = alloc::vec![AuditRecord::zeroed(); count];
    let n = audit::read_records(&mut records);

    if n > 0 {
        // Copy records to user space using the validated output slice helper.
        let total_bytes = n * expected_size;
        user_memory::with_optional_output_slice(buf_ptr, total_bytes, |out| {
            let src = records.as_ptr() as *const u8;
            // SAFETY: `out` has been validated against the user address space
            // and has exactly `total_bytes` bytes of writable capacity.
            unsafe {
                core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), total_bytes);
            }
            Ok(())
        })?;
    }

    Ok(SyscallDispatch::complete(n))
}

#[cfg(test)]
mod tests {
    use super::{audit_read_log, audit_set_enable};
    use crate::kernel::audit::types::AUDIT_ENABLE_ALL;
    use crate::kernel::syscall::{SyscallContext, SyscallDispatch, SyscallNumber};
    use crate::Error;

    #[test]
    fn audit_set_enable_rejects_unknown_mask_bits() {
        let mut context = SyscallContext::new(
            SyscallNumber::AuditSetEnable as usize,
            [(AUDIT_ENABLE_ALL | (1u64 << 63)) as usize, 0, 0, 0, 0, 0],
        );

        assert_eq!(audit_set_enable(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn audit_read_log_rejects_null_buffer() {
        let mut context = SyscallContext::new(
            SyscallNumber::AuditReadLog as usize,
            [
                0,
                1,
                core::mem::size_of::<crate::kernel::audit::types::AuditRecord>(),
                0,
                0,
                0,
            ],
        );

        assert_eq!(audit_read_log(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn audit_read_log_rejects_wrong_record_size() {
        let mut context =
            SyscallContext::new(SyscallNumber::AuditReadLog as usize, [1, 1, 1, 0, 0, 0]);

        assert_eq!(audit_read_log(&mut context), Err(Error::InvalidArgument));
    }

    #[test]
    fn audit_read_log_returns_zero_when_audit_buffer_is_absent() {
        let mut buffer = [0u8; 8];
        let mut context = SyscallContext::new(
            SyscallNumber::AuditReadLog as usize,
            [
                buffer.as_mut_ptr() as usize,
                4,
                core::mem::size_of::<crate::kernel::audit::types::AuditRecord>(),
                0,
                0,
                0,
            ],
        );

        // With no audit buffer installed, read_records returns 0 records.
        let result = audit_read_log(&mut context);
        assert_eq!(result, Ok(SyscallDispatch::complete(0)));
    }
}
