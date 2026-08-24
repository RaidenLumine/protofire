//! src/kernel/syscall/seccomp.rs
//!
//! Seccomp syscall handler (#129).
//!
//! Dispatches seccomp operations to the core logic in
//! `src/kernel/process/seccomp.rs`.

use crate::abi::seccomp::{
    SeccompFilterRule, SeccompRuleHeader, SECCOMP_FILTER_RULE_SIZE, SECCOMP_MAX_RULES,
    SECCOMP_RULE_HEADER_SIZE, SECCOMP_SET_MODE_FILTER,
};
use crate::kernel::process::seccomp as seccomp_core;
use crate::{Error, Result};

use super::user_memory;
use super::{runtime, SyscallContext, SyscallDispatch};

/// Syscall #129: Seccomp — secure computing / syscall filtering.
///
/// Arguments:
///   arg0 = operation (i32) — SECCOMP_SET_*
///   arg1 = flags (u32) — reserved, must be 0
///   arg2 = data_ptr (usize) — pointer to filter data (header + rules)
///   arg3 = data_len (usize) — total size of filter data in bytes
///
/// For `SECCOMP_SET_MODE_FILTER`:
///   `data_ptr` points to a `SeccompRuleHeader` followed by `rule_count`
///   `SeccompFilterRule` entries.  The total `data_len` must equal
///   `SECCOMP_RULE_HEADER_SIZE + rule_count * SECCOMP_FILTER_RULE_SIZE`.
///
/// Returns 0 on success, or an error code.
pub(super) fn seccomp(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    let operation = context.arg(0) as i32;
    let _flags = context.arg(1) as u32;
    let data_ptr = context.arg(2) as *const u8;
    let data_len = context.arg(3);

    let process = runtime::current_process().map_err(|_| Error::Unsupported)?;

    match operation {
        SECCOMP_SET_MODE_FILTER => {
            if data_ptr.is_null() || data_len < SECCOMP_RULE_HEADER_SIZE {
                return Err(Error::InvalidArgument);
            }

            // Read the header from user space.
            let header: SeccompRuleHeader =
                user_memory::read_user_value(data_ptr, data_len, SECCOMP_RULE_HEADER_SIZE)?;

            if header.flags != 0 {
                return Err(Error::InvalidArgument);
            }
            let rule_count = header.rule_count as usize;
            if rule_count > SECCOMP_MAX_RULES {
                return Err(Error::InvalidArgument);
            }

            let rules_byte_len = rule_count
                .checked_mul(SECCOMP_FILTER_RULE_SIZE)
                .ok_or(Error::InvalidArgument)?;
            let expected_total = SECCOMP_RULE_HEADER_SIZE
                .checked_add(rules_byte_len)
                .ok_or(Error::InvalidArgument)?;
            if data_len != expected_total {
                return Err(Error::InvalidArgument);
            }

            // Read the rules from user space via the validated input-slice API.
            let rules_ptr = unsafe { data_ptr.add(SECCOMP_RULE_HEADER_SIZE) };
            user_memory::with_optional_input_slice(rules_ptr, rules_byte_len, |bytes| {
                if bytes.len() != rules_byte_len {
                    return Err(Error::InvalidArgument);
                }
                let rules = unsafe {
                    core::slice::from_raw_parts(
                        bytes.as_ptr() as *const SeccompFilterRule,
                        rule_count,
                    )
                };
                seccomp_core::install_filter(&process, &header, rules)
            })?;

            Ok(SyscallDispatch::complete(0))
        }
        _ => Err(Error::NotImplemented),
    }
}
