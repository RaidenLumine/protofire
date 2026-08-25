//! src/kernel/syscall/mac.rs
//!
//! MAC (mandatory access control) type-enforcement policy syscalls (#175-178).

use crate::abi::mac::MacRule as AbiMacRule;
use crate::abi::mac::MAC_FLAG_REPLACE;
use crate::abi::mac::MAC_RULE_SIZE;
use crate::abi::mac::MAC_STATUS_SIZE;
use crate::kernel::process::mac::policy_state;
use crate::kernel::process::mac::set_path_type;
use crate::kernel::process::mac::MacRule;
use crate::kernel::process::mac::MacStatus;
use crate::Error;
use crate::Result;

/// Syscall 175: mac_set_mode(enabled, default_deny, flags) → previous enabled.
pub(super) fn mac_set_mode(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let enabled = context.arg(0) as u32;
    let default_deny = context.arg(1) as u32;
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;

    let mut state = policy_state().lock();
    let previous = u32::from(state.policy.enabled);
    state.policy.enabled = enabled != 0;
    state.policy.default_deny = default_deny != 0;
    drop(state);

    Ok(super::SyscallDispatch::complete(previous as usize))
}

/// Syscall 176: mac_add_rule(&MacRule, len, flags).
pub(super) fn mac_add_rule(context: &mut super::SyscallContext) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    let flags = context.arg(2) as u32;
    super::validate_known_flags(flags as usize, MAC_FLAG_REPLACE as usize)?;
    super::validate_zeroed_args(context, 3)?;
    if len != MAC_RULE_SIZE {
        return Err(Error::InvalidArgument);
    }

    let abi_rule: AbiMacRule = super::user_memory::read_user_value(ptr, len, MAC_RULE_SIZE)?;
    let rule = MacRule {
        subject: abi_rule.subject,
        object: abi_rule.object,
        class: abi_rule.class,
        perms: abi_rule.perms,
    };
    let replace = flags & MAC_FLAG_REPLACE != 0;
    policy_state().lock().policy.add_rule(rule, replace);
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 177: mac_set_path_type(path, path_len, mac_type, flags).
pub(super) fn mac_set_path_type(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    let mac_type = context.arg(2) as u32;
    let flags = context.arg(3) as u32;
    super::validate_known_flags(flags as usize, MAC_FLAG_REPLACE as usize)?;
    super::validate_zeroed_args(context, 4)?;

    let path = super::user_memory::user_bounded_str(ptr, len, 4096)?;
    set_path_type(path, mac_type);
    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall 178: mac_get_status(&MacStatus, len, flags).
pub(super) fn mac_get_status(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);
    super::validate_known_flags(context.arg(2), 0)?;
    super::validate_zeroed_args(context, 3)?;
    if len != MAC_STATUS_SIZE {
        return Err(Error::InvalidArgument);
    }
    super::user_memory::validate_current_process_user_output_buffer(ptr, len, MAC_STATUS_SIZE)?;

    let state = policy_state().lock();
    let status = MacStatus {
        enabled: state.policy.enabled,
        default_deny: state.policy.default_deny,
        rule_count: state.policy.rule_count(),
        label_count: state.label_count(),
    };
    drop(state);

    let mut buf = [0u8; MAC_STATUS_SIZE];
    buf[0..4].copy_from_slice(&u32::from(status.enabled).to_ne_bytes());
    buf[4..8].copy_from_slice(&u32::from(status.default_deny).to_ne_bytes());
    buf[8..12].copy_from_slice(&(status.rule_count as u32).to_ne_bytes());
    buf[12..16].copy_from_slice(&(status.label_count as u32).to_ne_bytes());

    super::user_memory::copy_user_bytes(&buf, ptr, len)?;
    Ok(super::SyscallDispatch::complete(0))
}
