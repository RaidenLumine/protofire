//! src/kernel/syscall/filter.rs
//!
//! Packet filter / firewall syscall handlers.
//!
//! Provides syscalls #122–#125 for managing the kernel's packet filter:
//! - `FilterAddRule` (122)   — add a firewall rule, returns rule_id
//! - `FilterRemoveRule` (123) — remove a rule by id
//! - `FilterSetDefaultAction` (124) — set default allow/deny
//! - `FilterGetStats` (125)  — retrieve filter statistics

use crate::abi::filter::{
    FilterRuleDef, FilterStats, FILTER_DEFAULT_ALLOW, FILTER_DEFAULT_DENY, FILTER_RULE_DEF_SIZE,
    FILTER_STATS_SIZE,
};
use crate::kernel::network::filter::FilterAction;
use crate::{Error, Result};

/// Syscall #122: FilterAddRule — add a firewall rule from a user-supplied
/// `FilterRuleDef` struct.
///
/// Arguments:
///   arg0 = pointer to FilterRuleDef in user memory
///   arg1 = length of FilterRuleDef (must equal FILTER_RULE_DEF_SIZE)
///   arg2 = flags (must be 0)
///   arg3 = reserved (must be 0)
///
/// Returns the assigned rule id (u64).
pub(super) fn filter_add_rule(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *const u8;
    let len = context.arg(1);
    let flags = context.arg(2);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 3)?;

    if len != FILTER_RULE_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }

    let def: FilterRuleDef = super::user_memory::read_user_value(ptr, len, FILTER_RULE_DEF_SIZE)?;

    let result = crate::kernel::network::stack::NetworkStack::global()
        .ok_or(Error::Unsupported)
        .and_then(|stack| {
            let mut filter = stack.filter_table().lock();
            filter.add_rule(&def)
        })?;

    Ok(super::SyscallDispatch::complete(result as usize))
}

/// Syscall #123: FilterRemoveRule — remove a firewall rule by id.
///
/// Arguments:
///   arg0 = rule_id
///   arg1 = flags (must be 0)
///
/// Returns 0 on success, or Error::NotFound if no such rule.
pub(super) fn filter_remove_rule(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let rule_id = context.arg(0) as u64;
    let flags = context.arg(1);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 2)?;

    crate::kernel::network::stack::NetworkStack::global()
        .ok_or(Error::Unsupported)
        .and_then(|stack| {
            let mut filter = stack.filter_table().lock();
            if filter.remove_rule(rule_id) {
                Ok(())
            } else {
                Err(Error::NotFound)
            }
        })?;

    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall #124: FilterSetDefaultAction — set the default filter policy.
///
/// Arguments:
///   arg0 = action (0 = Allow, 1 = Deny)
///   arg1 = flags (must be 0)
///
/// Returns 0 on success.
pub(super) fn filter_set_default_action(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let action = context.arg(0);
    let flags = context.arg(1);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 2)?;

    match action {
        0 => {
            // FILTER_DEFAULT_ALLOW
            crate::kernel::network::stack::NetworkStack::global()
                .ok_or(Error::Unsupported)?
                .filter_table()
                .lock()
                .set_default_action(FilterAction::Allow);
        }
        1 => {
            // FILTER_DEFAULT_DENY
            crate::kernel::network::stack::NetworkStack::global()
                .ok_or(Error::Unsupported)?
                .filter_table()
                .lock()
                .set_default_action(FilterAction::Deny);
        }
        _ => return Err(Error::InvalidArgument),
    }

    Ok(super::SyscallDispatch::complete(0))
}

/// Syscall #125: FilterGetStats — retrieve filter statistics into a
/// user-supplied `FilterStats` struct.
///
/// Arguments:
///   arg0 = pointer to FilterStats output buffer in user memory
///   arg1 = length of output buffer (must equal FILTER_STATS_SIZE)
///   arg2 = flags (must be 0)
///
/// Returns 0 on success.
pub(super) fn filter_get_stats(
    context: &mut super::SyscallContext,
) -> Result<super::SyscallDispatch> {
    let ptr = context.arg(0) as *mut u8;
    let len = context.arg(1);
    let flags = context.arg(2);

    super::validate_known_flags(flags, 0)?;
    super::validate_zeroed_args(context, 3)?;

    if len != FILTER_STATS_SIZE {
        return Err(Error::InvalidArgument);
    }

    let stats = crate::kernel::network::stack::NetworkStack::global()
        .ok_or(Error::Unsupported)
        .map(|stack| {
            let filter = stack.filter_table().lock();
            FilterStats {
                enabled: if filter.is_enabled() { 1 } else { 0 },
                default_action: match filter.default_action() {
                    FilterAction::Allow => FILTER_DEFAULT_ALLOW,
                    FilterAction::Deny => FILTER_DEFAULT_DENY,
                },
                num_rules: filter.num_rules(),
                active_flows: filter.num_flows(),
                packets_dropped: filter.packets_dropped(),
                packets_allowed: filter.packets_allowed(),
            }
        })?;

    // Serialize FilterStats (32 bytes: 4 u32s + 2 u64s) and write to user memory.
    let mut buf = [0u8; FILTER_STATS_SIZE];
    let (header, body) = buf.split_at_mut(16);
    // enabled (u32 LE) at offset 0
    header[0..4].copy_from_slice(&stats.enabled.to_ne_bytes());
    // default_action (u32 LE) at offset 4
    header[4..8].copy_from_slice(&stats.default_action.to_ne_bytes());
    // num_rules (u32 LE) at offset 8
    header[8..12].copy_from_slice(&stats.num_rules.to_ne_bytes());
    // active_flows (u32 LE) at offset 12
    header[12..16].copy_from_slice(&stats.active_flows.to_ne_bytes());
    // packets_dropped (u64 LE) at offset 16
    body[0..8].copy_from_slice(&stats.packets_dropped.to_ne_bytes());
    // packets_allowed (u64 LE) at offset 24
    body[8..16].copy_from_slice(&stats.packets_allowed.to_ne_bytes());

    super::user_memory::copy_user_bytes(&buf, ptr, len)?;

    Ok(super::SyscallDispatch::complete(0))
}
