//! src/kernel/syscall/power.rs
//! CPU frequency scaling system call handlers.

use crate::kernel::power;
use crate::kernel::power::governors::GovernorType;
use crate::kernel::syscall::{SyscallContext, SyscallDispatch};
use crate::{Error, Result};

/// Get current CPU frequency (KHz) — SYS_CPUFREQ_GET = 145
pub(super) fn cpufreq_get(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    // All extra arguments must be zero
    for arg in ctx.args.iter().skip(1) {
        if *arg != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    let freq = power::get_current_freq();
    Ok(SyscallDispatch::complete(freq as usize))
}

/// Set CPU frequency (KHz) — SYS_CPUFREQ_SET = 146
pub(super) fn cpufreq_set(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let target_freq = ctx.args[0];
    if target_freq == 0 {
        return Err(Error::InvalidArgument);
    }

    // Extra arguments must be zero
    for arg in ctx.args.iter().skip(1) {
        if *arg != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    match crate::arch::arch_set_freq(target_freq as u32) {
        Ok(()) => {
            power::update_freq_cache();
            Ok(SyscallDispatch::complete(0))
        }
        Err(e) => Err(e),
    }
}

/// Get frequency range (KHz) — SYS_CPUFREQ_GET_RANGE = 147
/// Returns: low 32 bits = min, high 32 bits = max
pub(super) fn cpufreq_get_range(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    for arg in ctx.args.iter().skip(1) {
        if *arg != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    if let Some((min, max)) = power::get_freq_range() {
        let result = ((max as u64) << 32) | (min as u64);
        Ok(SyscallDispatch::complete(result as usize))
    } else {
        Err(Error::Unsupported)
    }
}

/// Set governor — SYS_CPUFREQ_SET_GOVERNOR = 148
pub(super) fn cpufreq_set_governor(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    let gov_type = ctx.args[0];
    for arg in ctx.args.iter().skip(1) {
        if *arg != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    let gov = match gov_type {
        0 => GovernorType::Performance,
        1 => GovernorType::Powersave,
        2 => GovernorType::Ondemand,
        3 => GovernorType::Schedutil,
        4 => GovernorType::Userspace,
        _ => return Err(Error::InvalidArgument),
    };

    power::set_governor(gov);
    Ok(SyscallDispatch::complete(0))
}

/// Get CPU temperature (millidegrees C) — SYS_CPUFREQ_GET_TEMP = 149
pub(super) fn cpufreq_get_temp(ctx: &mut SyscallContext) -> Result<SyscallDispatch> {
    for arg in ctx.args.iter().skip(1) {
        if *arg != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    match power::get_temperature_mc() {
        Some(temp) => Ok(SyscallDispatch::complete(temp as usize)),
        None => Err(Error::Unsupported),
    }
}
