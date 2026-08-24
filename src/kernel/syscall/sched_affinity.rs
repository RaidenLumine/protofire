//! src/kernel/syscall/sched_affinity.rs
//!
//! sched_setaffinity / sched_getaffinity — CPU affinity management.
//!
//! # Syscalls
//!
//! `SchedSetAffinity = 110`
//! - `arg(0)` = `cpu_mask: u32` — bitmask of allowed CPUs (bit N = CPU N)
//!
//! `SchedGetAffinity = 111`
//! - no arguments — returns the current thread's CPU affinity mask

use super::runtime;
use crate::kernel::smp;
use crate::kernel::syscall::SyscallContext;
use crate::Result;

/// Handler for `SchedSetAffinity` syscall (#110).
///
/// Pins the calling thread to the CPUs indicated in `cpu_mask`.
/// Returns an error if the mask is empty or contains no online CPUs.
pub fn sched_setaffinity(
    ctx: &mut SyscallContext,
) -> Result<crate::kernel::syscall::SyscallDispatch> {
    let cpu_mask = ctx.arg(0) as u32;

    if cpu_mask == 0 {
        return Err(crate::Error::InvalidArgument);
    }

    // Find the first online CPU in the mask.
    let online_count = smp::online_cpu_count();
    let target = (0..online_count).find(|cpu| (cpu_mask & (1 << cpu)) != 0);

    match target {
        Some(cpu) => runtime::with_current_thread(|thread| {
            thread.set_cpu_affinity(cpu);
            Ok(crate::kernel::syscall::SyscallDispatch::complete(0))
        }),
        None => Err(crate::Error::InvalidArgument),
    }
}

/// Handler for `SchedGetAffinity` syscall (#111).
///
/// Returns the current thread's CPU affinity as a bitmask.
pub fn sched_getaffinity(
    _ctx: &mut SyscallContext,
) -> Result<crate::kernel::syscall::SyscallDispatch> {
    runtime::with_current_thread(|thread| {
        let cpu = thread.cpu_affinity();
        let mask = if cpu == 0 {
            // "Any CPU" — return mask of all online CPUs.
            let online = smp::online_cpu_count();
            let all: u32 = if online >= 32 {
                !0u32
            } else {
                (1 << online) - 1
            };
            all
        } else {
            1 << cpu
        };
        Ok(crate::kernel::syscall::SyscallDispatch::complete(
            mask as usize,
        ))
    })
}
