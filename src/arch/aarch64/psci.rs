//! src/arch/aarch64/psci.rs
//!
//! ARM Power State Coordination Interface (PSCI) calls, used for reboot and
//! power-off on AArch64.
//!
//! PSCI is reached through the SMCCC conduit: register-only `smc` (secure
//! monitor, e.g. QEMU virt) or `hvc` (hypervisor) calls.  All function IDs
//! and argument conventions are compile-time constants, so there is no
//! untrusted input surface.

use core::arch::asm;

/// Conduit used to reach EL3/EL2 via SMCCC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciConduit {
    /// Secure monitor call (`smc #0`) — used by QEMU virt and most
    /// bare-metal firmware.
    Smc,
    /// Hypervisor call (`hvc #0`).
    Hvc,
}

// PSCI 0.2 function IDs (PSCI specification, §5).
// The FN64 (0xC4xx_xxxx) range uses 64-bit arguments in x1..x3.
const PSCI_0_2_FN_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_0_2_FN64_SYSTEM_RESET: u64 = 0xC400_0009;
const PSCI_0_2_FN64_SYSTEM_RESET2: u64 = 0xC400_0012;
const PSCI_0_2_FN_PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_0_2_FN64_CPU_ON: u64 = 0xC400_0003;

/// PSCI version, or `None` when the interface does not answer.
///
/// Worth asking before anything else: a call that is unsupported returns a
/// negative status, and a bring-up path that assumed support would report a
/// core as started that never moved.
#[allow(dead_code)] // the AP wiring calls this next
pub fn version() -> Option<u32> {
    let result = unsafe { psci_call(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0) };
    (result >= 0).then_some(result as u32)
}

/// Bring one CPU up at `entry`, with `context` placed in its `x0`.
///
/// Returns the PSCI status rather than a flag the caller has to watch: a core
/// that did not start says so, at the call, with a reason.
///
/// # Safety
///
/// `entry` must be a valid kernel entry point and `context` whatever that
/// entry expects to receive.
#[allow(dead_code)] // the AP wiring calls this next
pub unsafe fn cpu_on(target_cpu: u64, entry: u64, context: u64) -> Result<(), i64> {
    let result = unsafe { psci_call(PSCI_0_2_FN64_CPU_ON, target_cpu, entry, context) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

/// Configured conduit.  QEMU virt and most firmware expose PSCI via `smc`;
/// a firmware tree walker could set `hvc` at boot if needed.
static CONDUIT: PsciConduit = PsciConduit::Smc;

/// Invoke a PSCI call via the configured conduit.
///
/// SMCCC convention: x0 = function ID, x1..x3 = arguments, x0 = return
/// value.  A negative return is an error (e.g. NOT_SUPPORTED).
///
/// # Safety
///
/// The function IDs and arguments must be valid PSCI values.  A malformed
/// call may trap to EL3/EL2.
unsafe fn psci_call(fnid: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let mut result: i64;
    match CONDUIT {
        PsciConduit::Smc => {
            asm!(
                "smc #0",
                in("x0") fnid,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                lateout("x0") result,
                options(nomem, nostack, preserves_flags),
            );
        }
        PsciConduit::Hvc => {
            asm!(
                "hvc #0",
                in("x0") fnid,
                in("x1") arg0,
                in("x2") arg1,
                in("x3") arg2,
                lateout("x0") result,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    result
}

/// Reset the machine.  Tries `SYSTEM_RESET`, then `SYSTEM_RESET2`
/// (for firmware that only implements the v1.1 entry point), and falls back
/// to an infinite halt loop if PSCI is unavailable or errors.
pub fn system_reset() -> ! {
    unsafe {
        let status = psci_call(PSCI_0_2_FN64_SYSTEM_RESET, 0, 0, 0);
        if status < 0 {
            let _ = psci_call(PSCI_0_2_FN64_SYSTEM_RESET2, 0, 0, 0);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Power off the machine.  Falls back to an infinite halt loop if PSCI is
/// unavailable or errors.
pub fn system_off() -> ! {
    unsafe {
        let _ = psci_call(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}
