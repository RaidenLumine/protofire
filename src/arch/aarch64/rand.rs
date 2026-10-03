//! src/arch/aarch64/rand.rs
//!
//! Hardware random number generator wrappers for AArch64 (RNDR / RNDRRS).
//!
//! ARMv8.5+ defines RNDR (architecturally-conditioned random number) and
//! RNDRRS (reseeding random number).  Both return a 64-bit value and set
//! the Z flag (NZCV bit 30) to 1 when a valid random number was produced.
//! When the hardware entropy pool is exhausted, Z=0 and the returned value
//! should be discarded.

// The RNDR wrappers are bare-metal only; a host build keeps them for the
// entropy API but never calls them.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

/// Collect this machine's hardware entropy: RNDR, then RNDRRS.
///
/// The bytes are raw material, not a seed: the caller mixes them with
/// whatever else it has and hashes the result.  An empty return means the CPU
/// has no RNDR — a pre-ARMv8.5 part, or any host build — and the caller's own
/// fallback is then the only entropy there is.
#[must_use]
pub fn hardware_entropy() -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;

    let mut material = Vec::new();

    if has_rndr() {
        let mut buf = [0u8; 64];
        let filled = rndr_fill(&mut buf);
        material.extend_from_slice(&buf[..filled]);
        // RNDRRS reseeds the source before reading, so a few of them add
        // what the RNDR stream cannot.
        for _ in 0..4 {
            if let Some(value) = rndrrs_u64() {
                material.extend_from_slice(&value.to_ne_bytes());
            }
        }
    }

    material
}

#[cfg(target_os = "none")]
use core::arch::asm;

/// Maximum retry count when the entropy source is temporarily exhausted.
const RNDR_MAX_RETRIES: u32 = 10;

/// Check whether the CPU supports RNDR/RNDRRS (ARMv8.5+).
///
/// Reads `ID_AA64ISAR0_EL1` and checks the RNDR field (bits [63:60]).
/// A non-zero value indicates hardware RNG support.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn has_rndr() -> bool {
    let isar0: u64;

    // SAFETY: ID_AA64ISAR0_EL1 is readable from EL1 and the instruction touches no
    // memory.
    unsafe {
        asm!(
            "mrs {isar0}, ID_AA64ISAR0_EL1",
            isar0 = out(reg) isar0,
            options(nomem, nostack),
        );
    }

    // RNDR field is bits [63:60] of ID_AA64ISAR0_EL1.
    let rndr_field = (isar0 >> 60) & 0xF;
    rndr_field != 0
}

/// Read a 64-bit random value via RNDR.
///
/// Returns `Some(u64)` on success (Z=1) or `None` after exhausting retries.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn rndr_u64() -> Option<u64> {
    for _ in 0..RNDR_MAX_RETRIES {
        let value: u64;
        let success: u64;

        // SAFETY: `RNDR` writes one register and reports success in PSTATE, which the
        // `cset` captures; no memory operand.
        unsafe {
            // RNDR writes to the destination register and updates PSTATE,
            // setting Z=1 when a valid random number was produced.  CSET EQ
            // captures that condition into a general register we can test.
            asm!(
                "mrs {value}, RNDR",
                "cset {success}, eq",
                value = out(reg) value,
                success = out(reg) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }
    }

    None
}

/// Read a 64-bit reseeding random value via RNDRRS.
///
/// RNDRRS guarantees a fresh entropy draw (not just a PRNG output).
/// Returns `Some(u64)` on success or `None` after exhausting retries.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn rndrrs_u64() -> Option<u64> {
    for _ in 0..RNDR_MAX_RETRIES {
        let value: u64;
        let success: u64;

        // SAFETY: as the `RNDR` loop above — `RNDRRS`, same shape.
        unsafe {
            asm!(
                "mrs {value}, RNDRRS",
                "cset {success}, eq",
                value = out(reg) value,
                success = out(reg) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }
    }

    None
}

/// Fill `buf` with random bytes using RNDR in 8-byte chunks.
///
/// Returns the number of bytes filled (may be less than `buf.len()`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn rndr_fill(buf: &mut [u8]) -> usize {
    let mut filled = 0;

    while filled + 8 <= buf.len() {
        match rndr_u64() {
            Some(value) => {
                buf[filled..filled + 8].copy_from_slice(&value.to_ne_bytes());
                filled += 8;
            }
            None => break,
        }
    }

    if filled < buf.len() {
        if let Some(value) = rndr_u64() {
            let bytes = value.to_ne_bytes();
            let remaining = buf.len() - filled;
            buf[filled..].copy_from_slice(&bytes[..remaining]);
            filled += remaining;
        }
    }

    filled
}

// Stubs for non-bare-metal / non-aarch64 targets.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn has_rndr() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn rndr_u64() -> Option<u64> {
    None
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn rndrrs_u64() -> Option<u64> {
    None
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn rndr_fill(_buf: &mut [u8]) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rndr_stubs_return_none_on_host() {
        assert_eq!(rndr_u64(), None);
        assert_eq!(rndrrs_u64(), None);

        let mut buf = [0u8; 32];
        assert_eq!(rndr_fill(&mut buf), 0);
    }
}
