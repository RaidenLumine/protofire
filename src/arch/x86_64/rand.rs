//! src/arch/x86_64/rand.rs
//!
//! Hardware random number generator wrappers (RDRAND / RDSEED).
//!
//! RDRAND provides a hardware-backed random value reseeded at up to 800 MB/s.
//! RDSEED draws directly from the entropy source and may be slower.
//! Both instructions set CF=1 on success and return 0 / CF=0 when the
//! hardware is temporarily exhausted (Intel recommends up to 10 retries).

/// Maximum retry count per Intel RNG software implementation guide (§4.2.1).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const RDRAND_MAX_RETRIES: u32 = 10;

/// Read a 64-bit hardware random value via RDRAND.
///
/// Returns `Some(u64)` on success or `None` after exhausting retries.
/// RDRAND is available on Ivy Bridge+ (2012).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rdrand_u64() -> Option<u64> {
    for _ in 0..RDRAND_MAX_RETRIES {
        let mut value: u64;
        let success: u8;

        unsafe {
            core::arch::asm!(
                "rdrand {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }

        // Intel recommends a PAUSE in the retry loop on hot paths.
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }

    None
}

/// Read a 64-bit hardware seed value via RDSEED.
///
/// Returns `Some(u64)` on success or `None` after exhausting retries.
/// RDSEED draws from a lower-bandwidth entropy source; prefer RDRAND for
/// bulk CSPRNG seeding, RDSEED for one-shot seeds.
/// RDSEED is available on Broadwell+ (2014).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rdseed_u64() -> Option<u64> {
    for _ in 0..RDRAND_MAX_RETRIES {
        let mut value: u64;
        let success: u8;

        unsafe {
            core::arch::asm!(
                "rdseed {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }

        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }

    None
}

/// Fill `buf` with hardware random bytes using RDRAND in 8-byte chunks.
///
/// Returns the number of bytes successfully filled (may be less than
/// `buf.len()` if the hardware entropy source is exhausted).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn rdrand_fill(buf: &mut [u8]) -> usize {
    let mut filled = 0;

    while filled + 8 <= buf.len() {
        match rdrand_u64() {
            Some(value) => {
                buf[filled..filled + 8].copy_from_slice(&value.to_ne_bytes());
                filled += 8;
            }
            None => break,
        }
    }

    // Handle trailing bytes (fewer than 8).
    if filled < buf.len() {
        match rdrand_u64() {
            Some(value) => {
                let bytes = value.to_ne_bytes();
                let remaining = buf.len() - filled;
                buf[filled..].copy_from_slice(&bytes[..remaining]);
                filled += remaining;
            }
            None => {}
        }
    }

    filled
}

// Stub for non-bare-metal targets.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn rdrand_u64() -> Option<u64> {
    None
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn rdseed_u64() -> Option<u64> {
    None
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub fn rdrand_fill(_buf: &mut [u8]) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdrand_stubs_return_none_on_host() {
        // On host targets (not bare-metal), RDRAND/RDSEED are unavailable
        // and the stubs always return None.
        assert_eq!(rdrand_u64(), None);
        assert_eq!(rdseed_u64(), None);

        let mut buf = [0u8; 32];
        assert_eq!(rdrand_fill(&mut buf), 0);
    }
}
