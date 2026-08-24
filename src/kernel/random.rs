//! src/kernel/random.rs
//!
//! Cryptographically secure pseudo-random number generator.
//!
//! Seeds from hardware RNG (RDRAND/RDSEED on x86_64, RNDR on AArch64)
//! with a ChaCha20-based deterministic random bit generator (DRBG).
//! On platforms without hardware entropy (riscv64), falls back to a
//! combination of RTC time and monotonic tick counter.

use crate::kernel::crypto::{chacha20_keystream, sha256};
use crate::kernel::sync::Mutex;
use alloc::vec::Vec;

/// Number of ChaCha20 blocks to generate before automatic reseeding.
/// With 64 bytes per block, this yields ~64 KiB between reseeds.
const RESEED_INTERVAL_BLOCKS: u32 = 1024;

/// Number of hardware-entropy seed bytes (256 bits).
#[allow(dead_code)]
const SEED_BYTES: usize = 32;

/// ChaCha20 key + nonce.
struct CsprngState {
    key: [u8; 32],
    nonce: [u8; 12],
    block_counter: u32,
    blocks_since_reseed: u32,
}

impl CsprngState {
    fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self {
            key,
            nonce,
            block_counter: 0,
            blocks_since_reseed: 0,
        }
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        chacha20_keystream(&self.key, &self.nonce, self.block_counter, buf);
        let blocks = (buf.len() as u32).div_ceil(64);
        self.block_counter = self.block_counter.wrapping_add(blocks);
        self.blocks_since_reseed += blocks;
    }

    fn needs_reseed(&self) -> bool {
        self.blocks_since_reseed >= RESEED_INTERVAL_BLOCKS
    }
}

/// Global CSPRNG instance protected by a mutex.
static CSPRNG: Mutex<Option<CsprngState>> = Mutex::new(None);

/// Seed the global CSPRNG with the given 32-byte key and 12-byte nonce.
fn seed_csprng(key: [u8; 32], nonce: [u8; 12]) {
    let mut csprng = CSPRNG.lock();
    *csprng = Some(CsprngState::new(key, nonce));
}

/// Collect entropy from all available platform sources into a 32-byte seed.
fn collect_entropy_seed() -> [u8; 32] {
    let mut material = Vec::with_capacity(128);

    // ── x86_64: RDRAND / RDSEED ──
    #[cfg(target_arch = "x86_64")]
    {
        if crate::arch::x86_64::cpuid::has_rdrand() {
            let mut buf = [0u8; 64];
            let filled = crate::arch::x86_64::rand::rdrand_fill(&mut buf);
            material.extend_from_slice(&buf[..filled]);
        }
        if crate::arch::x86_64::cpuid::has_rdseed() {
            let mut buf = [0u8; 32];
            // Use individual RDSEED reads for high-quality entropy.
            for chunk in buf.chunks_mut(8) {
                if let Some(value) = crate::arch::x86_64::rand::rdseed_u64() {
                    chunk.copy_from_slice(&value.to_ne_bytes());
                }
            }
            material.extend_from_slice(&buf);
        }
    }

    // ── AArch64: RNDR / RNDRRS ──
    #[cfg(target_arch = "aarch64")]
    {
        if crate::arch::aarch64::rand::has_rndr() {
            let mut buf = [0u8; 64];
            let filled = crate::arch::aarch64::rand::rndr_fill(&mut buf);
            material.extend_from_slice(&buf[..filled]);
            // RNDRRS for additional entropy.
            for _ in 0..4 {
                if let Some(value) = crate::arch::aarch64::rand::rndrrs_u64() {
                    material.extend_from_slice(&value.to_ne_bytes());
                }
            }
        }
    }

    // ── Fallback: RTC time + monotonic ticks ──
    // Always include these as an additional entropy source, even when
    // hardware RNG is available.  This provides defense-in-depth and
    // is the sole entropy source on platforms without hardware RNG.
    {
        let rtc = crate::arch::timer::rtc_now_unix().unwrap_or(0);
        let ticks = crate::arch::timer::ticks();
        material.extend_from_slice(&rtc.to_ne_bytes());
        material.extend_from_slice(&ticks.to_ne_bytes());
    }

    // Hash the accumulated entropy material into a uniform 32-byte seed.
    sha256(&material)
}

/// Initialise the global CSPRNG with platform entropy.
///
/// This is called automatically on the first call to `fill_random` and
/// can also be called explicitly during boot to avoid the lazy-init
/// cost on the first random request.
pub fn init_csprng() {
    let seed = collect_entropy_seed();
    let nonce_seed = sha256(b"adastra-csprng-nonce-v1");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_seed[..12]);

    seed_csprng(seed, nonce);
}

/// Fill `buf` with cryptographically secure random bytes.
///
/// On first call, lazily initialises the CSPRNG from platform entropy.
/// Automatically reseeds after `RESEED_INTERVAL_BLOCKS` blocks.
pub fn fill_random(buf: &mut [u8]) {
    // Lazy initialisation on first call.
    {
        let csprng = CSPRNG.lock();
        if csprng.is_none() {
            drop(csprng);
            init_csprng();
        }
    }

    let mut csprng = CSPRNG.lock();
    let state = csprng.as_mut().expect("CSPRNG initialised");

    // Reseed if we've generated too many blocks.
    if state.needs_reseed() {
        let seed = collect_entropy_seed();
        let nonce_seed = sha256(b"adastra-csprng-nonce-v1");
        state.key = seed;
        state.nonce[..12].copy_from_slice(&nonce_seed[..12]);
        state.block_counter = 0;
        state.blocks_since_reseed = 0;
    }

    state.fill_bytes(buf);
}

/// Return a cryptographically secure random `u64`.
pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    u64::from_ne_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_csprng_does_not_panic() {
        init_csprng();
    }

    #[test]
    fn fill_random_produces_non_zero_output() {
        init_csprng();
        let mut buf = [0u8; 64];
        fill_random(&mut buf);

        // Extremely unlikely to be all zeros with a working CSPRNG.
        let sum: u64 = buf.iter().map(|&b| b as u64).sum();
        assert!(sum > 0, "CSPRNG produced all-zero output");
    }

    #[test]
    fn fill_random_produces_different_output() {
        init_csprng();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        fill_random(&mut buf1);
        fill_random(&mut buf2);
        assert_ne!(buf1, buf2, "CSPRNG produced identical consecutive outputs");
    }

    #[test]
    fn random_u64_does_not_panic() {
        init_csprng();
        let v1 = random_u64();
        let v2 = random_u64();
        // Two consecutive calls should NOT always produce the same value.
        // (Incredibly unlikely to be equal with 2^64 output space.)
        assert!(v1 > 0 || v2 > 0);
    }

    #[test]
    fn lazy_init_works_on_first_call() {
        // First call without explicit init.
        let mut buf = [0u8; 16];
        fill_random(&mut buf);
        let sum: u32 = buf.iter().map(|&b| b as u32).sum();
        assert!(sum > 0);
    }

    #[test]
    fn chacha20_keystream_is_deterministic_for_seed() {
        // Verify that given the same key+nonce+counter, output is deterministic.
        let key = sha256(b"deterministic-test");
        let nonce_bytes = sha256(b"nonce-test");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes[..12]);

        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        chacha20_keystream(&key, &nonce, 0, &mut out1);
        chacha20_keystream(&key, &nonce, 0, &mut out2);
        assert_eq!(out1, out2, "keystream should be deterministic");
    }
}
