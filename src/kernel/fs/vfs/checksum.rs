//! src/kernel/fs/vfs/checksum.rs
//!
//! Unified checksum verification interface for filesystem drivers.
//!
//! # Design
//!
//! The [`ChecksumVerifier`] trait provides default implementations for CRC32C
//! and CRC32 verification that each filesystem driver can opt into.  A
//! [`ChecksumPolicy`] controls what happens when a checksum mismatch is
//! detected:
//!
//! | Policy   | Behaviour |
//! |----------|-----------|
//! | `Strict` | Return `Error::InvalidArgument` immediately (default). |
//! | `Lax`    | Print a diagnostic message and continue. |
//! | `Off`    | Skip all verification. |
//!
//! # Integration checklist
//!
//! | Driver | Checksum | Status |
//! |--------|----------|--------|
//! | Btrfs  | CRC32C on every B-tree node | ✓ verified in `read_node()` |
//! | XFS v5 | CRC32C on superblock, inodes, B+tree blocks | Policy-gated |
//! | F2FS   | CRC32 on superblock and checkpoint | Policy-gated |
//! | ext4   | CRC32C on journal commit blocks | Policy stub |

use crate::Error;

// ── ChecksumPolicy ─────────────────────────────────────────────────────────

/// Controls how the system reacts to a checksum mismatch.
///
/// Used by [`ChecksumVerifier::checksum_policy`] to select the verification
/// strategy at runtime.  The default is [`ChecksumPolicy::Strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChecksumPolicy {
    /// Reject the data immediately on mismatch.  This is the safe default.
    #[default]
    Strict,
    /// Print a diagnostic but allow the operation to proceed.
    /// Useful during recovery or when mounting a damaged volume.
    Lax,
    /// Do not compute or verify checksums at all.
    Off,
}

// ── ChecksumVerifier ───────────────────────────────────────────────────────

/// Unified checksum verification interface for filesystem drivers.
///
/// Provides default method bodies for CRC32C (Castagnoli) and CRC32 (IEEE
/// 802.3) verification.  Drivers only need to implement
/// [`checksum_policy`](Self::checksum_policy) to control the policy; they
/// may override the verify methods if the driver has special requirements
/// (e.g. zeroing a header field before hashing).
pub trait ChecksumVerifier {
    /// Return the current [`ChecksumPolicy`].
    fn checksum_policy(&self) -> ChecksumPolicy;

    /// Verify a CRC32C (Castagnoli) checksum over `data`.
    ///
    /// `expected` is the stored checksum value (typically u32 LE on disk).
    /// `context` is a human-readable label printed in Lax-mode diagnostics
    /// (e.g. `"Btrfs node @ 0x1234000"`).
    fn verify_crc32c(&self, data: &[u8], expected: u32, context: &str) -> Result<(), Error> {
        if self.checksum_policy() == ChecksumPolicy::Off {
            return Ok(());
        }
        let computed = crate::kernel::crypto::crc32c(data);
        if computed == expected {
            return Ok(());
        }
        if matches!(self.checksum_policy(), ChecksumPolicy::Lax) {
            crate::println!(
                "[checksum] CRC32C mismatch in {}: expected={:08x} computed={:08x} (lax — continuing)",
                context, expected, computed
            );
            return Ok(());
        }
        crate::println!(
            "[checksum] CRC32C mismatch in {}: expected={:08x} computed={:08x}",
            context,
            expected,
            computed
        );
        Err(Error::InvalidArgument)
    }

    /// Verify a CRC32 (IEEE 802.3) checksum over `data`.
    fn verify_crc32(&self, data: &[u8], expected: u32, context: &str) -> Result<(), Error> {
        if self.checksum_policy() == ChecksumPolicy::Off {
            return Ok(());
        }
        let computed = crate::kernel::crypto::crc32(data);
        if computed == expected {
            return Ok(());
        }
        if matches!(self.checksum_policy(), ChecksumPolicy::Lax) {
            crate::println!(
                "[checksum] CRC32 mismatch in {}: expected={:08x} computed={:08x} (lax — continuing)",
                context, expected, computed
            );
            return Ok(());
        }
        crate::println!(
            "[checksum] CRC32 mismatch in {}: expected={:08x} computed={:08x}",
            context,
            expected,
            computed
        );
        Err(Error::InvalidArgument)
    }
}
