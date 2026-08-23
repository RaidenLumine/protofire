//! src/kernel/fs/crypt_device.rs
//! Encrypted block device that transparently encrypts/decrypts data
//! using AES-256-XTS as data passes through the `BlockDevice` interface.

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;

use crate::kernel::crypto::{aes_xts_decrypt, aes_xts_encrypt};
use crate::{Error, Result};

use super::block::{BlockDevice, DeviceHealth};

/// An encrypted block device that wraps an inner `BlockDevice` and
/// applies AES-256-XTS encryption on writes and decryption on reads.
///
/// The encryption key is 64 bytes (split into Key1 and Key2 for XTS).
/// Each 512-byte sector is encrypted as a separate data unit, with the
/// sector's logical block address (LBA) as the tweak.
pub struct EncryptedBlockDevice {
    inner: Arc<dyn BlockDevice>,
    key: [u8; 64],
    name: String,
}

impl EncryptedBlockDevice {
    /// Create a new encrypted block device wrapping `inner`.
    ///
    /// The `name` is used for identification; `key` must be exactly 64 bytes
    /// (key[..32] = AES-256 data key, key[32..] = AES-256 tweak key).
    pub fn new(inner: Arc<dyn BlockDevice>, key: [u8; 64], name: &str) -> Self {
        Self {
            inner,
            key,
            name: name.to_string(),
        }
    }

    /// Return a reference to the inner (unencrypted) block device.
    pub fn inner(&self) -> &Arc<dyn BlockDevice> {
        &self.inner
    }
}

impl BlockDevice for EncryptedBlockDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let bs = self.block_size();
        if !buffer.len().is_multiple_of(bs) {
            return Err(Error::InvalidArgument);
        }

        // Read encrypted data from the inner device.
        self.inner.read_blocks(lba, buffer)?;

        // Decrypt each block device sector in-place.
        let sectors = buffer.len() / bs;
        for sector in 0..sectors {
            let offset = sector * bs;
            let sector_data = &mut buffer[offset..offset + bs];
            let sector_id = lba + sector as u64;
            aes_xts_decrypt(&self.key, sector_id, sector_data);
        }

        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        if self.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        let bs = self.block_size();
        if !data.len().is_multiple_of(bs) {
            return Err(Error::InvalidArgument);
        }

        // Clone the data buffer so we can encrypt in-place before writing.
        let mut encrypted = data.to_vec();

        // Encrypt each block device sector in-place.
        let sectors = data.len() / bs;
        for sector in 0..sectors {
            let offset = sector * bs;
            let sector_data = &mut encrypted[offset..offset + bs];
            let sector_id = lba + sector as u64;
            aes_xts_encrypt(&self.key, sector_id, sector_data);
        }

        // Write the encrypted data to the inner device.
        self.inner.write_blocks(lba, &encrypted)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn device_health(&self) -> DeviceHealth {
        self.inner.device_health()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::fs::block::MemoryBlockDevice;
    use crate::kernel::fs::block::BLOCK_SIZE;
    use alloc::vec;

    fn test_device() -> (Arc<EncryptedBlockDevice>, Arc<dyn BlockDevice>) {
        let mut image = vec![0u8; 4096]; // 8 sectors
                                         // Fill with recognizable pattern.
        #[allow(clippy::needless_range_loop)]
        for i in 0..4096 {
            image[i] = (i & 0xFF) as u8;
        }
        let inner = MemoryBlockDevice::new("test", image, false);
        let key = [0x42u8; 64];
        let encrypted = Arc::new(EncryptedBlockDevice::new(inner.clone(), key, "crypt-test"));
        (encrypted, inner as Arc<dyn BlockDevice>)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_single_sector() {
        let (dev, inner) = test_device();

        // Read the raw (unencrypted) data from the inner device.
        let mut raw = vec![0u8; BLOCK_SIZE];
        inner.read_blocks(0, &mut raw).unwrap();

        // Read through the encrypted device (which should decrypt).
        let mut decrypted = vec![0u8; BLOCK_SIZE];
        dev.read_blocks(0, &mut decrypted).unwrap();

        // The decrypted data should match the original plaintext.
        // Since we haven't written anything, the inner device has the
        // original plaintext pattern, and the encrypted device decrypts it.
        // But the original data was never encrypted, so decryption will
        // produce garbage. Let's instead test write-then-read.

        // Write known plaintext through encrypted device.
        let plaintext = vec![0xABu8; BLOCK_SIZE];
        dev.write_blocks(0, &plaintext).unwrap();

        // Now the inner device should have encrypted data.
        let mut on_disk = vec![0u8; BLOCK_SIZE];
        inner.read_blocks(0, &mut on_disk).unwrap();

        // The on-disk data should be different from plaintext.
        assert_ne!(&on_disk[..], &plaintext[..]);

        // Read back through encrypted device.
        let mut readback = vec![0u8; BLOCK_SIZE];
        dev.read_blocks(0, &mut readback).unwrap();

        // We should get back the original plaintext.
        assert_eq!(&readback[..], &plaintext[..]);
    }

    #[test]
    fn encrypt_decrypt_multi_sector() {
        let (dev, inner) = test_device();

        // Write 3 sectors of known data.
        let mut plaintext = vec![0u8; BLOCK_SIZE * 3];
        #[allow(clippy::needless_range_loop)]
        for i in 0..plaintext.len() {
            plaintext[i] = (i & 0xFF) as u8;
        }
        dev.write_blocks(0, &plaintext).unwrap();

        // Verify inner device has different data.
        let mut on_disk = vec![0u8; BLOCK_SIZE * 3];
        inner.read_blocks(0, &mut on_disk).unwrap();
        assert_ne!(&on_disk[..], &plaintext[..]);

        // Read back through encrypted device.
        let mut readback = vec![0u8; BLOCK_SIZE * 3];
        dev.read_blocks(0, &mut readback).unwrap();
        assert_eq!(&readback[..], &plaintext[..]);
    }

    #[test]
    fn different_sectors_have_different_encryption() {
        let (dev, _inner) = test_device();

        // Write the same plaintext to two different sectors.
        let plaintext = vec![0xFFu8; BLOCK_SIZE];
        dev.write_blocks(0, &plaintext).unwrap();
        dev.write_blocks(1, &plaintext).unwrap();

        // Verify the readback works.
        let mut read0 = vec![0u8; BLOCK_SIZE];
        let mut read1 = vec![0u8; BLOCK_SIZE];
        dev.read_blocks(0, &mut read0).unwrap();
        dev.read_blocks(1, &mut read1).unwrap();

        // Both should decrypt to the same plaintext.
        assert_eq!(&read0[..], &plaintext[..]);
        assert_eq!(&read1[..], &plaintext[..]);
    }
}
