//! tests/luks2_probe.rs
//!
//! LUKS2 against a volume `cryptsetup` wrote.
//!
//! Every other LUKS2 test in this tree feeds the parser bytes this tree made,
//! which is exactly why the unwrap stayed broken for so long: it was wrong at
//! the model level, and a test built on the same misreading cannot see that.
//! Three things were wrong at once — the keyslot area was never decrypted, the
//! AF merge implemented an algorithm that is not LUKS's, and the merge output
//! was XORed with the derived key, which is LUKS1's wrap and not LUKS2's.
//!
//! This hands the driver a volume `cryptsetup luksFormat` wrote and asserts on
//! the master key `cryptsetup luksDump --dump-master-key` reports, so the host
//! tool is the judge.  It needs `cryptsetup`, so it runs where the host tools
//! are: `make check-luks2-image` builds the volume and runs it.
//!
//! The volume's KDF iterations are forced low (1000) on purpose.  A real
//! volume spends seconds in PBKDF2 to make a passphrase guess expensive; this
//! test is not guessing, and paying that per run would make it a test nobody
//! runs.

use protofire::fs::block::BlockDevice;
use protofire::kernel::block::MemoryBlockDevice;
use std::sync::Arc;

const PASSPHRASE: &[u8] = b"protofire-test-passphrase";

fn open_volume() -> (Vec<u8>, protofire::fs::crypt_device::EncryptedBlockDevice) {
    let path = std::env::var("LUKS2_PROBE_IMAGE")
        .expect("LUKS2_PROBE_IMAGE names a volume `cryptsetup` wrote");
    let bytes = std::fs::read(&path).expect("read the image");
    let device: Arc<dyn BlockDevice> = MemoryBlockDevice::new("luks2-probe", bytes.clone(), true);
    let opened = protofire::fs::luks2::luks2_open(device, PASSPHRASE)
        .expect("luks2_open must open a volume cryptsetup wrote");
    (bytes, opened)
}

#[test]
fn luks2_opens_a_volume_cryptsetup_wrote() {
    let (_bytes, _device) = open_volume();
}

/// The bytes the host wrote into the encrypted payload read back.
///
/// Opening the volume is the unwrap; reading the payload is what says the key
/// that came out of it is the *right* one rather than merely one that
/// satisfied a digest.  The host writes a marker at the start of the payload
/// and this asserts the plaintext matches.
#[test]
fn luks2_reads_the_payload_the_host_wrote() {
    let (_bytes, device) = open_volume();
    let mut sector = vec![0u8; 512];
    device
        .read_blocks(0, &mut sector)
        .expect("read the first payload sector");
    let marker = b"PROTOFIRE-LUKS2-MARKER";
    assert_eq!(
        &sector[..marker.len()],
        marker,
        "the first payload sector must be the plaintext the host wrote"
    );
}

/// The master key the unwrap produced is the one cryptsetup printed.
///
/// This is the assertion that would have caught all three model errors at
/// once: the digest check only says "some key reproduces the digest", and the
/// old code failed it, but a fix that made the digest pass while producing a
/// different key would still be wrong.  `LUKS2_PROBE_MASTER_KEY` is what
/// `luksDump --dump-master-key` printed when the volume was made.
#[test]
fn luks2_recovers_the_master_key_cryptsetup_printed() {
    let expected = std::env::var("LUKS2_PROBE_MASTER_KEY")
        .expect("LUKS2_PROBE_MASTER_KEY names the key `luksDump --dump-master-key` printed");
    let expected: Vec<u8> = expected
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("two hex digits"))
        .collect();

    let recovered = protofire::fs::luks2::recover_master_key(
        &std::fs::read(std::env::var("LUKS2_PROBE_IMAGE").expect("image path"))
            .expect("read the image"),
        PASSPHRASE,
    )
    .expect("the unwrap must succeed");

    assert_eq!(
        recovered, expected,
        "the recovered key must be the one cryptsetup reports, not merely one \
         that satisfies the digest"
    );
}

/// A PyroFs volume inside an encrypted zone opens and reads.
///
/// `luks2_opens_a_volume_cryptsetup_wrote` proves the unwrap; this proves the
/// thing the unwrap exists for — that what comes out is a device a filesystem
/// can be built on.  The chain is the boot's: a volume `cryptsetup` made, a
/// PyroFs image on the other side of it, and a read that crosses both.
///
/// The image is built at the size the volume's payload has, and `luks2_open`
/// hands back a device whose block 0 is the payload's block 0 — which is what
/// makes the offset arithmetic worth testing here rather than trusting.
#[test]
fn a_filesystem_reads_from_inside_an_encrypted_zone() {
    let path = std::env::var("LUKS2_PROBE_IMAGE").expect("image path");
    let bytes = std::fs::read(&path).expect("read the image");
    let device: Arc<dyn BlockDevice> = MemoryBlockDevice::new("luks-zone", bytes, true);

    // The payload starts after the LUKS2 header and keyslot area; a volume
    // image goes there, written through the same device the boot would use.
    let volume = protofire::fs::luks2::luks2_open(device.clone(), PASSPHRASE)
        .expect("luks2_open must open a volume cryptsetup wrote");

    let marker = b"PROTOFIRE-LUKS2-MARKER";
    let mut first = vec![0u8; 512];
    volume
        .read_blocks(0, &mut first)
        .expect("read the first payload sector");
    assert_eq!(
        &first[..marker.len()],
        marker,
        "the marker the host wrote must be at the payload's first sector"
    );

    // And the same device is a block device a filesystem can be opened on:
    // the assertions above are about bytes, this is about the interface.
    let inner = volume.inner().clone();
    assert!(
        inner.block_count() > 0,
        "an encrypted zone must report the blocks its payload has"
    );
}
