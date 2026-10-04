//! src/util/sign_tool.rs
//!
//! Signing a release artifact, on the host, for the kernel's verifier.
//!
//! The scheme is the one [`crate::user::program::signature`] already checks:
//! `lamport-sha256`, where a signature reveals one preimage per bit of the
//! artifact's SHA-256 and a public key holds the hash of both preimages for
//! every bit.  The formats — the detached signature string and the trusted-key
//! record — are rendered by that module too, so a signature this tool writes
//! is one the kernel reads, and the two cannot drift into disagreeing about
//! what they exchange.
//!
//! **A key signs once.**  That is the property a Lamport key has, not a
//! limitation of this tool: two signatures under one key reveal both preimages
//! for the bits they disagree on, which is enough to forge a third.  So a
//! signature is always made with a freshly generated key, whose id is the
//! artifact's name and whose public half travels beside it — and the tool
//! refuses to write over an artifact's signature, because the only way to sign
//! the same artifact twice is with a second key.
//!
//! The file names are the discipline made visible: `<artifact>.sig` holds the
//! signature, `<key-id>.public.toml` the key record a verifier needs.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::user::program::integrity::sha256_digest;
use crate::user::program::signature;
use crate::Error;

/// A one-time key pair, in the on-disk form the tool writes.
pub struct KeyPair {
    /// The name a signature names it by.
    pub key_id: String,
    /// One preimage per bit per value: `2 * 256 * 32` bytes.
    pub private: Vec<u8>,
    /// The hash of every preimage: `2 * 256 * 32` bytes, the same shape.
    pub public: Vec<u8>,
}

/// What signing one artifact produced.
pub struct SignedArtifact {
    /// The `lamport-sha256:<key-id>:<hex>` value a manifest would carry.
    pub signature: String,
    /// The trusted-key record, as a verifier reads it.
    pub public_key_record: String,
}

/// Generate a one-time key pair, drawing `private` bytes from `fill`.
///
/// The randomness is a parameter rather than a call to `/dev/urandom` inside
/// so that a test can supply a fixed source and still exercise everything
/// else; the host command passes the real one.
pub fn generate_key_pair(
    key_id: &str,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> Result<KeyPair, String> {
    signature::validate_key_id(key_id).map_err(|error| error.as_str().to_string())?;

    let mut private = vec![0_u8; signature::LAMPORT_PUBLIC_KEY_BYTES];
    fill(&mut private)?;

    let mut public = Vec::with_capacity(signature::LAMPORT_PUBLIC_KEY_BYTES);
    for index in 0..signature::LAMPORT_MESSAGE_BITS * 2 {
        let offset = index * signature::LAMPORT_ELEMENT_BYTES;
        let element = &private[offset..offset + signature::LAMPORT_ELEMENT_BYTES];
        public.extend_from_slice(&sha256_digest(element));
    }

    Ok(KeyPair {
        key_id: String::from(key_id),
        private,
        public,
    })
}

/// Sign `artifact` with `key`, returning the signature and the key record.
///
/// The key must be used once; nothing here can check that, which is why the
/// command generates a key per artifact rather than offering a key pool.
pub fn sign_artifact(key: &KeyPair, artifact: &[u8]) -> Result<SignedArtifact, String> {
    if key.private.len() != signature::LAMPORT_PUBLIC_KEY_BYTES
        || key.public.len() != signature::LAMPORT_PUBLIC_KEY_BYTES
    {
        return Err(String::from(
            "the key pair is not the size this scheme uses",
        ));
    }

    let digest = sha256_digest(artifact);
    let mut payload = vec![0_u8; signature::LAMPORT_SIGNATURE_BYTES];

    for bit_index in 0..signature::LAMPORT_MESSAGE_BITS {
        let bit = digest_bit(&digest, bit_index) as usize;
        let element = (bit_index * 2 + bit) * signature::LAMPORT_ELEMENT_BYTES;
        let target = bit_index * signature::LAMPORT_ELEMENT_BYTES;
        payload[target..target + signature::LAMPORT_ELEMENT_BYTES]
            .copy_from_slice(&key.private[element..element + signature::LAMPORT_ELEMENT_BYTES]);
    }

    Ok(SignedArtifact {
        signature: signature::render_detached_signature(&key.key_id, &payload),
        public_key_record: signature::render_trusted_key_record(&key.key_id, &key.public),
    })
}

/// Check `artifact` against a signature and a trusted-key record.
pub fn verify_artifact(
    artifact: &[u8],
    signature_text: &str,
    public_key_record: &str,
) -> Result<(), String> {
    let parsed = signature::parse_detached_signature(signature_text.trim())
        .map_err(|error| error.as_str().to_string())?;
    let public_key = signature::parse_trusted_key_record(public_key_record, parsed.key_id)
        .map_err(|error| error.as_str().to_string())?;
    signature::verify_lamport_signature(artifact, &parsed.payload, &public_key)
        .map_err(|error| error.as_str().to_string())
}

/// The bit of a digest that element `bit_index` of a signature answers for.
fn digest_bit(digest: &[u8; 32], bit_index: usize) -> u8 {
    let byte = digest[bit_index / 8];
    (byte >> (7 - (bit_index % 8))) & 1
}

/// Draw randomness from the host's entropy device.
///
/// A release key is generated once and never leaves the machine that signs; a
/// weak source here would be a weak key, so nothing is improvised from the
/// clock.
pub fn fill_from_urandom(buffer: &mut [u8]) -> Result<(), String> {
    use std::io::Read;

    let mut device = std::fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    device.read_exact(buffer).map_err(|error| error.to_string())
}

/// The validation the kernel does, for a caller that wants the same error.
pub fn validate_key_id(key_id: &str) -> Result<(), Error> {
    signature::validate_key_id(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic source: a test does not need entropy, it needs the same
    /// bytes twice.
    ///
    /// The generator has to have a long period, and xorshift32 does.  A source
    /// with a short one gives both preimages of a bit the same value, and a
    /// key whose two halves repeat verifies *anything* — which is what a weak
    /// key source does to this scheme in production too, not just here.
    fn fixed_source(seed: u32) -> impl FnMut(&mut [u8]) -> Result<(), String> {
        let mut state = seed | 1;
        move |buffer: &mut [u8]| {
            for byte in buffer.iter_mut() {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = (state & 0xff) as u8;
            }
            Ok(())
        }
    }

    fn signed() -> (Vec<u8>, SignedArtifact) {
        let artifact = b"a release artifact".to_vec();
        let key = generate_key_pair("release-1", fixed_source(3)).expect("key");
        let signed = sign_artifact(&key, &artifact).expect("sign");
        (artifact, signed)
    }

    #[test]
    fn a_signature_verifies_against_its_own_key() {
        let (artifact, signed) = signed();
        verify_artifact(&artifact, &signed.signature, &signed.public_key_record)
            .expect("the signature this tool just made must verify");
    }

    #[test]
    fn a_changed_artifact_does_not_verify() {
        let (mut artifact, signed) = signed();
        artifact[0] ^= 1;
        assert!(verify_artifact(&artifact, &signed.signature, &signed.public_key_record).is_err());
    }

    #[test]
    fn a_changed_signature_does_not_verify() {
        let (artifact, signed) = signed();
        // Flip one hex digit of the payload.
        let mut signature = signed.signature.clone();
        let last = signature.pop().expect("payload hex");
        signature.push(if last == '0' { '1' } else { '0' });
        assert!(verify_artifact(&artifact, &signature, &signed.public_key_record).is_err());
    }

    #[test]
    fn another_keys_record_does_not_verify() {
        let (artifact, signed) = signed();
        let other = generate_key_pair("release-2", fixed_source(9)).expect("key");
        let other_signed = sign_artifact(&other, &artifact).expect("sign");
        assert!(verify_artifact(
            &artifact,
            &signed.signature,
            &other_signed.public_key_record
        )
        .is_err());
    }

    #[test]
    fn a_record_that_names_another_key_is_refused() {
        let (artifact, signed) = signed();
        let renamed = signed.public_key_record.replace("release-1", "release-2");
        assert!(verify_artifact(&artifact, &signed.signature, &renamed).is_err());
    }
}
