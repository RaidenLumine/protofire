//! fuzz/fuzz_targets/luks2.rs
//!
//! Coverage-guided fuzzing for the LUKS2 header, metadata scanner and keyslot
//! decode — the whole `luks2_open` path, not just its leaf parsers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use protofire::fs::block::MemoryBlockDevice;
use protofire::fs::luks2::base64_decode;
use protofire::fs::luks2::json_find_object;
use protofire::fs::luks2::json_find_string;
use protofire::fs::luks2::luks2_open;
use protofire::fs::luks2::parse_decimal;

/// Object keys the metadata scanner is asked about; the same list the
/// deterministic harness uses.
const KEYS: &[&str] = &[
    "config",
    "keyslots",
    "0",
    "kdf",
    "argon2id",
    "salt",
    "size",
    "offset",
    "iterations",
    "priority",
    "cipher",
    "hashing",
    "stripes",
    "key",
    "digest",
    "uuid",
    "enforce",
    "segments",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let _ = base64_decode(data);
    let _ = parse_decimal(data);
    for key in KEYS {
        let _ = json_find_string(data, key);
        let _ = json_find_object(data, key);
    }

    // The header gate only opens for the LUKS magic, so the mutator has to
    // find it before the JSON walk and keyslot scan run at all; the in-tree
    // harness plants it, and coverage is what lets this one keep it.
    let device = MemoryBlockDevice::new("fuzz-luks2", data.to_vec(), true);
    let _ = luks2_open(device, b"passphrase");
});
