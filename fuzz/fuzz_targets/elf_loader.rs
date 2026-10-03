//! fuzz/fuzz_targets/elf_loader.rs
//!
//! Coverage-guided fuzzing for the ELF loader chain.
//!
//! The contract is the deterministic parser harness's contract, taken to the
//! inputs a fixed seed cannot reach: malformed input produces a clean `Err`,
//! never a panic, a hang, or an out-of-bounds read.  A `parse_elf64` that
//! succeeds is driven through the segment planner, because that is where a
//! header the parser accepted is turned into addresses and lengths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use protofire::user::elf::parse_elf64;
use protofire::user::program::plan_user_image_load;

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = parse_elf64(data) {
        let _ = elf.load_segments();
        let _ = elf.load_segment_count();
        let _ = elf.entry_in_load_segment();
        let _ = plan_user_image_load(&elf);
    }
});
