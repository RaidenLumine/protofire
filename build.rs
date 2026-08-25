//! build.rs
//!
//! Build script for the kernel.

use std::env;

fn main() {
    // Link the kernel with its own linker script.  This is set here rather
    // than in .cargo/config.toml so that any co-located crates (shell) can
    // use their own linker scripts without conflict.
    // Only apply for the bare-metal kernel target, NOT host test builds.
    let target = env::var("TARGET").unwrap_or_default();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if target == "x86_64-unknown-none" {
        println!("cargo:rustc-link-arg=-T{manifest_dir}/linker.ld");
        // --emit-relocs keeps all link-time relocations in the output ELF as
        // .rela.* sections.  The KASLR self-relocator scans these at boot to
        // find absolute-address references (R_X86_64_64) and adjusts them by
        // the kernel-slide delta.  This is much simpler than full PIE.
        //
        // NOTE: we use --emit-relocs (not -pie) because:
        //   - The x86_64-unknown-none target doesn't support PIE natively.
        //   - --emit-relocs preserves every relocation in the final ELF without
        //     changing the ELF type (stays ET_EXEC).
        //   - R_X86_64_32 relocations (e.g. AP trampoline) are harmless because they're
        //     stored but never executed through the GOT.
        println!("cargo:rustc-link-arg=--emit-relocs");
    }
    if target == "aarch64-unknown-none" {
        println!("cargo:rustc-link-arg=-T{manifest_dir}/linker-aarch64.ld");
    }
    if target == "riscv64gc-unknown-none-elf" {
        println!("cargo:rustc-link-arg=-T{manifest_dir}/linker-riscv64.ld");
    }
}
