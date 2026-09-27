//! build.rs
//!
//! Build script for the kernel.

use std::env;

/// A short identity for the tree this build came from.
///
/// `git describe --always --dirty` when there is a repository to ask, and a
/// fixed word when there is not (a source tarball, a vendored copy) — the
/// banner has to say something either way.  The identity is what tells a
/// serial log which commit produced the image it is showing, and the `-dirty`
/// suffix is what marks a build made from a tree with uncommitted changes.
fn build_id() -> String {
    std::process::Command::new("git")
        .args(["describe", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| String::from("unknown"))
}

fn main() {
    // The banner names the tree: see `build_id`.  Re-run this script when the
    // checked-out commit, the branch it is on, or the staged state changes, so
    // a commit updates the identity without a source edit — and watch the
    // sources too, because the `-dirty` suffix has to be recomputed on every
    // build that could have been made from a modified tree.
    println!("cargo:rustc-env=PROTOFIRE_BUILD_ID={}", build_id());
    for watched in [
        ".git/HEAD",
        ".git/index",
        ".git/packed-refs",
        ".git/refs/heads",
        "src",
        "tests",
        "Cargo.toml",
    ] {
        if std::path::Path::new(watched).exists() {
            println!("cargo:rerun-if-changed={watched}");
        }
    }

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
