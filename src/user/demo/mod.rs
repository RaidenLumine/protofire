//! src/user/demo/mod.rs
//!
//! Module entry that registers per-architecture demo payload builders.

// These modules are `pub` so the in-repo demo-disk builder and tests can
// import the legacy assembly demo ELF builders via `protofire::user::demo::*`.

/// Declare a payload module that exists on one architecture only.
///
/// A payload *is* its architecture: it is a blob of that target's machine
/// code, extracted from the section its items are placed in.  The kernel-side
/// ELF builders are compiled for the host as well — that is where their tests
/// run — and they ask a payload for its bytes and entry point whether or not
/// this target can have that payload, so everywhere else needs a stub that
/// answers "no bytes, entry at zero".
///
/// Stating it once is the point: the payload files used to carry the same
/// `#[cfg]` on every item inside them, which meant a new item was one line
/// away from breaking the host build.
macro_rules! payload_or_stub {
    ($arch:literal, $name:ident) => {
        #[cfg(all(target_arch = $arch, any(target_os = "linux", target_os = "none")))]
        pub mod $name;

        /// A host (or another architecture) sees a payload it cannot have.
        #[cfg(not(all(target_arch = $arch, any(target_os = "linux", target_os = "none"))))]
        pub mod $name {
            pub fn payload_bytes() -> &'static [u8] {
                &[]
            }

            pub fn payload_entry_offset() -> usize {
                0
            }
        }
    };
}

payload_or_stub!("aarch64", demo_program_aarch64);
payload_or_stub!("aarch64", demo_program_aarch64_fault);
payload_or_stub!("aarch64", demo_program_aarch64_rust);
payload_or_stub!("riscv64", demo_program_riscv64);
payload_or_stub!("x86_64", demo_program_x86_64);
payload_or_stub!("x86_64", demo_program_x86_64_rust);
payload_or_stub!("x86_64", demo_program_x86_64_rust_io);
payload_or_stub!("x86_64", shell_payload_x86_64);

#[cfg(any(target_arch = "aarch64", test))]
pub mod demo_program_aarch64_elf;
#[cfg(any(target_arch = "riscv64", test))]
pub mod demo_program_riscv64_elf;
#[cfg(any(target_arch = "x86_64", test))]
pub mod demo_program_x86_64_elf;
#[cfg(test)]
pub(crate) mod payload_test_support;

/// Shared ELF64 artifact construction.  See [`crate::user::demo::elf_builder`].
pub mod elf_builder;

/// Demo VIRGL 3D renderer driving the GPU syscall surface.
pub mod virgl_renderer;
