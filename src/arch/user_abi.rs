//! src/arch/user_abi.rs
//!
//! The parts of the user ABI that belong to the target: which ELF machine
//! this kernel builds for, and the program-format name it reports.
//!
//! They live here for the same reason the loader's halves do — a new
//! architecture has to answer them, so the question is asked in the one place
//! an architecture is allowed to answer from, and everything else in the tree
//! stays free of the architecture's name.
//!
//! The values are the ELF standard's, not this kernel's choices: `e_machine`
//! is what makes an image this target's, and the format string is what the
//! launch metadata calls it.

/// The ELF `e_machine` of the images this kernel builds, and the only one it
/// will load.
#[cfg(target_arch = "x86_64")]
pub(crate) const ELF_MACHINE: u16 = 0x3E; // EM_X86_64
#[cfg(target_arch = "aarch64")]
pub(crate) const ELF_MACHINE: u16 = 0xB7; // EM_AARCH64
#[cfg(target_arch = "riscv64")]
pub(crate) const ELF_MACHINE: u16 = 0xF3; // EM_RISCV
/// A target this kernel does not build user programs for: no image can
/// declare it, and `0` is not a defined machine.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
pub(crate) const ELF_MACHINE: u16 = 0;

/// The program-format name carried in launch metadata and catalogs.
#[cfg(target_arch = "x86_64")]
pub(crate) const PROGRAM_FORMAT: &str = "elf64-x86_64-user";
#[cfg(target_arch = "aarch64")]
pub(crate) const PROGRAM_FORMAT: &str = "elf64-aarch64-user";
#[cfg(target_arch = "riscv64")]
pub(crate) const PROGRAM_FORMAT: &str = "elf64-riscv64-user";
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
pub(crate) const PROGRAM_FORMAT: &str = "elf64-user";
