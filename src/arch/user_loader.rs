//! src/arch/user_loader.rs
//!
//! Loading a program image onto a target: the address space it needs, the
//! stack it starts on, and the registers its first instruction reads.
//!
//! What is the same everywhere lives in the kernel's loader — planning an ELF
//! image into segments, building the initial stack, walking the argument
//! vectors.  What is not the same is what a target's entry takes: x86_64 is
//! handed a stack pointer, aarch64 an entry and a stack, riscv64 a stack
//! pointer and two argument registers, and each builds its address space
//! through its own MMU.  That half is one file per architecture under
//! `src/arch/<arch>/user_loader.rs`, and this file names no architecture
//! outside the picker below.
//!
//! A new architecture adds its own half, one `#[path]` line here, and one
//! `pub(crate) use`: the loader that calls these entry points does not change.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// Only the "no architecture here" address space and the shared thread-start
// adjustments name it; the halves that do define their own bring it in
// themselves.
#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
use crate::kernel::process::ProcessUserAddressSpace;
use crate::kernel::process::UserThreadStart;
use crate::user::program::align_down;
use crate::user::program::UserImageLoadPlan;
use crate::user::program::AUXV_AT_NULL;
use crate::Error;
use crate::Result;

// ── Per-architecture halves ────────────────────────────────────────────
//
// Each module defines the same entry points, so the picker below re-exports
// whichever half this target has: a call site names what it wants, not which
// architecture it is.  The `#[path]` is deliberate — the files live in the
// architecture's own directory, beside everything else that touches its
// registers, while the gate that selects one is written once, here, next to
// the others.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[path = "aarch64/user_loader.rs"]
mod aarch64_loader;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[path = "riscv64/user_loader.rs"]
mod riscv64_loader;
#[cfg(target_arch = "x86_64")]
#[path = "x86_64/user_loader.rs"]
mod x86_64_loader;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) use aarch64_loader::*;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) use riscv64_loader::*;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64_loader::*;

/// A target this kernel cannot build a user process for: there is no address
/// space to prepare, and the loader above gets `None` rather than a
/// half-built one.
#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn prepare_arch_user_address_space(
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    _arguments: &[String],
    _environment: &[String],
) -> Result<Option<ProcessUserAddressSpace>> {
    Ok(None)
}

/// Ask the target to adjust the thread's start descriptor, if its entry reads
/// anything the generic one cannot fill in.
///
/// The architectures whose entry takes argument registers define this
/// themselves; the rest have nothing to add, so the shared answer stands.
#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn prepare_loaded_user_thread_start(
    _prepared_user_address_space: Option<&ProcessUserAddressSpace>,
    image_layout: Option<&UserImageLoadPlan>,
    image: &[u8],
    arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    prepare_arch_user_thread_start(image_layout, image, arguments)
}

#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) fn prepare_arch_user_thread_start(
    _image_layout: Option<&UserImageLoadPlan>,
    _image: &[u8],
    _arguments: &[String],
) -> Result<Option<UserThreadStart>> {
    Ok(None)
}

/// The start descriptor for a freshly loaded image, built from the plan.
///
/// x86_64's entry reads its arguments off the stack it is handed, so the
/// stack is built here; the architectures that pass them in registers leave
/// the descriptor to their own half.
pub(crate) fn build_initial_user_thread_start(
    instruction_pointer: usize,
    image_layout: Option<&UserImageLoadPlan>,
    arguments: &[String],
    environment: &[String],
) -> Result<Option<UserThreadStart>> {
    let Some(image_layout) = image_layout else {
        return Ok(None);
    };

    #[cfg(target_arch = "x86_64")]
    {
        let stack_pointer =
            build_x86_64_initial_user_stack(image_layout, arguments, environment)?.stack_pointer;
        Ok(Some(UserThreadStart::new(
            instruction_pointer,
            stack_pointer,
            Some(image_layout.exception_stack_top),
        )))
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = arguments;
        let _ = environment;
        Ok(Some(UserThreadStart::new(
            instruction_pointer,
            image_layout.stack_top,
            Some(image_layout.exception_stack_top),
        )))
    }
}

// ── the initial stack ──────────────────────────────────────────────────
//
// The stack a user program starts on, built the way a C runtime reads it: the
// argument and environment strings pushed downwards from the top, then
// `argc`, the argument vector, `envp`, the auxiliary vector, and `AT_NULL`.
// Every architecture gets it in the same shape; what differs is which
// registers the entry reads the pointers out of, and that is the half above.

/// The stack a target just built for a user program: where its top ended up,
/// and the bytes to write there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedInitialUserStack {
    pub(crate) stack_pointer: usize,
    pub(crate) bytes: Vec<u8>,
}

// The aarch64 host compiles no half of the loader — it has no user address
// space to build — so on that one target the shared stack shape is unused.
#[cfg_attr(
    all(target_arch = "aarch64", not(target_os = "none")),
    allow(dead_code)
)]
pub(crate) fn build_initial_user_stack(
    stack_bottom: usize,
    stack_top: usize,
    arguments: &[String],
    environment: &[String],
    auxv_entries: &[(u64, u64)],
) -> Result<PreparedInitialUserStack> {
    let mut stack_pointer = stack_top;
    let mut writes = Vec::new();

    let argument_addresses = push_c_strings(&mut stack_pointer, arguments, &mut writes)?;
    let environment_addresses = push_c_strings(&mut stack_pointer, environment, &mut writes)?;

    // Build a conventional C runtime initial stack:
    // argc, argv[], NULL, envp[], NULL, auxv[], AT_NULL.
    let metadata_slots = 1_usize
        .checked_add(argument_addresses.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(environment_addresses.len()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(auxv_entries.len().checked_mul(2)?))
        .and_then(|value| value.checked_add(2))
        .ok_or(Error::OutOfMemory)?;
    let metadata_size = metadata_slots
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(Error::OutOfMemory)?;
    // Keep the final SP 16-byte aligned before first user instructions run.
    let final_stack_pointer = align_down(
        stack_pointer
            .checked_sub(metadata_size)
            .ok_or(Error::OutOfMemory)?,
        16,
    );

    if final_stack_pointer < stack_bottom {
        return Err(Error::OutOfMemory);
    }

    let mut cursor = final_stack_pointer;
    write_u64_stack_entry(&mut writes, &mut cursor, arguments.len() as u64)?;
    for address in &argument_addresses {
        write_u64_stack_entry(&mut writes, &mut cursor, *address as u64)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;
    for address in &environment_addresses {
        write_u64_stack_entry(&mut writes, &mut cursor, *address as u64)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;
    for (key, value) in auxv_entries {
        write_u64_stack_entry(&mut writes, &mut cursor, *key)?;
        write_u64_stack_entry(&mut writes, &mut cursor, *value)?;
    }
    write_u64_stack_entry(&mut writes, &mut cursor, AUXV_AT_NULL)?;
    write_u64_stack_entry(&mut writes, &mut cursor, 0)?;

    let total_len = stack_top
        .checked_sub(final_stack_pointer)
        .ok_or(Error::OutOfMemory)?;
    let mut bytes = vec![0_u8; total_len];
    for (address, data) in writes {
        let start = address
            .checked_sub(final_stack_pointer)
            .ok_or(Error::OutOfMemory)?;
        let end = start.checked_add(data.len()).ok_or(Error::OutOfMemory)?;
        bytes
            .get_mut(start..end)
            .ok_or(Error::OutOfMemory)?
            .copy_from_slice(&data);
    }

    Ok(PreparedInitialUserStack {
        stack_pointer: final_stack_pointer,
        bytes,
    })
}

#[cfg_attr(
    all(target_arch = "aarch64", not(target_os = "none")),
    allow(dead_code)
)]
fn push_c_strings(
    stack_pointer: &mut usize,
    values: &[String],
    writes: &mut Vec<(usize, Vec<u8>)>,
) -> Result<Vec<usize>> {
    let mut addresses = Vec::with_capacity(values.len());

    // Push from the end downward, then reverse the saved addresses so argv/env
    // pointers preserve the original caller-visible order.
    for value in values.iter().rev() {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        *stack_pointer = stack_pointer
            .checked_sub(bytes.len())
            .ok_or(Error::OutOfMemory)?;
        writes.push((*stack_pointer, bytes));
        addresses.push(*stack_pointer);
    }

    addresses.reverse();
    Ok(addresses)
}

#[cfg_attr(
    all(target_arch = "aarch64", not(target_os = "none")),
    allow(dead_code)
)]
fn write_u64_stack_entry(
    writes: &mut Vec<(usize, Vec<u8>)>,
    cursor: &mut usize,
    value: u64,
) -> Result<()> {
    writes.push((*cursor, value.to_le_bytes().to_vec()));
    *cursor = cursor
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(Error::OutOfMemory)?;
    Ok(())
}
