//! src/user/program/loader/arch/mod.rs
//!
//! Loading a program image onto a target: the address space it needs, the
//! stack it starts on, and the registers its first instruction reads.
//!
//! The *shape* of that is the same everywhere and lives here — the stack
//! layout, the string and pointer pushing, the segment planning and the
//! permissions each segment gets.  What is not the same is what a target's
//! entry takes: x86_64 is handed a stack pointer, aarch64 an entry and a
//! stack, riscv64 a stack pointer and two argument registers, and each builds
//! its address space through its own MMU.  That half is one file per
//! architecture below, and this file names no architecture except in the
//! picker that chooses one.

use super::*;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::process::ProcessUserAddressSpace;
use crate::kernel::process::UserThreadStart;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "none")
))]
use crate::memory::paging::MappingKind;
use crate::memory::paging::PagePermissions;
use crate::Error;
use crate::Result;

use super::super::constants;
use crate::user::elf::ElfLoadSegment;
use crate::user::elf::ElfSegmentFlags;

// ── Per-architecture halves ────────────────────────────────────────────
//
// Each module defines the same entry points, so the picker below re-exports
// whichever pair this target has: a call site names what it wants, not which
// architecture it is.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod aarch64;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
mod absent;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) use aarch64::*;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) use riscv64::*;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
pub(crate) use absent::*;

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
    let final_stack_pointer = constants::align_down(
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
    write_u64_stack_entry(&mut writes, &mut cursor, constants::AUXV_AT_NULL)?;
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
pub(crate) fn push_c_strings(
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
pub(crate) fn write_u64_stack_entry(
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

pub(crate) fn plan_user_image_segment(segment: ElfLoadSegment) -> Result<UserImageSegmentPlan> {
    if segment.memory_size == 0 {
        return Err(Error::InvalidArgument);
    }

    // File offset and virtual address must agree modulo alignment so the mapped
    // page image can be reconstructed correctly.
    if segment.alignment != 0
        && (segment.virtual_address & (segment.alignment - 1))
            != (segment.file_offset & (segment.alignment - 1))
    {
        return Err(Error::InvalidArgument);
    }

    let virtual_end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or(Error::InvalidArgument)?;
    let zero_start = segment
        .virtual_address
        .checked_add(segment.file_size)
        .ok_or(Error::InvalidArgument)?;
    let page_start = constants::align_down(segment.virtual_address, constants::USER_PAGE_SIZE);
    let page_end = constants::align_up(virtual_end, constants::USER_PAGE_SIZE)
        .ok_or(Error::InvalidArgument)?;

    if page_start < constants::USER_PAGE_SIZE || page_end <= page_start {
        return Err(Error::InvalidArgument);
    }

    Ok(UserImageSegmentPlan {
        virtual_start: segment.virtual_address,
        virtual_end,
        page_start,
        page_end,
        file_offset: segment.file_offset,
        file_size: segment.file_size,
        zero_start,
        zero_end: virtual_end,
        permissions: page_permissions_from_segment_flags(segment.flags)?,
    })
}

pub(crate) fn page_permissions_from_segment_flags(
    flags: ElfSegmentFlags,
) -> Result<PagePermissions> {
    if !flags.readable() && !flags.writable() && !flags.executable() {
        return Err(Error::InvalidArgument);
    }

    Ok(match (flags.writable(), flags.executable()) {
        (false, false) => PagePermissions::READ,
        (true, false) => PagePermissions::READ_WRITE,
        (false, true) => PagePermissions::READ_EXECUTE,
        (true, true) => PagePermissions::READ_WRITE_EXECUTE,
    })
}
