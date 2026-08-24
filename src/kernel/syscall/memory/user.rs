//! src/kernel/syscall/memory/user.rs
//!
//! User-pointer and user-buffer validation helpers for syscall argument decoding.
//!
//! ## SMAP (Supervisor Mode Access Prevention)
//!
//! On x86_64 bare-metal, SMAP is enabled in CR4.  The kernel cannot read or
//! write user-accessible pages unless EFLAGS.AC is set (via `stac`).  This
//! module provides `with_user_access_guard` which sets AC for the duration of
//! a single user-memory access, then clears it.
//!
//! Functions that return references into user memory (`user_str`,
//! `optional_user_input_slice`) bracket the *dereference* with a SMAP guard,
//! but the returned reference may still point to user pages.  Callers must
//! ensure that any further reads through that reference also happen inside a
//! SMAP guard — typically by consuming the data (copying into kernel memory)
//! while the guard is still active.  The guard is scoped to the access
//! function; callers that need longer-lived access should use the
//! closure-based APIs (`with_optional_input_slice`,
//! `with_optional_output_slice`) or copy the data immediately.

use alloc::string::{String, ToString};
use core::marker::PhantomData;

use crate::{Error, Result};

/// Execute a closure inside a SMAP user-access window on bare-metal
/// architectures that support it (x86_64 SMAP, aarch64 PAN-equivalent,
/// riscv64 SUM).
///
/// On host test targets this is a no-op.
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
#[inline]
pub(super) fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    unsafe {
        crate::arch::x86_64::user_access::with_user_access(f)
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    unsafe {
        crate::arch::aarch64::user_access::with_user_access(f)
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    unsafe {
        crate::arch::riscv64::user_access::with_user_access(f)
    }
}

/// Execute a closure as-is (no-op for host test targets).
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
#[inline]
pub(super) fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    f()
}

pub(super) struct FixedOutputBuffer<T: PaddingFree> {
    buffer_ptr: *mut u8,
    buffer_len: usize,
    marker: PhantomData<T>,
}

impl<T: PaddingFree> FixedOutputBuffer<T> {
    pub(super) fn new(buffer_ptr: *mut u8, buffer_len: usize) -> Result<Self> {
        validate_fixed_output_buffer(buffer_ptr, buffer_len, core::mem::size_of::<T>())?;
        Ok(Self {
            buffer_ptr,
            buffer_len,
            marker: PhantomData,
        })
    }

    pub(super) fn copy_value(&self, value: &T) -> Result<super::SyscallDispatch> {
        copy_user_value(value, self.buffer_ptr, self.buffer_len)
            .map(super::SyscallDispatch::complete)
    }

    pub(super) fn finish_with(
        self,
        produce: impl FnOnce() -> Result<T>,
    ) -> Result<super::SyscallDispatch> {
        let value = produce()?;
        self.copy_value(&value)
    }
}

pub(super) fn fixed_output_buffer_arg<T: PaddingFree>(
    context: &super::SyscallContext,
    ptr_arg: usize,
    len_arg: usize,
) -> Result<FixedOutputBuffer<T>> {
    FixedOutputBuffer::new(context.arg(ptr_arg) as *mut u8, context.arg(len_arg))
}

pub(super) fn validate_fixed_output_buffer(
    buffer_ptr: *mut u8,
    buffer_len: usize,
    required_len: usize,
) -> Result<()> {
    if buffer_len != required_len {
        return Err(Error::InvalidArgument);
    }

    validate_current_process_user_output_buffer(buffer_ptr, buffer_len, required_len)
}

pub(super) fn process_pid_arg(pid: usize) -> Result<u32> {
    u32::try_from(pid).map_err(|_| Error::InvalidArgument)
}

pub(super) fn user_path_arg<'a>(
    context: &super::SyscallContext,
    path_arg: usize,
    len_arg: usize,
) -> Result<&'a str> {
    user_str(context.arg(path_arg) as *const u8, context.arg(len_arg))
}

pub(super) fn user_bounded_str<'a>(ptr: *const u8, len: usize, max_len: usize) -> Result<&'a str> {
    if len > max_len {
        return Err(Error::InvalidArgument);
    }

    user_str(ptr, len)
}

pub(super) fn copy_user_bytes(bytes: &[u8], buffer_ptr: *mut u8, length: usize) -> Result<usize> {
    copy_variable_user_payload(buffer_ptr, length, bytes.len(), |buffer| {
        buffer.copy_from_slice(bytes);
    })
}

/// Marker trait for types that are safe to reinterpret as byte slices.
///
/// # Safety
///
/// Implementing this trait for a type that contains padding bytes causes
/// **undefined behaviour**: [`value_as_bytes`] reads every byte of the value
/// through [`core::slice::from_raw_parts`], and reading uninitialised padding
/// bytes as `u8` is UB per the Rust abstract machine.
///
/// **Safe types** — always padding-free:
/// - All Rust integer types (`u8`, `u16`, `u32`, `u64`, `u128`, `usize`).
/// - `[u8; N]` arrays (bytes have alignment 1, no padding).
///
/// **Safe types** — when structurally verified:
/// - `#[repr(C)]` structs whose fields are all the same type (e.g. all `u64`
///   or all `usize`) — these have no inter-field padding and the compiler
///   cannot insert trailing padding when all fields share the same alignment.
///
/// **Unsafe types** — never implement:
/// - Rust default-layout structs (compiler may insert arbitrary padding).
/// - `#[repr(C)]` structs mixing field sizes (e.g. `u8` then `u64`).
/// - Types containing `bool`, `enum` discriminants, or zero-sized fields.
pub(super) unsafe trait PaddingFree: Sized {}

// SAFETY: Rust guarantees integer types have no padding bytes.
unsafe impl PaddingFree for u8 {}
unsafe impl PaddingFree for u16 {}
unsafe impl PaddingFree for u32 {}
unsafe impl PaddingFree for u64 {}
unsafe impl PaddingFree for u128 {}
unsafe impl PaddingFree for usize {}

// SAFETY: `[u8; N]` is N consecutive bytes — no padding possible.
unsafe impl<const N: usize> PaddingFree for [u8; N] {}

// SAFETY: these `#[repr(C)]` structs consist entirely of homogeneous `u64` or
// `usize` fields — verified by inspection: every field has the same alignment,
// so the compiler inserts no inter-field or trailing padding.
unsafe impl PaddingFree for crate::abi::diagnostic::SystemInfoRecord {}
unsafe impl PaddingFree for crate::abi::diagnostic::AllocProfilerRecord {}
unsafe impl PaddingFree for crate::abi::diagnostic::FaultProfilerRecord {}
unsafe impl PaddingFree for crate::abi::fs::DirectoryEntryRecord {}

// SAFETY: `FileStat` is `#[repr(C)]` with two `usize` fields — homogeneous,
// no padding.  Verified: size == 2 × size_of::<usize>() on all targets.
unsafe impl PaddingFree for crate::abi::fs::FileStat {}

// SAFETY: `AccessQueryRecord` is `#[repr(C)]` with `u16, u16, u32` —
// fields pack at offsets 0, 2, 4 with total size 8 (multiple of alignment 4).
// No inter-field or trailing padding.
unsafe impl PaddingFree for crate::abi::fs::AccessQueryRecord {}

// SAFETY: `PermissionMetadataRecord` is `#[repr(C)]` with `u32, u32, u16, u16` —
// fields pack at offsets 0, 4, 8, 10 with total size 12 (multiple of alignment 4).
// No padding.
unsafe impl PaddingFree for crate::abi::fs::PermissionMetadataRecord {}
unsafe impl PaddingFree for crate::abi::fs::FileFlagsRecord {}

// SAFETY: `ProcessSignalRecord` is `#[repr(C)]` with three `usize` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::process::ProcessSignalRecord {}

// SAFETY: `SignalFrame` is `#[repr(C)]` with four `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::process::SignalFrame {}

// SAFETY: `RuntimeAbiInfo` is `#[repr(C)]`.  The `_pad: u32` field at offset 12
// explicitly initialises the 4 bytes that `#[repr(C)]` would otherwise leave as
// implicit inter-field padding before the `u64`-aligned `feature_flags` field.
// All remaining fields are `u32`/`u64` (no inter-field or trailing padding), so
// the whole struct is initialised and safe to reinterpret as a byte slice.
unsafe impl PaddingFree for crate::abi::runtime::RuntimeAbiInfo {}

// SAFETY: `ProcessTerminationRecord` is `#[repr(C)]` with `usize, usize, u64,
// u64, usize, usize`.  On all 64-bit targets (the only targets this kernel
// supports), `usize` and `u64` both occupy 8 bytes with alignment 8 — all six
// fields are homogeneous in practice, so no inter-field or trailing padding.
unsafe impl PaddingFree for crate::abi::process::ProcessTerminationRecord {}

// SAFETY: `BootReportRecord` is `#[repr(C)]` with all `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::BootReportRecord {}

// SAFETY: `SystemHealthRecord` is `#[repr(C)]` with all `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::SystemHealthRecord {}

// SAFETY: `IrqProfilerRecord` is `#[repr(C)]` with only `u64` fields and
// `u64` arrays (`[u64; 256]`, `[u64; 16]`) — homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::IrqProfilerRecord {}

// SAFETY: `FsProfilerRecord` is `#[repr(C)]` with all `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::FsProfilerRecord {}

// SAFETY: `NetProfilerRecord` is `#[repr(C)]` with all `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::NetProfilerRecord {}

// SAFETY: `PerCpuRecord` is `#[repr(C)]` with all `u64` fields —
// homogeneous, no padding.
unsafe impl PaddingFree for crate::abi::diagnostic::PerCpuRecord {}

// SAFETY: `[usize; N]` arrays are contiguous usize values.  On all targets
// supported by this kernel, `usize` has the same size as its alignment
// (8 bytes on 64-bit), so arrays have no inter-element gaps.
unsafe impl<const N: usize> PaddingFree for [usize; N] {}

pub(super) fn copy_user_value<T: PaddingFree>(
    value: &T,
    buffer_ptr: *mut u8,
    length: usize,
) -> Result<usize> {
    copy_user_value_with_trailing_bytes(value, &[], buffer_ptr, length)
}

pub(super) fn copy_user_value_with_trailing_bytes<T: PaddingFree>(
    value: &T,
    trailing_bytes: &[u8],
    buffer_ptr: *mut u8,
    buffer_len: usize,
) -> Result<usize> {
    let value_bytes = value_as_bytes(value);
    let total_len = value_bytes
        .len()
        .checked_add(trailing_bytes.len())
        .ok_or(Error::InvalidArgument)?;

    copy_variable_user_payload(buffer_ptr, buffer_len, total_len, |buffer| {
        buffer[..value_bytes.len()].copy_from_slice(value_bytes);
        buffer[value_bytes.len()..].copy_from_slice(trailing_bytes);
    })
}

/// Return a byte-slice view of `value`.
///
/// The `PaddingFree` bound guarantees at compile time that `T` has no internal
/// padding bytes, so every byte read through the returned slice is initialised.
fn value_as_bytes<T: PaddingFree>(value: &T) -> &[u8] {
    // SAFETY: `PaddingFree` guarantees T has no padding bytes, so
    // `from_raw_parts` does not expose uninitialised memory.
    unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    }
}

fn copy_variable_user_payload(
    buffer_ptr: *mut u8,
    buffer_len: usize,
    required_len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> Result<usize> {
    if is_user_output_size_probe(buffer_len) {
        // Probe mode: return required size without writing user memory.
        return Ok(required_len);
    }

    validate_current_process_user_output_buffer(buffer_ptr, buffer_len, required_len)?;
    with_user_access_guard(|| {
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, required_len) };
        fill(buffer);
    });
    Ok(required_len)
}

fn is_user_output_size_probe(buffer_len: usize) -> bool {
    buffer_len == 0
}

pub(super) fn optional_user_input_slice<'a>(
    ptr: *const u8,
    length: usize,
) -> Result<Option<&'a [u8]>> {
    if length == 0 {
        // Caller can stay on the shared syscall validation path without
        // dereferencing a user pointer for empty payloads.
        return Ok(None);
    }

    validate_current_process_user_input_buffer(ptr, length, length)?;
    // SAFETY: The returned reference still points into user memory.  Callers
    // must consume the data inside a SMAP guard (see module-level docs).
    Ok(Some(unsafe { core::slice::from_raw_parts(ptr, length) }))
}

pub(super) fn with_optional_input_slice<T>(
    ptr: *const u8,
    length: usize,
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    if length == 0 {
        let empty = [];
        return f(&empty);
    }

    // Validate before entering the SMAP guard so page-table walk errors
    // (which are kernel-internal operations) don't run with AC set.
    validate_current_process_user_input_buffer(ptr, length, length)?;

    // SMAP guard wraps the dereference and the closure so user-memory
    // reads happen while AC is set.
    with_user_access_guard(|| {
        let buffer = unsafe { core::slice::from_raw_parts(ptr, length) };
        f(buffer)
    })
}

pub(super) fn optional_user_output_slice<'a>(
    ptr: *mut u8,
    length: usize,
) -> Result<Option<&'a mut [u8]>> {
    if length == 0 {
        return Ok(None);
    }

    validate_current_process_user_output_buffer(ptr, length, length)?;
    Ok(Some(unsafe {
        core::slice::from_raw_parts_mut(ptr, length)
    }))
}

pub(super) fn with_optional_output_slice<T>(
    ptr: *mut u8,
    length: usize,
    f: impl FnOnce(&mut [u8]) -> Result<T>,
) -> Result<T> {
    if length == 0 {
        let mut empty = [];
        return f(&mut empty);
    }

    // Validate before entering the SMAP guard so page-table walk errors
    // (which are kernel-internal operations) don't run with AC set.
    validate_current_process_user_output_buffer(ptr, length, length)?;

    // SMAP guard wraps the dereference and the closure so user-memory
    // writes happen while AC is set.
    with_user_access_guard(|| {
        let buffer = unsafe { core::slice::from_raw_parts_mut(ptr, length) };
        f(buffer)
    })
}

pub(super) fn read_user_value<T: Copy>(
    ptr: *const u8,
    length: usize,
    required_length: usize,
) -> Result<T> {
    validate_current_process_user_input_buffer(ptr, length, required_length)?;
    Ok(with_user_access_guard(|| unsafe {
        core::ptr::read_unaligned(ptr.cast::<T>())
    }))
}

/// Write `value` to user memory at `addr`, with SMAP guarding.
///
/// The caller must have already validated that the range `[addr, addr +
/// size_of::<T>())` is mapped writable in the current process's address
/// space.  This is used by the async signal delivery path in the interrupt
/// dispatcher.
///
/// # Safety
///
/// `addr` must point to writable user memory of at least `size_of::<T>()`
/// bytes.  The caller must have already validated the address range.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn write_user_value_untracked<T: Copy>(addr: u64, value: &T) {
    with_user_access_guard(|| {
        (addr as *mut T).write_unaligned(*value);
    })
}

pub(super) fn user_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str> {
    with_user_access_guard(|| {
        let bytes = optional_user_input_slice(ptr, len)?.ok_or(Error::InvalidArgument)?;
        core::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument)
    })
}

pub(super) fn user_string(ptr: *const u8, len: usize) -> Result<String> {
    if len == 0 {
        return Ok(String::new());
    }

    // SMAP guard wraps the read from user memory through to_string()'s copy
    // into kernel-owned storage.
    with_user_access_guard(|| {
        // user_str internally guards its own dereference; the outer guard
        // extends coverage to the to_string() copy into kernel memory.
        let bytes = optional_user_input_slice(ptr, len)?.ok_or(Error::InvalidArgument)?;
        let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument)?;
        Ok(s.to_string())
    })
}

pub(super) fn validate_current_process_user_input_buffer(
    buffer_ptr: *const u8,
    length: usize,
    required_length: usize,
) -> Result<()> {
    validate_user_input_buffer(buffer_ptr, length, required_length)?;

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    {
        validate_current_process_user_mapping(
            buffer_ptr as usize,
            required_length,
            crate::kernel::memory::paging::PagePermissions::READ,
        )?;
    }

    Ok(())
}

pub(super) fn validate_current_process_user_output_buffer(
    buffer_ptr: *mut u8,
    length: usize,
    required_length: usize,
) -> Result<()> {
    validate_user_output_buffer(buffer_ptr, length, required_length)?;

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_os = "none"
    ))]
    {
        if length != 0 {
            validate_current_process_user_mapping(
                buffer_ptr as usize,
                required_length,
                crate::kernel::memory::paging::PagePermissions::WRITE,
            )?;
        }
    }

    Ok(())
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "none"
))]
fn validate_current_process_user_mapping(
    start: usize,
    length: usize,
    required_permissions: crate::kernel::memory::paging::PagePermissions,
) -> Result<()> {
    if current_thread_requires_user_memory_validation()? {
        super::runtime::with_current_process(|process| {
            validate_user_mapping(process, start, length, required_permissions)
        })?;
    }

    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn current_thread_requires_user_memory_validation() -> Result<bool> {
    super::runtime::with_current_thread(|thread| Ok(thread.x86_64_user_context().is_some()))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_thread_requires_user_memory_validation() -> Result<bool> {
    super::runtime::with_current_thread(|thread| {
        thread
            .validated_aarch64_user_context()
            .map(|context| context.is_some())
    })
}

#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
const USER_MAPPING_VALIDATION_PAGE_SIZE: usize = 4096;

#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
pub(crate) fn validate_user_mapping(
    process: &crate::kernel::process::Process,
    start: usize,
    length: usize,
    required_permissions: crate::kernel::memory::paging::PagePermissions,
) -> Result<()> {
    if length == 0 {
        return Ok(());
    }

    let end = start.checked_add(length).ok_or(Error::InvalidArgument)?;
    let mut address = start;
    // Walk page-by-page to ensure every covered page has required permissions.
    while address < end {
        let translation = process
            .translate_user_address(address)
            .ok_or(Error::InvalidArgument)?;
        if !translation.permissions.contains(required_permissions) {
            return Err(Error::PermissionDenied);
        }

        address = next_user_mapping_validation_address(address, end);
    }

    Ok(())
}

#[cfg(all(target_arch = "x86_64", not(target_os = "none"), not(test),))]
pub(crate) fn validate_user_mapping(
    _process: &crate::kernel::process::Process,
    _start: usize,
    _length: usize,
    _required_permissions: crate::kernel::memory::paging::PagePermissions,
) -> Result<()> {
    // Host builds have no user page tables to walk; ptrace operates directly on
    // host-visible memory, so the mapping check is a no-op.
    Ok(())
}

#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
fn next_user_mapping_validation_address(address: usize, end: usize) -> usize {
    let next_page = (address | (USER_MAPPING_VALIDATION_PAGE_SIZE - 1))
        .checked_add(1)
        .unwrap_or(end);
    core::cmp::min(next_page, end)
}

fn validate_user_slice_length(length: usize) -> Result<()> {
    if length > isize::MAX as usize {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

fn validate_user_input_buffer(
    buffer_ptr: *const u8,
    length: usize,
    required_length: usize,
) -> Result<()> {
    if required_length == 0 {
        return Ok(());
    }

    validate_user_buffer_layout(buffer_ptr as usize, length, required_length)
}

/// Maximum inclusive canonical user virtual address.
///
/// x86_64 48-bit canonical lower half ends at `0x0000_7FFF_FFFF_FFFF`;
/// addresses at or above `0xFFFF_8000_0000_0000` belong to the kernel.
/// AArch64 39-bit TTBR0 space tops out well below this bound, so the
/// same constant provides a safe conservative gate on both architectures.
const USER_ADDRESS_MAX: usize = 0x0000_7FFF_FFFF_FFFF;

fn validate_user_pointer_range(start: usize, required_length: usize) -> Result<()> {
    if required_length == 0 {
        return Ok(());
    }

    // Overflow-safe exclusive end calculation for [start, start + required_length).
    let end = start
        .checked_add(required_length)
        .ok_or(Error::InvalidArgument)?;

    // Reject any range that extends into (or beyond) the kernel half of the
    // address space.  This is a cheap first-pass filter before the per-page
    // table walk in `validate_user_mapping`.
    if end > USER_ADDRESS_MAX.saturating_add(1) {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

fn validate_user_output_buffer(
    buffer_ptr: *mut u8,
    length: usize,
    required_length: usize,
) -> Result<()> {
    if length == 0 {
        // Zero-sized output is only valid when caller also requests zero bytes.
        return if required_length == 0 {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        };
    }

    validate_user_buffer_layout(buffer_ptr as usize, length, required_length)
}

fn validate_user_buffer_layout(
    buffer_ptr: usize,
    length: usize,
    required_length: usize,
) -> Result<()> {
    validate_user_slice_length(length)?;

    if buffer_ptr == 0 || length < required_length {
        return Err(Error::InvalidArgument);
    }

    validate_user_pointer_range(buffer_ptr, required_length)
}

// ── Centralized syscall-pointer pre-validation ──────────────────────────
//
// Each syscall that accepts user-memory pointers registers a concise
// descriptor in the static table below.  The trap dispatcher calls
// `validate_syscall_pointers()` *before* invoking the handler so that a
// missing or incorrect per-handler check cannot silently pass a bad pointer
// into the kernel.
//
// Syscalls not listed in the table rely on their own handler-side validation
// and are not pre-validated.

/// Whether the kernel will read from or write to the user pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerDirection {
    /// Kernel reads user memory (input buffer / string).
    In,
    /// Kernel writes user memory (output buffer / struct).
    Out,
    /// Kernel reads then writes (e.g. probe-mode buffers).
    #[allow(dead_code)]
    InOut,
}

/// Describes one pointer argument in a syscall's six-argument ABI.
struct SyscallPointerSpec {
    /// Which positional argument (0..5) holds the pointer.
    arg_index: usize,
    /// Read / write direction.
    direction: PointerDirection,
    /// Which positional argument carries the byte-length of the buffer,
    /// if the length is dynamic.
    size_arg_index: Option<usize>,
    /// For fixed-size structs (e.g. `ProcessSpawnOptions`), the exact
    /// byte size the kernel expects.
    fixed_size: Option<usize>,
}

impl SyscallPointerSpec {
    const fn input(
        arg_index: usize,
        size_arg_index: Option<usize>,
        fixed_size: Option<usize>,
    ) -> Self {
        Self {
            arg_index,
            direction: PointerDirection::In,
            size_arg_index,
            fixed_size,
        }
    }

    const fn output(
        arg_index: usize,
        size_arg_index: Option<usize>,
        fixed_size: Option<usize>,
    ) -> Self {
        Self {
            arg_index,
            direction: PointerDirection::Out,
            size_arg_index,
            fixed_size,
        }
    }
}

/// Static table of pointer layouts, indexed by syscall number.
///
/// Each entry is a slice of [`SyscallPointerSpec`] descriptors.  An empty
/// slice means the syscall either takes no pointer arguments or its pointers
/// are validated entirely inside the handler body.
const SYSCALL_POINTER_SPECS: &[&[SyscallPointerSpec]] = &[
    //  0  Yield              — no pointers
    &[],
    //  1  WriteDebug         — arg0=ptr (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    //  2  Open               — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    //  3  Exit               — no pointers
    &[],
    //  4  ReadConsole        — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    //  5  Read               — arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    //  6  Write              — arg1=ptr (in), arg2=len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    //  7  Close              — no pointers
    &[],
    //  8  Dup                — no pointers
    &[],
    //  9  Seek               — no pointers
    &[],
    // 10  ArgCount           — no pointers
    &[],
    // 11  ArgValue           — arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 12  EnvCount           — no pointers
    &[],
    // 13  EnvValue           — arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 14  CurrentDir         — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 15  AppId              — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 16  AppVersion         — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 17  ImagePath          — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 18  ManifestPath       — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 19  CreateDir          — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 20  SetLength          — no pointers (fd + length as integers)
    &[],
    // 21  RemovePath         — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 22  InstallExceptionHandler — validated inside handler (structured)
    &[],
    // 23  ReturnFromException — arg0=frame_ptr (in), fixed size
    &[],
    // 24  WaitProcess        — arg0=pid, arg1=timeout, arg2=ptr (out), arg3=len
    &[SyscallPointerSpec::output(2, Some(3), None)],
    // 25  SpawnProcess       — arg0=options_ptr (in), arg1=options_len (struct input)
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 26  ExecProcess        — arg0=options_ptr (in), arg1=options_len (struct input)
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 27  Stat               — arg0=path_ptr (in), arg1=path_len; arg2=stat_ptr (out), arg3=stat_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(2, Some(3), None),
    ],
    // 28  ReadDir            — arg0=path_ptr (in), arg1=path_len; arg2=index; arg3=out_ptr (out), arg4=out_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(3, Some(4), None),
    ],
    // 29  Rename             — arg0=old_ptr (in), arg1=old_len; arg2=new_ptr (in), arg3=new_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
    ],
    // 30  StatFd             — arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 31  ReadDirFd          — arg0=fd; arg1=index; arg2=ptr (out), arg3=len
    &[SyscallPointerSpec::output(2, Some(3), None)],
    // 32  OpenAt             — arg1=path_ptr (in), arg2=path_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 33  StatAt             — arg1=path_ptr (in), arg2=path_len; arg3=stat_ptr (out), arg4=stat_len
    &[
        SyscallPointerSpec::input(1, Some(2), None),
        SyscallPointerSpec::output(3, Some(4), None),
    ],
    // 34  RenameAt           — arg1=old_ptr (in), arg2=old_len; arg3=new_ptr (in), arg4=new_len
    &[
        SyscallPointerSpec::input(1, Some(2), None),
        SyscallPointerSpec::input(3, Some(4), None),
    ],
    // 35  CreateDirAt        — arg1=path_ptr (in), arg2=path_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 36  RemovePathAt       — arg1=path_ptr (in), arg2=path_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 37  NetworkStatus      — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 38  ConnectTcp         — arg0=host ptr (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 39  AbiInfo            — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 40  SendSignal         — no pointers
    &[],
    // 41  WaitSignal         — arg0=timeout, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 42  AccessQuery        — arg0=path_ptr (in), arg1=path_len; arg2=required_access;
    //                           arg3=out_ptr (out), arg4=out_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(3, Some(4), None),
    ],
    // 43  AccessQueryAt      — arg0=dirfd, arg1=path_ptr (in), arg2=path_len;
    //                           arg3=required_access; arg4=out_ptr (out), arg5=out_len
    &[
        SyscallPointerSpec::input(1, Some(2), None),
        SyscallPointerSpec::output(4, Some(5), None),
    ],
    // 44  AccessQueryFd      — arg0=fd, arg1=required_access, arg2=ptr (out), arg3=len
    &[SyscallPointerSpec::output(2, Some(3), None)],
    // 45  PermissionMetadata  — arg0=path_ptr (in), arg1=path_len; arg2=out_ptr (out), arg3=out_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(2, Some(3), None),
    ],
    // 46  PermissionMetadataAt — arg1=path_ptr (in), arg2=path_len; arg3=out_ptr (out), arg4=out_len
    &[
        SyscallPointerSpec::input(1, Some(2), None),
        SyscallPointerSpec::output(3, Some(4), None),
    ],
    // 47  PermissionMetadataFd — arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 48  SetFdFlags         — no pointers
    &[],
    // 49  Sleep              — no pointers
    &[],
    // 50  ListProcesses      — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 51  ListThreads        — arg0=pid, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 52  KernelLog          — arg0=offset, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 53  SystemInfo         — arg0=info_type, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 54  Fsync              — no pointers
    &[],
    // 55  Fdatasync          — no pointers
    &[],
    // 56  ListenTcp           — no pointers (port + backlog + flags as integers)
    &[],
    // 57  AcceptTcp           — no pointers (fd + flags as integers)
    &[],
    // 58  BindUdp             — no pointers (port + flags as integers)
    &[],
    // 59  SendToUdp           — arg3=data_ptr (input), arg4=data_len
    &[SyscallPointerSpec::input(3, Some(4), None)],
    // 60  RecvFromUdp         — arg1=buffer_ptr (output), arg2=buffer_len;
    //                           arg3=src_addr_out_ptr (output, fixed 8 bytes)
    &[
        SyscallPointerSpec::output(1, Some(2), None),
        SyscallPointerSpec::output(3, None, Some(8)),
    ],
    // 61  ListProcessFaults   — arg1=buffer_ptr (output), arg2=buffer_len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 62  Fork               — no pointer arguments
    &[],
    // 63  ReclaimPages       — no pointer arguments
    &[],
    // 64  Pipe               — arg0=buffer_ptr (output, 2 × usize), arg1=buffer_len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 65  Mount              — arg0=target_ptr (in), arg1=target_len; arg2=fstype_ptr (in), arg3=fstype_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
    ],
    // 66  Umount             — arg0=target_ptr (in), arg1=target_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 67  Mmap               — no pointer arguments (addr, length, prot, flags are integers)
    &[],
    // 68  Munmap             — no pointer arguments (addr, length are integers)
    &[],
    // 69  Dup2               — no pointers
    &[],
    // 70  GetTimeOfDay        — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 71  GetHostName          — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 72  SetHostName          — arg0=ptr (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 73  GetSockName          — arg0=fd, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 74  GetPeerName          — arg0=fd, arg1=ptr (out), arg2=len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 75  GetRandom            — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 76  CreateRawSocket      — arg0=protocol, arg1=flags (no pointers)
    &[],
    // 77  SendRawPacket        — arg0=fd, arg1=dest_ip_ptr (in), arg2=len,
    //                             arg3=data_ptr (in), arg4=len, arg5=flags
    &[
        SyscallPointerSpec::input(1, Some(2), None),
        SyscallPointerSpec::input(3, Some(4), None),
    ],
    // 78  RecvRawPacket        — arg0=fd, arg1=buffer_ptr (out), arg2=len,
    //                             arg3=src_addr_out_ptr (out), arg4=flags
    &[
        SyscallPointerSpec::output(1, Some(2), None),
        SyscallPointerSpec::output(3, None, None),
    ],
    // 79  SetSockOpt           — arg0=fd, arg1=level, arg2=name,
    //                             arg3=val_ptr (in), arg4=val_len, arg5=reserved
    &[SyscallPointerSpec::input(3, Some(4), None)],
    // 80  GetSockOpt           — arg0=fd, arg1=level, arg2=name,
    //                             arg3=val_ptr (out), arg4=val_len, arg5=reserved
    &[SyscallPointerSpec::output(3, Some(4), None)],
    // 81  GetPid                — no pointers
    &[],
    // 82  GetPpid               — no pointers
    &[],
    // 83  GetUid                — no pointers
    &[],
    // 84  GetGid                — no pointers
    &[],
    // 85  SetCurrentDir         — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 86  ListMounts            — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 87  ListBlockDevices      — arg0=ptr (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 88  SetSecurityDescriptor — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 89  AddUser               — arg0=name_ptr (in), arg1=name_len,
    //                             arg2=uid, arg3=gid,
    //                             arg4=home_ptr (in), arg5=home_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(4, Some(5), None),
    ],
    // 90  RemoveUser            — arg0=uid
    &[],
    // 91  SetUserPassword       — arg0=username_ptr (in), arg1=username_len,
    //                             arg2=password_ptr (in), arg3=password_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
    ],
    // 92  Brk                   — arg0=new_break (optional)
    &[],
    // 93  ResolveHostname       — arg0=host_ptr (in), arg1=host_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 94  SetSignalMask         — no pointers (arg0 is an integer mask)
    &[],
    // 95  RepairVolume          — arg0=path_ptr (in), arg1=path_len; arg2=report_ptr (out), arg3=report_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(2, Some(3), None),
    ],
    // 96  Poll                  — pointer validation inside handler
    &[],
    // 97  BindLocal             — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 98  ConnectLocal          — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 99  AcceptLocal           — arg0=listener_fd (no pointers)
    &[],
    // 100 ShmGet                — no pointers (key, size, flags are ints)
    &[],
    // 101 ShmAt                 — arg0=shmid, arg1=addr_hint, arg2=flags (all ints)
    &[],
    // 102 ShmDt                 — arg0=shmid (int)
    &[],
    // 103 ShmCtl                — arg0=shmid, arg1=cmd, arg2=buf (all ints for now)
    &[],
    // 104 SetSignalHandler       — arg0=signal, arg1=action (all ints)
    &[],
    // 105 FuseMount              — arg0=path_ptr(in), arg1=path_len, arg2=name_ptr(in), arg3=name_len, arg4=fds_ptr(out), arg5=fds_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
        SyscallPointerSpec::output(4, Some(5), None),
    ],
    // 106 Futex                  — arg0=uaddr (validated inline by handler)
    &[],
    // 107 EventFd                — arg0=initval, arg1=flags (all ints)
    &[],
    // 108 SignalFd               — arg0=sigset, arg1=flags (all ints)
    &[],
    // 109 TimerFd                — arg0=expiry_delta, arg1=interval_ticks, arg2=flags (all ints)
    &[],
    // 110 SchedSetAffinity       — arg0=cpu_mask (int)
    &[],
    // 111 SchedGetAffinity       — no arguments
    &[],
    // 112 MqOpen                 — arg0=name_ptr(in), arg1=name_len; all other args ints
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 113 MqClose                — arg0=fd (int)
    &[],
    // 114 MqSend                 — arg1=buf_ptr(in), arg2=buf_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 115 MqReceive              — arg1=buf_ptr(out), arg2=buf_len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 116 MqNotify               — arg0=fd, arg1=signo (all ints)
    &[],
    // 117 MqUnlink               — arg0=name_ptr(in), arg1=name_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 118 EpollCreate            — arg0=flags (int)
    &[],
    // 119 EpollCtl               — arg3=event_ptr(in), arg4=event_len
    &[SyscallPointerSpec::input(3, Some(4), None)],
    // 120 EpollWait              — arg1=events_ptr(out), arg2=events_len
    &[SyscallPointerSpec::output(1, Some(2), None)],
    // 121 TlsConnect              — arg0=host_ptr(in), arg1=host_len (same layout as ConnectTcp #38)
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 122 FilterAddRule           — arg0=rule_def_ptr(in), arg1=rule_def_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 123 FilterRemoveRule        — no pointers
    &[],
    // 124 FilterSetDefaultAction  — no pointers
    &[],
    // 125 FilterGetStats          — arg0=stats_ptr(out), arg1=stats_len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 126 IoUringSetup            — arg0=entries, arg1=flags (all ints)
    &[],
    // 127 IoUringEnter            — packed arg layout; validated inside handler
    &[],
    // 128 Ptrace                  — arg0=request, arg1=pid, arg2=addr, arg3=data, arg4=data_len
    &[],
    // 129 Seccomp                 — arg0=operation, arg1=flags, arg2=data_ptr, arg3=data_len
    &[SyscallPointerSpec::input(2, Some(3), None)],
    // 130 Prctl                    — dispatch inside handler (opcode-dependent)
    &[],
    // 131 Mlock                    — arg0=addr, arg1=len (no pointers)
    &[],
    // 132 Munlock                  — arg0=addr, arg1=len (no pointers)
    &[],
    // 133 Madvise                  — arg0=addr, arg1=len, arg2=advice (no pointers)
    &[],
    // 134 SigReturn                — arg0=frame_ptr (kernel reads via read_user_value)
    &[],
    // 135 SigSuspend               — no pointer arguments (signal mask is integer)
    &[],
    // 136 RestartSyscall           — no pointer arguments
    &[],
    // 137 TimerCreate               — no pointer arguments (clock_id + sevp as ints)
    &[],
    // 138 TimerSetTime              — arg2=new_value_ptr(in), arg3=old_value_ptr(out)
    &[
        SyscallPointerSpec::input(2, None, Some(16)), // struct itimerspec
        SyscallPointerSpec::output(3, None, Some(16)),
    ],
    // 139 TimerGetTime              — arg1=value_ptr(out)
    &[SyscallPointerSpec::output(1, None, Some(16))],
    // 140 TimerDelete               — no pointer arguments
    &[],
    // 141 — reserved (gap between TimerDelete=140 and AuditSetEnable=143)
    &[],
    // 142 — reserved (gap)
    &[],
    // 143 AuditSetEnable            — arg0=mask (integer, no pointers)
    &[],
    // 144 AuditReadLog              — arg0=buffer_ptr(out), arg1=max_records, arg2=record_size
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 145 CpufreqGet                — no pointer arguments
    &[],
    // 146 CpufreqSet                — arg0=freq_khz (integer, no pointers)
    &[],
    // 147 CpufreqGetRange           — no pointer arguments
    &[],
    // 148 CpufreqSetGovernor        — arg0=governor (integer, no pointers)
    &[],
    // 149 CpufreqGetTemp            — no pointer arguments
    &[],
    // 150 CompactMemory             — no pointer arguments
    &[],
    // 151 SetXattr                 — arg0=path_ptr (in), arg1=path_len; arg2=name_ptr (in), arg3=name_len; arg4=value_ptr (in), arg5=value_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
        SyscallPointerSpec::input(4, Some(5), None),
    ],
    // 152 GetXattr                 — arg0=path_ptr (in), arg1=path_len; arg2=name_ptr (in), arg3=name_len; arg4=value_ptr (out), arg5=value_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
        SyscallPointerSpec::output(4, Some(5), None),
    ],
    // 153 ListXattr                — arg0=path_ptr (in), arg1=path_len; arg2=buf_ptr (out), arg3=buf_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(2, Some(3), None),
    ],
    // 154 RemoveXattr              — arg0=path_ptr (in), arg1=path_len; arg2=name_ptr (in), arg3=name_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
    ],
    // 155 SetFileFlags             — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 156 GetFileFlags             — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 157 DccpBind               — no pointers (port + service_code integers)
    &[],
    // 158 DccpListen             — no pointers (port/backlog/service_code integers)
    &[],
    // 159 DccpConnect            — arg0 is a packed IPv4 address (integer) or
    //                              an IPv6 pointer when the IPV6 flag is set;
    //                              the handler validates the v6 pointer itself.
    &[],
    // 160 DccpAccept             — no pointers (fd + flags integers)
    &[],
    // 161 DccpSend               — arg1=data_ptr (input), arg2=data_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 162 DccpRecv               — arg1=buffer_ptr (output), arg2=buffer_len;
    //                              arg3=src_addr_out_ptr (output, 8 or 20 bytes)
    &[
        SyscallPointerSpec::output(1, Some(2), None),
        SyscallPointerSpec::output(3, None, Some(20)),
    ],
    // 163 DccpClose              — no pointers (fd + flags integers)
    &[],
    // 164 IpsecAddSp             — arg0=&IpsecSpDef (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 165 IpsecDelSp             — no pointers (sp_id integer)
    &[],
    // 166 IpsecAddSa             — arg0=&IpsecSaDef (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 167 IpsecDelSa             — no pointers (spi integer)
    &[],
    // 168 IpsecGetStats          — arg0=&IpsecStats (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 169 MrtInit                — no pointers (flags integer)
    &[],
    // 170 MrtDone                — no pointers (flags integer)
    &[],
    // 171 MrtAddVif              — arg0=&MrtVifDef (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 172 MrtDelVif              — no pointers (vif index integer)
    &[],
    // 173 MrtAddMfc              — arg0=&MrtMfcDef (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 174 MrtDelMfc              — no pointers (packed addresses)
    &[],
    // 175 MacSetMode              — no pointers (enabled + default_deny integers)
    &[],
    // 176 MacAddRule              — arg0=&MacRule (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 177 MacSetPathType          — arg0=path_ptr (in), arg1=path_len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 178 MacGetStatus            — arg0=&MacStatus (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
    // 179 Fcntl                    — no pointers (fd + cmd + arg integers)
    &[],
    // 180 Sync                     — no pointers
    &[],
    // 181 GpuCtxCreate             — no pointers (ctx_id integer)
    &[],
    // 182 GpuCtxDestroy            — no pointers (ctx_id integer)
    &[],
    // 183 GpuResCreate3d           — arg0=&GpuResCreate3dDesc (in), arg1=len
    &[SyscallPointerSpec::input(0, Some(1), None)],
    // 184 GpuResUnref              — no pointers (resource_id integer)
    &[],
    // 185 GpuTransferToHost3d      — arg0=&GpuTransfer3dDesc (in), arg1=len;
    //                                arg2=data (in), arg3=data_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::input(2, Some(3), None),
    ],
    // 186 GpuTransferFromHost3d    — arg0=&GpuTransfer3dDesc (in), arg1=len;
    //                                arg2=data (out), arg3=data_len
    &[
        SyscallPointerSpec::input(0, Some(1), None),
        SyscallPointerSpec::output(2, Some(3), None),
    ],
    // 187 GpuSubmit3d              — arg1=cmd_stream (in), arg2=cmd_len
    &[SyscallPointerSpec::input(1, Some(2), None)],
    // 188 GpuSetScanout            — no pointers (ids/size integers)
    &[],
    // 189 GpuDeviceInfo            — arg0=&GpuDeviceInfo (out), arg1=len
    &[SyscallPointerSpec::output(0, Some(1), None)],
];

/// Pre-validate every user-memory pointer declared in the syscall's
/// pointer-spec entry before the handler runs.
///
/// This is a defense-in-depth check: even if an individual handler forgets to
/// validate a pointer, the centralized check catches obvious violations
/// (null pointers, kernel-half addresses, insufficient buffer length).
///
/// Returns `Ok(())` when the syscall number has no pointer spec or when all
/// declared pointers pass validation.
pub(crate) fn validate_syscall_pointers(number: usize, args: &[usize; 6]) -> Result<()> {
    let specs = match SYSCALL_POINTER_SPECS.get(number) {
        Some(specs) => *specs,
        None => return Ok(()),
    };

    for spec in specs {
        let ptr = args[spec.arg_index];
        let size = resolve_size(spec, args);

        match spec.direction {
            PointerDirection::In | PointerDirection::InOut => {
                if let Err(e) =
                    validate_current_process_user_input_buffer(ptr as *const u8, size, size)
                {
                    Err(e)?
                }
            }
            PointerDirection::Out => {
                if let Err(e) =
                    validate_current_process_user_output_buffer(ptr as *mut u8, size, size)
                {
                    Err(e)?
                }
            }
        }
    }

    Ok(())
}

/// Resolve the byte length for a pointer spec.
///
/// Prefers `fixed_size` when present; otherwise reads the length from the
/// argument at `size_arg_index`.
fn resolve_size(spec: &SyscallPointerSpec, args: &[usize; 6]) -> usize {
    if let Some(fixed) = spec.fixed_size {
        return fixed;
    }
    if let Some(size_index) = spec.size_arg_index {
        return args[size_index];
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{
        copy_user_bytes, copy_user_value_with_trailing_bytes, fixed_output_buffer_arg,
        optional_user_input_slice, optional_user_output_slice, user_bounded_str, user_str,
        user_string, validate_user_input_buffer, validate_user_output_buffer,
        validate_user_pointer_range, FixedOutputBuffer, USER_ADDRESS_MAX,
    };
    use crate::Error;
    use alloc::string::String;
    use alloc::vec;

    const TEST_MAX_STRING_BYTES: usize = 4096;

    #[test]
    fn validate_user_input_buffer_rejects_pointer_range_overflow() {
        assert_eq!(
            validate_user_input_buffer(usize::MAX as *const u8, 2, 2),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_output_buffer_rejects_pointer_range_overflow() {
        assert_eq!(
            validate_user_output_buffer(usize::MAX as *mut u8, 2, 2),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_input_buffer_rejects_exclusive_end_overflow() {
        assert_eq!(
            validate_user_input_buffer(usize::MAX as *const u8, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_output_buffer_rejects_exclusive_end_overflow() {
        assert_eq!(
            validate_user_output_buffer(usize::MAX as *mut u8, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_output_buffer_rejects_zero_length_when_data_is_required() {
        assert_eq!(
            validate_user_output_buffer(core::ptr::dangling_mut::<u8>(), 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_output_buffer_accepts_zero_length_when_no_data_is_required() {
        assert_eq!(
            validate_user_output_buffer(core::ptr::null_mut(), 0, 0),
            Ok(())
        );
    }

    #[test]
    fn fixed_output_buffer_finish_with_writes_produced_value() {
        let mut output = 0_u32;
        let buffer = FixedOutputBuffer::<u32>::new(
            (&mut output as *mut u32).cast::<u8>(),
            core::mem::size_of::<u32>(),
        )
        .expect("construct typed output buffer");

        let dispatch = buffer
            .finish_with(|| Ok(0x1234_5678))
            .expect("write produced value");

        assert_eq!(
            dispatch,
            crate::kernel::syscall::SyscallDispatch::complete(4)
        );
        assert_eq!(output, 0x1234_5678);
    }

    #[test]
    fn fixed_output_buffer_finish_with_keeps_buffer_unchanged_on_error() {
        let mut output = 0xfeed_beefu32;
        let buffer = FixedOutputBuffer::<u32>::new(
            (&mut output as *mut u32).cast::<u8>(),
            core::mem::size_of::<u32>(),
        )
        .expect("construct typed output buffer");

        assert_eq!(
            buffer.finish_with(|| Err(Error::TimedOut)),
            Err(Error::TimedOut)
        );
        assert_eq!(output, 0xfeed_beef);
    }

    #[test]
    fn fixed_output_buffer_arg_reads_pointer_and_length_from_context() {
        let mut output = 0_u32;
        let context = crate::kernel::syscall::SyscallContext::new(
            0,
            [
                (&mut output as *mut u32).cast::<u8>() as usize,
                core::mem::size_of::<u32>(),
                0,
                0,
                0,
                0,
            ],
        );

        let dispatch = fixed_output_buffer_arg::<u32>(&context, 0, 1)
            .expect("decode typed output buffer from syscall arguments")
            .finish_with(|| Ok(0x89ab_cdef))
            .expect("write produced value");

        assert_eq!(
            dispatch,
            crate::kernel::syscall::SyscallDispatch::complete(4)
        );
        assert_eq!(output, 0x89ab_cdef);
    }

    #[test]
    fn user_bounded_str_rejects_length_above_limit() {
        let bytes = vec![b'a'; TEST_MAX_STRING_BYTES + 1];

        assert_eq!(
            user_bounded_str(bytes.as_ptr(), bytes.len(), TEST_MAX_STRING_BYTES),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn user_str_accepts_long_utf8_when_caller_does_not_impose_extra_limit() {
        let bytes = vec![b'a'; TEST_MAX_STRING_BYTES + 1];

        let decoded = user_str(bytes.as_ptr(), bytes.len()).expect("decode long user string");

        assert_eq!(decoded.len(), bytes.len());
    }

    #[test]
    fn user_bounded_str_accepts_utf8_within_limit() {
        let bytes = b"/data/users/guest/downloads";

        let decoded = user_bounded_str(bytes.as_ptr(), bytes.len(), TEST_MAX_STRING_BYTES)
            .expect("decode bounded user string");

        assert_eq!(decoded, "/data/users/guest/downloads");
    }

    #[test]
    fn user_string_accepts_empty_payload() {
        assert_eq!(user_string(core::ptr::null(), 0), Ok(String::new()));
    }

    #[test]
    fn copy_user_value_with_trailing_bytes_supports_size_probe() {
        assert_eq!(
            copy_user_value_with_trailing_bytes(&0x1234_5678_u32, b"xyz", core::ptr::null_mut(), 0),
            Ok(core::mem::size_of::<u32>() + 3)
        );
    }

    #[test]
    fn copy_user_bytes_size_probe_skips_invalid_pointer() {
        assert_eq!(copy_user_bytes(b"hello", usize::MAX as *mut u8, 0), Ok(5));
    }

    #[test]
    fn copy_user_value_with_trailing_bytes_writes_contiguous_payload() {
        let value = 0x1234_5678_u32;
        let mut buffer = [0_u8; 7];

        assert_eq!(
            copy_user_value_with_trailing_bytes(&value, b"xyz", buffer.as_mut_ptr(), buffer.len()),
            Ok(buffer.len())
        );
        assert_eq!(&buffer[..4], &value.to_ne_bytes());
        assert_eq!(&buffer[4..], b"xyz");
    }

    #[test]
    fn copy_user_value_with_trailing_bytes_rejects_short_buffer_without_partial_write() {
        let value = 0x1234_5678_u32;
        let mut buffer = [0xa5_u8; 6];

        assert_eq!(
            copy_user_value_with_trailing_bytes(&value, b"xyz", buffer.as_mut_ptr(), buffer.len()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(buffer, [0xa5; 6]);
    }

    #[test]
    fn copy_user_value_with_trailing_bytes_rejects_null_non_probe_buffer() {
        assert_eq!(
            copy_user_value_with_trailing_bytes(&0x1234_5678_u32, b"", core::ptr::null_mut(), 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn copy_user_bytes_empty_payload_accepts_probe() {
        assert_eq!(copy_user_bytes(b"", core::ptr::null_mut(), 0), Ok(0));
    }

    #[test]
    fn copy_user_bytes_empty_payload_rejects_null_non_probe_buffer() {
        assert_eq!(
            copy_user_bytes(b"", core::ptr::null_mut(), 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn copy_user_bytes_empty_payload_leaves_valid_non_probe_buffer_unchanged() {
        let mut buffer = [0x5a_u8; 1];

        assert_eq!(
            copy_user_bytes(b"", buffer.as_mut_ptr(), buffer.len()),
            Ok(0)
        );
        assert_eq!(buffer, [0x5a]);
    }

    #[test]
    fn optional_user_input_slice_skips_pointer_validation_for_empty_payload() {
        assert_eq!(
            optional_user_input_slice(usize::MAX as *const u8, 0),
            Ok(None)
        );
    }

    #[test]
    fn optional_user_output_slice_skips_pointer_validation_for_empty_payload() {
        assert_eq!(
            optional_user_output_slice(usize::MAX as *mut u8, 0),
            Ok(None)
        );
    }

    // ── kernel address range rejection ──

    #[test]
    fn validate_user_input_buffer_rejects_x86_64_kernel_address() {
        // 0xFFFF_8000_0000_0000 is the first address in the x86_64 kernel
        // higher-half — it must be rejected before the page-table walk.
        assert_eq!(
            validate_user_input_buffer(0xFFFF_8000_0000_0000_usize as *const u8, 8, 8),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_input_buffer_rejects_address_at_canonical_hole() {
        // The x86_64 non-canonical hole starts at 0x0000_8000_0000_0000.
        assert_eq!(
            validate_user_input_buffer(0x0000_8000_0000_0000_usize as *const u8, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_input_buffer_accepts_max_valid_user_address() {
        // 0x0000_7FFF_FFFF_FFFF is the last canonical user address on x86_64.
        // The pointer-range check accepts it; the page-table walk would
        // follow (and likely fail, but that's a separate concern).
        let range_result = validate_user_pointer_range(0x0000_7FFF_FFFF_FFFF_usize, 1);
        assert_eq!(range_result, Ok(()));
    }

    #[test]
    fn validate_user_input_buffer_rejects_range_straddling_user_kernel_boundary() {
        // Start valid, end in kernel half — must be rejected.
        assert_eq!(
            validate_user_input_buffer((USER_ADDRESS_MAX - 3) as *const u8, 8, 8,),
            Err(Error::InvalidArgument)
        );
    }

    // ── pointer-spec table completeness ──

    #[test]
    fn pointer_spec_table_covers_every_syscall() {
        assert_eq!(
            super::SYSCALL_POINTER_SPECS.len(),
            crate::kernel::syscall::table::PUBLIC_SYSCALL_COUNT as usize,
            "SYSCALL_POINTER_SPECS must have an entry for every public syscall \
             (found {} entries for {} syscalls)",
            super::SYSCALL_POINTER_SPECS.len(),
            crate::kernel::syscall::table::PUBLIC_SYSCALL_COUNT,
        );
    }

    #[test]
    fn pointer_specs_use_valid_arg_indices() {
        for (number, specs) in super::SYSCALL_POINTER_SPECS.iter().enumerate() {
            for spec in *specs {
                assert!(
                    spec.arg_index < 6,
                    "syscall {number}: arg_index {} out of range (must be 0-5)",
                    spec.arg_index
                );
                if let Some(size_idx) = spec.size_arg_index {
                    assert!(
                        size_idx < 6,
                        "syscall {number}: size_arg_index {size_idx} out of range (must be 0-5)",
                    );
                }
            }
        }
    }
}
