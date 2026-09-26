//! src/arch/user_access.rs
//!
//! The kernel's view of memory a caller owns, per architecture.
//!
//! Two questions live here.  The first is whether the CPU needs a window
//! opened around a user-memory access — x86_64's SMAP, aarch64's PAN, riscv64's
//! SUM — and what that window costs.  The second is whether a thread's user
//! addresses can be checked against a page table at all, and how: the answer
//! is a walk on the bare-metal targets that have one, a refusal to pretend on
//! the host, and "the prototype does not check" on riscv64.
//!
//! Both are the architecture's to answer, so the syscall layer asks here
//! rather than naming an architecture to copy a buffer.

use crate::kernel::process::Process;
use crate::kernel::process::Thread;
use crate::memory::paging::PagePermissions;
// Only the mapping walk refuses a range, and the walk exists only where a
// user page table does.
#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
use crate::Error;
use crate::Result;

// ── the user-access window ─────────────────────────────────────────────

/// Run `f` with supervisor access to user memory permitted.
///
/// x86_64 sets EFLAGS.AC for the duration, aarch64 clears PSTATE.PAN, riscv64
/// sets SUM; each restores the previous state when the guard drops.  On a
/// host there is nothing to permit: plain memory is both.
#[cfg(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
#[inline]
pub(crate) fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: the closure is the user-memory access itself; the guard only
    // widens access for its duration and restores the previous state on drop,
    // so a panic or an early return cannot leave the window open.
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

/// The same call where there is no window to open.
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "none"),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
)))]
#[inline]
pub(crate) fn with_user_access_guard<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// Write a value to user memory that the caller has already validated.
///
/// x86_64's asynchronous signal delivery writes the frame the handler will
/// see straight into the caller's stack; there is no other architecture with
/// that path yet.
///
/// # Safety
///
/// `addr` must point to writable user memory of at least `size_of::<T>()`
/// bytes.  The caller must have already validated the address range.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn write_user_value_untracked<T: Copy>(addr: u64, value: &T) {
    unsafe {
        with_user_access_guard(|| {
            (addr as *mut T).write_unaligned(*value);
        })
    }
}

// ── the user-mapping check ─────────────────────────────────────────────

/// Whether this target checks a syscall's user addresses against the current
/// thread's address space.
///
/// x86_64 and aarch64 bare metal do; riscv64's prototype does not, and a host
/// has no address space of the kind these checks need.  The users of this
/// constant skip the lookup rather than ask it, because on a target that does
/// not check there may be no current thread yet, and asking would turn "no
/// check here" into an error.
pub(crate) const VALIDATES_USER_MAPPINGS: bool = cfg!(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "none"
));

#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
const USER_MAPPING_VALIDATION_PAGE_SIZE: usize = 4096;

/// Reject a range the current thread's address space does not cover with the
/// permissions the operation needs.
///
/// This is the version that walks: it asks the process to translate each page
/// and checks what it finds.  The host gets the other one — there are no user
/// page tables to walk, and ptrace operates on host-visible memory there.
#[cfg(any(
    all(target_arch = "x86_64", any(test, target_os = "none")),
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
pub(crate) fn validate_user_mapping(
    process: &Process,
    start: usize,
    length: usize,
    required_permissions: PagePermissions,
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

#[cfg(any(
    all(target_arch = "x86_64", not(target_os = "none"), not(test)),
    all(target_arch = "aarch64", not(target_os = "none")),
    all(target_arch = "riscv64", not(target_os = "none"))
))]
pub(crate) fn validate_user_mapping(
    _process: &Process,
    _start: usize,
    _length: usize,
    _required_permissions: PagePermissions,
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

/// Does this thread have a user half whose addresses must be checked?
///
/// x86_64 answers with the saved user context it carries, aarch64 with the
/// validated one; riscv64's threads have neither yet, so the answer is no
/// rather than a guess.
pub(crate) fn thread_requires_user_memory_validation(thread: &Thread) -> Result<bool> {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        Ok(thread.x86_64_user_context().is_some())
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        thread
            .validated_aarch64_user_context()
            .map(|context| context.is_some())
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none")
    )))]
    {
        let _ = thread;
        Ok(false)
    }
}
