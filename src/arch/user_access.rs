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

// ── tests ──────────────────────────────────────────────────────────────

/// The mapping check walks a real user address space, and only the x86_64
/// host build can materialize one in-process; the other targets take the
/// no-op arm above and have nothing to walk.  The gate is on the module, so
/// the tests below do not each carry it.
#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use alloc::sync::Arc;

    use super::validate_user_mapping;
    use crate::arch::mmu::materialize_user_address_space;
    use crate::kernel::process::Process;
    use crate::kernel::process::ProcessUserAddressSpace;
    use crate::kernel::sync::Mutex as KernelMutex;
    use crate::memory::paging::PagePermissions;
    use crate::user::program::UserImageLoadPlan;
    use crate::user::program::UserImageSegmentPlan;
    use crate::user::program::USER_EXCEPTION_STACK_GUARD_SIZE;
    use crate::user::program::USER_EXCEPTION_STACK_SIZE;
    use crate::user::program::USER_IMAGE_STACK_GAP;
    use crate::user::program::USER_PAGE_SIZE;
    use crate::user::program::USER_STACK_GUARD_SIZE;
    use crate::user::program::USER_STACK_SIZE;
    use crate::user::program::X86_64_USER_STACK_TOP;
    use crate::Error;

    // The pointer-validation fixture materializes a real user address space,
    // which only the x86_64 host build can do in-process.
    #[derive(Clone)]
    struct ValidationFixture {
        process: Arc<crate::kernel::process::Process>,
        entry_point: usize,
        image_end: usize,
        stack_bottom: usize,
        stack_pointer: usize,
        guard_start: usize,
    }

    fn build_validation_fixture() -> ValidationFixture {
        let entry_point = 0x0000_0000_0040_1000;
        let image_start = 0x0000_0000_0040_1000;
        let image_end = image_start + USER_PAGE_SIZE;
        let stack_top = X86_64_USER_STACK_TOP;
        let stack_bottom = stack_top - USER_STACK_SIZE;
        let stack_guard_start = stack_bottom - USER_STACK_GUARD_SIZE;
        let exception_stack_top = stack_guard_start;
        let exception_stack_bottom = exception_stack_top - USER_EXCEPTION_STACK_SIZE;
        let exception_stack_guard_start = exception_stack_bottom - USER_EXCEPTION_STACK_GUARD_SIZE;

        assert!(image_end + USER_IMAGE_STACK_GAP <= exception_stack_guard_start);

        let plan = UserImageLoadPlan {
            entry_point,
            image_start,
            image_end,
            stack_guard_start,
            stack_guard_end: stack_bottom,
            stack_bottom,
            stack_top,
            exception_stack_guard_start,
            exception_stack_guard_end: exception_stack_bottom,
            exception_stack_bottom,
            exception_stack_top,
            segments: alloc::vec![UserImageSegmentPlan {
                virtual_start: image_start,
                virtual_end: image_end,
                page_start: image_start,
                page_end: image_end,
                file_offset: 0,
                file_size: USER_PAGE_SIZE,
                zero_start: image_end,
                zero_end: image_end,
                permissions: PagePermissions::READ_EXECUTE,
            }],
        };
        let image = alloc::vec![0x90_u8; USER_PAGE_SIZE];
        let prepared =
            materialize_user_address_space(&plan, &image).expect("materialize user address space");
        let process = Process::new(7, "validation-user");
        process.install_user_address_space(ProcessUserAddressSpace::from_prepared(
            crate::arch::mmu::ProcessAddressSpace::from_prepared_user(prepared),
        ));

        ValidationFixture {
            process,
            entry_point,
            image_end,
            stack_bottom,
            stack_pointer: stack_top - core::mem::size_of::<usize>(),
            guard_start: stack_guard_start,
        }
    }

    fn validation_fixture() -> ValidationFixture {
        static FIXTURE: KernelMutex<Option<ValidationFixture>> = KernelMutex::new(None);
        let mut slot = FIXTURE.lock();
        if let Some(fixture) = slot.as_ref() {
            return fixture.clone();
        }

        let fixture = build_validation_fixture();
        *slot = Some(fixture.clone());
        fixture
    }

    #[test]
    fn validate_user_mapping_accepts_readable_user_pages() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.stack_pointer,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_zero_length_without_translation() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                usize::MAX,
                0,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_single_byte_at_mapped_page_tail() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.image_end - 1,
                1,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_accepts_exact_mapped_page_range() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                USER_PAGE_SIZE,
                PagePermissions::READ,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_rejects_unmapped_user_pages() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.guard_start,
                1,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_mapping_rejects_missing_permissions() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.entry_point,
                1,
                PagePermissions::WRITE,
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn validate_user_mapping_accepts_ranges_crossing_mapped_stack_pages() {
        let fixture = validation_fixture();
        let cross_page_start = fixture.stack_bottom + USER_PAGE_SIZE - 1;

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                cross_page_start,
                2,
                PagePermissions::READ,
            ),
            Ok(())
        );
        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                cross_page_start,
                2,
                PagePermissions::WRITE,
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_user_mapping_rejects_ranges_crossing_into_unmapped_gap() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                fixture.image_end - 1,
                2,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_user_mapping_rejects_address_range_overflow() {
        let fixture = validation_fixture();

        assert_eq!(
            validate_user_mapping(
                fixture.process.as_ref(),
                usize::MAX,
                2,
                PagePermissions::READ,
            ),
            Err(Error::InvalidArgument)
        );
    }
}
