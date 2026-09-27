//! src/syscall/mod.rs
//!
//! Syscall global dispatch entry and installation of active syscall table.

use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use crate::Error;
use crate::Result;

pub mod table;

pub use crate::abi::syscall as abi;
pub use table::SyscallAction;
pub use table::SyscallContext;
pub use table::SyscallDispatch;
pub use table::SyscallNumber;
pub use table::Table;
// `user_memory` is declared inside `table` (via `#[path = "memory/user.rs"]`),
// which is where its callers live: the handlers are all `#[path]`-declared
// inside `table` too, so they reach it as `super::user_memory`.
// Table-internal helpers that sibling code reaches through the `syscall::`
// path (`runtime`, `validate_zeroed_args`).  The remaining table helpers
// (`validate_known_flags`, launch-flag masks, ...) are reached directly via
// `super::` from modules that live inside `table`, so they are not re-exported
// here.
pub(crate) use table::runtime;
pub(crate) use table::validate_zeroed_args;

static GLOBAL_TABLE: AtomicPtr<Table> = AtomicPtr::new(ptr::null_mut());

pub fn install_global(table: &'static Table) {
    GLOBAL_TABLE.store(table as *const _ as *mut _, Ordering::SeqCst);
}

/// # Safety
///
/// The caller must guarantee `table` outlives every future `global()` access.
/// Prefer `install_global` whenever a `'static` reference is available.
pub unsafe fn install_global_unchecked(table: &Table) {
    GLOBAL_TABLE.store(table as *const _ as *mut _, Ordering::SeqCst);
}

impl Drop for Table {
    fn drop(&mut self) {
        let self_ptr = self as *mut Self;
        let _ = GLOBAL_TABLE.compare_exchange(
            self_ptr,
            ptr::null_mut(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

pub fn global() -> Option<&'static Table> {
    let table = GLOBAL_TABLE.load(Ordering::SeqCst);
    // SAFETY: the pointer is either null or one that was published through
    // that atomic by `install_global`, which requires a `'static` table and
    // clears the slot in `Table::drop`, so a non-null one names a live table.
    unsafe { table.as_ref() }
}

pub fn dispatch(context: &mut SyscallContext) -> Result<usize> {
    global().ok_or(Error::InternalError)?.dispatch(context)
}

pub fn dispatch_with_action(context: &mut SyscallContext) -> Result<SyscallDispatch> {
    global()
        .ok_or(Error::InternalError)?
        .dispatch_with_action(context)
}
