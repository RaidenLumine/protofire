//! src/lib.rs
//!
//! Protofire Kernel Library
//!
//! This is the main library crate for the Protofire kernel.
//! It provides the core error types, module structure, and logging macros used
//! throughout the kernel and shared ring-3 library.

#![no_std]

extern crate alloc;
#[cfg(not(target_os = "none"))]
extern crate std;

pub mod abi;
pub mod arch;
pub mod drivers;
pub mod fs;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod syscall;
pub mod user;
pub mod util;

/// The `__stack_chk_guard` slot a `-Z stack-protector` build links against.
///
/// It is `#[no_mangle]` because the protector's ABI names the *symbol*, not a
/// Rust path: the compiler emits a load of `__stack_chk_guard` and a call to
/// `__stack_chk_fail`, and a mangled static leaves the first undefined at link
/// time — which is what it did until this attribute was added.
///
/// **A fixed value from the initialiser, never written at run time.**  Three
/// boots settled that, and each ruled out the previous explanation:
///
/// 1. Written on every context switch with the incoming thread's canary — the
///    wiring the tree had — panicked on every boot.
/// 2. Written on every switch with the *same* constant for every thread still
///    panicked, which ruled out "two threads disagree" and left the write
///    itself.
/// 3. A compile-time constant with nothing writing it ran clean.
///
/// The mechanism is the ABI: a protected function stores this value into its
/// frame in the prologue and reloads the global slot to compare in the
/// epilogue.  Any write in between — a context switch, an install call, this
/// thread's or another CPU's — makes that frame report corruption that never
/// happened.  There is no placement for the write that avoids it, because the
/// write happens while some frame is always live on some CPU.
///
/// What that costs is unpredictability: a value in the image is a value an
/// attacker who can read the image knows.  Per-CPU canaries need a slot each
/// CPU reads without a memory load that another CPU can rewrite mid-frame — an
/// `fs:`/`tp:`-relative slot, a change to the context switch rather than to
/// this static.  `docs/status.md` records that as the remaining work.
///
/// **What this does not do yet: guard a frame.**  No build in the tree passes
/// `-Z stack-protector`, so no function stores or compares this value and
/// `__stack_chk_fail` is never reached by generated code.  What exists is the
/// slot and the handler, which is what turning the flag on needs; the flag
/// waits on the payloads being their own compilation unit, and
/// `docs/status.md` records why.  A comment here that claimed an overflow is
/// caught today would be the defect this tree names most often.
const STACK_CANARY: usize = 0x4F3A_9C15_B7E2_D806;

#[allow(non_upper_case_globals)]
#[no_mangle]
pub static __stack_chk_guard: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(STACK_CANARY);

/// Returns a raw `*mut usize` to the stack canary guard slot.
///
/// For a test that wants to read the slot through the address the protector
/// names.  The compiler does not call this — it emits a load of the symbol
/// directly, which is why the static is `#[no_mangle]` — so the only caller in
/// the tree is `the_canary_guard_is_a_fixed_value_the_protector_can_read`.
pub fn __stack_chk_guard_ptr() -> *mut usize {
    &__stack_chk_guard as *const core::sync::atomic::AtomicUsize as *mut usize
}

/// What a `-Z stack-protector` build calls when a frame's canary did not come
/// back.
///
/// The kernel aborts rather than returns: a canary that changed means the
/// frame it belonged to was written past its end, and continuing runs code
/// whose return address may have been written by whatever did it.  The abort is
/// the right answer here because the alternative — unwinding — needs a frame
/// whose return address is exactly what is in doubt.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    crate::println!("[panic ] stack canary mismatch: a frame was written past its end");
    loop {
        crate::arch::halt();
    }
}

/// Result type used throughout the kernel.
///
/// Re-exported from `protofire-bits`, which is where it lives: every module
/// names it, and a module that names this crate's root cannot itself be a
/// crate.  The path is unchanged so that the three hundred call sites are too.
/// The base crate, under the name the tree already uses for its own modules.
pub use protofire_bits as bits;

pub use protofire_bits::Error;
pub use protofire_bits::Result;

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::util::debug::_print(core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n");
    };
    ($fmt:expr) => {
        $crate::print!(concat!($fmt, "\n"));
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::print!(concat!($fmt, "\n"), $($arg)*);
    };
}
