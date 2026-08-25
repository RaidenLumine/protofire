//! src/user/shared/runtime.rs
//!
//! Ring-3 runtime syscall bridge (raw status-word to isize translation).
// ── Syscall bridge for the shared module ─────────────────────────────────────
//
// These #[no_mangle] extern "Rust" functions implement the symbols declared
// in crate::user::shared::syscall.  Each ring3 binary (shell, asm) previously
// duplicated them; they now live here once so the raw status-word → isize
// translation is consistent everywhere.
//
