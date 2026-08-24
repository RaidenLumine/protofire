//! src/user/program/shell/commands/mod.rs
//!
//! Shell builtin command implementations, organised by category.
//!
//! Kernel-only commands (network, user mgmt, job control, file ownership) stay
//! here.  Shared commands are served by `crate::user::shared::commands` via the
//! dispatch table.

mod env;
mod network;
mod process;
mod user;

// ── Active kernel-only commands ─────────────────────────────────────────
// These stay kernel-side because they depend on kernel internals (ICMP
// packet construction, SecurityToken, Scheduler, JOBS globals).
// The former builtins fetch, nslookup, whoami, id, users, useradd, userdel,
// passwd, and chown were ring3 utility ELFs; no such payloads are built or
// shipped in this repo, so those commands are unavailable.
pub(crate) use env::cmd_source;
pub(crate) use network::cmd_ping;
pub(crate) use process::{cmd_bg, cmd_fg, cmd_jobs};
pub(crate) use user::{cmd_login, cmd_su};
