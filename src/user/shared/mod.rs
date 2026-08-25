//! src/user/shared/mod.rs
//!
//! Shared shell/user runtime logic for ring0 (kernel) and ring3 (user-space).
//!
//! This module provides platform-independent shell utilities and ABI record
//! types used by both the
//! kernel's built-in shell and (in the future) standalone ring3 ELF binaries:
//!
//! - **abi**           — ABI record types and constants (FileStat,
//!   DirectoryEntryRecord, …)
//! - **syscall**       — Syscall bridge: extern declarations + higher-level
//!   wrappers
//! - **types**         — Shared types (CmdResult)
//! - **path_util**     — Path resolution and normalization
//! - **tokenizer**     — Shell word tokenizer (quotes, escapes, whitespace)
//! - **pipeline**      — Conditional chaining (&&/||), pipeline splitting,
//!   redirect parsing
//! - **glob**          — Glob pattern matching (*, ?, [...] character classes)
//! - **expand**        — Environment variable expansion, get/set env
//! - **history**       — Command history: add, expand, common_prefix
//! - **control_flow**  — if/for/while parsing and execution
//!
//! All submodules are `#![no_std]` compatible and only use `alloc` (no std).

pub mod abi;
pub mod commands;
pub mod control_flow;
pub mod dispatch;
pub mod expand;
pub mod glob;
pub mod history;
pub mod jobs;
pub mod passwd;
pub mod path_util;
pub mod pipeline;
pub mod runtime;
pub mod signal;
pub mod syscall;
pub mod tokenizer;
pub mod types;
