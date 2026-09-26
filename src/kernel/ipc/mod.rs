//! src/kernel/ipc/mod.rs
//!
//! Inter-process communication endpoints that present the filesystem's
//! `VNode` interface.
//!
//! An anonymous pipe lives here rather than under `fs` because of what it does
//! when its buffer is empty or full: it parks the calling thread, and parking
//! is a scheduler act.  The filesystem is storage, and it has no business
//! naming the scheduler to describe a buffer; the pipe borrows the `VNode`
//! interface so that it can sit in the namespace, which leaves the dependency
//! pointing one way — this module names `fs`, and `fs` names nothing here.

pub mod pipe;
