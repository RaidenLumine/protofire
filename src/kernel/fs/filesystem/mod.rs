//! src/kernel/fs/filesystem/mod.rs
//! FileSystem implementation modules — construction, mount, I/O, query,
//! security, rename, overlay, profiler, and supporting helpers & types.

pub(crate) mod access_helpers;
pub(crate) mod dir;
pub(crate) mod init;
pub(crate) mod io;
pub(crate) mod layout;
pub(crate) mod mount;
pub(crate) mod open;
pub(crate) mod overlay;
pub(crate) mod path_helpers;
pub(crate) mod profiler;
pub(crate) mod query;
pub(crate) mod rename;
pub(crate) mod resolve;
pub(crate) mod security;
pub(crate) mod security_helpers;
#[cfg(test)]
mod tests;
pub(crate) mod types;
pub(crate) mod xattr;
