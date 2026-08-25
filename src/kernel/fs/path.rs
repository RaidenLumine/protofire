//! src/kernel/fs/path.rs
//!
//! Path normalization and path-manipulation helpers for syscall and VFS
//! callers.

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::Result;

/// Normalise a user-supplied path against the current working directory.
///
/// The returned path is:
/// 1. Absolute (begins with `/`).
/// 2. Free of `.`, `..`, empty components, and redundant slashes.
/// 3. Pure UTF-8 — no Unicode normalisation is applied.  Like Linux and
///    HarmonyOS, the kernel treats filenames as opaque byte sequences and does
///    not second-guess the encoding form chosen by userspace.  Callers that
///    need NFD/NFC equivalence can opt into it via the `unicode` module.
pub fn normalize_path(path: &str, cwd: &str) -> Result<String> {
    let raw = sanitize_normalizable_path(path)?;
    // Force callers to provide an absolute cwd up front instead of silently
    // accepting relative working directories.
    let cwd = sanitize_absolute_cwd(cwd)?;
    // Resolve relative input against normalized cwd before canonical cleanup.
    if is_absolute(raw) {
        normalize_absolute_path(raw)
    } else {
        let absolute = join_paths(&cwd, raw);
        normalize_absolute_path(&absolute)
    }
}

fn sanitize_normalizable_path(path: &str) -> Result<&str> {
    let trimmed = sanitize_path_input(path)?;
    reject_drive_prefixed_path(trimmed)?;
    Ok(trimmed)
}

fn sanitize_absolute_cwd(cwd: &str) -> Result<String> {
    normalize_absolute_path(sanitize_normalizable_path(cwd)?)
}

fn sanitize_path_input(path: &str) -> Result<&str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Keep paths log-safe and parser-simple by rejecting embedded ASCII control
    // characters up front instead of letting them flow into VFS lookup logic.
    if trimmed.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(Error::InvalidArgument);
    }
    if trimmed.starts_with("//?/") {
        return Err(Error::InvalidArgument);
    }
    if trimmed.as_bytes().contains(&b'\\') {
        // Keep one public path language: callers must spell paths with `/`
        // instead of relying on backslash or NT-prefix compatibility.
        return Err(Error::InvalidArgument);
    }

    Ok(trimmed)
}

fn normalize_absolute_path(path: &str) -> Result<String> {
    reject_drive_prefixed_path(path)?;
    if !path.starts_with('/') {
        return Err(Error::InvalidArgument);
    }

    Ok(build_normalized_path(&collect_parts(
        path.trim_start_matches('/'),
    )))
}

fn collect_parts<'a>(path: &'a str) -> Vec<&'a str> {
    let mut parts: Vec<&'a str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                // Parent traversal clamps at root by dropping only when possible.
                let _ = parts.pop();
            }
            _ => parts.push(part),
        }
    }

    parts
}

fn build_normalized_path(parts: &[&str]) -> String {
    if parts.is_empty() {
        return String::from("/");
    }

    let mut capacity: usize = 1;
    for part in parts {
        capacity = capacity.saturating_add(part.len());
    }
    capacity = capacity.saturating_add(parts.len().saturating_sub(1));

    let mut normalized = String::with_capacity(capacity);
    normalized.push('/');
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    normalized
}

fn join_paths(base: &str, relative: &str) -> String {
    // This only concatenates. `normalize_path` canonicalizes the result after
    // joining.
    let trimmed_relative = relative.trim_start_matches('/');
    let mut joined = String::with_capacity(base.len() + 1 + trimmed_relative.len());
    joined.push_str(base);

    if !joined.ends_with('/') {
        joined.push('/');
    }

    joined.push_str(trimmed_relative);
    joined
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

fn reject_drive_prefixed_path(path: &str) -> Result<()> {
    if has_drive_prefix(path) {
        // Keep one internal filesystem truth rooted at `/system`, `/apps`, and
        // `/data` instead of silently projecting drive-prefixed syntax.
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

pub(crate) fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}
