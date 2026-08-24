//! src/user/shared/path_util.rs
//!
//! Path resolution and normalization utilities.

use alloc::string::String;
use alloc::vec::Vec;

/// Resolve a user-supplied path against the current working directory.
pub fn resolve_path(cwd: &str, path: &str) -> String {
    if path.is_empty() {
        return cwd.into();
    }

    // Absolute paths are used as-is.
    if path.starts_with('/') {
        return normalize_path_segments(path);
    }

    // Relative path — join with cwd.
    let base = cwd.trim_end_matches('/');
    let joined = if base.is_empty() {
        alloc::format!("/{path}")
    } else {
        alloc::format!("{base}/{path}")
    };
    normalize_path_segments(&joined)
}

/// Collapse `.` and `..` segments and strip trailing slashes.
pub fn normalize_path_segments(path: &str) -> String {
    let parts: Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();

    let mut result: Vec<&str> = Vec::new();
    for part in parts {
        if part == ".." {
            result.pop();
        } else {
            result.push(part);
        }
    }

    if result.is_empty() {
        return String::from("/");
    }

    let mut normalized = String::from("/");
    for (i, part) in result.iter().enumerate() {
        if i > 0 {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    normalized
}
