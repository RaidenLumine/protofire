//! src/user/shared/passwd.rs
//! `/etc/passwd` parsing helpers shared by the kernel shell and ring3 tools.
//!
//! The kernel user database (`sys_add_user`) persists user records to
//! `/data/etc/passwd` in standard `name:x:uid:gid:gecos:home:shell` format.
//! This module parses those records without depending on the kernel's
//! in-memory user manager, so it works identically in ring0 and ring3.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::user::shared::abi::io::OPEN_FLAG_READ;
use crate::user::shared::syscall;

/// Path to the persisted user database.
pub const PASSWD_PATH: &str = "/data/etc/passwd";

/// One parsed entry from the passwd file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Parse a single `name:x:uid:gid:gecos:home:shell` line.
///
/// Returns `None` for malformed lines (missing fields or non-numeric uid/gid).
pub fn parse_passwd_line(line: &str) -> Option<PasswdEntry> {
    let mut fields = line.trim().split(':');
    let username = fields.next()?.to_string();
    let _passwd_placeholder = fields.next()?;
    let uid = fields.next()?.parse::<u32>().ok()?;
    let gid = fields.next()?.parse::<u32>().ok()?;
    let _gecos = fields.next().unwrap_or("").to_string();
    let home = fields.next().unwrap_or("").to_string();
    let shell = fields.next().unwrap_or("").to_string();
    Some(PasswdEntry {
        username,
        uid,
        gid,
        home,
        shell,
    })
}

/// Load all entries from the passwd file.
///
/// Returns `None` when the file is absent, unreadable, or contains no valid
/// entries (so callers can fall back to a default user).
pub fn load_passwd_entries() -> Option<Vec<PasswdEntry>> {
    let fd = syscall::sys_open(PASSWD_PATH, OPEN_FLAG_READ).ok()?;
    let mut buf = [0u8; 4096];
    let n = syscall::sys_read(fd, &mut buf, 0).ok()?;
    let _ = syscall::sys_close(fd);

    let contents = core::str::from_utf8(&buf[..n]).ok()?;
    let entries: Vec<PasswdEntry> = contents.lines().filter_map(parse_passwd_line).collect();

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Look up an entry by username.
pub fn lookup_user(username: &str) -> Option<PasswdEntry> {
    load_passwd_entries()?
        .into_iter()
        .find(|entry| entry.username == username)
}

#[cfg(test)]
mod tests {
    use super::parse_passwd_line;

    #[test]
    fn parses_valid_line() {
        let entry = parse_passwd_line("root:x:0:0:root:/root:/bin/sh").unwrap();
        assert_eq!(entry.username, "root");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.home, "/root");
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse_passwd_line("").is_none());
        assert!(parse_passwd_line("nocolons").is_none());
        assert!(parse_passwd_line("u:x:notanumber:0::/:/bin/sh").is_none());
        assert!(parse_passwd_line("u:x:0").is_none());
    }
}
