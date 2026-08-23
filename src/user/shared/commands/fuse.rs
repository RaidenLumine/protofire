//! src/user/shared/commands/fuse.rs
//! FUSE (Filesystem in Userspace) shell command and RAM FS daemon.
//!
//! Provides the `fuse` shell command:
//! - `fuse mount <path> <name>` — mounts a FUSE filesystem at `<path>` and
//!   runs a built-in RAM FS daemon that handles all VFS operations.
//! - `fuse umount <path>` — unmounts a FUSE filesystem.
//!
//! The daemon implements a simple in-memory filesystem using a `BTreeMap` of
//! inodes.  No external daemon process is required — the daemon runs inline
//! in the shell command.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::user::shared::syscall;
use crate::user::shared::types::CmdResult;

// ── Wire-format constants (match kernel/fuse/mod.rs) ──────────────────────

const FUSE_HEADER_SIZE: usize = 24;

const FUSE_LOOKUP: u32 = 0x01;
const FUSE_STAT: u32 = 0x02;
const FUSE_READ: u32 = 0x03;
const FUSE_WRITE: u32 = 0x04;
const FUSE_READDIR: u32 = 0x05;
const FUSE_CREATE: u32 = 0x06;
const FUSE_REMOVE: u32 = 0x07;
const FUSE_CREATEDIR: u32 = 0x08;
const FUSE_RENAME: u32 = 0x09;
const FUSE_SETLEN: u32 = 0x0A;
const FUSE_FLUSH: u32 = 0x0B;
const FUSE_ERROR: u32 = 0xFF;

/// Unlimited wait for reads.
const WAIT_FOREVER: u64 = u64::MAX;

// ── In-memory filesystem types ───────────────────────────────────────────

#[derive(Clone)]
struct Inode {
    /// 0 = File, 1 = Directory
    kind: u32,
    /// File content (directories store an empty Vec).
    data: Vec<u8>,
    /// Child directory entries: name → inode number.
    /// Only meaningful when kind == 1 (Directory).
    children: BTreeMap<String, u64>,
}

/// FUSE RAM FS daemon.
struct FuseDaemon {
    req_fd: usize,
    resp_fd: usize,
    inodes: BTreeMap<u64, Inode>,
    next_ino: u64,
}

impl FuseDaemon {
    fn new(req_fd: usize, resp_fd: usize) -> Self {
        let mut inodes = BTreeMap::new();
        // Root directory at inode 1 (FUSE convention).
        inodes.insert(
            1,
            Inode {
                kind: 1,
                data: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        Self {
            req_fd,
            resp_fd,
            inodes,
            next_ino: 2,
        }
    }

    /// Allocate a fresh inode number.
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    // ── I/O helpers ────────────────────────────────────────────────────

    fn read_exact(&self, fd: usize, buf: &mut [u8]) -> Result<(), isize> {
        let mut offset = 0;
        while offset < buf.len() {
            let n = syscall::sys_read(fd, &mut buf[offset..], WAIT_FOREVER)?;
            if n == 0 {
                return Err(-6); // DeviceError (EOF)
            }
            offset += n;
        }
        Ok(())
    }

    fn write_all(&self, fd: usize, buf: &[u8]) -> Result<(), isize> {
        let mut offset = 0;
        while offset < buf.len() {
            let n = syscall::sys_write(fd, &buf[offset..])?;
            if n == 0 {
                return Err(-6);
            }
            offset += n;
        }
        Ok(())
    }

    // ── Request/response helpers ────────────────────────────────────────

    /// Read a complete FUSE request from the request pipe.
    fn read_request(&self) -> Result<(u64, u32, u64, Vec<u8>), isize> {
        let mut header_buf = [0u8; FUSE_HEADER_SIZE];
        self.read_exact(self.req_fd, &mut header_buf)?;

        let seq = u64::from_le_bytes(header_buf[0..8].try_into().unwrap());
        let opcode = u32::from_le_bytes(header_buf[8..12].try_into().unwrap());
        let ino = u64::from_le_bytes(header_buf[12..20].try_into().unwrap());
        let payload_len = u32::from_le_bytes(header_buf[20..24].try_into().unwrap()) as usize;

        let mut payload = Vec::with_capacity(payload_len);
        if payload_len > 0 {
            payload.resize(payload_len, 0);
            self.read_exact(self.req_fd, &mut payload)?;
        }

        Ok((seq, opcode, ino, payload))
    }

    /// Write a FUSE response (header + payload) to the response pipe.
    fn write_response(&self, seq: u64, opcode: u32, ino: u64, payload: &[u8]) -> Result<(), isize> {
        let mut header_buf = [0u8; FUSE_HEADER_SIZE];
        header_buf[0..8].copy_from_slice(&seq.to_le_bytes());
        header_buf[8..12].copy_from_slice(&opcode.to_le_bytes());
        header_buf[12..20].copy_from_slice(&ino.to_le_bytes());
        header_buf[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());

        self.write_all(self.resp_fd, &header_buf)?;
        if !payload.is_empty() {
            self.write_all(self.resp_fd, payload)?;
        }
        Ok(())
    }

    /// Write an ERROR response.
    fn write_error(&self, seq: u64, error_code: u32) -> Result<(), isize> {
        let payload = error_code.to_le_bytes().to_vec();
        self.write_response(seq, FUSE_ERROR, 0, &payload)
    }

    // ── NodeInfo serialisation ─────────────────────────────────────────

    /// Build a NodeInfo payload from inode metadata.
    fn build_node_info(&self, ino: u64) -> Vec<u8> {
        let inode = self.inodes.get(&ino).expect("inode must exist");
        let name = ""; // Name is not stored in the inode — the caller fills it.
        let mut buf = Vec::with_capacity(24 + name.len());
        buf.extend_from_slice(&ino.to_le_bytes());       // ino (8)
        buf.extend_from_slice(&inode.kind.to_le_bytes()); // kind (4)
        buf.extend_from_slice(&(inode.data.len() as u64).to_le_bytes()); // size (8)
        buf.extend_from_slice(&0u32.to_le_bytes());       // name_len (4)
        buf
    }

    fn build_node_info_with_name(&self, ino: u64, name: &str) -> Vec<u8> {
        let inode = self.inodes.get(&ino).expect("inode must exist");
        let name_bytes = name.as_bytes();
        let mut buf = Vec::with_capacity(24 + name_bytes.len());
        buf.extend_from_slice(&ino.to_le_bytes());
        buf.extend_from_slice(&inode.kind.to_le_bytes());
        buf.extend_from_slice(&(inode.data.len() as u64).to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf
    }

    // ── Request handlers ────────────────────────────────────────────────

    /// Handle a LOOKUP request.
    ///
    /// Payload: component name (UTF-8 bytes)
    /// Response: NodeInfo of the child, or ERROR if not found.
    fn handle_lookup(&mut self, seq: u64, parent_ino: u64, payload: &[u8]) -> Result<(), isize> {
        let name = core::str::from_utf8(payload).map_err(|_| -1)?; // InvalidArgument
        let parent = self.inodes.get(&parent_ino).ok_or(-2)?; // NotFound

        let child_ino = *parent.children.get(name).ok_or(-2)?; // NotFound
        let node_info = self.build_node_info_with_name(child_ino, name);
        self.write_response(seq, FUSE_LOOKUP, child_ino, &node_info)
    }

    /// Handle a STAT request.
    ///
    /// Payload: (none)
    /// Response: NodeInfo of the inode.
    fn handle_stat(&self, seq: u64, ino: u64) -> Result<(), isize> {
        if !self.inodes.contains_key(&ino) {
            return self.write_error(seq, 1); // ENoEnt
        }
        let node_info = self.build_node_info(ino);
        self.write_response(seq, FUSE_STAT, ino, &node_info)
    }

    /// Handle a READ request.
    ///
    /// Payload: offset(8) + size(4)
    /// Response: file data bytes.
    fn handle_read(&self, seq: u64, ino: u64, payload: &[u8]) -> Result<(), isize> {
        if payload.len() < 12 {
            return self.write_error(seq, 8); // EInval
        }
        let offset = u64::from_le_bytes(payload[0..8].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;

        let inode = self.inodes.get(&ino).ok_or(-2)?; // NotFound
        let data = &inode.data;
        let end = (offset + size).min(data.len());
        let slice = if offset < data.len() {
            &data[offset..end]
        } else {
            &[]
        };

        self.write_response(seq, FUSE_READ, ino, slice)
    }

    /// Handle a WRITE request.
    ///
    /// Payload: offset(8) + data
    /// Response: bytes_written(4)
    fn handle_write(&mut self, seq: u64, ino: u64, payload: &[u8]) -> Result<(), isize> {
        if payload.len() < 8 {
            return self.write_error(seq, 8); // EInval
        }
        let offset = u64::from_le_bytes(payload[0..8].try_into().unwrap()) as usize;
        let data = &payload[8..];

        let inode = self.inodes.get_mut(&ino).ok_or(-2)?; // NotFound
        if offset + data.len() > inode.data.len() {
            inode.data.resize(offset + data.len(), 0);
        }
        inode.data[offset..offset + data.len()].copy_from_slice(data);

        let written = data.len() as u32;
        self.write_response(seq, FUSE_WRITE, ino, &written.to_le_bytes())
    }

    /// Handle a READDIR request.
    ///
    /// Payload: index(4)
    /// Response: DirEntry (NodeInfo format), or empty for "no more entries".
    fn handle_readdir(&self, seq: u64, ino: u64, payload: &[u8]) -> Result<(), isize> {
        let index = if payload.len() >= 4 {
            u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize
        } else {
            return self.write_error(seq, 8); // EInval
        };

        let inode = self.inodes.get(&ino).ok_or(-2)?; // NotFound
        let children: Vec<(&String, &u64)> = inode.children.iter().collect();

        if index >= children.len() {
            // No more entries: return empty payload.
            return self.write_response(seq, FUSE_READDIR, ino, &[]);
        }

        let (name, child_ino) = children[index];
        let entry = self.build_node_info_with_name(*child_ino, name);
        self.write_response(seq, FUSE_READDIR, ino, &entry)
    }

    /// Handle a CREATE request.
    ///
    /// Payload: filename (UTF-8 bytes)
    /// Response: NodeInfo of the new file.
    fn handle_create(&mut self, seq: u64, parent_ino: u64, payload: &[u8]) -> Result<(), isize> {
        let name = core::str::from_utf8(payload).map_err(|_| -1)?; // InvalidArgument

        let parent = self.inodes.get(&parent_ino).ok_or(-2)?; // NotFound
        if parent.kind != 1 {
            return self.write_error(seq, 8); // EInval — not a directory
        }
        if parent.children.contains_key(name) {
            return self.write_error(seq, 5); // EExists
        }

        let child_ino = self.alloc_ino();
        self.inodes.insert(
            child_ino,
            Inode {
                kind: 0, // File
                data: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        self.inodes
            .get_mut(&parent_ino)
            .unwrap()
            .children
            .insert(name.to_string(), child_ino);

        let node_info = self.build_node_info_with_name(child_ino, name);
        self.write_response(seq, FUSE_CREATE, child_ino, &node_info)
    }

    /// Handle a REMOVE request.
    ///
    /// Payload: filename (UTF-8 bytes)
    fn handle_remove(&mut self, seq: u64, parent_ino: u64, payload: &[u8]) -> Result<(), isize> {
        let name = core::str::from_utf8(payload).map_err(|_| -1)?; // InvalidArgument

        let child_ino = {
            let parent = self.inodes.get(&parent_ino).ok_or(-2)?; // NotFound
            let child_ino = *parent.children.get(name).ok_or(-2)?;
            // Only allow removing empty directories or files.
            let child = self.inodes.get(&child_ino).ok_or(-2)?;
            if child.kind == 1 && !child.children.is_empty() {
                return self.write_error(seq, 7); // EBusy
            }
            child_ino
        };

        self.inodes.remove(&child_ino);
        self.inodes
            .get_mut(&parent_ino)
            .unwrap()
            .children
            .remove(name);
        self.write_response(seq, FUSE_REMOVE, parent_ino, &[])
    }

    /// Handle a CREATEDIR request (mkdir).
    ///
    /// Payload: filename (UTF-8 bytes)
    fn handle_create_dir(&mut self, seq: u64, parent_ino: u64, payload: &[u8]) -> Result<(), isize> {
        let name = core::str::from_utf8(payload).map_err(|_| -1)?; // InvalidArgument

        let parent = self.inodes.get(&parent_ino).ok_or(-2)?; // NotFound
        if parent.kind != 1 {
            return self.write_error(seq, 8); // EInval
        }
        if parent.children.contains_key(name) {
            return self.write_error(seq, 5); // EExists
        }

        let child_ino = self.alloc_ino();
        self.inodes.insert(
            child_ino,
            Inode {
                kind: 1, // Directory
                data: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        self.inodes
            .get_mut(&parent_ino)
            .unwrap()
            .children
            .insert(name.to_string(), child_ino);

        self.write_response(seq, FUSE_CREATEDIR, child_ino, &[])
    }

    /// Handle a RENAME request.
    ///
    /// Payload: old_name NUL new_name
    fn handle_rename(&mut self, seq: u64, parent_ino: u64, payload: &[u8]) -> Result<(), isize> {
        // Split payload on NUL byte.
        let nul_pos = payload.iter().position(|&b| b == 0).ok_or(-1)?; // InvalidArgument
        let old_name =
            core::str::from_utf8(&payload[..nul_pos]).map_err(|_| -1)?;
        let new_name =
            core::str::from_utf8(&payload[nul_pos + 1..]).map_err(|_| -1)?;

        let child_ino = {
            let parent = self.inodes.get(&parent_ino).ok_or(-2)?;
            *parent.children.get(old_name).ok_or(-2)? // NotFound
        };

        // Remove old name, insert new name.
        self.inodes
            .get_mut(&parent_ino)
            .unwrap()
            .children
            .remove(old_name);
        self.inodes
            .get_mut(&parent_ino)
            .unwrap()
            .children
            .insert(new_name.to_string(), child_ino);

        self.write_response(seq, FUSE_RENAME, child_ino, &[])
    }

    /// Handle a SETLEN request (truncate).
    ///
    /// Payload: length(8)
    fn handle_set_len(&mut self, seq: u64, ino: u64, payload: &[u8]) -> Result<(), isize> {
        if payload.len() < 8 {
            return self.write_error(seq, 8); // EInval
        }
        let length = u64::from_le_bytes(payload[0..8].try_into().unwrap()) as usize;

        let inode = self.inodes.get_mut(&ino).ok_or(-2)?; // NotFound
        inode.data.resize(length, 0);
        self.write_response(seq, FUSE_SETLEN, ino, &[])
    }

    /// Handle a FLUSH request.
    fn handle_flush(&self, seq: u64, ino: u64) -> Result<(), isize> {
        // RAM FS — nothing to flush.
        self.write_response(seq, FUSE_FLUSH, ino, &[])
    }

    // ── Main dispatch loop ──────────────────────────────────────────────

    /// Run the daemon loop forever (or until the pipe breaks).
    fn run(&mut self) -> Result<(), isize> {
        loop {
            let (seq, opcode, ino, payload) = self.read_request()?;

            let result = match opcode {
                FUSE_LOOKUP => self.handle_lookup(seq, ino, &payload),
                FUSE_STAT => self.handle_stat(seq, ino),
                FUSE_READ => self.handle_read(seq, ino, &payload),
                FUSE_WRITE => self.handle_write(seq, ino, &payload),
                FUSE_READDIR => self.handle_readdir(seq, ino, &payload),
                FUSE_CREATE => self.handle_create(seq, ino, &payload),
                FUSE_REMOVE => self.handle_remove(seq, ino, &payload),
                FUSE_CREATEDIR => self.handle_create_dir(seq, ino, &payload),
                FUSE_RENAME => self.handle_rename(seq, ino, &payload),
                FUSE_SETLEN => self.handle_set_len(seq, ino, &payload),
                FUSE_FLUSH => self.handle_flush(seq, ino),
                _ => self.write_error(seq, 6), // ENOSYS
            };

            if let Err(e) = result {
                // Write errors (pipe break) are fatal.
                if e != 0 {
                    return Err(e);
                }
            }
        }
    }
}

// ── Shell command ─────────────────────────────────────────────────────────

/// FUSE shell command.
///
/// Usage:
///   fuse mount <path> <name>    — Mount a FUSE filesystem and run the daemon.
///   fuse umount <path>          — Unmount a FUSE filesystem.
pub fn cmd_fuse(argv: &[String]) -> CmdResult {
    let subcommand = argv.get(1).map(|s| s.as_str()).unwrap_or("");
    match subcommand {
        "mount" => cmd_fuse_mount(argv),
        "umount" => cmd_fuse_umount(argv),
        _ => CmdResult::error(
            1,
            format!("usage: fuse mount <path> <name>\n       fuse umount <path>\n"),
        ),
    }
}

/// `fuse mount <path> <name>`
///
/// Calls `sys_fuse_mount` to create a FUSE mount, then runs a RAM FS daemon
/// inline in this process.  The shell blocks while the daemon runs.
fn cmd_fuse_mount(argv: &[String]) -> CmdResult {
    let path = argv.get(2).map(|s| s.as_str()).unwrap_or("");
    let name = argv.get(3).map(|s| s.as_str()).unwrap_or("");

    if path.is_empty() || name.is_empty() {
        return CmdResult::error(
            1,
            String::from("usage: fuse mount <path> <name>\n"),
        );
    }

    // Mount via the FuseMount syscall.
    let (req_fd, resp_fd) = match syscall::sys_fuse_mount(path, name) {
        Ok(fds) => fds,
        Err(e) => {
            return CmdResult::error(
                1,
                format!("fuse: mount failed at {path}: {}\n", errno_msg(e)),
            );
        }
    };

    // Run the RAM FS daemon.
    let mut daemon = FuseDaemon::new(req_fd, resp_fd);
    match daemon.run() {
        Ok(()) => CmdResult::empty(),
        Err(e) => {
            // Clean up FDs on error.
            let _ = syscall::sys_close(req_fd);
            let _ = syscall::sys_close(resp_fd);
            CmdResult::error(
                1,
                format!("fuse: daemon exited: {}\n", errno_msg(e)),
            )
        }
    }
}

/// `fuse umount <path>`
fn cmd_fuse_umount(argv: &[String]) -> CmdResult {
    let path = argv.get(2).map(|s| s.as_str()).unwrap_or("");
    if path.is_empty() {
        return CmdResult::error(1, String::from("usage: fuse umount <path>\n"));
    }

    match syscall::sys_umount(path) {
        Ok(_) => CmdResult::empty(),
        Err(e) => CmdResult::error(
            1,
            format!("fuse: umount {path}: {}\n", errno_msg(e)),
        ),
    }
}

// ── Error message helper ──────────────────────────────────────────────────

fn errno_msg(code: isize) -> &'static str {
    match code {
        -1 => "invalid argument",
        -2 => "not found",
        -3 => "already exists",
        -4 => "permission denied",
        -5 => "out of memory",
        -6 => "device error",
        -7 => "resource busy",
        -8 => "timed out",
        -9 => "unsupported",
        _ => "unknown error",
    }
}
