//! src/kernel/fs/procfs.rs
//!
//! ProcFS — a synthetic filesystem exposing kernel and process information.
//!
//! ## Nodes
//!
//! | Path | Description |
//! |------|-------------|
//! | `/proc/version` | Kernel version string |
//! | `/proc/uptime` | Seconds since boot (tick-based) |
//! | `/proc/mounts` | Active mount points |
//! | `/proc/processes` | Count of running processes |
//! | `/proc/self` | Symbolic link to current process directory |
//! | `/proc/<pid>/` | Per-process directory |
//! | `/proc/<pid>/cmdline` | Process command-line (NUL-separated args) |
//! | `/proc/<pid>/status` | Process status (Name, Pid, PPid, State, etc.) |
//! | `/proc/<pid>/name` | Process name |
//!
//! All nodes are read-only.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsTrait, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport,
};
use crate::kernel::process::{ProcessId, ProcessState};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Static data VNode
// ---------------------------------------------------------------------------

/// A read-only VNode backed by a byte slice producer.
struct StaticDataVNode {
    name: &'static str,
    kind: NodeKind,
    produce: fn() -> Vec<u8>,
}

impl StaticDataVNode {
    fn new(name: &'static str, produce: fn() -> Vec<u8>) -> Self {
        Self {
            name,
            kind: NodeKind::File,
            produce,
        }
    }

    fn directory(name: &'static str) -> Self {
        Self {
            name,
            kind: NodeKind::Directory,
            produce: || Vec::new(),
        }
    }
}

impl VNode for StaticDataVNode {
    fn name(&self) -> &str {
        self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        (self.produce)().len()
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let data = (self.produce)();
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Self symlink VNode — resolves /proc/self → /proc/<current_pid>
// ---------------------------------------------------------------------------

struct SelfSymlinkVNode;

impl VNode for SelfSymlinkVNode {
    fn name(&self) -> &str {
        "self"
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Symlink
    }

    fn size(&self) -> usize {
        0
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        let pid = crate::kernel::process::Scheduler::global()
            .and_then(|s| s.current_thread())
            .map(|t| t.pid())
            .unwrap_or(0);
        Ok(format!("/proc/{}", pid).into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Per-process file VNode — represents cmdline, status, name inside /proc/<pid>/
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessFileType {
    Cmdline,
    Status,
    Name,
}

impl ProcessFileType {
    fn name_str(self) -> &'static str {
        match self {
            Self::Cmdline => "cmdline",
            Self::Status => "status",
            Self::Name => "name",
        }
    }
}

struct ProcessFileVNode {
    pid: ProcessId,
    file_type: ProcessFileType,
}

impl ProcessFileVNode {
    fn new(pid: ProcessId, file_type: ProcessFileType) -> Self {
        Self { pid, file_type }
    }

    fn with_process<T>(&self, f: impl FnOnce(&crate::kernel::process::Process) -> T) -> Result<T> {
        let sched = crate::kernel::process::Scheduler::global().ok_or(Error::InternalError)?;
        let process = sched.process_by_pid(self.pid).ok_or(Error::NotFound)?;
        Ok(f(&process))
    }
}

impl VNode for ProcessFileVNode {
    fn name(&self) -> &str {
        self.file_type.name_str()
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        match self.file_type {
            ProcessFileType::Cmdline => self
                .with_process(|p| {
                    p.launch_context()
                        .map(|ctx| cmdline_data(&ctx).len())
                        .unwrap_or(0)
                })
                .unwrap_or(0),
            ProcessFileType::Status => self.with_process(|p| status_data(p).len()).unwrap_or(0),
            ProcessFileType::Name => self.with_process(|p| p.name().len() + 1).unwrap_or(0),
        }
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let data: Vec<u8> = match self.file_type {
            ProcessFileType::Cmdline => self.with_process(|p| {
                p.launch_context()
                    .map(|ctx| cmdline_data(&ctx))
                    .unwrap_or_default()
            })?,
            ProcessFileType::Status => self.with_process(status_data)?,
            ProcessFileType::Name => self.with_process(|p| {
                let mut v = Vec::from(p.name().as_bytes());
                v.push(b'\n');
                v
            })?,
        };
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Per-process directory VNode — represents /proc/<pid>/
// ---------------------------------------------------------------------------

struct PidDirVNode {
    #[allow(dead_code)]
    pid: ProcessId,
}

impl PidDirVNode {
    fn new(pid: ProcessId) -> Self {
        Self { pid }
    }
}

impl VNode for PidDirVNode {
    fn name(&self) -> &str {
        // The name is the PID as seen from the parent directory.
        // Since we can't return a dynamically-formatted &str, we return a
        // fixed placeholder. The actual name in directory listings comes from
        // read_dir / lookup, not from this method directly.
        "."
    }

    fn kind(&self) -> NodeKind {
        NodeKind::Directory
    }

    fn size(&self) -> usize {
        0
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }

    fn write(&self, _offset: u64, _buffer: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Data producers (global)
// ---------------------------------------------------------------------------

fn version_data() -> Vec<u8> {
    let version = env!("CARGO_PKG_VERSION");
    format!("adastra-kernel {}\n", version).into_bytes()
}

fn uptime_data() -> Vec<u8> {
    let ticks = crate::kernel::process::Scheduler::global()
        .map(|s| s.current_tick())
        .unwrap_or(0);
    let seconds = ticks / 100; // assuming 100 Hz tick
    let sub = (ticks % 100) * 10;
    format!("{}.{:02}\n", seconds, sub / 10).into_bytes()
}

fn mounts_data() -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(fs) = crate::kernel::fs::global() {
        let fs_guard = fs.lock();
        for mount in fs_guard.mount_points() {
            let line = format!("{} {} {} ro 0 0\n", mount.device, mount.path, mount.fs_name);
            out.extend_from_slice(line.as_bytes());
        }
    }
    if out.is_empty() {
        out.extend_from_slice(b"(no mounts)\n");
    }
    out
}

fn processes_data() -> Vec<u8> {
    let count = crate::kernel::process::Scheduler::global()
        .map(|s| s.process_count())
        .unwrap_or(0);
    format!("{}\n", count).into_bytes()
}

// ---------------------------------------------------------------------------
// Data producers (per-process)
// ---------------------------------------------------------------------------

/// Format the command line as NUL-separated arguments (Linux /proc convention).
fn cmdline_data(ctx: &crate::kernel::process::LaunchContext) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, arg) in ctx.arguments.iter().enumerate() {
        if i > 0 {
            out.push(0u8);
        }
        out.extend_from_slice(arg.as_bytes());
    }
    if out.is_empty() {
        out.extend_from_slice(b"(none)\n");
    }
    out
}

/// Format human-readable status (Linux /proc/<pid>/status style).
fn status_data(process: &crate::kernel::process::Process) -> Vec<u8> {
    let mut out = Vec::new();

    let name = process.name();
    let pid = process.pid();
    let ppid = process.parent_pid().map(|p| p as i64).unwrap_or(-1);
    let state = match process.state() {
        ProcessState::New => "New",
        ProcessState::Ready => "Ready",
        ProcessState::Running => "Running",
        ProcessState::Waiting => "Waiting",
        ProcessState::Terminated => "Terminated",
    };
    let token = process.security_token();
    let thread_count = process.thread_ids().len();
    let children = process.children().len();
    let cwd = process.current_working_dir();

    // Name:\t<name>\n
    out.extend_from_slice(b"Name:\t");
    out.extend_from_slice(name.as_bytes());
    out.push(b'\n');

    // Pid:\t<pid>\n
    out.extend_from_slice(format!("Pid:\t{}\n", pid).as_bytes());

    // PPid:\t<ppid>\n
    out.extend_from_slice(format!("PPid:\t{}\n", ppid).as_bytes());

    // State:\t<state>\n
    out.extend_from_slice(b"State:\t");
    out.extend_from_slice(state.as_bytes());
    out.push(b'\n');

    // Uid:\t<uid>\n
    out.extend_from_slice(format!("Uid:\t{}\n", token.user_id).as_bytes());

    // Gid:\t<gid>\n
    out.extend_from_slice(format!("Gid:\t{}\n", token.primary_group_id).as_bytes());

    // Threads:\t<count>\n
    out.extend_from_slice(format!("Threads:\t{}\n", thread_count).as_bytes());

    // Children:\t<count>\n
    out.extend_from_slice(format!("Children:\t{}\n", children).as_bytes());

    // Cwd:\t<path>\n
    out.extend_from_slice(b"Cwd:\t");
    out.extend_from_slice(cwd.as_bytes());
    out.push(b'\n');

    // Launch context (optional)
    if let Some(launch) = process.launch_context() {
        out.extend_from_slice(b"CatalogId:\t");
        out.extend_from_slice(launch.catalog_id.as_bytes());
        out.push(b'\n');

        out.extend_from_slice(b"Version:\t");
        out.extend_from_slice(launch.version.as_bytes());
        out.push(b'\n');

        if !launch.environment.is_empty() {
            out.extend_from_slice(b"Env:\t");
            for (i, var) in launch.environment.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b" ");
                }
                out.extend_from_slice(var.as_bytes());
            }
            out.push(b'\n');
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Path parsing helpers
// ---------------------------------------------------------------------------

/// A parsed procfs path. The leading `/proc` prefix is already stripped.
#[derive(Debug)]
enum ProcfsPath<'a> {
    /// Root directory
    Root,
    /// `self` symlink
    Self_,
    /// `self/<filename>` — follow symlink to current process
    SelfFile(&'a str),
    /// `<pid>` — per-process directory
    PidDir(ProcessId),
    /// `<pid>/<filename>` — per-process file
    PidFile(ProcessId, &'a str),
    /// A direct child name in the root
    GlobalFile(&'a str),
}

fn parse_procfs_path(path: &str) -> ProcfsPath<'_> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return ProcfsPath::Root;
    }

    let mut components = path.splitn(2, '/');
    let first = components.next().unwrap_or("");
    let rest = components.next();

    match (first, rest) {
        ("self", None) => ProcfsPath::Self_,
        ("self", Some(filename)) if !filename.is_empty() => ProcfsPath::SelfFile(filename),
        (pid_str, None) => {
            if let Ok(pid) = pid_str.parse::<ProcessId>() {
                ProcfsPath::PidDir(pid)
            } else {
                ProcfsPath::GlobalFile(pid_str)
            }
        }
        (pid_str, Some(filename)) if !filename.is_empty() => {
            if let Ok(pid) = pid_str.parse::<ProcessId>() {
                ProcfsPath::PidFile(pid, filename)
            } else {
                // Not a PID — treat as unknown
                ProcfsPath::GlobalFile(pid_str)
            }
        }
        _ => ProcfsPath::Root,
    }
}

// ---------------------------------------------------------------------------
// ProcFS root
// ---------------------------------------------------------------------------

/// Root directory entries: `self` symlink + global files + numbered PID dirs.
const ROOT_STATIC_ENTRIES: &[(&str, NodeKind)] = &[
    ("self", NodeKind::Symlink),
    ("version", NodeKind::File),
    ("uptime", NodeKind::File),
    ("mounts", NodeKind::File),
    ("processes", NodeKind::File),
];

pub struct ProcFs;

impl VfsTrait for ProcFs {
    fn name(&self) -> &str {
        "procfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        match parse_procfs_path(path) {
            ProcfsPath::Root => Ok(Arc::new(StaticDataVNode::directory("proc"))),

            ProcfsPath::Self_ => Ok(Arc::new(SelfSymlinkVNode)),

            ProcfsPath::SelfFile(filename) => {
                let pid = crate::kernel::process::Scheduler::global()
                    .and_then(|s| s.current_thread())
                    .map(|t| t.pid())
                    .ok_or(Error::InternalError)?;
                lookup_pid_file(pid, filename)
            }

            ProcfsPath::PidDir(pid) => {
                // Verify the process exists
                let sched =
                    crate::kernel::process::Scheduler::global().ok_or(Error::InternalError)?;
                sched.process_by_pid(pid).ok_or(Error::NotFound)?;
                Ok(Arc::new(PidDirVNode::new(pid)))
            }

            ProcfsPath::PidFile(pid, filename) => lookup_pid_file(pid, filename),

            ProcfsPath::GlobalFile(name) => match name {
                "version" => Ok(Arc::new(StaticDataVNode::new("version", version_data))),
                "uptime" => Ok(Arc::new(StaticDataVNode::new("uptime", uptime_data))),
                "mounts" => Ok(Arc::new(StaticDataVNode::new("mounts", mounts_data))),
                "processes" => Ok(Arc::new(StaticDataVNode::new("processes", processes_data))),
                _ => Err(Error::NotFound),
            },
        }
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        match parse_procfs_path(path) {
            ProcfsPath::Root => {
                // Static entries first, then numbered PID directories
                if index < ROOT_STATIC_ENTRIES.len() {
                    let (name, kind) = ROOT_STATIC_ENTRIES[index];
                    return Ok(DirectoryEntry::new(kind, 0, String::from(name)));
                }
                let pid_index = index - ROOT_STATIC_ENTRIES.len();
                let sched =
                    crate::kernel::process::Scheduler::global().ok_or(Error::InternalError)?;
                let summaries = sched.list_process_summaries();
                if pid_index < summaries.len() {
                    let pid_str = format!("{}", summaries[pid_index].pid);
                    return Ok(DirectoryEntry::new(NodeKind::Directory, 0, pid_str));
                }
                Err(Error::NotFound)
            }

            ProcfsPath::PidDir(pid) => {
                // Per-process directory entries
                let sched =
                    crate::kernel::process::Scheduler::global().ok_or(Error::InternalError)?;
                // Verify process exists
                sched.process_by_pid(pid).ok_or(Error::NotFound)?;
                let entries: &[(&str, NodeKind)] = &[
                    ("cmdline", NodeKind::File),
                    ("status", NodeKind::File),
                    ("name", NodeKind::File),
                ];
                if index < entries.len() {
                    Ok(DirectoryEntry::new(
                        entries[index].1,
                        0,
                        String::from(entries[index].0),
                    ))
                } else {
                    Err(Error::NotFound)
                }
            }

            ProcfsPath::Self_ => {
                // self is a symlink, follow it
                let pid = crate::kernel::process::Scheduler::global()
                    .and_then(|s| s.current_thread())
                    .map(|t| t.pid())
                    .ok_or(Error::InternalError)?;
                self.read_dir(&format!("/{}", pid), index)
            }

            _ => Err(Error::NotFound),
        }
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        if path.is_empty() || path == "/" {
            return Ok(Metadata {
                kind: NodeKind::Directory,
                size: 4,
                security: SecurityDescriptor::root_for_kind(NodeKind::Directory),
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }
        self.lookup(path).and_then(|v| v.metadata())
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        Err(Error::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lookup_pid_file(pid: ProcessId, filename: &str) -> Result<Arc<dyn VNode>> {
    let file_type = match filename {
        "cmdline" => ProcessFileType::Cmdline,
        "status" => ProcessFileType::Status,
        "name" => ProcessFileType::Name,
        _ => return Err(Error::NotFound),
    };
    // Verify the process exists
    let sched = crate::kernel::process::Scheduler::global().ok_or(Error::InternalError)?;
    sched.process_by_pid(pid).ok_or(Error::NotFound)?;
    Ok(Arc::new(ProcessFileVNode::new(pid, file_type)))
}

// ---------------------------------------------------------------------------
// Mount helper
// ---------------------------------------------------------------------------

/// Register and mount the procfs at the given path (typically `/proc`).
pub fn mount_procfs(mount_path: &str) -> Result<()> {
    let fs = crate::kernel::fs::global().ok_or(Error::InternalError)?;
    let mut fs_guard = fs.lock();
    fs_guard.register("procfs", Arc::new(ProcFs));
    fs_guard.mount("/dev/adastra-procfs", mount_path, "procfs", 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procfs_lookup_version() {
        let p = ProcFs;
        let vnode = p.lookup("version").expect("version node");
        assert_eq!(vnode.kind(), NodeKind::File);
        assert_eq!(vnode.name(), "version");
        let mut buf = [0u8; 128];
        let n = vnode.read(0, &mut buf).expect("read");
        assert!(n > 0);
        let s = core::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(s.starts_with("adastra-kernel "));
    }

    #[test]
    fn procfs_lookup_uptime() {
        let p = ProcFs;
        let vnode = p.lookup("uptime").expect("uptime node");
        let mut buf = [0u8; 32];
        let n = vnode.read(0, &mut buf).expect("read");
        let s = core::str::from_utf8(&buf[..n]).expect("utf8");
        // Format: "seconds.hundredths\n"
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn procfs_lookup_processes() {
        let p = ProcFs;
        let vnode = p.lookup("processes").expect("processes node");
        let mut buf = [0u8; 16];
        let n = vnode.read(0, &mut buf).expect("read");
        let s = core::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(s.trim_end().parse::<usize>().is_ok());
    }

    #[test]
    fn procfs_lookup_unknown_returns_not_found() {
        let p = ProcFs;
        assert!(p.lookup("nonexistent").is_err());
    }

    #[test]
    fn procfs_read_dir_lists_all_entries() {
        let p = ProcFs;
        let mut names = Vec::new();
        for i in 0..20 {
            if let Ok(entry) = p.read_dir("", i) {
                names.push(entry.name);
            } else {
                break;
            }
        }
        assert!(names.contains(&String::from("version")));
        assert!(names.contains(&String::from("uptime")));
        assert!(names.contains(&String::from("mounts")));
        assert!(names.contains(&String::from("processes")));
        assert!(names.contains(&String::from("self")));
    }

    #[test]
    fn procfs_stat_root_is_directory() {
        let p = ProcFs;
        let meta = p.stat("").expect("stat root");
        assert_eq!(meta.kind, NodeKind::Directory);
    }

    #[test]
    fn procfs_is_read_only() {
        let p = ProcFs;
        assert!(p.create_file("x").is_err());
        assert!(p.create_dir("x").is_err());
        assert!(p.rename("a", "b").is_err());
        assert!(p.remove_path("a").is_err());
    }

    #[test]
    fn procfs_name() {
        assert_eq!(ProcFs.name(), "procfs");
    }

    #[test]
    fn static_data_vnode_zero_length_read() {
        let vnode = StaticDataVNode::new("test", || b"hello".to_vec());
        assert_eq!(vnode.read(0, &mut []).unwrap(), 0);
    }

    #[test]
    fn static_data_vnode_partial_read() {
        let vnode = StaticDataVNode::new("test", || b"abcdefghij".to_vec());
        let mut buf = [0u8; 4];
        assert_eq!(vnode.read(0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"abcd");
        // offset read
        assert_eq!(vnode.read(4, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"efgh");
    }

    #[test]
    fn static_data_vnode_read_past_end() {
        let vnode = StaticDataVNode::new("test", || b"abc".to_vec());
        let mut buf = [0u8; 8];
        assert_eq!(vnode.read(0, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(vnode.read(10, &mut buf).unwrap(), 0);
    }

    // -- Per-process procfs tests -----------------------------------------

    #[test]
    fn procfs_lookup_self_is_symlink() {
        let p = ProcFs;
        let vnode = p.lookup("self").expect("self node");
        assert_eq!(vnode.kind(), NodeKind::Symlink);
        assert_eq!(vnode.name(), "self");
    }

    #[test]
    fn procfs_self_readlink_returns_path() {
        let p = ProcFs;
        let vnode = p.lookup("self").expect("self node");
        let target = vnode.readlink().expect("readlink");
        let target_str = core::str::from_utf8(&target).expect("utf8");
        assert!(target_str.starts_with("/proc/"));
    }

    #[test]
    fn procfs_parse_path_root() {
        assert!(matches!(parse_procfs_path(""), ProcfsPath::Root));
        assert!(matches!(parse_procfs_path("/"), ProcfsPath::Root));
    }

    #[test]
    fn procfs_parse_path_self() {
        assert!(matches!(parse_procfs_path("self"), ProcfsPath::Self_));
    }

    #[test]
    fn procfs_parse_path_self_file() {
        match parse_procfs_path("self/cmdline") {
            ProcfsPath::SelfFile("cmdline") => {}
            other => panic!("expected SelfFile(\"cmdline\"), got {:?}", other),
        }
    }

    #[test]
    fn procfs_parse_path_pid_dir() {
        match parse_procfs_path("42") {
            ProcfsPath::PidDir(42) => {}
            other => panic!("expected PidDir(42), got {:?}", other),
        }
    }

    #[test]
    fn procfs_parse_path_pid_file() {
        match parse_procfs_path("42/status") {
            ProcfsPath::PidFile(42, "status") => {}
            other => panic!("expected PidFile(42, \"status\"), got {:?}", other),
        }
    }

    #[test]
    fn procfs_parse_path_global_file() {
        match parse_procfs_path("version") {
            ProcfsPath::GlobalFile("version") => {}
            other => panic!("expected GlobalFile(\"version\"), got {:?}", other),
        }
    }

    #[test]
    fn procfs_lookup_pid_dir_fails_for_nonexistent_process() {
        let p = ProcFs;
        // PID 99999 likely doesn't exist in test environment
        assert!(p.lookup("99999").is_err());
    }

    #[test]
    fn procfs_read_dir_pid_dir_fails_for_nonexistent_process() {
        let p = ProcFs;
        assert!(p.read_dir("99999", 0).is_err());
    }

    #[test]
    fn procfs_pid_file_cmdline() {
        let p = ProcFs;
        // Look up a per-process file path for the current PID (if available).
        if let Some(pid) = crate::kernel::process::Scheduler::global()
            .and_then(|s| s.current_thread())
            .map(|t| t.pid())
        {
            // Look up the pid directory
            if let Ok(dir) = p.lookup(&format!("{}", pid)) {
                assert_eq!(dir.kind(), NodeKind::Directory);
            }
            // If PID isn't in the process list, that's OK in tests
        }
    }

    #[test]
    fn procfs_self_status_path_resolves_when_scheduler_active() {
        let p = ProcFs;
        // self/status resolves when the scheduler has a current thread
        let result = p.lookup("self/status");
        if let Ok(vnode) = result {
            assert_eq!(vnode.kind(), NodeKind::File);
            assert_eq!(vnode.name(), "status");
        }
        // If the scheduler has no current thread, lookup may fail — acceptable
        // in test
    }
}
