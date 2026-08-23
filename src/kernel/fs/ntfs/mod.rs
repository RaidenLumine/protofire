//! src/kernel/fs/ntfs/mod.rs
//! NTFS read-only filesystem driver.
//!
//! ## Supported features
//!
//! - Boot sector parsing
//! - MFT record reading with USA fixup
//! - Resident and non-resident attribute parsing
//! - Data run traversal for file I/O
//! - Index-based directory enumeration
//! - UTF-16LE filename decoding
//!
//! ## Limitations
//!
//! - Read-only (all mutating operations return [`Error::PermissionDenied`]).
//! - Extended attribute listing via `$EA` attribute.
//! - No compression support.
//! - No security descriptor parsing.

mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::kernel::fs::block::BlockDevice;
use crate::kernel::fs::filesystem::profiler::{FsProfiler, FsProfilerSnapshot};
use crate::kernel::fs::vfs::{
    DirectoryEntry, FileSystem as VfsFileSystem, Metadata, NodeKind, SecurityDescriptor,
    SecurityDescriptorMutationSupport, VNode, VolumeCheckReport, XattrEntry,
};
use crate::{Error, Result};

use self::fs::NtfsInfo;

// ── NtfsVolume ────────────────────────────────────────────────────────────

pub struct NtfsVolume {
    device: Arc<dyn BlockDevice>,
    info: NtfsInfo,
    profiler: Arc<FsProfiler>,
}

impl NtfsVolume {
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let mut buf = [0u8; 512];
        read_device_bytes_ntfs(&device, 0, &mut buf)?;
        let bs = types::BootSector::parse(&buf).ok_or(Error::InvalidArgument)?;
        let info = NtfsInfo::new(bs);
        Ok(Self {
            device,
            info,
            profiler: Arc::new(FsProfiler::default()),
        })
    }

    fn resolve_path(&self, path: &str) -> Result<u64> {
        let clean = clean_path(path);
        if clean.is_empty() || clean == "/" {
            return Ok(5); // Root directory is MFT record 5
        }

        let segments: Vec<&str> = clean
            .strip_prefix('/')
            .unwrap_or(&clean)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_mft: u64 = 5;

        for name in &segments {
            let entries = fs::read_dir_entries(&self.device, &self.info, current_mft)?;
            let lower = name.to_lowercase();
            current_mft = entries
                .iter()
                .find(|(n, _)| n.to_lowercase() == lower)
                .map(|(_, mft)| *mft)
                .ok_or(Error::NotFound)?;
        }

        Ok(current_mft)
    }
}

impl VfsFileSystem for NtfsVolume {
    fn name(&self) -> &str {
        "ntfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.profiler.inc_lookups();
        let mft_ref = self.resolve_path(path)?;
        let (header, buf) = fs::read_mft_record(&self.device, &self.info, mft_ref)?;
        let attrs = types::parse_attributes(&buf, header.first_attr_offset as usize);

        // Check for reparse point (symlink or junction).
        let reparse_attr = fs::find_attr(&attrs, types::ATTR_TYPE_REPARSE_POINT);
        let (kind, symlink_target) = if let Some(ra) = reparse_attr {
            if let Some((_tag, target)) = types::parse_reparse_point(&ra.content) {
                (NodeKind::Symlink, target)
            } else {
                (NodeKind::Symlink, None)
            }
        } else if header.is_dir() {
            (NodeKind::Directory, None)
        } else if fs::get_standard_info(&attrs).is_some_and(|si| si.is_directory()) {
            // Directory flag may be carried in $STANDARD_INFORMATION when the
            // MFT header flag is unreliable.
            (NodeKind::Directory, None)
        } else {
            (NodeKind::File, None)
        };

        // Timestamps from $STANDARD_INFORMATION (NTFS 100 ns ticks -> Unix secs).
        let (created, modified, accessed) = fs::get_standard_info(&attrs)
            .map(|si| {
                (
                    types::StandardInfoAttr::to_unix_secs(si.created),
                    types::StandardInfoAttr::to_unix_secs(si.modified),
                    types::StandardInfoAttr::to_unix_secs(si.accessed),
                )
            })
            .unwrap_or((0, 0, 0));

        let size = fs::get_file_size(&attrs) as usize;

        // Parse extended attributes from $EA attribute.
        let xattrs: Vec<XattrEntry> =
            if let Some(ea_attr) = fs::find_attr(&attrs, types::ATTR_TYPE_EA) {
                types::parse_ea_entries(&ea_attr.content)
            } else {
                Vec::new()
            };

        // Parse data runs for files.
        let runs = if kind == NodeKind::File {
            if let Some(data_attr) = fs::find_attr(&attrs, types::ATTR_TYPE_DATA) {
                if let Some(off) = data_attr.data_runs_offset {
                    let run_start = header.first_attr_offset as usize + off as usize;
                    if run_start < buf.len() {
                        types::parse_data_runs(&buf[run_start..])
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Arc::new(NtfsVNode {
            name: extract_name(path),
            kind,
            size,
            runs,
            xattrs,
            device: self.device.clone(),
            info: self.info.clone(),
            symlink_target,
            created,
            modified,
            accessed,
            profiler: self.profiler.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        self.lookup(path)?.metadata()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.profiler.inc_lookups();
        let mft_ref = self.resolve_path(path)?;
        let entries = fs::read_dir_entries(&self.device, &self.info, mft_ref)?;
        let (name, child_mft) = entries.get(index).ok_or(Error::NotFound)?;

        // Get child inode info.
        let (child_hdr, child_buf) = fs::read_mft_record(&self.device, &self.info, *child_mft)?;
        let child_attrs = types::parse_attributes(&child_buf, child_hdr.first_attr_offset as usize);

        let kind = if child_hdr.is_dir()
            || fs::get_standard_info(&child_attrs).is_some_and(|si| si.is_directory())
        {
            NodeKind::Directory
        } else {
            NodeKind::File
        };
        let size = fs::get_file_size(&child_attrs) as usize;

        // Prefer the child record's own best-namespace `$FILE_NAME` spelling
        // (Win32/Win32&DOS > POSIX > DOS) over the index entry's embedded
        // name, so directory listings surface the human-friendly spelling.
        let display_name = fs::get_best_filename(&child_attrs)
            .map(|f| f.name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| name.clone());

        Ok(DirectoryEntry {
            kind,
            size,
            name: display_name,
            security: SecurityDescriptor {
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o555,
            },
        })
    }

    fn rename(&self, _o: &str, _n: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn create_file(&self, _p: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn create_dir(&self, _p: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn create_symlink(&self, _t: &str, _p: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn create_device(&self, _p: &str, _m: u32, _n: u32) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }
    fn remove_path(&self, _p: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }
    fn update_security_descriptor(&self, _p: &str, _s: SecurityDescriptor) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        if self.info.cluster_size == 0 || self.info.mft_record_size == 0 {
            issues += 1;
        }

        if self.lookup("/").is_err() {
            issues += 1;
        }

        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }
    fn fs_profiler_snapshot(&self) -> FsProfilerSnapshot {
        self.profiler.snapshot()
    }
    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        self.lookup(path)?.list_xattrs()
    }
}

// ── NtfsVNode ─────────────────────────────────────────────────────────────

use self::types::DataRun;

struct NtfsVNode {
    name: String,
    kind: NodeKind,
    size: usize,
    runs: Vec<DataRun>,
    xattrs: Vec<XattrEntry>,
    device: Arc<dyn BlockDevice>,
    info: NtfsInfo,
    symlink_target: Option<String>,
    /// Unix timestamps from `$STANDARD_INFORMATION` (0 when unavailable).
    created: u64,
    modified: u64,
    accessed: u64,
    profiler: Arc<FsProfiler>,
}

impl NtfsInfo {
    fn clone(&self) -> Self {
        Self {
            bs: self.bs.clone(),
            cluster_size: self.cluster_size,
            mft_record_size: self.mft_record_size,
            index_block_size: self.index_block_size,
        }
    }
}

impl VNode for NtfsVNode {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> NodeKind {
        self.kind
    }
    fn size(&self) -> usize {
        self.size
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            kind: self.kind,
            size: self.size,
            security: SecurityDescriptor {
                owner_uid: 0,
                owner_gid: 0,
                mode: 0o555,
            },
            created: self.created,
            modified: self.modified,
            accessed: self.accessed,
        })
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.profiler.inc_reads();
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        fs::read_from_runs(
            &self.device,
            &self.info,
            &self.runs,
            self.size as u64,
            offset,
            buffer,
        )
    }

    fn write(&self, _o: u64, _b: &[u8]) -> Result<usize> {
        Err(Error::PermissionDenied)
    }
    fn set_len(&self, _l: u64) -> Result<()> {
        Err(Error::PermissionDenied)
    }
    fn readlink(&self) -> Result<Vec<u8>> {
        match &self.symlink_target {
            Some(target) => Ok(target.as_bytes().to_vec()),
            None => Err(Error::InvalidArgument),
        }
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn sync_data(&self) -> Result<()> {
        Ok(())
    }
    fn list_xattrs(&self) -> Result<Vec<XattrEntry>> {
        Ok(self.xattrs.clone())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn clean_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn extract_name(path: &str) -> String {
    let clean = clean_path(path);
    if clean == "/" {
        return "/".into();
    }
    clean
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}

fn read_device_bytes_ntfs(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let dev_bs = device.block_size() as u64;
    let start_lba = byte_offset / dev_bs;
    let start_off = (byte_offset % dev_bs) as usize;
    let end_byte = byte_offset + buf.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);

    let total = (end_lba - start_lba) as usize;
    let mut scratch = vec![0u8; total * dev_bs as usize];
    for i in 0..total {
        let lba = start_lba + i as u64;
        let out = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, out)?;
    }
    buf.copy_from_slice(&scratch[start_off..start_off + buf.len()]);
    Ok(())
}
