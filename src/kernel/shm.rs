//! src/kernel/shm.rs
//! Shared memory (SystV shm) infrastructure — segment lifecycle, registry,
//! attach/detach tracking on the per-process side.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::abi::shm as abi;
use crate::kernel::memory;
use crate::kernel::memory::frame::FRAME_SIZE;
use crate::kernel::memory::paging::PagePermissions;
use crate::kernel::process::Process;
use crate::kernel::sync::Mutex;
use crate::Error;
use crate::Result;

// ─── Segment descriptor ────────────────────────────────────────────────

/// A shared memory segment backed by a set of physical frames.
pub struct SharedMemorySegment {
    /// IPC key (from shmget).
    pub key: usize,
    /// Size in bytes (rounded up to page boundary).
    pub size: usize,
    /// Number of frames backing this segment.
    pub frame_count: usize,
    /// Physical frame addresses (each FRAME_SIZE bytes).
    pub(crate) frames: Vec<usize>,
    /// Permissions / metadata for shmctl IPC_STAT/IPC_SET.
    pub perm: Mutex<abi::IpcPerm>,
    /// PID of the creator process.
    pub creator_pid: u32,
    /// Last attach time (ticks).
    pub atime: AtomicU64,
    /// Last detach time (ticks).
    pub dtime: AtomicU64,
    /// Last change time (ticks).
    pub ctime: AtomicU64,
    /// PID of the last shmat caller.
    pub last_attach_pid: AtomicU32,
    /// Number of current attaches.
    pub attach_count: AtomicU32,
    /// Marked for deletion (IPC_RMID).  New attaches are rejected; memory
    /// is freed when the last process detaches.
    pub deleted: AtomicBool,
}

impl SharedMemorySegment {
    /// Create a new segment, allocating physical frames immediately.
    pub fn new(key: usize, size: usize, perm: abi::IpcPerm, creator_pid: u32) -> Result<Arc<Self>> {
        let frame_count = size.div_ceil(FRAME_SIZE);
        let mut memory = memory::global_mut().ok_or(Error::InternalError)?;
        let mut frames = Vec::with_capacity(frame_count);

        for _ in 0..frame_count {
            let ptr = memory.allocate_frames(1).ok_or(Error::OutOfMemory)?;
            // Zero the frame.
            unsafe { core::ptr::write_bytes(ptr, 0, FRAME_SIZE) }
            frames.push(ptr as usize);
        }
        drop(memory);

        Ok(Arc::new(Self {
            key,
            size,
            frame_count,
            frames,
            perm: Mutex::new(perm),
            creator_pid,
            atime: AtomicU64::new(0),
            dtime: AtomicU64::new(0),
            ctime: AtomicU64::new(0),
            last_attach_pid: AtomicU32::new(0),
            attach_count: AtomicU32::new(0),
            deleted: AtomicBool::new(false),
        }))
    }

    /// Attach this segment to the current process at `virtual_address`.
    ///
    /// Installs each physical frame into the live hardware page tables and
    /// registers in the software page table as `MappingKind::Shared`.
    ///
    /// Returns the number of pages mapped.
    pub fn attach_to_process(
        self: &Arc<Self>,
        process: &Process,
        virtual_address: usize,
        perms: PagePermissions,
    ) -> Result<usize> {
        if self.deleted.load(Ordering::Acquire) {
            return Err(Error::InvalidArgument);
        }

        let frame_count = self.frame_count;
        let mut mapped = 0usize;

        for i in 0..frame_count {
            let va = virtual_address + i * FRAME_SIZE;
            let pa = self.frames[i];

            // 1. Install in live hardware page tables.
            if !crate::kernel::memory::arch::install_user_page_arch(va, pa, perms) {
                // Roll back on failure.
                for j in 0..i {
                    let rollback_va = virtual_address + j * FRAME_SIZE;
                    let _ = crate::kernel::memory::arch::unmap_user_page_arch(rollback_va);
                }
                return Err(Error::InternalError);
            }

            // 2. Register in software page table.
            let mut memory = memory::global_mut().ok_or(Error::InternalError)?;
            if memory.register_shared_page(va, pa, perms).is_err() {
                // Roll back.
                let _ = crate::kernel::memory::arch::unmap_user_page_arch(va);
                for j in 0..i {
                    let rollback_va = virtual_address + j * FRAME_SIZE;
                    let _ = crate::kernel::memory::arch::unmap_user_page_arch(rollback_va);
                    memory.unregister_user_page_range(rollback_va, FRAME_SIZE);
                }
                return Err(Error::InternalError);
            }
            mapped += 1;
            drop(memory);
        }

        self.attach_count.fetch_add(1, Ordering::Release);
        self.atime
            .store(crate::kernel::scheduler::current_tick(), Ordering::Release);
        self.last_attach_pid.store(process.pid(), Ordering::Release);

        Ok(mapped)
    }

    /// Detach a single page of this segment from the live hardware page
    /// tables and the software page table.
    fn detach_one(&self, virtual_address: usize) {
        // 1. Unmap from hardware page tables.
        let _ = crate::kernel::memory::arch::unmap_user_page_arch(virtual_address);
        // 2. Remove from software page table.
        if let Some(mut memory) = memory::global_mut() {
            memory.unregister_user_page_range(virtual_address, FRAME_SIZE);
        }
    }

    /// Detach all pages of this segment mapped at `virtual_address`.
    pub fn detach_from_process(&self, process_pid: u32, virtual_address: usize, page_count: usize) {
        for i in 0..page_count {
            self.detach_one(virtual_address + i * FRAME_SIZE);
        }
        self.attach_count.fetch_sub(1, Ordering::Release);
        self.dtime
            .store(crate::kernel::scheduler::current_tick(), Ordering::Release);
        self.last_attach_pid.store(process_pid, Ordering::Release);
    }

    /// Free all physical frames backing this segment.
    pub fn free_frames(&self) {
        if let Some(mut memory) = memory::global_mut() {
            for &pa in &self.frames {
                memory.deallocate_frames(pa as *mut u8, 1);
            }
        }
    }
}

impl Drop for SharedMemorySegment {
    fn drop(&mut self) {
        // Only free frames if no one is attached anymore.
        // This is a safety net — normally the registry handles this.
        if self.attach_count.load(Ordering::Acquire) == 0 {
            // Can't call free_frames here because it needs &mut MemoryManager
            // and we're in Drop (which is &mut self).  Instead, let the
            // registry's cleanup path handle it.
        }
    }
}

// ─── Per-process attach tracking ──────────────────────────────────────

/// Tracks one shared memory segment attached to a process.
///
/// The detached page count comes from the registry segment
/// (`seg.frame_count`), so only the shmid and mapping base are carried here.
#[derive(Debug, Clone)]
pub(crate) struct ProcessShmAttachment {
    pub(crate) shmid: usize,
    pub(crate) virtual_address: usize,
}

// ─── Global segment registry ──────────────────────────────────────────

/// Global registry of all shared memory segments.
pub struct ShmRegistry {
    /// Key → segment (fast lookup for shmget with IPC_CREAT).
    by_key: BTreeMap<usize, Arc<SharedMemorySegment>>,
    /// shmid (sequential ID) → segment.
    by_id: BTreeMap<usize, Arc<SharedMemorySegment>>,
    next_id: usize,
}

impl Default for ShmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ShmRegistry {
    pub const fn new() -> Self {
        Self {
            by_key: BTreeMap::new(),
            by_id: BTreeMap::new(),
            next_id: 0,
        }
    }
}

/// Global shm registry, guarded by a mutex.
static SHM_REGISTRY: Mutex<ShmRegistry> = Mutex::new(ShmRegistry::new());

// ─── Public API ───────────────────────────────────────────────────────

/// shmget: create or find a shared memory segment.
pub fn shmget(
    key: usize,
    size: usize,
    flags: usize,
    pid: u32,
    uid: u32,
    gid: u32,
) -> Result<usize> {
    if size > abi::SHM_MAX_SIZE {
        return Err(Error::InvalidArgument);
    }
    let aligned_size = size.next_multiple_of(FRAME_SIZE);

    let mut registry = SHM_REGISTRY.lock();

    // Check if key already exists.
    if let Some(seg) = registry.by_key.get(&key) {
        if flags & abi::IPC_EXCL != 0 && flags & abi::IPC_CREAT != 0 {
            return Err(Error::AlreadyExists);
        }
        let id = registry
            .by_id
            .iter()
            .find(|(_, v)| Arc::as_ptr(v) == Arc::as_ptr(seg))
            .map(|(&id, _)| id)
            .ok_or(Error::InternalError)?;
        return Ok(id);
    }

    // Key not found: create if IPC_CREAT.
    if flags & abi::IPC_CREAT == 0 {
        return Err(Error::NotFound);
    }
    if registry.by_id.len() >= abi::SHM_SEG_COUNT_MAX {
        return Err(Error::OutOfMemory);
    }

    let id = registry.next_id;
    registry.next_id += 1;

    let perm = abi::IpcPerm::new(key, uid, gid, (flags & 0o777) as u16);
    let seg = SharedMemorySegment::new(key, aligned_size, perm, pid)?;

    registry.by_key.insert(key, seg.clone());
    registry.by_id.insert(id, seg);

    Ok(id)
}

/// shmat: attach a shared memory segment.  Returns the virtual address.
pub fn shmat(
    shmid: usize,
    _addr_hint: usize, // currently ignored — kernel picks address
    flags: usize,
    process: &Process,
) -> Result<usize> {
    let registry = SHM_REGISTRY.lock();
    let seg = registry.by_id.get(&shmid).ok_or(Error::NotFound)?;

    // Reject attaches to deleted segments.
    if seg.deleted.load(Ordering::Acquire) {
        return Err(Error::InvalidArgument);
    }

    let readonly = flags & 1 != 0; // SHM_RDONLY
    let perms = if readonly {
        PagePermissions::READ
    } else {
        PagePermissions::READ_WRITE
    };

    // Pick a virtual address: use a fixed range below the stack guard.
    let va = pick_shm_address(process, seg.size)?;

    // Attach (maps physical frames into process page tables).
    seg.attach_to_process(process, va, perms)?;

    // Record the attachment for cleanup on exit/fork.
    process.record_shm_attachment(shmid, va, seg.size);

    Ok(va)
}

/// shmdt: detach a shared memory segment.
pub fn shmdt(shmid: usize, process: &Process) -> Result<()> {
    let attachment = process.find_shm_attachment(shmid).ok_or(Error::NotFound)?;

    let registry = SHM_REGISTRY.lock();
    let seg = registry.by_id.get(&shmid).ok_or(Error::NotFound)?;

    seg.detach_from_process(process.pid(), attachment.virtual_address, seg.frame_count);

    process.remove_shm_attachment(shmid);

    // If the segment was marked for deletion and no more attaches, free frames.
    if seg.deleted.load(Ordering::Acquire) && seg.attach_count.load(Ordering::Acquire) == 0 {
        seg.free_frames();
        // Remove from registry — deferred to shmctl IPC_RMID handler.
    }

    Ok(())
}

/// shmctl: control operations on a shared memory segment.
pub fn shmctl(shmid: usize, cmd: usize, buf: Option<&mut abi::ShmidDs>) -> Result<()> {
    let mut registry = SHM_REGISTRY.lock();
    let seg = registry.by_id.get(&shmid).ok_or(Error::NotFound)?;

    match cmd {
        abi::IPC_RMID => {
            seg.deleted.store(true, Ordering::Release);
            // If no attaches, free frames now and remove from registry.
            if seg.attach_count.load(Ordering::Acquire) == 0 {
                seg.free_frames();
                let key = seg.key;
                registry.by_key.remove(&key);
                registry.by_id.remove(&shmid);
            }
            Ok(())
        }
        abi::IPC_STAT => {
            if let Some(ds) = buf {
                let perm = *seg.perm.lock();
                *ds = abi::ShmidDs {
                    shm_perm: perm,
                    shm_segsz: seg.size,
                    shm_atime: seg.atime.load(Ordering::Acquire),
                    shm_dtime: seg.dtime.load(Ordering::Acquire),
                    shm_ctime: seg.ctime.load(Ordering::Acquire),
                    shm_cpid: seg.creator_pid,
                    shm_lpid: seg.last_attach_pid.load(Ordering::Acquire),
                    shm_nattch: seg.attach_count.load(Ordering::Acquire),
                    _pad: 0,
                };
                Ok(())
            } else {
                Err(Error::InvalidArgument)
            }
        }
        abi::IPC_SET => {
            if let Some(ds) = buf {
                let mut perm = seg.perm.lock();
                // Only uid, gid, mode can be changed.
                perm.uid = ds.shm_perm.uid;
                perm.gid = ds.shm_perm.gid;
                perm.mode = ds.shm_perm.mode;
                seg.ctime
                    .store(crate::kernel::scheduler::current_tick(), Ordering::Release);
                Ok(())
            } else {
                Err(Error::InvalidArgument)
            }
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Clean up all segments that were marked deleted (IPC_RMID) and have no
/// attaches, freeing their frames and removing them from the registry.
///
/// Intended to be called from a periodic memory-management tick.  The
/// per-process detach at teardown is wired in the process lifecycle; this
/// reaper currently has no live call site, so it is kept for the reaping
/// feature.
#[allow(dead_code)]
pub(crate) fn reap_deleted_segments() {
    let mut registry = SHM_REGISTRY.lock();
    let to_remove: Vec<usize> = registry
        .by_id
        .iter()
        .filter(|(_, seg)| {
            seg.deleted.load(Ordering::Acquire) && seg.attach_count.load(Ordering::Acquire) == 0
        })
        .map(|(&id, _)| id)
        .collect();

    for id in to_remove {
        if let Some(seg) = registry.by_id.remove(&id) {
            registry.by_key.remove(&seg.key);
            seg.free_frames();
        }
    }
}

/// Detach all shm segments for a terminating process.
///
/// Called from the process-teardown path
/// (`Process::release_termination_resources`) before the address space is
/// torn down.
pub(crate) fn detach_all_for_process(process: &Process) {
    let attachments: Vec<ProcessShmAttachment> = process
        .collect_shm_attachments()
        .into_iter()
        .map(|a| ProcessShmAttachment {
            shmid: a.shmid,
            virtual_address: a.virtual_address,
        })
        .collect();
    let registry = SHM_REGISTRY.lock();
    for att in &attachments {
        if let Some(seg) = registry.by_id.get(&att.shmid) {
            seg.detach_from_process(process.pid(), att.virtual_address, seg.frame_count);
        }
    }
    drop(registry);
    process.clear_shm_attachments();
}

// ─── Address allocation helpers ───────────────────────────────────────

/// Pick a virtual address for a shared memory mapping.
///
/// Uses a range between the brk heap max and the user stack that is reserved
/// for shared memory mappings.  This is a simple bump allocator; a real
/// implementation would use the software page table to find a gap.
const SHM_BASE: usize = 0x0000_6000_0000_0000;
const SHM_LIMIT: usize = 0x0000_7000_0000_0000;

/// Per-process shm virtual address bump.
fn pick_shm_address(process: &Process, size: usize) -> Result<usize> {
    let aligned_size = size.next_multiple_of(FRAME_SIZE);
    let current = process.shm_va_hint();
    let va = if current == 0 { SHM_BASE } else { current };

    let next = va.checked_add(aligned_size).ok_or(Error::OutOfMemory)?;
    if next > SHM_LIMIT {
        return Err(Error::OutOfMemory);
    }

    process.set_shm_va_hint(next);
    Ok(va)
}
