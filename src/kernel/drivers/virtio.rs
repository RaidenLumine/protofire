//! src/kernel/drivers/virtio.rs
//! VirtIO MMIO transport layer: register interface, device discovery, feature
//! negotiation, and status state-machine transitions.
//!
//! Based on the VirtIO v1.2 specification, MMIO transport section.

use crate::kernel::fs::block::{BlockDevice, DeviceHealth};
use crate::{Error, Result};

// ─── MMIO register offsets (section 4.2.2) ───

pub const REG_MAGIC_VALUE: u64 = 0x000;
pub const REG_VERSION: u64 = 0x004;
pub const REG_DEVICE_ID: u64 = 0x008;
pub const REG_VENDOR_ID: u64 = 0x00C;
pub const REG_DEVICE_FEATURES: u64 = 0x010;
pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const REG_DRIVER_FEATURES: u64 = 0x020;
pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const REG_QUEUE_SEL: u64 = 0x030;
pub const REG_QUEUE_NUM_MAX: u64 = 0x034;
pub const REG_QUEUE_NUM: u64 = 0x038;
pub const REG_QUEUE_NOTIFY: u64 = 0x050;
pub const REG_QUEUE_READY: u64 = 0x044;
pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
pub const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
pub const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
pub const REG_QUEUE_DEVICE_LOW: u64 = 0x0A0;
pub const REG_QUEUE_DEVICE_HIGH: u64 = 0x0A4;
pub const REG_STATUS: u64 = 0x070;
pub const REG_CONFIG_GENERATION: u64 = 0x0FC;

// ─── Magic value and device IDs ───

pub const MAGIC_VALUE: u32 = 0x74726976; // "virt"
pub const DEVICE_ID_NET: u32 = 1;
pub const DEVICE_ID_BLOCK: u32 = 2;
pub const VIRTIO_VERSION: u32 = 2;

// ─── Status bits (section 4.2.2) ───

pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_FAILED: u32 = 128;

// ─── Virtqueue descriptor flags (section 2.6.4.3) ───

pub(crate) const VIRTQ_DESC_F_NEXT: u16 = 1;
pub(crate) const VIRTQ_DESC_F_WRITE: u16 = 2;

// ─── Block device constants (section 5.2) ───

/// Read request.
const VIRTIO_BLK_T_IN: u32 = 0;
/// Write request.
const VIRTIO_BLK_T_OUT: u32 = 1;
/// Flush request.
const VIRTIO_BLK_T_FLUSH: u32 = 4;
/// Operation completed successfully.
const VIRTIO_BLK_S_OK: u8 = 0;
/// I/O error.
const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Operation not supported.
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const SECTOR_SIZE: usize = 512;
const QUEUE_SIZE: u16 = 64;
/// Sentinel value for the status byte before the device writes the real status.
const STATUS_BYTE_SENTINEL: u8 = 0xFF;

/// Block device config space offsets (section 5.2.4).
#[cfg(target_os = "none")]
const BLOCK_CONFIG_CAPACITY_LO: u64 = 0x100;
#[cfg(target_os = "none")]
const BLOCK_CONFIG_CAPACITY_HI: u64 = 0x104;

/// Spin-loop iteration limit for bare-metal completion polling.
#[cfg(target_os = "none")]
const VIRTIO_POLL_LIMIT: u32 = 1_000_000;

/// Size of the mock MMIO region backing store (covers all register offsets).
#[cfg(test)]
const MOCK_REGION_SIZE: usize = 0x200;

// ─── MMIO register region abstraction ───

/// Opaque handle for a memory-mapped VirtIO register region.  On bare-metal
/// this is a pointer to physical MMIO space; in host tests it is backed by
/// the [`MockMmioRegion`].
pub trait MmioRegion: Send + Sync {
    fn read32(&self, offset: u64) -> u32;
    fn write32(&self, offset: u64, value: u32);
}

// ─── Transport layer ───

pub struct VirtIoMmio {
    regs: alloc::boxed::Box<dyn MmioRegion>,
    device_id: u32,
}

impl VirtIoMmio {
    pub fn new(regs: alloc::boxed::Box<dyn MmioRegion>) -> Self {
        Self { regs, device_id: 0 }
    }

    /// Discover the device: check the magic value and read device/vendor IDs.
    pub fn discover(&mut self) -> Result<()> {
        let magic = self.regs.read32(REG_MAGIC_VALUE);
        if magic != MAGIC_VALUE {
            return Err(Error::Unsupported);
        }

        let version = self.regs.read32(REG_VERSION);
        if version != VIRTIO_VERSION {
            return Err(Error::Unsupported);
        }

        self.device_id = self.regs.read32(REG_DEVICE_ID);
        let _vendor = self.regs.read32(REG_VENDOR_ID);
        Ok(())
    }

    /// Return a reference to the underlying MMIO register region.
    pub fn regs(&self) -> &dyn MmioRegion {
        &*self.regs
    }

    /// The device ID discovered during [`discover`].
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// Standard VirtIO initialization sequence (section 3.1):
    /// 1. Reset the device
    /// 2. Set ACKNOWLEDGE
    /// 3. Set DRIVER
    /// 4. Negotiate features
    /// 5. Set FEATURES_OK
    /// 6. Perform device-specific setup
    /// 7. Set DRIVER_OK
    ///
    /// Initialise the device, negotiating only the features present in
    /// `supported` and returning the negotiated feature set
    /// (`device_features & supported`).  Pass `!0` to accept all
    /// device-offered features (legacy behaviour).
    pub fn init_device_with_features(&self, supported: u32) -> Result<u32> {
        // Reset
        self.regs.write32(REG_STATUS, 0);

        // Acknowledge the device
        self.set_status(STATUS_ACKNOWLEDGE)?;

        // Indicate driver presence
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;

        // Negotiate features — only accept the subset the driver supports.
        self.regs.write32(REG_DRIVER_FEATURES_SEL, 0);
        let device_features = self.regs.read32(REG_DEVICE_FEATURES);
        let negotiated = device_features & supported;
        self.regs.write32(REG_DRIVER_FEATURES, negotiated);

        // Re-read and set FEATURES_OK
        self.regs.write32(REG_DRIVER_FEATURES_SEL, 0);
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK)?;

        // Check FEATURES_OK took
        let status = self.regs.read32(REG_STATUS);
        if status & STATUS_FEATURES_OK == 0 {
            return Err(Error::DeviceError);
        }

        // NOTE: DRIVER_OK is NOT set here.  The caller must invoke
        // `set_driver_ok()` after completing device-specific setup
        // (queue configuration, MAC read, etc.) per VirtIO §3.1.

        Ok(negotiated)
    }

    /// Set the DRIVER_OK status bit.  Must be called after queue
    /// configuration and device-specific setup (VirtIO §3.1 step 8).
    pub fn set_driver_ok(&self) -> Result<()> {
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK)
    }

    /// Initialise the device accepting all device-offered features.
    pub fn init_device(&self) -> Result<()> {
        self.init_device_with_features(!0).map(|_| ())
    }

    /// Select a virtqueue for subsequent configuration.
    pub fn select_queue(&self, index: u16) {
        self.regs.write32(REG_QUEUE_SEL, index as u32);
    }

    /// Return the maximum number of entries for the currently selected queue.
    pub fn queue_num_max(&self) -> u32 {
        self.regs.read32(REG_QUEUE_NUM_MAX)
    }

    /// Set the queue size and mark it ready, providing descriptor/driver/device
    /// ring addresses.
    pub fn configure_queue(
        &self,
        size: u32,
        desc_addr: u64,
        driver_addr: u64,
        device_addr: u64,
    ) -> Result<()> {
        self.regs.write32(REG_QUEUE_NUM, size);
        self.regs.write32(REG_QUEUE_DESC_LOW, desc_addr as u32);
        self.regs
            .write32(REG_QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
        self.regs.write32(REG_QUEUE_DRIVER_LOW, driver_addr as u32);
        self.regs
            .write32(REG_QUEUE_DRIVER_HIGH, (driver_addr >> 32) as u32);
        self.regs.write32(REG_QUEUE_DEVICE_LOW, device_addr as u32);
        self.regs
            .write32(REG_QUEUE_DEVICE_HIGH, (device_addr >> 32) as u32);
        self.regs.write32(REG_QUEUE_READY, 1);
        Ok(())
    }

    // ─── helpers ───

    fn set_status(&self, bits: u32) -> Result<()> {
        self.regs.write32(REG_STATUS, bits);
        // Let the write settle by reading back (MMIO may be posted).
        let _ = self.regs.read32(REG_STATUS);
        Ok(())
    }
}

// ─── Virtqueue descriptor and block request layouts ───

/// A VirtIO split-virtqueue descriptor (section 2.6.4.3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

/// An element in the used ring (section 2.6.4.5).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct VirtqUsedElem {
    pub(crate) id: u32,
    pub(crate) len: u32,
}

/// VirtIO block request header (section 5.2.6.1).
#[repr(C)]
struct VirtioBlkReqHeader {
    blk_type: u32,
    reserved: u32,
    sector: u64,
}

// ─── VirtQueue ───

/// A VirtIO split virtqueue owned by the driver.
///
/// In bare-metal use the three ring buffers are allocated in contiguous
/// physical memory and their addresses are given to the device via
/// `configure_queue`.  In host-side tests the mock device processes
/// descriptor chains synchronously by calling into the same in-process
/// `VirtQueue`.
pub struct VirtQueue {
    pub(crate) descriptors: alloc::vec::Vec<VirtqDesc>,
    pub(crate) avail_ring: alloc::vec::Vec<u16>,
    pub(crate) used_ring: alloc::vec::Vec<VirtqUsedElem>,
    /// Next entry the driver will write into the available ring.
    pub(crate) driver_avail_idx: u16,
    /// Next entry the device (or mock) has written into the used ring.
    pub(crate) device_used_idx: u16,
    /// Next entry the driver has already consumed from the used ring.
    pub(crate) driver_used_idx: u16,
    /// Head of the free-descriptor chain (linked through `next`).
    free_head: u16,
    /// Number of descriptors currently allocated.
    used_count: u16,
    queue_size: u16,
    // ── PCI page-aligned backing ──────────────────────────────
    // Non-null when the queue was created with `new_pci`.  The
    // page owns all three rings; the Vec fields are slices into
    // this page.  Freed on Drop; the Vecs MUST NOT be dropped.
    #[allow(dead_code)]
    queue_page: Option<*mut u8>,
    // Base pointers returned by ring_addrs() for the PCI case.
    // These point to the start of each ring structure (including
    // the spec-mandated flags/idx prefixes).
    #[allow(dead_code)]
    pci_desc_base: Option<*const u8>,
    #[allow(dead_code)]
    pci_avail_base: Option<*const u8>,
    #[allow(dead_code)]
    pci_used_base: Option<*const u8>,
}

impl Drop for VirtQueue {
    fn drop(&mut self) {
        if let Some(page) = self.queue_page {
            // PCI mode: the three Vec fields are slices into a single
            // 4 KiB page.  Swap them out with empty Vecs (which are safe
            // to deallocate) so the automatic drop glue has nothing to
            // free.  Then free the backing page.
            let empty_desc: alloc::vec::Vec<VirtqDesc> = alloc::vec::Vec::new();
            let empty_avail: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
            let empty_used: alloc::vec::Vec<VirtqUsedElem> = alloc::vec::Vec::new();
            let _old_d = core::mem::replace(&mut self.descriptors, empty_desc);
            let _old_a = core::mem::replace(&mut self.avail_ring, empty_avail);
            let _old_u = core::mem::replace(&mut self.used_ring, empty_used);
            // The old Vecs are now on the stack and will be dropped when
            // they go out of scope.  We must forget them to prevent that.
            core::mem::forget(_old_d);
            core::mem::forget(_old_a);
            core::mem::forget(_old_u);
            // Free the page.
            let layout = core::alloc::Layout::from_size_align(4096, 4096).unwrap();
            unsafe { alloc::alloc::dealloc(page, layout) };
        }
    }
}

// Safety: VirtQueue is always accessed under the transport Mutex in
// practice.  The raw pointers inside the PCI variant are stable and
// never shared across threads without synchronisation.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    pub fn new(queue_size: u16) -> Self {
        let qsz = queue_size as usize;
        let mut descriptors = alloc::vec![
            VirtqDesc { addr: 0, len: 0, flags: 0, next: 0 };
            qsz
        ];

        // Build free list: descriptor i points to i+1; last points to 0
        for (i, desc) in descriptors.iter_mut().enumerate() {
            desc.next = if i + 1 < qsz { (i + 1) as u16 } else { 0 };
        }

        let avail_ring = alloc::vec![0_u16; qsz];
        let used_ring = alloc::vec![VirtqUsedElem { id: 0, len: 0 }; qsz];

        Self {
            descriptors,
            avail_ring,
            used_ring,
            driver_avail_idx: 0,
            device_used_idx: 0,
            driver_used_idx: 0,
            free_head: 0,
            used_count: 0,
            queue_size,
            queue_page: None,
            pci_desc_base: None,
            pci_avail_base: None,
            pci_used_base: None,
        }
    }

    /// Create a VirtQueue whose three rings live in a single 4 KiB page,
    /// suitable for the PCI legacy QueuePFN mechanism.
    ///
    /// Layout (same as the PCI legacy specification):
    ///   offset 0      → descriptor table  (qsz × 16 B)
    ///   offset D      → available ring     (6 + 2×qsz B, 2‑B aligned)
    ///   offset 4096‑U → used ring          (6 + 8×qsz B, 4‑B aligned)
    pub fn new_pci(queue_size: u16) -> Self {
        let qsz = queue_size as usize;

        // Size computation.
        let desc_sz = qsz * core::mem::size_of::<VirtqDesc>(); // qsz × 16
        let avail_hdr = 4usize; // flags + idx
        let used_hdr = 4usize; // flags + idx
        let avail_data = qsz * 2; // u16 ring
        let used_data = qsz * core::mem::size_of::<VirtqUsedElem>(); // id + len
        let avail_sz = (avail_hdr + avail_data + 1) & !1usize; // 2‑B aligned
        let used_sz = (used_hdr + used_data + 3) & !3usize; // 4‑B aligned
        let total = desc_sz + avail_sz + used_sz;
        assert!(
            total <= 4096,
            "VirtQueue::new_pci: queue_size={} needs {} B > 4 KiB",
            queue_size,
            total
        );

        // Single page allocation.
        let layout = core::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let page: *mut u8 = unsafe { alloc::alloc::alloc(layout) };
        assert!(!page.is_null(), "VirtQueue PCI page alloc failed");
        unsafe { core::ptr::write_bytes(page, 0u8, 4096) };

        // Build slices that borrow from the page.
        // Safety: the page outlives the VirtQueue; the Vecs are never
        // deallocated individually — only the page is freed on Drop.
        let desc_ptr = page as *mut VirtqDesc;
        for i in 0..qsz {
            unsafe {
                (*desc_ptr.add(i)).next = if i + 1 < qsz { (i + 1) as u16 } else { 0 };
            }
        }
        let descriptors = unsafe { alloc::vec::Vec::from_raw_parts(desc_ptr, qsz, qsz) };

        let avail_ptr = unsafe { page.add(desc_sz) } as *mut u16;
        unsafe {
            core::ptr::write_volatile(avail_ptr, 0u16); // flags
            core::ptr::write_volatile(avail_ptr.add(1), 0u16); // idx
        }
        let avail_ring = unsafe { alloc::vec::Vec::from_raw_parts(avail_ptr.add(2), qsz, qsz) };

        let used_offset = 4096 - used_sz;
        let used_prefix = unsafe { page.add(used_offset) } as *mut u16;
        unsafe {
            core::ptr::write_volatile(used_prefix, 0u16); // flags
            core::ptr::write_volatile(used_prefix.add(1), 0u16); // idx
        }
        let used_ptr = unsafe { (page.add(used_offset)).add(used_hdr) } as *mut VirtqUsedElem;
        let used_ring = unsafe { alloc::vec::Vec::from_raw_parts(used_ptr, qsz, qsz) };

        Self {
            descriptors,
            avail_ring,
            used_ring,
            driver_avail_idx: 0,
            device_used_idx: 0,
            driver_used_idx: 0,
            free_head: 0,
            used_count: 0,
            queue_size,
            queue_page: Some(page),
            // ring_addrs returns pointers to structure starts (incl.
            // prefixes) for the PCI transport.
            pci_desc_base: Some(desc_ptr as *const u8),
            pci_avail_base: Some(avail_ptr as *const u8),
            pci_used_base: Some(used_prefix as *const u8),
        }
    }

    /// Allocate a free descriptor.  Returns `None` when the queue is full.
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.used_count >= self.queue_size {
            return None;
        }
        let idx = self.free_head;
        self.free_head = self.descriptors[idx as usize].next;
        // Clear all fields — stale values from a previous use of this slot
        // must not leak into the new descriptor (especially flags, which
        // alloc_chain / set_desc may otherwise retain NEXT spuriously).
        self.descriptors[idx as usize] = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        self.used_count += 1;
        Some(idx)
    }

    /// Return a descriptor to the free list.
    fn free_desc(&mut self, idx: u16) {
        // Clear the descriptor so stale values cannot leak on re-allocation
        // (alloc_desc also clears, but this is defence in depth for any
        // code path that might bypass alloc_desc).
        self.descriptors[idx as usize] = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: self.free_head,
        };
        self.free_head = idx;
        self.used_count = self.used_count.saturating_sub(1);
    }

    /// Allocate `count` descriptors linked into a chain.  Returns the head
    /// index on success; frees any already-allocated descriptors on failure.
    pub(crate) fn alloc_chain(&mut self, count: u16) -> Option<u16> {
        if count == 0 {
            return None;
        }
        let head = self.alloc_desc()?;
        let mut prev = head;
        for _ in 1..count {
            let next = match self.alloc_desc() {
                Some(n) => n,
                None => {
                    // Roll back
                    let mut cur = head;
                    loop {
                        let n = self.descriptors[cur as usize].next;
                        self.free_desc(cur);
                        if cur == prev {
                            break;
                        }
                        cur = n;
                    }
                    return None;
                }
            };
            self.descriptors[prev as usize].flags |= VIRTQ_DESC_F_NEXT;
            self.descriptors[prev as usize].next = next;
            prev = next;
        }
        Some(head)
    }

    /// Configure a descriptor's buffer address, length, and flags.
    pub(crate) fn set_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16) {
        let d = &mut self.descriptors[idx as usize];
        d.addr = addr;
        d.len = len;
        // Preserve NEXT and next field if already set by alloc_chain; OR in
        // the caller-supplied flags.
        d.flags = (d.flags & VIRTQ_DESC_F_NEXT) | (flags & !VIRTQ_DESC_F_NEXT);
        // If the caller explicitly set NEXT in its flags, ensure it sticks.
        if flags & VIRTQ_DESC_F_NEXT != 0 {
            d.flags |= VIRTQ_DESC_F_NEXT;
        }
    }

    /// Submit a descriptor chain by writing its head index to the available
    /// ring and advancing the driver-side index.  Also writes the new idx
    /// to the avail-ring structure memory so the hardware device can see it
    /// (PCI mode only; in standard/MMIO mode the device reads idx via a
    /// separate mechanism).
    pub(crate) fn submit(&mut self, head: u16) {
        let slot = (self.driver_avail_idx % self.queue_size) as usize;
        self.avail_ring[slot] = head;
        self.driver_avail_idx = self.driver_avail_idx.wrapping_add(1);
        // Write the new idx to the device-visible avail-ring structure.
        // Layout: [0] flags (2 B), [2] idx (2 B), [4] ring entries.
        // The avail_ring Vec starts at the entries; the prefix is before it.
        if let Some(base) = self.pci_avail_base {
            unsafe {
                core::ptr::write_volatile((base as *mut u16).add(1), self.driver_avail_idx);
            }
            // Verify the write took effect (debug).
            let readback = unsafe { core::ptr::read_volatile((base as *const u16).add(1)) };
            if self.driver_avail_idx <= 3 {
                // Only log the first few to avoid spam.
                crate::println!(
                    "[virtio] submit: avail_idx={} base=0x{:x} idx_addr=0x{:x} readback={}",
                    self.driver_avail_idx,
                    base as usize,
                    base as usize + 2,
                    readback
                );
            }
        }
        // Memory barrier: make descriptor and idx writes visible to the device
        // before a subsequent kick (QueueNotify).
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }

    /// Return the number of newly completed entries in the used ring (written
    /// by the device / mock but not yet consumed by the driver).
    pub(crate) fn completed_count(&self) -> u16 {
        self.device_used_idx.wrapping_sub(self.driver_used_idx)
    }

    /// Synchronise `device_used_idx` from the device-written `idx` field in
    /// the used-ring structure.  Must be called periodically on bare-metal
    /// so that [`completed_count`] reflects completions written by the
    /// hardware device.
    ///
    /// PCI mode (`new_pci`): the used-ring prefix fields (flags + idx) are
    /// at a known offset below the `used_ring` Vec base.
    /// Standard mode (`new`): no prefix is allocated; this is a no-op and
    /// the caller must use mock processing or interrupts.
    ///
    /// Only callers are the bare-metal virtio-net and virtio-gpu drivers,
    /// both of which are gated on `target_os = "none"`.
    #[cfg(target_os = "none")]
    pub(crate) fn sync_device_used_idx(&mut self) {
        // PCI mode: the idx is a le16 at offset 2 from the used-ring base.
        if let Some(base) = self.pci_used_base {
            let idx_ptr = unsafe { (base as *const u16).add(1) };
            let idx = unsafe { core::ptr::read_volatile(idx_ptr) };
            self.device_used_idx = idx;
        }
    }

    /// Return the PCI used-ring base address, for diagnostic purposes.
    #[allow(dead_code)]
    pub(crate) fn pci_used_base_addr(&self) -> Option<usize> {
        self.pci_used_base.map(|b| b as usize)
    }

    /// Return the maximum number of entries the queue can hold.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Return the number of descriptors currently allocated (in use).
    pub fn used_count(&self) -> u16 {
        self.used_count
    }

    /// Return raw pointers to the three ring buffers as `*const u8` so the
    /// transport layer can program the device registers.
    ///
    /// For PCI-backed queues (`new_pci`) the pointers point to the start of
    /// each ring structure including the spec-defined flags/idx prefix; for
    /// standard queues (`new`) they point to the Vec allocations directly.
    pub fn ring_addrs(&self) -> (*const u8, *const u8, *const u8) {
        if let (Some(d), Some(a), Some(u)) =
            (self.pci_desc_base, self.pci_avail_base, self.pci_used_base)
        {
            (d, a, u)
        } else {
            (
                self.descriptors.as_ptr() as *const u8,
                self.avail_ring.as_ptr() as *const u8,
                self.used_ring.as_ptr() as *const u8,
            )
        }
    }

    /// Consume one completion from the used ring, returning the descriptor
    /// chain head index.  Returns `None` when no completions are available.
    pub(crate) fn consume_completion(&mut self) -> Option<u16> {
        if self.completed_count() == 0 {
            return None;
        }
        let slot = (self.driver_used_idx % self.queue_size) as usize;
        let elem = self.used_ring[slot];
        self.driver_used_idx = self.driver_used_idx.wrapping_add(1);

        // Free the entire descriptor chain
        let mut cur = elem.id as u16;
        loop {
            let desc = self.descriptors[cur as usize];
            let has_next = desc.flags & VIRTQ_DESC_F_NEXT != 0;
            let next = desc.next;
            self.free_desc(cur);
            if !has_next {
                break;
            }
            cur = next;
        }

        Some(elem.id as u16)
    }
}

// ─── Block virtqueue processing (mock / test helper) ───

/// Process all pending block I/O requests from `queue` against the given
/// `storage` slice.  This function is the mock equivalent of the device
/// hardware: it reads descriptor chains from the available ring, performs
/// the requested read/write operations, and writes completions to the used
/// ring.
///
/// `storage` is indexed by sector number (LBA × 512 bytes).
pub fn process_block_virtqueue(queue: &mut VirtQueue, storage: &mut [u8]) -> Result<()> {
    // Determine how many new entries the driver has submitted since we last
    // looked.  In a real device this is `driver_avail_idx` from the avail
    // ring page; here the mock tracks its own view.
    let pending_start = queue.device_used_idx; // reuse as "device-seen avail idx"
    let pending_end = queue.driver_avail_idx;
    let pending = pending_end.wrapping_sub(pending_start);

    for offset in 0..pending {
        let avail_slot = ((pending_start.wrapping_add(offset)) % queue.queue_size) as usize;
        let head = queue.avail_ring[avail_slot];

        // Walk the descriptor chain looking for header (device-readable),
        // data buffer(s), and status byte (device-writable).
        let mut cur = head;
        let mut header: Option<VirtioBlkReqHeader> = None;
        let mut data_buf: Option<(*mut u8, usize)> = None;
        let mut status_buf: Option<*mut u8> = None;

        loop {
            let desc = &queue.descriptors[cur as usize];
            let is_write = desc.flags & VIRTQ_DESC_F_WRITE != 0;
            let has_next = desc.flags & VIRTQ_DESC_F_NEXT != 0;
            let next = desc.next;

            let ptr = desc.addr as *mut u8;

            if header.is_none() && !is_write {
                // First device-readable descriptor → block request header
                if desc.len as usize >= core::mem::size_of::<VirtioBlkReqHeader>() {
                    let hdr: VirtioBlkReqHeader =
                        unsafe { core::ptr::read_unaligned(ptr as *const VirtioBlkReqHeader) };
                    header = Some(hdr);
                }
            } else if is_write && desc.len == 1 {
                // Single-byte writable descriptor → status byte
                status_buf = Some(ptr);
            } else if data_buf.is_none() {
                // Data buffer
                data_buf = Some((ptr, desc.len as usize));
            }

            if !has_next {
                break;
            }
            cur = next;
        }

        // Execute the I/O
        let status_val = match (header, data_buf) {
            (Some(hdr), Some((data_ptr, data_len))) => {
                let sector_offset = hdr.sector as usize * SECTOR_SIZE;
                let end = sector_offset.checked_add(data_len).unwrap_or(0);
                if end > storage.len() {
                    VIRTIO_BLK_S_IOERR
                } else {
                    match hdr.blk_type {
                        VIRTIO_BLK_T_IN => {
                            // Read: copy from storage to data buffer
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    storage.as_ptr().add(sector_offset),
                                    data_ptr,
                                    data_len,
                                );
                            }
                            VIRTIO_BLK_S_OK
                        }
                        VIRTIO_BLK_T_OUT => {
                            // Write: copy from data buffer to storage
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data_ptr,
                                    storage.as_mut_ptr().add(sector_offset),
                                    data_len,
                                );
                            }
                            VIRTIO_BLK_S_OK
                        }
                        VIRTIO_BLK_T_FLUSH => VIRTIO_BLK_S_OK,
                        _ => VIRTIO_BLK_S_UNSUPP,
                    }
                }
            }
            // Flush requests have no data buffer — header alone is sufficient.
            (Some(hdr), None) if hdr.blk_type == VIRTIO_BLK_T_FLUSH => VIRTIO_BLK_S_OK,
            _ => VIRTIO_BLK_S_IOERR,
        };

        // Write status byte
        if let Some(status_ptr) = status_buf {
            unsafe {
                core::ptr::write_unaligned(status_ptr, status_val);
            }
        }

        // Complete: write to used ring
        let used_slot = (queue.device_used_idx % queue.queue_size) as usize;
        queue.used_ring[used_slot] = VirtqUsedElem {
            id: head as u32,
            len: 1, // one status byte written
        };
        queue.device_used_idx = queue.device_used_idx.wrapping_add(1);
    }

    Ok(())
}

// ─── VirtIO block driver ───

use crate::kernel::sync::Mutex;

/// A VirtIO block device that communicates through an MMIO transport and a
/// single virtqueue.  On bare-metal this would use DMA-able memory; in host
/// tests the mock device processes the virtqueue synchronously.
///
/// The `storage` field holds a copy of the device's block data for mock /
/// test use.  On real hardware this buffer is ignored — the physical device
/// owns the actual storage and the driver merely submits I/O requests.
pub struct VirtIoBlock {
    pub(crate) transport: VirtIoMmio,
    queue: Mutex<VirtQueue>,
    block_count: u64,
    // In mock mode (host) this holds device data; on bare-metal the
    // physical device owns its own storage and this field is unused.
    #[cfg_attr(target_os = "none", allow(dead_code))]
    storage: Mutex<alloc::vec::Vec<u8>>,
    health: Mutex<DeviceHealth>,
}

impl VirtIoBlock {
    /// Create a new VirtIO block driver with the given backing `storage`.
    ///
    /// The transport must have already completed `discover()` and
    /// `init_device()`.  `storage` must be large enough to cover
    /// `block_count` × 512 bytes.  Pass an empty `Vec` when running on
    /// real hardware (the device owns its own storage).
    pub fn new(transport: VirtIoMmio, block_count: u64, storage: alloc::vec::Vec<u8>) -> Self {
        let queue_size = QUEUE_SIZE; // small queue for simplicity
        Self {
            transport,
            queue: Mutex::new(VirtQueue::new(queue_size)),
            block_count,
            storage: Mutex::new(storage),
            health: Mutex::new(DeviceHealth::Healthy),
        }
    }

    /// Kick the device (write to QueueNotify) to signal that new descriptors
    /// are available.  On the mock this is a no-op because processing is
    /// synchronous.
    fn kick(&self) {
        self.transport.regs.write32(REG_QUEUE_NOTIFY, 0);
    }

    /// Downgrade device health on I/O error.
    /// Healthy → Degraded; Degraded or Failed stays as-is.
    fn downgrade_health_on_error(&self) {
        let mut health = self.health.lock();
        if *health == DeviceHealth::Healthy {
            *health = DeviceHealth::Degraded;
        }
    }

    /// Execute a block I/O request through the virtqueue.
    ///
    /// On host (test) builds the mock device processes the queue
    /// synchronously against the in-memory storage.  On bare-metal the
    /// driver polls the used ring until the hardware signals completion.
    ///
    /// `buffer` carries the data to write (`is_write=true`) or a buffer to
    /// fill on read (`is_write=false`).  It is `&[u8]` (not `&mut [u8]`)
    /// because the device accesses it through raw pointers which are
    /// valid for the synchronous duration of this call.
    fn do_io(&self, lba: u64, buffer: &[u8], is_write: bool) -> Result<()> {
        let mut queue = self.queue.lock();

        // Allocate 3 descriptors: header, data, status
        let head = queue.alloc_chain(3).ok_or(Error::DeviceError)?;

        // Descriptor indices within the chain
        let header_desc = head;
        let data_desc = queue.descriptors[header_desc as usize].next;
        let status_desc = queue.descriptors[data_desc as usize].next;

        // Build the request header on the stack (accessed by mock via raw
        // pointer — safe because mock runs synchronously before we return).
        let header = VirtioBlkReqHeader {
            blk_type: if is_write {
                VIRTIO_BLK_T_OUT
            } else {
                VIRTIO_BLK_T_IN
            },
            reserved: 0,
            sector: lba,
        };

        #[allow(unused_mut)]
        let mut status_byte: u8 = STATUS_BYTE_SENTINEL;

        // Configure descriptors
        queue.set_desc(
            header_desc,
            &header as *const VirtioBlkReqHeader as u64,
            core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            0, // device-readable (no WRITE flag); NEXT already set by alloc_chain
        );

        let data_flags = if is_write {
            0 // device reads data from buffer
        } else {
            VIRTQ_DESC_F_WRITE // device writes data to buffer
        };
        queue.set_desc(
            data_desc,
            buffer.as_ptr() as u64,
            buffer.len() as u32,
            data_flags,
        );

        queue.set_desc(
            status_desc,
            &status_byte as *const u8 as u64,
            1,
            VIRTQ_DESC_F_WRITE,
        );

        // Submit and process
        queue.submit(head);
        self.kick();

        // On host / test builds the mock device processes the queue
        // synchronously.  On bare-metal the driver polls the used ring
        // for hardware completion.
        #[cfg(not(target_os = "none"))]
        {
            let mut storage = self.storage.lock();
            process_block_virtqueue(&mut queue, &mut storage)?;
        }
        #[cfg(target_os = "none")]
        {
            // Drop the queue lock so poll_completion can re-acquire it.
            drop(queue);
            self.poll_completion()?;
            // Re-acquire to consume the completion below.
            queue = self.queue.lock();
        }

        // Consume completion
        let completed = queue.consume_completion().ok_or(Error::DeviceError)?;
        // completed should equal head
        let _ = completed;

        if status_byte != VIRTIO_BLK_S_OK {
            return Err(Error::DeviceError);
        }

        Ok(())
    }

    /// Issue a cache-flush request through the virtqueue.
    ///
    /// The flush request has no data payload — only the request header
    /// (with `blk_type = VIRTIO_BLK_T_FLUSH`) and a status byte.
    fn do_flush(&self) -> Result<()> {
        let mut queue = self.queue.lock();

        // A flush needs only 2 descriptors: header + status (no data).
        let head = queue.alloc_chain(2).ok_or(Error::DeviceError)?;

        let header_desc = head;
        let status_desc = queue.descriptors[header_desc as usize].next;

        let header = VirtioBlkReqHeader {
            blk_type: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        };

        #[allow(unused_mut)]
        let mut status_byte: u8 = 0xFF;

        queue.set_desc(
            header_desc,
            &header as *const VirtioBlkReqHeader as u64,
            core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            0, // device-readable
        );

        queue.set_desc(
            status_desc,
            &status_byte as *const u8 as u64,
            1,
            VIRTQ_DESC_F_WRITE,
        );

        queue.submit(head);
        self.kick();

        #[cfg(not(target_os = "none"))]
        {
            let mut storage = self.storage.lock();
            process_block_virtqueue(&mut queue, &mut storage)?;
        }
        #[cfg(target_os = "none")]
        {
            drop(queue);
            self.poll_completion()?;
            queue = self.queue.lock();
        }

        let completed = queue.consume_completion().ok_or(Error::DeviceError)?;
        let _ = completed;

        if status_byte != VIRTIO_BLK_S_OK {
            return Err(Error::DeviceError);
        }

        Ok(())
    }
}

impl BlockDevice for VirtIoBlock {
    fn name(&self) -> &str {
        "virtio-blk"
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn device_health(&self) -> DeviceHealth {
        *self.health.lock()
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        if *self.health.lock() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }

        if !buffer.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }
        let blocks = (buffer.len() / SECTOR_SIZE) as u64;
        let end = lba.checked_add(blocks).ok_or(Error::InvalidArgument)?;
        if end > self.block_count {
            return Err(Error::InvalidArgument);
        }

        if let Err(e) = self.do_io(lba, buffer, false) {
            self.downgrade_health_on_error();
            return Err(e);
        }
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        if *self.health.lock() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }

        if !data.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }
        let blocks = (data.len() / SECTOR_SIZE) as u64;
        let end = lba.checked_add(blocks).ok_or(Error::InvalidArgument)?;
        if end > self.block_count {
            return Err(Error::InvalidArgument);
        }

        if let Err(e) = self.do_io(lba, data, true) {
            self.downgrade_health_on_error();
            return Err(e);
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if *self.health.lock() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }

        if let Err(e) = self.do_flush() {
            self.downgrade_health_on_error();
            return Err(e);
        }
        Ok(())
    }
}

// ─── VirtIO driver (bare-metal device discovery) ───

use crate::kernel::drivers::{Driver, DriverCategory};

struct VirtIoDriver;

impl Driver for VirtIoDriver {
    fn name(&self) -> &'static str {
        "virtio"
    }

    fn category(&self) -> DriverCategory {
        DriverCategory::Bus
    }

    fn init(&self) -> Result<()> {
        // Driver registration is cheap; real hardware discovery is deferred
        // to `probe_boot_disk()` so boot can continue on machines without
        // a VirtIO block device.
        Ok(())
    }
}

/// Return the singleton VirtIO bus driver for registration with the
/// [`DriverManager`].
pub fn driver() -> alloc::sync::Arc<dyn Driver> {
    alloc::sync::Arc::new(VirtIoDriver)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
const VIRTIO_MMIO_STRIDE: usize = 0x200;
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
const VIRTIO_MMIO_STRIDE: usize = 0x1000;
#[cfg(all(
    target_os = "none",
    not(any(target_arch = "aarch64", target_arch = "riscv64"))
))]
const VIRTIO_MMIO_BASE: usize = 0x0A00_0000;
#[cfg(all(
    target_os = "none",
    not(any(target_arch = "aarch64", target_arch = "riscv64"))
))]
const VIRTIO_MMIO_STRIDE: usize = 0x200;
#[cfg(target_os = "none")]
const VIRTIO_MMIO_MAX_SLOTS: usize = 8;

/// Probe VirtIO MMIO devices (discovered via FDT) for a block device.
///
/// On platforms where the FDT provides VirtIO MMIO addresses (aarch64 and
/// riscv64 QEMU virt), we iterate the actual device list.  Falls back to a
/// blind scan of a fixed range when FDT info is unavailable.
#[cfg(target_os = "none")]
pub fn probe_boot_disk() -> Option<alloc::sync::Arc<dyn BlockDevice>> {
    // Try FDT-discovered devices first.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        let info = crate::arch::fdt::platform_info();
        if let (Some(base), Some(count), Some(stride)) = (
            info.virtio_mmio_base,
            info.virtio_mmio_count,
            info.virtio_mmio_stride,
        ) {
            for slot in 0..count {
                let addr = base + slot * stride;
                if let Some(block) = try_virtio_block_at(addr) {
                    return Some(block);
                }
            }
            return None;
        }
    }

    // Fallback: blind scan of a fixed MMIO window.
    for slot in 0..VIRTIO_MMIO_MAX_SLOTS {
        let addr = VIRTIO_MMIO_BASE + slot * VIRTIO_MMIO_STRIDE;
        if let Some(block) = try_virtio_block_at(addr) {
            return Some(block);
        }
    }
    None
}

/// Attempt to initialise a VirtIO block device at the given MMIO address.
/// Returns `None` if no valid block device is present.
#[cfg(target_os = "none")]
fn try_virtio_block_at(base: usize) -> Option<alloc::sync::Arc<dyn BlockDevice>> {
    let region = unsafe { BareMmioRegion::new(base) };
    let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));

    if transport.discover().is_err() {
        return None;
    }
    if transport.device_id() != DEVICE_ID_BLOCK {
        return None;
    }
    if transport.init_device().is_err() {
        return None;
    }

    let capacity_low = transport.regs.read32(BLOCK_CONFIG_CAPACITY_LO) as u64;
    let capacity_high = transport.regs.read32(BLOCK_CONFIG_CAPACITY_HI) as u64;
    let block_count = capacity_low | (capacity_high << 32);
    if block_count == 0 {
        return None;
    }

    let block = VirtIoBlock::new_bare(transport, block_count);
    if block.configure_bare_queue().is_err() {
        return None;
    }
    // Set DRIVER_OK after queue configuration (VirtIO §3.1 step 8).
    if block.transport.set_driver_ok().is_err() {
        return None;
    }

    Some(alloc::sync::Arc::new(block))
}

/// Host-side stub: no MMIO to scan.
#[cfg(not(target_os = "none"))]
pub fn probe_boot_disk() -> Option<alloc::sync::Arc<dyn BlockDevice>> {
    None
}

// ─── Bare-metal MMIO region ───

/// Memory-mapped I/O region backed by a raw physical address.  Used on
/// bare-metal to access VirtIO MMIO register space through volatile
/// pointer operations.
#[cfg(target_os = "none")]
pub struct BareMmioRegion {
    base: *mut u8,
}

#[cfg(target_os = "none")]
impl BareMmioRegion {
    /// Create a new MMIO region at the given physical base address.
    ///
    /// # Safety
    ///
    /// `base_addr` must point to a valid, accessible VirtIO MMIO register
    /// region that remains mapped for the lifetime of the returned value.
    pub unsafe fn new(base_addr: usize) -> Self {
        Self {
            base: base_addr as *mut u8,
        }
    }
}

// Safety: BareMmioRegion wraps a raw pointer to MMIO space.  The pointer is
// never deallocated and the region is valid for the entire kernel lifetime.
// Concurrent access is guarded by the Mutex in VirtIoBlock (or by the
// transport layer itself for MMIO registers that are device-synchronized).
#[cfg(target_os = "none")]
unsafe impl Send for BareMmioRegion {}
#[cfg(target_os = "none")]
unsafe impl Sync for BareMmioRegion {}

#[cfg(target_os = "none")]
impl MmioRegion for BareMmioRegion {
    fn read32(&self, offset: u64) -> u32 {
        unsafe { core::ptr::read_volatile(self.base.add(offset as usize) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        unsafe {
            core::ptr::write_volatile(self.base.add(offset as usize) as *mut u32, value);
        }
    }
}

// ─── VirtIO block driver: bare-metal extension ───

#[cfg(target_os = "none")]
impl VirtIoBlock {
    /// Create a new VirtIO block driver for bare-metal use.
    ///
    /// On real hardware the device owns its own storage; the driver
    /// merely submits I/O requests through the virtqueue.  No mock
    /// backing store is needed.
    pub fn new_bare(transport: VirtIoMmio, block_count: u64) -> Self {
        let queue_size = QUEUE_SIZE;
        Self {
            transport,
            // Use the prefixed ring layout (`new_pci`) so the hardware
            // device sees the spec-mandated avail/used idx fields and the
            // driver can sync the device-written used idx from ring memory.
            queue: Mutex::new(VirtQueue::new_pci(queue_size)),
            block_count,
            storage: Mutex::new(alloc::vec::Vec::new()),
            health: Mutex::new(DeviceHealth::Healthy),
        }
    }

    /// Configure the virtqueue on the device so it knows the ring
    /// addresses.  This must be called after construction and before
    /// the first I/O request.
    pub fn configure_bare_queue(&self) -> Result<()> {
        let queue = self.queue.lock();
        let (desc_ptr, avail_ptr, used_ptr) = queue.ring_addrs();
        self.transport.select_queue(0);
        self.transport.configure_queue(
            queue.queue_size() as u32,
            desc_ptr as u64,
            avail_ptr as u64,
            used_ptr as u64,
        )?;
        Ok(())
    }

    /// Poll the used ring until at least one completion is available
    /// or the spin-limit is exhausted.
    fn poll_completion(&self) -> Result<()> {
        let mut queue = self.queue.lock();
        for _ in 0..VIRTIO_POLL_LIMIT {
            // Refresh the device-written used index from the used-ring
            // prefix before checking for completions (the hardware writes
            // idx into guest RAM, not into our cached copy).
            queue.sync_device_used_idx();
            if queue.completed_count() > 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::TimedOut)
    }
}

// ─── Mock MMIO region for host-side testing ───

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use crate::kernel::sync::Mutex;

    pub struct MockMmioRegion {
        storage: Mutex<alloc::vec::Vec<u8>>,
    }

    impl MockMmioRegion {
        pub fn new() -> Self {
            // Allocate enough space for all register offsets including
            // device-specific config space (offset 0x100+).
            Self {
                storage: Mutex::new(alloc::vec![0_u8; MOCK_REGION_SIZE]),
            }
        }

        /// Pre-populate a register value (e.g. MAGIC_VALUE for discovery).
        pub fn set32(&self, offset: u64, value: u32) {
            let mut storage = self.storage.lock();
            let base = offset as usize;
            storage[base..base + 4].copy_from_slice(&value.to_le_bytes());
        }

        /// Read a register as a raw u32 for test assertions.
        #[allow(dead_code)]
        pub fn get32(&self, offset: u64) -> u32 {
            let storage = self.storage.lock();
            let base = offset as usize;
            u32::from_le_bytes(storage[base..base + 4].try_into().expect("u32 in bounds"))
        }
    }

    impl MmioRegion for MockMmioRegion {
        fn read32(&self, offset: u64) -> u32 {
            let storage = self.storage.lock();
            let base = offset as usize;
            u32::from_le_bytes(storage[base..base + 4].try_into().expect("u32 in bounds"))
        }

        fn write32(&self, offset: u64, value: u32) {
            let mut storage = self.storage.lock();
            let base = offset as usize;
            storage[base..base + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
}

// ─── tests ───

#[cfg(test)]
mod tests {
    use super::mock::MockMmioRegion;
    use super::*;

    fn make_block_device_region() -> MockMmioRegion {
        let region = MockMmioRegion::new();
        region.set32(REG_MAGIC_VALUE, MAGIC_VALUE);
        region.set32(REG_VERSION, VIRTIO_VERSION);
        region.set32(REG_DEVICE_ID, DEVICE_ID_BLOCK);
        region.set32(REG_VENDOR_ID, 0x1AF4); // Red Hat vendor
                                             // Advertise no optional features.
        region.set32(REG_DEVICE_FEATURES, 0);
        region.set32(REG_QUEUE_NUM_MAX, 128);
        region
    }

    #[test]
    fn discover_rejects_missing_magic() {
        let region = MockMmioRegion::new();
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        assert_eq!(transport.discover(), Err(Error::Unsupported));
    }

    #[test]
    fn discover_accepts_valid_block_device() {
        let region = make_block_device_region();
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        transport.discover().expect("discover block device");
        assert_eq!(transport.device_id(), DEVICE_ID_BLOCK);
    }

    #[test]
    fn init_device_transitions_through_status_states() {
        let region = make_block_device_region();
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        transport.discover().expect("discover");

        // Before init, status register should be 0 (reset).
        assert_eq!(transport.regs.read32(REG_STATUS), 0);

        transport.init_device().expect("init device");

        // init_device drives the state machine through Acknowledge →
        // Driver → FeaturesOK, but deliberately leaves DRIVER_OK unset
        // (device-specific setup must finish first, VirtIO §3.1 step 8).
        let status = transport.regs.read32(REG_STATUS);
        assert_eq!(
            status,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK
        );
        assert_eq!(status & STATUS_DRIVER_OK, 0);

        // Completing setup then publishes DRIVER_OK.
        transport.set_driver_ok().expect("set driver ok");
        let status = transport.regs.read32(REG_STATUS);
        assert!(
            status & STATUS_DRIVER_OK != 0,
            "expected DRIVER_OK, got status={status:#x}"
        );
    }

    #[test]
    fn queue_configuration_stores_addresses() {
        let region = make_block_device_region();
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        transport.discover().expect("discover");
        transport.init_device().expect("init");

        let max = transport.queue_num_max();
        assert_eq!(max, 128);

        transport.select_queue(0);
        transport
            .configure_queue(64, 0x1000, 0x2000, 0x3000)
            .expect("configure queue");

        assert_eq!(transport.regs.read32(REG_QUEUE_NUM), 64);
        assert_eq!(transport.regs.read32(REG_QUEUE_DESC_LOW), 0x1000);
        assert_eq!(transport.regs.read32(REG_QUEUE_DRIVER_LOW), 0x2000);
        assert_eq!(transport.regs.read32(REG_QUEUE_DEVICE_LOW), 0x3000);
        assert_eq!(transport.regs.read32(REG_QUEUE_READY), 1);
    }

    #[test]
    fn discover_rejects_wrong_version() {
        let region = make_block_device_region();
        region.set32(REG_VERSION, 1); // old spec
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        assert_eq!(transport.discover(), Err(Error::Unsupported));
    }

    // ─── VirtQueue unit tests ───

    #[test]
    fn virtqueue_alloc_free_cycle() {
        let mut vq = VirtQueue::new(8);
        // Allocate all 8 descriptors
        let mut indices = alloc::vec::Vec::new();
        for _ in 0..8 {
            let idx = vq.alloc_desc().expect("should allocate");
            indices.push(idx);
        }
        // Queue should be full now
        assert!(vq.alloc_desc().is_none());

        // Free half
        for &idx in &indices[..4] {
            vq.free_desc(idx);
        }
        // Should be able to allocate 4 more
        for _ in 0..4 {
            vq.alloc_desc().expect("should allocate after free");
        }
        assert!(vq.alloc_desc().is_none());
    }

    #[test]
    fn virtqueue_chain_alloc_and_rollback() {
        let mut vq = VirtQueue::new(4);
        // Allocate 3-descriptor chain
        let head = vq.alloc_chain(3).expect("chain alloc");
        assert_eq!(vq.used_count, 3);

        // Verify chain linking
        let d0 = vq.descriptors[head as usize];
        assert!(d0.flags & VIRTQ_DESC_F_NEXT != 0);
        let d1 = vq.descriptors[d0.next as usize];
        assert!(d1.flags & VIRTQ_DESC_F_NEXT != 0);
        let d2 = vq.descriptors[d1.next as usize];
        assert_eq!(d2.flags & VIRTQ_DESC_F_NEXT, 0);

        // Only 1 left — allocating another 3-chain should fail and roll back
        assert!(vq.alloc_chain(3).is_none());
        // used_count should still be 3 (rollback succeeded)
        assert_eq!(vq.used_count, 3);
    }

    #[test]
    fn virtqueue_submit_and_complete() {
        let mut vq = VirtQueue::new(8);

        // Allocate a 3-descriptor chain and submit
        let head = vq.alloc_chain(3).expect("alloc chain");
        vq.submit(head);
        assert_eq!(vq.driver_avail_idx, 1);
        assert_eq!(vq.avail_ring[0], head);

        // Manually inject a used-ring completion (simulating device response)
        vq.used_ring[0] = VirtqUsedElem {
            id: head as u32,
            len: 1,
        };
        vq.device_used_idx = 1;

        assert_eq!(vq.completed_count(), 1);
        let completed = vq.consume_completion().expect("should complete");
        assert_eq!(completed, head);
        assert_eq!(vq.used_count, 0); // chain freed
    }

    // ─── VirtIO block device tests ───

    fn make_block_driver(storage: alloc::vec::Vec<u8>) -> VirtIoBlock {
        let block_count = (storage.len() / SECTOR_SIZE) as u64;
        let region = make_block_device_region();
        let mut transport = VirtIoMmio::new(alloc::boxed::Box::new(region));
        transport.discover().expect("discover");
        transport.init_device().expect("init");
        VirtIoBlock::new(transport, block_count, storage)
    }

    #[test]
    fn virtio_block_read_sector_zero() {
        let mut storage = alloc::vec![0_u8; SECTOR_SIZE * 4];
        storage[0] = 0xAB;
        storage[1] = 0xCD;
        storage[511] = 0xEF;

        let block = make_block_driver(storage);

        let mut buf = [0_u8; SECTOR_SIZE];
        block.read_blocks(0, &mut buf).expect("read");

        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[1], 0xCD);
        assert_eq!(buf[511], 0xEF);
    }

    #[test]
    fn virtio_block_write_then_read() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 4];
        let block = make_block_driver(storage);

        // Write
        let data = [0x42_u8; SECTOR_SIZE];
        block.write_blocks(2, &data).expect("write");

        // Read back via read_blocks
        let mut buf = [0_u8; SECTOR_SIZE];
        block.read_blocks(2, &mut buf).expect("read back");

        assert_eq!(&buf[..], &data[..], "read must match written data");
    }

    #[test]
    fn virtio_block_rejects_out_of_bounds() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 2];
        let block = make_block_driver(storage);

        let mut buf = [0_u8; SECTOR_SIZE];
        // LBA == block_count is out of bounds
        assert_eq!(block.read_blocks(2, &mut buf), Err(Error::InvalidArgument));
        // LBA overflow
        assert_eq!(
            block.read_blocks(u64::MAX, &mut buf),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            block.write_blocks(u64::MAX, &buf),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn virtio_block_rejects_unaligned_buffer() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 4];
        let block = make_block_driver(storage);

        let mut buf = [0_u8; 100]; // not a multiple of 512
        assert_eq!(block.read_blocks(0, &mut buf), Err(Error::InvalidArgument));
        assert_eq!(block.write_blocks(0, &buf), Err(Error::InvalidArgument));
    }

    #[test]
    fn virtio_block_device_identity() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 8];
        let block = make_block_driver(storage);

        assert_eq!(block.name(), "virtio-blk");
        assert_eq!(block.block_count(), 8);
        assert!(!block.is_read_only());
    }

    #[test]
    fn virtio_block_starts_healthy() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 2];
        let block = make_block_driver(storage);

        assert_eq!(block.device_health(), DeviceHealth::Healthy);
    }

    #[test]
    fn virtio_block_flush_is_noop_on_healthy_device() {
        let storage = alloc::vec![0_u8; SECTOR_SIZE * 2];
        let block = make_block_driver(storage);

        assert_eq!(block.flush(), Ok(()));
    }
}
