//! src/kernel/memory/paging.rs
//!
//! Page-table model and mapping primitives for virtual-to-physical translation.

use alloc::vec::Vec;

use crate::kernel::memory::alloc_profiler::AllocProfiler;
use crate::{Error, Result};

pub const PAGE_SIZE: usize = 4096;

/// Advice hint for memory usage patterns (set via madvise).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdviceHint {
    #[default]
    Normal,
    Random,
    Sequential,
}

impl AdviceHint {
    /// Return a human-readable string for this advice hint.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Random => "random",
            Self::Sequential => "sequential",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    KernelHeap,
    Anonymous,
    Identity,
    DeviceMemory,
    /// Page allocated lazily on first access.  Initially mapped as
    /// not-present in hardware; the page-fault handler allocates a
    /// zeroed frame and makes it present.
    DemandPaged,
    /// Copy-on-write page: shared read-only until a write fault
    /// triggers a private copy.  Used for fork() optimisation.
    Cow,
    /// Shared memory page: mapped into multiple process address
    /// spaces, backed by a `SharedMemorySegment`.  Frames are
    /// managed by the shm registry, not by the frame refcount
    /// table.
    Shared,
    /// Locked page: pinned in physical memory, never swapped out.
    /// Corresponds to mlock/munlock (syscalls #131-132).
    Locked,
}

impl MappingKind {
    /// Return a human-readable string for this mapping kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelHeap => "kernel-heap",
            Self::Anonymous => "anonymous",
            Self::Identity => "identity",
            Self::DeviceMemory => "device-memory",
            Self::DemandPaged => "demand-paged",
            Self::Cow => "copy-on-write",
            Self::Shared => "shared",
            Self::Locked => "locked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions(u8);

impl PagePermissions {
    pub const READ: Self = Self(0b001);
    pub const WRITE: Self = Self(0b010);
    pub const EXECUTE: Self = Self(0b100);
    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);
    pub const READ_EXECUTE: Self = Self(Self::READ.0 | Self::EXECUTE.0);
    pub const READ_WRITE_EXECUTE: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0);

    /// Returns `true` if `self` includes all the permission bits set in `other`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// assert!(PagePermissions::READ_WRITE.contains(PagePermissions::READ));
    /// ```
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Return a three-character string representing the permission bits
    /// in the style of `ls` output (e.g. `"rw-"`, `"r-x"`).
    pub const fn as_rwx(self) -> &'static str {
        match self.0 {
            0b000 => "---",
            0b001 => "r--",
            0b010 => "-w-",
            0b011 => "rw-",
            0b100 => "--x",
            0b101 => "r-x",
            0b110 => "-wx",
            0b111 => "rwx",
            _ => "???",
        }
    }
}

impl core::ops::BitOr for PagePermissions {
    type Output = Self;
    fn bitor(self, other: Self) -> Self::Output {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOrAssign for PagePermissions {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MappingSnapshot {
    pub virtual_address: usize,
    pub physical_address: usize,
    #[allow(dead_code)]
    pub length: usize,
    #[allow(dead_code)]
    pub permissions: PagePermissions,
    pub kind: MappingKind,
    /// Whether the page has been accessed since the last clock-hand sweep.
    /// Used by the page reclamation clock algorithm.
    pub accessed: bool,
    /// Advice hint for memory usage (set via madvise).
    pub advice: AdviceHint,
}

#[derive(Debug, Clone, Copy)]
struct Mapping {
    virtual_address: usize,
    physical_address: usize,
    length: usize,
    permissions: PagePermissions,
    kind: MappingKind,
    /// Accessed bit for the clock page-reclamation algorithm.
    accessed: bool,
    /// Advice hint for memory usage (set via madvise).
    advice: AdviceHint,
}

pub struct PageTable {
    mappings: Vec<Mapping>,
    initialized: bool,
    /// Page table profiler (zero-cost when `alloc_profiler` feature is disabled).
    pub profiler: AllocProfiler,
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PageTable {
    /// Create an empty, uninitialised page table.
    ///
    /// No mappings can be added until [`init()`] is called.
    pub const fn new() -> Self {
        Self {
            mappings: Vec::new(),
            initialized: false,
            profiler: AllocProfiler::new(),
        }
    }

    /// Mark this page table as initialised and ready for use.
    ///
    /// Must be called before any `map_*` or `unmap` operation.  Calling
    /// `init` on an already-initialised table is idempotent.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Map an anonymous region of `length` bytes at `virtual_address`
    /// with the given `permissions`.
    ///
    /// This is a convenience wrapper around [`map_region_with_kind`]
    /// that uses [`MappingKind::Anonymous`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if any part of the requested
    /// range overlaps an existing mapping.
    pub fn map_region(
        &mut self,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        self.map_region_with_kind(virtual_address, length, permissions, MappingKind::Anonymous)
    }

    /// Map an anonymous region at `virtual_address` with a specific
    /// [`MappingKind`] and the given `permissions`.
    ///
    /// The physical address is set to the same value as `virtual_address`
    /// (identity mapping).  For a non-identity mapping use [`map_to_with_kind`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the range overlaps an existing
    /// mapping.
    pub fn map_region_with_kind(
        &mut self,
        virtual_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        self.map_to_with_kind(virtual_address, virtual_address, length, permissions, kind)
    }

    /// Map a region with an explicit physical address.
    ///
    /// Creates an identity-like mapping that translates `virtual_address`
    /// to `physical_address`.  This is a convenience wrapper around
    /// [`map_to_with_kind`] that uses [`MappingKind::Anonymous`].
    ///
    /// # Parameters
    ///
    /// * `virtual_address` — start of the virtual range.
    /// * `physical_address` — start of the physical range.
    /// * `length` — size of the region in bytes.
    /// * `permissions` — page-level access rights.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] on overlap, or
    /// [`Error::InvalidArgument`] if page-offset consistency
    /// requirements are not met.
    pub fn map_to(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        length: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        self.map_to_with_kind(
            virtual_address,
            physical_address,
            length,
            permissions,
            MappingKind::Anonymous,
        )
    }

    /// Map a virtual address range to a physical address range with a
    /// specific [`MappingKind`].
    ///
    /// This is the lowest-level mapping entry point.  All other mapping
    /// methods delegate here.
    ///
    /// # Parameters
    ///
    /// * `virtual_address` — start of the virtual range.
    /// * `physical_address` — start of the physical range.  The page
    ///   offset must match `virtual_address`'s page offset.
    /// * `length` — size of the region in bytes (rounded up to a page
    ///   boundary internally).
    /// * `permissions` — page-level access rights.
    /// * `kind` — semantic classification of the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the page table is not
    /// initialised, offsets are inconsistent, or arithmetic overflows.
    /// Returns [`Error::AlreadyExists`] on virtual address overlap.
    /// Returns [`Error::OutOfMemory`] if the mapping vector cannot
    /// grow.
    pub fn map_to_with_kind(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
        length: usize,
        permissions: PagePermissions,
        kind: MappingKind,
    ) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        // Normalize addresses/length to page boundaries with offset consistency checks.
        let (virtual_address, physical_address, length) =
            normalize_mapping(virtual_address, physical_address, length)?;

        // Reject overlapping virtual mappings to keep translation unambiguous.
        if self
            .mappings
            .iter()
            .any(|mapping| mapping.overlaps(virtual_address, length))
        {
            return Err(Error::AlreadyExists);
        }

        self.mappings
            .try_reserve(1)
            .map_err(|_| Error::OutOfMemory)?;
        self.mappings.push(Mapping {
            virtual_address,
            physical_address,
            length,
            permissions,
            kind,
            accessed: false,
            advice: AdviceHint::Normal,
        });
        self.profiler.inc_page_table_maps();
        Ok(())
    }

    /// Remove all mappings that intersect the range
    /// `[virtual_address, virtual_address + length)`.
    ///
    /// Partially-overlapping mappings are trimmed: the non-overlapping
    /// portions are preserved as separate entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping intersects the range.
    pub fn unmap(&mut self, virtual_address: usize, length: usize) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        let (unmap_start, unmap_length) = normalize_virtual_range(virtual_address, length)?;
        let unmap_end = range_end(unmap_start, unmap_length).ok_or(Error::InvalidArgument)?;
        let mut next = Vec::new();
        let replacement_capacity = self
            .mappings
            .len()
            .checked_add(1)
            .ok_or(Error::OutOfMemory)?;
        next.try_reserve(replacement_capacity)
            .map_err(|_| Error::OutOfMemory)?;

        let mut found = false;

        for mapping in self.mappings.iter().copied() {
            let mapping_end =
                range_end(mapping.virtual_address, mapping.length).ok_or(Error::InternalError)?;

            if unmap_start >= mapping_end || mapping.virtual_address >= unmap_end {
                // No overlap: keep the mapping as-is.
                next.push(mapping);
                continue;
            }

            found = true;

            if mapping.virtual_address < unmap_start {
                // Preserve prefix fragment left of removed range.
                next.push(Mapping {
                    length: unmap_start - mapping.virtual_address,
                    accessed: mapping.accessed,
                    ..mapping
                });
            }

            if unmap_end < mapping_end {
                // Preserve suffix fragment right of removed range.
                let removed_prefix = unmap_end - mapping.virtual_address;
                next.push(Mapping {
                    virtual_address: unmap_end,
                    physical_address: mapping.physical_address + removed_prefix,
                    length: mapping_end - unmap_end,
                    permissions: mapping.permissions,
                    kind: mapping.kind,
                    accessed: false,
                    advice: mapping.advice,
                });
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.mappings = next;
        self.profiler.inc_page_table_unmaps();
        Ok(())
    }

    /// Look up the physical address and permissions for the given virtual
    /// address.
    ///
    /// Returns `None` if the address is not covered by any mapping.
    pub fn lookup(&self, address: usize) -> Option<(usize, PagePermissions)> {
        self.lookup_mapping(address)
            .map(|(physical, permissions, _)| (physical, permissions))
    }

    /// Look up the physical address, permissions, and mapping kind for
    /// the given virtual address.
    ///
    /// This is the detailed variant of [`lookup()`] that also returns
    /// the [`MappingKind`].
    ///
    /// Returns `None` if the address is not covered by any mapping.
    pub fn lookup_mapping(&self, address: usize) -> Option<(usize, PagePermissions, MappingKind)> {
        self.profiler.inc_page_table_lookups();
        self.mappings.iter().find_map(|mapping| {
            let start = mapping.virtual_address;
            let end = range_end(start, mapping.length)?;

            if (start..end).contains(&address) {
                let offset = address - start;
                Some((
                    mapping.physical_address + offset,
                    mapping.permissions,
                    mapping.kind,
                ))
            } else {
                None
            }
        })
    }

    /// Return the total number of active mappings in this page table.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Return a snapshot of all current mappings for bulk operations
    /// (e.g., page reclamation scanning).
    pub fn mappings_snapshot(&self) -> alloc::vec::Vec<MappingSnapshot> {
        self.mappings
            .iter()
            .map(|m| MappingSnapshot {
                virtual_address: m.virtual_address,
                physical_address: m.physical_address,
                length: m.length,
                permissions: m.permissions,
                kind: m.kind,
                accessed: m.accessed,
                advice: m.advice,
            })
            .collect()
    }

    /// Mark the mapping at `virtual_address` as accessed (used by the
    /// clock page-reclamation algorithm to detect recently-used pages).
    /// Returns `true` if the mapping was found and marked.
    pub fn mark_accessed_va(&mut self, virtual_address: usize) -> bool {
        let page_addr = align_down(virtual_address);
        if let Some(mapping) = self
            .mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
        {
            mapping.accessed = true;
            true
        } else {
            false
        }
    }

    /// Clear the accessed bit on the mapping at `virtual_address`.
    /// Returns the previous accessed value, or `None` if not found.
    pub fn clear_accessed_va(&mut self, virtual_address: usize) -> Option<bool> {
        let page_addr = align_down(virtual_address);
        self.mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
            .map(|mapping| {
                let was = mapping.accessed;
                mapping.accessed = false;
                was
            })
    }

    /// Return the number of mappings of a given `kind`.
    pub fn mapping_count_by_kind(&self, kind: MappingKind) -> usize {
        self.mappings.iter().filter(|m| m.kind == kind).count()
    }

    /// Replace the `kind` of an existing mapping, keeping address, physical
    /// address, length, and permissions unchanged.
    pub fn replace_mapping_kind(
        &mut self,
        virtual_address: usize,
        kind: MappingKind,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
            .ok_or(Error::NotFound)?;
        mapping.kind = kind;
        Ok(())
    }

    /// Replace the `advice` of an existing mapping (set via madvise).
    pub fn replace_mapping_advice(
        &mut self,
        virtual_address: usize,
        advice: AdviceHint,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
            .ok_or(Error::NotFound)?;
        mapping.advice = advice;
        Ok(())
    }

    /// Replace the `permissions` of an existing mapping, keeping address,
    /// physical address, length, and kind unchanged.
    ///
    /// Used during fork() to downgrade parent pages from RW to R when they
    /// become CoW-shared with the child.
    pub fn replace_mapping_permissions(
        &mut self,
        virtual_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
            .ok_or(Error::NotFound)?;
        mapping.permissions = permissions;
        Ok(())
    }

    /// Replace the physical address of an existing mapping, keeping address,
    /// length, permissions, and kind unchanged.
    ///
    /// Used by memory compaction when a frame is relocated to a new physical
    /// address.  The new address must be page-aligned.
    pub fn replace_mapping_phys(
        &mut self,
        virtual_address: usize,
        physical_address: usize,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.virtual_address == page_addr)
            .ok_or(Error::NotFound)?;
        mapping.physical_address = align_down(physical_address);
        Ok(())
    }
}

impl Mapping {
    fn overlaps(&self, start: usize, length: usize) -> bool {
        let Some(self_end) = range_end(self.virtual_address, self.length) else {
            return true;
        };
        let Some(end) = range_end(start, length) else {
            return true;
        };

        self.virtual_address < end && start < self_end
    }
}

fn normalize_mapping(
    virtual_address: usize,
    physical_address: usize,
    length: usize,
) -> Result<(usize, usize, usize)> {
    let virtual_offset = virtual_address & (PAGE_SIZE - 1);
    let physical_offset = physical_address & (PAGE_SIZE - 1);
    // Require identical page offsets so VA->PA mapping preserves byte alignment.
    if virtual_offset != physical_offset {
        return Err(Error::InvalidArgument);
    }

    let (start, length) = normalize_virtual_range(virtual_address, length)?;
    let physical_start = align_down(physical_address);
    range_end(physical_start, length).ok_or(Error::InvalidArgument)?;
    Ok((start, physical_start, length))
}

fn normalize_virtual_range(virtual_address: usize, length: usize) -> Result<(usize, usize)> {
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    let start = align_down(virtual_address);
    let offset = virtual_address & (PAGE_SIZE - 1);
    let span = offset.checked_add(length).ok_or(Error::InvalidArgument)?;
    let length = align_up(span).ok_or(Error::InvalidArgument)?;
    range_end(start, length).ok_or(Error::InvalidArgument)?;
    Ok((start, length))
}

fn range_end(start: usize, length: usize) -> Option<usize> {
    start.checked_add(length)
}

const fn align_down(value: usize) -> usize {
    value & !(PAGE_SIZE - 1)
}

fn align_up(value: usize) -> Option<usize> {
    value.checked_add(PAGE_SIZE - 1).map(align_down)
}
