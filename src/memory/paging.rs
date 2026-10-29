//! src/memory/paging.rs
//!
//! Page-table model and mapping primitives for virtual-to-physical translation.

use alloc::vec::Vec;

use crate::memory::alloc_profiler::AllocProfiler;
use crate::Error;
use crate::Result;

/// The page size is the machine's, so the one definition is
/// [`crate::arch::PAGE_SIZE`]; this module re-exports it because the mapping
/// primitives below are written in terms of it.  It used to be defined here,
/// which made `kernel::smp` and `arch` itself reach up into the memory
/// subsystem for a number neither of them is about.
pub use crate::arch::PAGE_SIZE;

/// Advice hint for memory usage patterns (set via madvise).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdviceHint {
    #[default]
    Normal,
    Random,
    Sequential,
}

/// Which address space a software mapping belongs to.
///
/// The software page table is one table for the whole machine, and every user
/// process maps its image at the same addresses — the loader puts the entry at
/// `0x100001000` and the stack just below the top of the user half, in every
/// process.  Keying a mapping by virtual address alone therefore cannot tell
/// two processes apart: a spawn, an exec or an exit in one process would
/// rewrite or drop another's entries.
///
/// The identity is the address space's root table address, which is the same
/// number the hardware switches on: when the kernel asks "what does this
/// virtual address mean for the process I am running", it reads the root out
/// of `satp`/`TTBR0_EL1`/`CR3` and looks the mapping up under that.  Software
/// and hardware then agree by construction rather than by bookkeeping that has
/// to be kept in step.
///
/// [`KERNEL`](Self::KERNEL) is the exception: the kernel's heap, identity
/// window and device MMIO are mapped in every address space, so they match
/// every lookup.  That is a property of the layout, not a wildcard chosen for
/// convenience — those frames are the same frames in every root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AddressSpaceId(usize);

impl AddressSpaceId {
    /// The mappings every address space shares: the kernel heap, the identity
    /// window, device MMIO, and the kernel stacks.
    pub const KERNEL: Self = Self(0);

    /// The identity of the address space rooted at `root_table_address`.
    pub const fn from_root_table(root_table_address: usize) -> Self {
        Self(root_table_address)
    }

    /// The root table address this identity names, or 0 for the kernel.
    pub const fn root_table(self) -> usize {
        self.0
    }

    /// Does a mapping owned by this address space satisfy a lookup under
    /// `wanted`?
    ///
    /// The kernel's mappings are present in every root, so they answer for
    /// every address space.  A user mapping answers only for its own.
    pub const fn matches(self, wanted: Self) -> bool {
        wanted.0 == self.0 || self.0 == Self::KERNEL.0
    }
}

impl core::fmt::Display for AddressSpaceId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if *self == Self::KERNEL {
            formatter.write_str("kernel")
        } else {
            write!(formatter, "{:#x}", self.0)
        }
    }
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
    /// A kernel stack.
    ///
    /// Never reclaimed and never relocated.  The kernel writes to a stack
    /// while handling the very fault a missing mapping would raise, and a stack
    /// that moves leaves every frame pointer into it dangling — so this is not
    /// a label but the thing that keeps stacks out of the reclaim and
    /// relocation paths, which select their candidates by kind.
    KernelStack,
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
            Self::KernelStack => "kernel-stack",
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

    /// Returns `true` if `self` includes all the permission bits set in
    /// `other`.
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

// ── Rules a fork shares, whatever the page-table format ─────────────────
//
// The three things below were written three times — once in each
// architecture's MMU, byte for byte — and each time with its own copy of the
// tests that pin it.  What they decide is not the architecture's: a demoted
// page keeps its executable bit and loses only write, a range is inside a
// window or it is not, and rounding up refuses to wrap.  The encoding that
// follows from the answer is the architecture's, and that stays there.

/// The permissions a copy-on-write page takes in the child.
///
/// A page that was writable is demoted to read-only, because "shared" has to
/// mean the same frame on both sides and neither side may keep the write that
/// would reach it directly.  Execute is kept: a page can be writable and
/// executable in the parent, and dropping execute for the child would turn a
/// working code page into one that faults on its first instruction.
///
/// A page that was already read-only is returned unchanged, so this is
/// idempotent — which matters because a fork can inherit a page its parent
/// already shares with an ancestor, and demoting it twice must not change it.
pub const fn fork_child_permissions(permissions: PagePermissions) -> PagePermissions {
    if permissions.contains(PagePermissions::WRITE) {
        if permissions.contains(PagePermissions::EXECUTE) {
            PagePermissions::READ_EXECUTE
        } else {
            PagePermissions::READ
        }
    } else {
        permissions
    }
}

/// Round `value` up to a multiple of `align`, or `None` if that would wrap.
///
/// `None` rather than a wrapped answer because every caller here is computing
/// the end of a region it is about to validate: a wrapped end would read as a
/// tiny region instead of an impossible one.
pub const fn align_up_to(value: usize, align: usize) -> Option<usize> {
    match value.checked_add(align - 1) {
        Some(aligned) => Some(aligned & !(align - 1)),
        None => None,
    }
}

/// Is `[start, end)` contained within `[region_start, region_end)`?
///
/// The `start <= end` clause is what makes an inverted range fail rather than
/// pass vacuously — an empty range is inside every window, so a caller that
/// swapped its ends would otherwise be told its window is fine.
pub const fn range_within(
    start: usize,
    end: usize,
    region_start: usize,
    region_end: usize,
) -> bool {
    start >= region_start && end <= region_end && start <= end
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
    /// Which address space this mapping belongs to.
    pub owner: AddressSpaceId,
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
    /// Which address space this mapping belongs to.
    ///
    /// The table is machine-wide, so this is what keeps one process's user
    /// pages from being read, rewritten or reclaimed as another's.  Kernel
    /// mappings are [`AddressSpaceId::KERNEL`] and answer every lookup.
    owner: AddressSpaceId,
}

pub struct PageTable {
    mappings: Vec<Mapping>,
    initialized: bool,
    /// Page table profiler (zero-cost when `alloc_profiler` feature is
    /// disabled).
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
    /// (identity mapping).  For a non-identity mapping use
    /// [`map_to_with_kind`].
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
    /// * `physical_address` — start of the physical range.  The page offset
    ///   must match `virtual_address`'s page offset.
    /// * `length` — size of the region in bytes (rounded up to a page boundary
    ///   internally).
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
        self.map_to_owned(
            AddressSpaceId::KERNEL,
            virtual_address,
            physical_address,
            length,
            permissions,
            kind,
        )
    }

    /// Map a range on behalf of `owner`.
    ///
    /// The same contract as [`map_to_with_kind`](Self::map_to_with_kind), with
    /// the address space the mapping belongs to made explicit.  Overlap is
    /// checked against mappings visible to `owner` alone, so two processes can
    /// map the same virtual address without colliding — which they do, because
    /// every process's image and stack live at the same addresses.
    ///
    /// # Errors
    ///
    /// As [`map_to_with_kind`](Self::map_to_with_kind).
    pub fn map_to_owned(
        &mut self,
        owner: AddressSpaceId,
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
        // Only mappings this owner can see take part: kernel mappings answer
        // for every address space, and this owner's own answer for itself.
        if self.mappings.iter().any(|mapping| {
            mapping.owner.matches(owner) && mapping.overlaps(virtual_address, length)
        }) {
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
            owner,
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
        self.unmap_owned(AddressSpaceId::KERNEL, virtual_address, length)
    }

    /// Remove the mappings in a range that `owner` can see.
    ///
    /// A user mapping is visible only to the address space that owns it; the
    /// kernel's mappings are visible to every address space.  Removing a range
    /// on behalf of one process therefore leaves another process's entries
    /// alone even though they name the same virtual addresses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no visible mapping intersects the range.
    pub fn unmap_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
        length: usize,
    ) -> Result<()> {
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

            if !mapping.owner.matches(owner)
                || unmap_start >= mapping_end
                || mapping.virtual_address >= unmap_end
            {
                // Either another address space's mapping, or no overlap: keep
                // it as-is.
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
                    owner: mapping.owner,
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
    /// the given virtual address, as seen by the kernel.
    ///
    /// This is the detailed variant of [`lookup()`] that also returns
    /// the [`MappingKind`].  It answers for the kernel's own mappings; use
    /// [`lookup_mapping_owned`](Self::lookup_mapping_owned) for a process's.
    ///
    /// Returns `None` if the address is not covered by any mapping.
    pub fn lookup_mapping(&self, address: usize) -> Option<(usize, PagePermissions, MappingKind)> {
        self.lookup_mapping_owned(AddressSpaceId::KERNEL, address)
    }

    /// Look up an address as `owner` sees it.
    ///
    /// `owner`'s own mappings win; the kernel's mappings answer for every
    /// address space.  A user mapping that belongs to a different address
    /// space is not a match, even though it names the same virtual address.
    pub fn lookup_mapping_owned(
        &self,
        owner: AddressSpaceId,
        address: usize,
    ) -> Option<(usize, PagePermissions, MappingKind)> {
        self.profiler.inc_page_table_lookups();
        // Prefer the owner's own mapping.  Every process maps at the same
        // virtual addresses, so a kernel mapping and a user mapping can cover
        // the same address in different roots, and only the owner's entry
        // describes what the hardware under that root will do.
        let own = self
            .mappings
            .iter()
            .find(|mapping| mapping.owner == owner && self.mapping_covers(mapping, address));
        let chosen = own.or_else(|| {
            self.mappings.iter().find(|mapping| {
                mapping.owner == AddressSpaceId::KERNEL && self.mapping_covers(mapping, address)
            })
        })?;
        Some((
            chosen.physical_address + (address - chosen.virtual_address),
            chosen.permissions,
            chosen.kind,
        ))
    }

    fn mapping_covers(&self, mapping: &Mapping, address: usize) -> bool {
        let start = mapping.virtual_address;
        let end = match range_end(start, mapping.length) {
            Some(end) => end,
            None => return false,
        };
        (start..end).contains(&address)
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
                owner: m.owner,
            })
            .collect()
    }

    /// Mark the mapping at `virtual_address` as accessed (used by the
    /// clock page-reclamation algorithm to detect recently-used pages).
    /// Returns `true` if the mapping was found and marked.
    pub fn mark_accessed_va(&mut self, virtual_address: usize) -> bool {
        self.mark_accessed_owned(AddressSpaceId::KERNEL, virtual_address)
    }

    /// Mark `owner`'s mapping at `virtual_address` as accessed.
    pub fn mark_accessed_owned(&mut self, owner: AddressSpaceId, virtual_address: usize) -> bool {
        let page_addr = align_down(virtual_address);
        if let Some(mapping) = self
            .mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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
        self.clear_accessed_owned(AddressSpaceId::KERNEL, virtual_address)
    }

    /// Clear the accessed bit on `owner`'s mapping at `virtual_address`.
    pub fn clear_accessed_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
    ) -> Option<bool> {
        let page_addr = align_down(virtual_address);
        self.mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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
        self.replace_mapping_kind_owned(AddressSpaceId::KERNEL, virtual_address, kind)
    }

    /// Replace the kind of `owner`'s mapping at `virtual_address`.
    pub fn replace_mapping_kind_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
        kind: MappingKind,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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
        self.replace_mapping_advice_owned(AddressSpaceId::KERNEL, virtual_address, advice)
    }

    /// Replace the advice of `owner`'s mapping at `virtual_address`.
    pub fn replace_mapping_advice_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
        advice: AdviceHint,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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
        self.replace_mapping_permissions_owned(AddressSpaceId::KERNEL, virtual_address, permissions)
    }

    /// Replace the permissions of `owner`'s mapping at `virtual_address`.
    pub fn replace_mapping_permissions_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
        permissions: PagePermissions,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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
        self.replace_mapping_phys_owned(AddressSpaceId::KERNEL, virtual_address, physical_address)
    }

    /// Replace the physical address of `owner`'s mapping at `virtual_address`.
    pub fn replace_mapping_phys_owned(
        &mut self,
        owner: AddressSpaceId,
        virtual_address: usize,
        physical_address: usize,
    ) -> Result<()> {
        let page_addr = align_down(virtual_address);
        let mapping = self
            .mappings
            .iter_mut()
            .find(|m| m.owner == owner && m.virtual_address == page_addr)
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

/// What a fork's address-space clone hands back.
///
/// The clone itself is the architecture's — the table formats have nothing in
/// common — but what it must *produce* is the same three things on every
/// machine, and the pipeline that consumes them (`Process::fork`) is one
/// function.  Naming the shape here is what lets that pipeline be written once
/// and lets a reader see, at the type, that a clone which reports no demoted
/// pages is a clone that demoted nothing.
///
/// `Space` is the architecture's prepared process address space: the child's
/// own hierarchy, ready to be activated.
pub struct ForkedAddressSpace<Space> {
    /// The child's hierarchy, fully wired to its own tables.
    pub child: Space,
    /// Pages that became copy-on-write: `(virtual, physical, permissions)`.
    ///
    /// The parent's copies were demoted to read-only, so the same frame now
    /// answers for two processes and either side faults on its first store.
    /// A clone that demotes the child but not the parent reports nothing here,
    /// and that is the defect this list exists to make visible.
    pub shared_pages: Vec<(usize, usize, PagePermissions)>,
    /// Every user page in the child, for software page-table registration.
    pub child_pages: Vec<(usize, usize, PagePermissions)>,
}

impl<Space> ForkedAddressSpace<Space> {
    /// Assemble one.
    pub fn new(
        child: Space,
        shared_pages: Vec<(usize, usize, PagePermissions)>,
        child_pages: Vec<(usize, usize, PagePermissions)>,
    ) -> Self {
        Self {
            child,
            shared_pages,
            child_pages,
        }
    }
}

#[cfg(test)]
mod shared_rules_tests {
    use super::align_up_to;
    use super::fork_child_permissions;
    use super::range_within;
    use super::PagePermissions;

    /// A demoted page keeps execute and loses only write.
    ///
    /// This ran three times before — once in each architecture's MMU, with the
    /// same body — because `fork_child_permissions` lived in each of them.  The
    /// rule is not the architecture's: what the hardware does with the answer
    /// is, and that stays beside each table format.
    #[test]
    fn demotion_keeps_execute_and_drops_only_write() {
        let demoted = fork_child_permissions(PagePermissions::READ_WRITE_EXECUTE);
        assert!(demoted.contains(PagePermissions::EXECUTE));
        assert!(demoted.contains(PagePermissions::READ));
        assert!(!demoted.contains(PagePermissions::WRITE));
    }

    /// Demoting twice changes nothing.
    ///
    /// A fork can inherit a page its parent already shares with an ancestor,
    /// so the same page passes through this twice.  An implementation that
    /// dropped a bit each time would leave the grandchild executing a page
    /// that no longer says it may.
    #[test]
    fn demotion_is_idempotent() {
        for permissions in [
            PagePermissions::READ,
            PagePermissions::READ_WRITE,
            PagePermissions::READ_EXECUTE,
            PagePermissions::READ_WRITE_EXECUTE,
        ] {
            let once = fork_child_permissions(permissions);
            assert_eq!(fork_child_permissions(once), once, "{permissions:?}");
        }
    }

    /// A read-only page is returned unchanged, execute included.
    #[test]
    fn a_read_only_page_is_not_demoted() {
        assert_eq!(
            fork_child_permissions(PagePermissions::READ_EXECUTE),
            PagePermissions::READ_EXECUTE
        );
        assert_eq!(
            fork_child_permissions(PagePermissions::READ),
            PagePermissions::READ
        );
    }

    /// `align_up_to` rounds to the next multiple and refuses to wrap.
    #[test]
    fn align_up_rounds_up_and_refuses_to_overflow() {
        assert_eq!(align_up_to(0, 4096), Some(0));
        assert_eq!(align_up_to(1, 4096), Some(4096));
        assert_eq!(align_up_to(4096, 4096), Some(4096));
        assert_eq!(align_up_to(4097, 4096), Some(8192));
        assert_eq!(align_up_to(usize::MAX, 4096), None);
    }

    /// `range_within` refuses an inverted range instead of passing it
    /// vacuously, and refuses one byte outside on either side.
    #[test]
    fn range_within_rejects_outside_and_inverted_ranges() {
        assert!(range_within(10, 20, 0, 100));
        assert!(range_within(0, 100, 0, 100));
        assert!(!range_within(9, 20, 10, 100));
        assert!(!range_within(10, 101, 10, 100));
        assert!(!range_within(20, 10, 0, 100));
    }
}
