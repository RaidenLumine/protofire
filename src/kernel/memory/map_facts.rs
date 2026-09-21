// File: src/kernel/memory/map_facts.rs
// Purpose: the kernel's own mapping ranges, as one source of truth.
//
// What the kernel maps, and what each range is for, is currently worked out
// separately by the page plan, by each architecture's runtime table builder,
// and again by the fault-report classifier.  Three answers to one question is
// how they came to disagree — a plan that said "outside-kernel-plan" for an
// address the live tables covered, and tables built for a range nothing else
// agreed was the kernel's.
//
// This module is the answer in one place.  It is deliberately arch-neutral and
// dependency-free: callers hand it ranges, it validates them and answers
// questions about them, and nothing here allocates, because it is derived
// before the heap exists.

// Introduced as an unused skeleton: step 1b wires the consumers.  Removing
// this line is part of that step.
#![allow(dead_code)]

/// What a kernel range is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RegionKind {
    /// Kernel text.
    Text,
    /// Kernel read-only data.
    Rodata,
    /// Kernel initialised data.
    Data,
    /// Kernel zero-initialised data, which the heap and the frame pool live
    /// inside.
    Bss,
    /// The kernel heap.
    Heap,
    /// The frame pool the allocator hands frames out of.
    FramePool,
    /// The region kernel stacks are mapped in.
    StackWindow,
    /// Device MMIO windows.
    DeviceMmio,
}

/// One range of kernel address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Region {
    pub(crate) kind: RegionKind,
    /// Half-open: `start` is included, `end` is not.
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

impl Region {
    pub(crate) const fn new(
        kind: RegionKind,
        start: usize,
        end: usize,
        writable: bool,
        executable: bool,
    ) -> Self {
        Self {
            kind,
            start,
            end,
            writable,
            executable,
        }
    }

    pub(crate) const fn contains(&self, address: usize) -> bool {
        address >= self.start && address < self.end
    }
}

/// How many ranges the kernel may declare.
///
/// Fixed rather than growable: this is derived before the heap exists, and the
/// count is bounded by the list above.
pub(crate) const MAX_REGIONS: usize = 8;

/// The kernel's mapping ranges.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelMapFacts {
    regions: [Option<Region>; MAX_REGIONS],
    count: usize,
}

impl KernelMapFacts {
    pub(crate) const fn empty() -> Self {
        Self {
            regions: [None; MAX_REGIONS],
            count: 0,
        }
    }

    /// Build from the ranges the caller derived.
    ///
    /// Returns `None` when a range is empty, when there are more than
    /// [`MAX_REGIONS`] of them, or when two of them overlap.  A caller that
    /// cannot state the kernel's ranges consistently has a bug it should hear
    /// about at boot, not one to paper over later.
    pub(crate) fn from_ranges(ranges: &[Region]) -> Option<Self> {
        if ranges.is_empty() || ranges.len() > MAX_REGIONS {
            return None;
        }
        let mut facts = Self::empty();
        for region in ranges {
            if region.start >= region.end {
                return None;
            }
            facts.regions[facts.count] = Some(*region);
            facts.count += 1;
        }
        facts.ranges_are_consistent().then_some(facts)
    }

    /// Whether the declared ranges can all be true at once.
    ///
    /// Ranges must not overlap, with one exception: the kernel heap is a
    /// static array inside BSS, so `Heap` is contained in `Bss` by
    /// construction.  Allowing exactly that nesting keeps the facts a
    /// description of the real layout instead of a shape the layout has to
    /// satisfy — and anything else overlapping is still refused.
    fn ranges_are_consistent(&self) -> bool {
        for (index, first) in self.declared().enumerate() {
            for second in self.declared().skip(index + 1) {
                if !(first.start < second.end && second.start < first.end) {
                    continue; // no overlap at all
                }
                let nested = (second.start >= first.start && second.end <= first.end)
                    || (first.start >= second.start && first.end <= second.end);
                let bss_and_heap = matches!(
                    (first.kind, second.kind),
                    (RegionKind::Bss, RegionKind::Heap) | (RegionKind::Heap, RegionKind::Bss)
                );
                if !(nested && bss_and_heap) {
                    return false;
                }
            }
        }
        true
    }

    fn declared(&self) -> impl Iterator<Item = Region> + '_ {
        self.regions.iter().flatten().copied()
    }

    /// Every declared range, in the order the caller gave them.
    pub(crate) fn regions(&self) -> impl Iterator<Item = Region> + '_ {
        self.declared()
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// The first range declared for `kind`.
    pub(crate) fn region(&self, kind: RegionKind) -> Option<Region> {
        self.declared().find(|region| region.kind == kind)
    }

    /// What `address` belongs to, if it is kernel address space at all.
    ///
    /// The narrowest match wins, so an address in the heap answers `Heap` even
    /// though the heap also lies inside BSS.
    pub(crate) fn classify(&self, address: usize) -> Option<RegionKind> {
        self.declared()
            .filter(|region| region.contains(address))
            .min_by_key(|region| region.end - region.start)
            .map(|region| region.kind)
    }

    /// Addresses inside every region, for a caller that wants to check that
    /// the mapping it built actually covers them.
    ///
    /// [`MAX_PROBES`] evenly spaced samples per region, always including the
    /// first and last address.  Three points — first, middle, last — cannot
    /// see a gap inside six hundred megabytes of BSS, which is where this
    /// kernel's frame pool and its stacks live; a fixed budget of samples
    /// across each region is what makes the check able to answer at all.
    ///
    /// Allocation-free, like everything else here: the caller may be checking
    /// the tables before the heap exists.
    pub(crate) fn probe_addresses(&self) -> impl Iterator<Item = (RegionKind, usize)> + '_ {
        self.declared().flat_map(|region| {
            let length = region.end - region.start;
            let stride = (length / MAX_PROBES).max(1);
            let mut probes = [(region.kind, region.start); MAX_PROBES];
            for (index, slot) in probes.iter_mut().enumerate() {
                let address = region.start + index * stride;
                *slot = (region.kind, address.min(region.end - 1));
            }
            // The last address is always sampled, so a region is never checked
            // only up to whatever the stride happened to reach.
            probes[MAX_PROBES - 1] = (region.kind, region.end - 1);
            probes.into_iter()
        })
    }
}

/// Samples taken per region by [`KernelMapFacts::probe_addresses`].
pub(crate) const MAX_PROBES: usize = 64;

/// Where the facts live once they have been derived.
///
/// A `SyncUnsafeCell` in the same style as the kernel's other boot-time
/// tables rather than an atomic pointer: the value is written once, before any
/// second CPU runs, and read-only afterwards.  `INSTALLED` guards the
/// write-once rule so a later, differently-derived set cannot silently become
/// the answer for tables that were already built from the first.
static FACTS: crate::util::sync_unsafe_cell::SyncUnsafeCell<KernelMapFacts> =
    crate::util::sync_unsafe_cell::SyncUnsafeCell::new(KernelMapFacts::empty());
static INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Install the kernel's mapping facts.
///
/// Returns `true` when this call installed them, `false` when they were
/// already there.  The first derivation wins: rebuilding the answer after the
/// tables exist would let the facts describe something other than what was
/// built.
pub(crate) fn install(facts: KernelMapFacts) -> bool {
    if INSTALLED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return false;
    }
    unsafe {
        *FACTS.get() = facts;
    }
    true
}

/// The kernel's mapping facts, if they have been derived yet.
pub(crate) fn get() -> Option<&'static KernelMapFacts> {
    INSTALLED
        .load(core::sync::atomic::Ordering::Acquire)
        .then(|| unsafe { &*FACTS.get() })
}

/// The image ranges, in the order they appear in memory.
///
/// Every architecture derives the same five from its own linker symbols; this
/// is the one place that decides what they *mean* (read-only text, writable
/// data, and so on), so an architecture cannot end up describing a range
/// differently from the others.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ImageRanges {
    pub(crate) text: (usize, usize),
    pub(crate) rodata: (usize, usize),
    pub(crate) data: (usize, usize),
    pub(crate) bss: (usize, usize),
    pub(crate) heap: (usize, usize),
}

impl ImageRanges {
    /// The regions these ranges describe, ready for [`from_ranges`].
    ///
    /// [`from_ranges`]: Self::regions
    pub(crate) fn regions(&self) -> [Region; 5] {
        [
            Region::new(RegionKind::Text, self.text.0, self.text.1, false, true),
            Region::new(
                RegionKind::Rodata,
                self.rodata.0,
                self.rodata.1,
                false,
                false,
            ),
            Region::new(RegionKind::Data, self.data.0, self.data.1, true, false),
            Region::new(RegionKind::Bss, self.bss.0, self.bss.1, true, false),
            Region::new(RegionKind::Heap, self.heap.0, self.heap.1, true, false),
        ]
    }

    /// Validate and install in one step: what the architectures call.
    ///
    /// Returns `false` when the ranges are inconsistent (empty, out of order,
    /// overlapping) or when facts were already installed.  A caller that gets
    /// `false` at boot has a layout it did not expect, which is worth failing
    /// on rather than mapping something arbitrary.
    pub(crate) fn install(&self) -> bool {
        match KernelMapFacts::from_ranges(&self.regions()) {
            Some(facts) => install(facts),
            None => false,
        }
    }

    /// Validate and install the five image ranges, plus anything the
    /// architecture adds.
    ///
    /// The stack window is the reason this exists: it is a range the kernel
    /// reserves for its own stacks, and where it goes is an architecture's
    /// decision, not something derivable from the image.  Adding it to the same
    /// facts keeps one answer to "what does the kernel map" instead of an
    /// architecture's private side list.
    pub(crate) fn install_with(&self, extra: &[Region]) -> bool {
        let image = self.regions();
        if image.len() + extra.len() > MAX_REGIONS {
            return false;
        }
        let mut all = [image[0]; MAX_REGIONS];
        let mut count = 0usize;
        for region in image.into_iter().chain(extra.iter().copied()) {
            all[count] = region;
            count += 1;
        }
        match KernelMapFacts::from_ranges(&all[..count]) {
            Some(facts) => install(facts),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ImageRanges;
    use super::KernelMapFacts;
    use super::Region;
    use super::RegionKind;

    const TEXT: Region = Region::new(RegionKind::Text, 0x1000, 0x2000, false, true);
    const HEAP: Region = Region::new(RegionKind::Heap, 0x2000, 0x4000, true, false);

    #[test]
    fn classify_matches_half_open_ranges() {
        let facts = KernelMapFacts::from_ranges(&[TEXT, HEAP]).expect("valid ranges");
        assert_eq!(facts.classify(0x1000), Some(RegionKind::Text));
        assert_eq!(facts.classify(0x1fff), Some(RegionKind::Text));
        assert_eq!(facts.classify(0x2000), Some(RegionKind::Heap));
        assert_eq!(facts.classify(0x3fff), Some(RegionKind::Heap));
        assert_eq!(facts.classify(0x4000), None);
        assert_eq!(facts.classify(0x0fff), None);
    }

    #[test]
    fn overlapping_ranges_are_refused() {
        let overlapping = Region::new(RegionKind::Bss, 0x1800, 0x2800, true, false);
        assert!(KernelMapFacts::from_ranges(&[TEXT, overlapping]).is_none());
    }

    #[test]
    fn empty_ranges_and_empty_input_are_refused() {
        let empty = Region::new(RegionKind::Data, 0x2000, 0x2000, true, false);
        assert!(KernelMapFacts::from_ranges(&[empty]).is_none());
        assert!(KernelMapFacts::from_ranges(&[]).is_none());
    }

    #[test]
    fn regions_are_found_by_kind_and_order_is_kept() {
        let facts = KernelMapFacts::from_ranges(&[TEXT, HEAP]).expect("valid ranges");
        assert_eq!(facts.len(), 2);
        assert_eq!(facts.region(RegionKind::Heap), Some(HEAP));
        assert_eq!(facts.region(RegionKind::Text), Some(TEXT));
        assert_eq!(facts.region(RegionKind::StackWindow), None);
        let kinds: [RegionKind; 2] = {
            let mut kinds = [RegionKind::Text; 2];
            for (slot, region) in kinds.iter_mut().zip(facts.regions()) {
                *slot = region.kind;
            }
            kinds
        };
        assert_eq!(kinds, [RegionKind::Text, RegionKind::Heap]);
    }

    #[test]
    fn image_ranges_describe_the_five_standard_regions() {
        // The heap really is inside BSS in this kernel, so the standard shape
        // has to validate as it stands.
        let ranges = ImageRanges {
            text: (0x1000, 0x2000),
            rodata: (0x2000, 0x3000),
            data: (0x3000, 0x4000),
            bss: (0x4000, 0x6000),
            heap: (0x5000, 0x6000),
        };
        let regions = ranges.regions();
        assert_eq!(regions[0].kind, RegionKind::Text);
        assert!(!regions[0].writable && regions[0].executable);
        assert_eq!(regions[1].kind, RegionKind::Rodata);
        assert!(!regions[1].writable && !regions[1].executable);
        assert!(regions[2].writable && !regions[2].executable);
        assert!(regions[3].writable);
        assert_eq!(regions[4].kind, RegionKind::Heap);

        let facts = KernelMapFacts::from_ranges(&regions).expect("heap inside bss is the layout");
        assert_eq!(facts.classify(0x5000), Some(RegionKind::Heap));
        assert_eq!(facts.classify(0x4500), Some(RegionKind::Bss));
        assert_eq!(facts.classify(0x6000), None);
    }

    #[test]
    fn image_ranges_reject_a_layout_that_overlaps() {
        // `bss` and `data` overlapping is not a shape the kernel has; only the
        // heap-inside-BSS nesting is allowed.
        let ranges = ImageRanges {
            text: (0x1000, 0x2000),
            rodata: (0x2000, 0x3000),
            data: (0x3000, 0x4000),
            bss: (0x3800, 0x5000),
            heap: (0x5000, 0x6000),
        };
        assert!(!ranges.install());
    }

    #[test]
    fn probe_addresses_cover_each_region_including_its_edges() {
        use super::MAX_PROBES;

        let facts = KernelMapFacts::from_ranges(&[TEXT, HEAP]).expect("valid ranges");
        let probes: alloc::vec::Vec<(RegionKind, usize)> = facts.probe_addresses().collect();
        assert_eq!(probes.len(), 2 * MAX_PROBES);

        // Every probe is inside the range it names, and both edges are sampled.
        for (kind, address) in facts.probe_addresses() {
            assert_eq!(facts.classify(address), Some(kind));
        }
        assert!(probes.contains(&(RegionKind::Text, 0x1000)));
        assert!(probes.contains(&(RegionKind::Text, 0x1fff)));
        assert!(probes.contains(&(RegionKind::Heap, 0x2000)));
        assert!(probes.contains(&(RegionKind::Heap, 0x3fff)));
    }

    #[test]
    fn an_architecture_can_add_its_own_range() {
        // The stack window sits outside the image, and the facts must accept it
        // as one of the kernel's ranges rather than as an architecture's
        // private fact.
        let ranges = ImageRanges {
            text: (0x1000, 0x2000),
            rodata: (0x2000, 0x3000),
            data: (0x3000, 0x4000),
            bss: (0x4000, 0x6000),
            heap: (0x5000, 0x6000),
        };
        let window = Region::new(RegionKind::StackWindow, 0x8000, 0xa000, true, false);

        // A conflicting addition is refused.
        let overlapping = Region::new(RegionKind::DeviceMmio, 0x9000, 0xb000, true, false);
        assert!(!ranges.install_with(&[window, overlapping]));

        // A clean one is accepted, and classification sees it.
        let image = ranges.regions();
        let mut all = [window; 6];
        all[..image.len()].copy_from_slice(&image);
        let facts =
            KernelMapFacts::from_ranges(&all).expect("window outside the image is consistent");
        assert_eq!(facts.classify(0x8000), Some(RegionKind::StackWindow));
        assert_eq!(facts.classify(0x9fff), Some(RegionKind::StackWindow));
        assert_eq!(facts.classify(0xa000), None);
    }
}
