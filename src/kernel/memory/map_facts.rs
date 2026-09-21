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
        facts.ranges_are_disjoint().then_some(facts)
    }

    fn ranges_are_disjoint(&self) -> bool {
        for (index, first) in self.declared().enumerate() {
            for second in self.declared().skip(index + 1) {
                if first.start < second.end && second.start < first.end {
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
    /// Ranges are required to be disjoint, so at most one can match.
    pub(crate) fn classify(&self, address: usize) -> Option<RegionKind> {
        self.declared()
            .find(|region| region.contains(address))
            .map(|region| region.kind)
    }
}

#[cfg(test)]
mod tests {
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
}
